import Foundation
import Network
import Combine

/// A lightweight, asynchronous UDP DNS Server listening on port 53.
/// It intercepts DNS queries, blocks ad domains by returning 0.0.0.0, and forwards allowed queries to the upstream DNS.
class MiniDNSServer: ObservableObject {
    @Published var isRunning = false
    @Published var logs: [String] = []
    @Published var blockedCount = 0
    
    // Stats
    @Published var totalQueries = 0
    @Published var blockedQueries = 0
    @Published var allowedQueries = 0
    
    // Subscriptions, Whitelist and Upstream DNS settings
    @Published var isUpdatingList = false
    @Published var subscriptionURLs: [String] = []
    @Published var whitelistDomains: Set<String> = []
    @Published var upstreamDNS: String = "1.1.1.1"
    
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "com.antigravity.dnsserver.queue", qos: .userInitiated)
    private let port: UInt16 = 53
    
    var blockedDomains: Set<String> = []
    
    init() {
        loadConfig()
    }
    
    /// Starts the DNS server on UDP port 53.
    func start() {
        guard !isRunning else { return }
        
        do {
            let parameters = NWParameters.udp
            let listener = try NWListener(using: parameters, on: NWEndpoint.Port(rawValue: self.port)!)
            
            listener.stateUpdateHandler = { [weak self] (state: NWListener.State) in
                guard let self = self else { return }
                switch state {
                case .ready:
                    DispatchQueue.main.async {
                        self.isRunning = true
                        self.log("DNS Server listening on port \(self.port)")
                    }
                case .failed(let error):
                    DispatchQueue.main.async {
                        self.isRunning = false
                        self.log("DNS Server failed: \(error.localizedDescription)")
                    }
                    self.stop()
                case .cancelled:
                    DispatchQueue.main.async {
                        self.isRunning = false
                        self.log("DNS Server stopped.")
                    }
                default:
                    break
                }
            }
            
            listener.newConnectionHandler = { [weak self] connection in
                self?.handleConnection(connection)
            }
            
            self.listener = listener
            listener.start(queue: queue)
        } catch {
            self.log("Failed to start DNS: \(error.localizedDescription)")
        }
    }
    
    /// Stops the DNS server.
    func stop() {
        listener?.cancel()
        listener = nil
        DispatchQueue.main.async {
            self.isRunning = false
        }
    }
    
    // MARK: - Connections & Processing
    
    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: queue)
        connection.receiveMessage { [weak self] content, context, isComplete, error in
            guard let self = self else { return }
            if let error = error {
                print("DNS connection receive error: \(error.localizedDescription)")
                connection.cancel()
                return
            }
            
            if let data = content, !data.isEmpty {
                self.processDNSQuery(connection: connection, data: data)
            } else {
                connection.cancel()
            }
        }
    }
    
    private func processDNSQuery(connection: NWConnection, data: Data) {
        guard let parsed = extractDomainName(from: data) else {
            connection.cancel()
            return
        }
        
        let domain = parsed.domain
        let questionEndOffset = parsed.typeOffset
        
        // Check blocklist (exact match or subdomain matches)
        let isBlocked = shouldBlock(domain: domain)
        
        // Extract client IP address
        var clientIP = "Unknown"
        if case .hostPort(let host, _) = connection.endpoint {
            switch host {
            case .name(let name, _):
                clientIP = name
            case .ipv4(let ipv4Address):
                clientIP = "\(ipv4Address)"
            case .ipv6(let ipv6Address):
                clientIP = "\(ipv6Address)"
            @unknown default:
                clientIP = "\(host)"
            }
        }
        
        logQuery(domain: domain, blocked: isBlocked, clientIP: clientIP)
        incrementStats(blocked: isBlocked)
        
        if isBlocked {
            // Build response pointing to 0.0.0.0
            let responseData = buildBlockResponse(queryData: data, questionEndOffset: questionEndOffset)
            connection.send(content: responseData, completion: .contentProcessed { _ in
                connection.cancel()
            })
        } else {
            // Forward to upstream DNS
            forwardToUpstream(queryData: data) { [weak self] responseData in
                if let response = responseData {
                    connection.send(content: response, completion: .contentProcessed { _ in
                        connection.cancel()
                    })
                } else {
                    connection.cancel()
                }
            }
        }
    }
    
    func processDoHQuery(data: Data, clientIP: String, completion: @escaping (Data) -> Void) {
        guard let parsed = extractDomainName(from: data) else {
            completion(Data())
            return
        }
        
        let domain = parsed.domain
        let questionEndOffset = parsed.typeOffset
        
        let isBlocked = shouldBlock(domain: domain)
        
        logQuery(domain: domain, blocked: isBlocked, clientIP: clientIP)
        incrementStats(blocked: isBlocked)
        
        if isBlocked {
            let responseData = buildBlockResponse(queryData: data, questionEndOffset: questionEndOffset)
            completion(responseData)
        } else {
            forwardToUpstream(queryData: data) { responseData in
                if let response = responseData {
                    completion(response)
                } else {
                    completion(Data())
                }
            }
        }
    }
    
    private func shouldBlock(domain: String) -> Bool {
        let lowercaseDomain = domain.lowercased()
        
        // Whitelist checks (exact or subdomain)
        if whitelistDomains.contains(lowercaseDomain) {
            return false
        }
        for whitelisted in whitelistDomains {
            if lowercaseDomain.hasSuffix("." + whitelisted) {
                return false
            }
        }
        
        // Exact match in blocklist
        if blockedDomains.contains(lowercaseDomain) {
            return true
        }
        
        // Subdomain match (e.g. ad.doubleclick.net should be blocked if doubleclick.net is blocked)
        for blocked in blockedDomains {
            if lowercaseDomain.hasSuffix("." + blocked) {
                return true
            }
        }
        
        return false
    }
    
    private func forwardToUpstream(queryData: Data, completion: @escaping (Data?) -> Void) {
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(self.upstreamDNS), port: 53)
        let connection = NWConnection(to: endpoint, using: .udp)
        
        connection.stateUpdateHandler = { state in
            if case .failed(let error) = state {
                print("Upstream DNS connection failed: \(error.localizedDescription)")
                completion(nil)
                connection.cancel()
            }
        }
        
        connection.start(queue: queue)
        
        connection.send(content: queryData, completion: .contentProcessed { error in
            if let error = error {
                print("Failed to send DNS to upstream: \(error.localizedDescription)")
                completion(nil)
                connection.cancel()
                return
            }
            
            connection.receiveMessage { content, context, isComplete, error in
                if let error = error {
                    print("Failed to receive DNS response: \(error.localizedDescription)")
                    completion(nil)
                } else {
                    completion(content)
                }
                connection.cancel()
            }
        })
    }
    
    // MARK: - DNS Packet Parsing Helpers
    
    private func extractDomainName(from data: Data) -> (domain: String, typeOffset: Int)? {
        guard data.count > 12 else { return nil }
        
        var domainParts: [String] = []
        var offset = 12
        
        while offset < data.count {
            let labelLength = Int(data[offset])
            if labelLength == 0 {
                offset += 1
                break
            }
            
            // Handle DNS compression pointer
            if (labelLength & 0xC0) == 0xC0 {
                offset += 2
                break
            }
            
            offset += 1
            if offset + labelLength > data.count {
                return nil
            }
            
            let labelData = data.subdata(in: offset..<(offset + labelLength))
            if let label = String(data: labelData, encoding: .utf8) {
                domainParts.append(label)
            }
            
            offset += labelLength
        }
        
        let domain = domainParts.joined(separator: ".")
        return (domain, offset)
    }
    
    private func buildBlockResponse(queryData: Data, questionEndOffset: Int) -> Data {
        var response = Data()
        
        // 1. Transaction ID
        response.append(queryData.subdata(in: 0..<2))
        
        // 2. Flags: 0x8180 (Response, No Error)
        response.append(Data([0x81, 0x80]))
        
        // 3. Questions: 1, Answers: 1, Authority: 0, Additional: 0
        response.append(Data([0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]))
        
        // 4. Question Section (length = questionEndOffset + 4 bytes for Type and Class - 12 bytes header offset)
        let questionLength = (questionEndOffset + 4) - 12
        response.append(queryData.subdata(in: 12..<(12 + questionLength)))
        
        // 5. Answer Section (pointing to name at offset 12, Type A, Class IN, TTL 300, Length 4, IP 0.0.0.0)
        let answerBytes: [UInt8] = [
            0xC0, 0x0C,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x01, 0x2C,
            0x00, 0x04,
            0x00, 0x00, 0x00, 0x00
        ]
        response.append(Data(answerBytes))
        
        return response
    }
    
    // MARK: - DNS Configuration & Lists
    
    func block(domain: String) {
        let d = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !d.isEmpty else { return }
        blockedDomains.insert(d)
        saveConfig()
        log("Chặn tên miền: \(d)")
    }
    
    func unblock(domain: String) {
        let d = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        blockedDomains.remove(d)
        saveConfig()
        log("Bỏ chặn tên miền: \(d)")
    }
    
    func whitelist(domain: String) {
        let d = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !d.isEmpty else { return }
        whitelistDomains.insert(d)
        saveConfig()
        log("Thêm vào danh sách trắng: \(d)")
    }
    
    func unwhitelist(domain: String) {
        let d = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        whitelistDomains.remove(d)
        saveConfig()
        log("Bỏ chặn danh sách trắng: \(d)")
    }
    
    func addSubscription(url: String) {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let _ = URL(string: trimmed) else { return }
        if !subscriptionURLs.contains(trimmed) {
            subscriptionURLs.append(trimmed)
            saveConfig()
            log("Đã thêm nguồn bộ lọc: \(trimmed)")
        }
    }
    
    func removeSubscription(url: String) {
        if let idx = subscriptionURLs.firstIndex(of: url) {
            subscriptionURLs.remove(at: idx)
            saveConfig()
            log("Đã xóa nguồn bộ lọc: \(url)")
        }
    }
    
    func setUpstream(ip: String) {
        let trimmed = ip.trimmingCharacters(in: .whitespacesAndNewlines)
        let ipRegEx = "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"
        let ipTest = NSPredicate(format:"SELF MATCHES %@", ipRegEx)
        if ipTest.evaluate(with: trimmed) {
            self.upstreamDNS = trimmed
            saveConfig()
            log("Đã đổi DNS thượng nguồn thành: \(trimmed)")
        } else {
            log("IP DNS thượng nguồn không hợp lệ: \(trimmed)")
        }
    }
    
    func updateBlocklists() {
        guard !isUpdatingList else { return }
        isUpdatingList = true
        log("Bắt đầu cập nhật danh sách chặn từ các nguồn...")
        
        let urls = self.subscriptionURLs
        DispatchQueue.global(qos: .background).async {
            var newBlocked = Set<String>()
            let group = DispatchGroup()
            
            for urlString in urls {
                guard let url = URL(string: urlString) else { continue }
                group.enter()
                
                let task = URLSession.shared.dataTask(with: url) { data, response, error in
                    defer { group.leave() }
                    
                    if let error = error {
                        self.log("Lỗi tải \(urlString): \(error.localizedDescription)")
                        return
                    }
                    
                    guard let data = data, let content = String(data: data, encoding: .utf8) else {
                        self.log("Lỗi đọc dữ liệu từ \(urlString)")
                        return
                    }
                    
                    let lines = content.components(separatedBy: .newlines)
                    var parsedCount = 0
                    
                    for line in lines {
                        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                        if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("//") {
                            continue
                        }
                        
                        let parts = trimmed.split(separator: " ").map { String($0) }
                        if parts.count >= 2 {
                            let ip = parts[0]
                            let domain = parts[1].lowercased()
                            if (ip == "127.0.0.1" || ip == "0.0.0.0") && self.isValidDomain(domain) {
                                newBlocked.insert(domain)
                                parsedCount += 1
                            }
                        } else if parts.count == 1 {
                            var domain = parts[0].lowercased()
                            if domain.hasPrefix("||") && domain.hasSuffix("^") {
                                domain = String(domain.dropFirst(2).dropLast())
                            }
                            if self.isValidDomain(domain) {
                                newBlocked.insert(domain)
                                parsedCount += 1
                            }
                        }
                    }
                    self.log("Tải thành công \(urlString): \(parsedCount) tên miền")
                }
                task.resume()
            }
            
            group.wait()
            
            DispatchQueue.main.async {
                if !newBlocked.isEmpty {
                    self.blockedDomains = newBlocked
                    self.saveConfig()
                    self.log("Cập nhật thành công! Tổng số tên miền chặn: \(self.blockedDomains.count)")
                } else {
                    self.log("Không có tên miền mới nào được tải về.")
                }
                self.isUpdatingList = false
            }
        }
    }
    
    private func isValidDomain(_ domain: String) -> Bool {
        let domainRegEx = "^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,63}$"
        let domainTest = NSPredicate(format:"SELF MATCHES %@", domainRegEx)
        return domainTest.evaluate(with: domain)
    }
    
    func loadConfig() {
        let saved = UserDefaults.standard.stringArray(forKey: "BlockedDomains") ?? [
            "doubleclick.net",
            "pagead2.googlesyndication.com",
            "adservice.google.com",
            "ads.youtube.com",
            "telemetry.apple.com",
            "app-measurement.com"
        ]
        self.blockedDomains = Set(saved)
        
        let savedWhitelist = UserDefaults.standard.stringArray(forKey: "WhitelistDomains") ?? []
        self.whitelistDomains = Set(savedWhitelist)
        
        self.subscriptionURLs = UserDefaults.standard.stringArray(forKey: "SubscriptionURLs") ?? [
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        ]
        
        self.upstreamDNS = UserDefaults.standard.string(forKey: "UpstreamDNS") ?? "1.1.1.1"
        
        self.totalQueries = UserDefaults.standard.integer(forKey: "DNSTotalQueries")
        self.blockedQueries = UserDefaults.standard.integer(forKey: "DNSBlockedQueries")
        self.allowedQueries = UserDefaults.standard.integer(forKey: "DNSAllowedQueries")
        
        DispatchQueue.main.async {
            self.blockedCount = self.blockedDomains.count
        }
    }
    
    func saveConfig() {
        UserDefaults.standard.set(Array(blockedDomains), forKey: "BlockedDomains")
        UserDefaults.standard.set(Array(whitelistDomains), forKey: "WhitelistDomains")
        UserDefaults.standard.set(subscriptionURLs, forKey: "SubscriptionURLs")
        UserDefaults.standard.set(upstreamDNS, forKey: "UpstreamDNS")
        
        UserDefaults.standard.set(totalQueries, forKey: "DNSTotalQueries")
        UserDefaults.standard.set(blockedQueries, forKey: "DNSBlockedQueries")
        UserDefaults.standard.set(allowedQueries, forKey: "DNSAllowedQueries")
        
        DispatchQueue.main.async {
            self.blockedCount = self.blockedDomains.count
        }
    }
    
    func incrementStats(blocked: Bool) {
        totalQueries += 1
        if blocked {
            blockedQueries += 1
        } else {
            allowedQueries += 1
        }
        
        UserDefaults.standard.set(totalQueries, forKey: "DNSTotalQueries")
        UserDefaults.standard.set(blockedQueries, forKey: "DNSBlockedQueries")
        UserDefaults.standard.set(allowedQueries, forKey: "DNSAllowedQueries")
        
        DispatchQueue.main.async {
            self.objectWillChange.send()
        }
    }
    
    func resetStats() {
        totalQueries = 0
        blockedQueries = 0
        allowedQueries = 0
        
        UserDefaults.standard.set(0, forKey: "DNSTotalQueries")
        UserDefaults.standard.set(0, forKey: "DNSBlockedQueries")
        UserDefaults.standard.set(0, forKey: "DNSAllowedQueries")
        
        log("Đã lập lại chỉ số thống kê DNS.")
        DispatchQueue.main.async {
            self.objectWillChange.send()
        }
    }
    
    // MARK: - Logs
    
    func log(_ message: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        let timeStr = formatter.string(from: Date())
        let formattedMessage = "[\(timeStr)] \(message)"
        
        DispatchQueue.main.async {
            self.logs.append(formattedMessage)
            if self.logs.count > 100 {
                self.logs.removeFirst()
            }
        }
    }
    
    private func logQuery(domain: String, blocked: Bool, clientIP: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        let timeStr = formatter.string(from: Date())
        let status = blocked ? "❌ BLOCKED" : "✅ ALLOWED"
        let msg = "[\(timeStr)] [\(clientIP)] \(status) - \(domain)"
        
        DispatchQueue.main.async {
            self.logs.append(msg)
            if self.logs.count > 100 {
                self.logs.removeFirst()
            }
        }
    }
}
