import Foundation
import Network
import Combine

/// A lightweight, asynchronous UDP DNS Server listening on port 53.
/// It intercepts DNS queries, blocks ad domains by returning 0.0.0.0, and forwards allowed queries to 1.1.1.1.
class MiniDNSServer: ObservableObject {
    @Published var isRunning = false
    @Published var logs: [String] = []
    @Published var blockedCount = 0
    
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
            let listener = try NWListener(using: parameters, on: NWPort(rawValue: self.port)!)
            
            listener.stateUpdateHandler = { [weak self] state in
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
        
        logQuery(domain: domain, blocked: isBlocked)
        
        if isBlocked {
            // Build response pointing to 0.0.0.0
            let responseData = buildBlockResponse(queryData: data, questionEndOffset: questionEndOffset)
            connection.send(content: responseData, completion: .contentProcessed { _ in
                connection.cancel()
            })
        } else {
            // Forward to upstream DNS (1.1.1.1)
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
    
    private func shouldBlock(domain: String) -> Bool {
        let lowercaseDomain = domain.lowercased()
        
        // Exact match
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
        let endpoint = NWEndpoint.hostPort(host: "1.1.1.1", port: 53)
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
        DispatchQueue.main.async {
            self.blockedCount = self.blockedDomains.count
        }
    }
    
    func saveConfig() {
        UserDefaults.standard.set(Array(blockedDomains), forKey: "BlockedDomains")
        DispatchQueue.main.async {
            self.blockedCount = self.blockedDomains.count
        }
    }
    
    // MARK: - Logs
    
    private func log(_ message: String) {
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
    
    private func logQuery(domain: String, blocked: Bool) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        let timeStr = formatter.string(from: Date())
        let status = blocked ? "❌ BLOCKED" : "✅ ALLOWED"
        let msg = "[\(timeStr)] \(status) - \(domain)"
        
        DispatchQueue.main.async {
            self.logs.append(msg)
            if self.logs.count > 100 {
                self.logs.removeFirst()
            }
        }
    }
}
