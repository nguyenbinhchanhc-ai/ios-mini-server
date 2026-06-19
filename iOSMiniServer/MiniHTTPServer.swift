import Foundation
import Network
import Combine

extension Notification.Name {
    static let fileListDidChange = Notification.Name("FileListDidChange")
}

class MiniHTTPServer: ObservableObject {
    @Published var isRunning = false
    @Published var logs: [String] = []
    
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "com.antigravity.miniserver.queue", qos: .userInitiated)
    let port: UInt16
    weak var dnsServer: MiniDNSServer?
    
    init(port: UInt16 = 8080) {
        self.port = port
    }
    
    func start() {
        guard !isRunning else { return }
        
        do {
            let listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: self.port)!)
            
            listener.stateUpdateHandler = { [weak self] state in
                guard let self = self else { return }
                switch state {
                case .ready:
                    DispatchQueue.main.async {
                        self.isRunning = true
                        self.log("Server listening on port \(self.port)")
                    }
                case .failed(let error):
                    DispatchQueue.main.async {
                        self.isRunning = false
                        self.log("Server error: \(error.localizedDescription)")
                    }
                    self.stop()
                case .cancelled:
                    DispatchQueue.main.async {
                        self.isRunning = false
                        self.log("Server stopped.")
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
            self.log("Failed to start server: \(error.localizedDescription)")
        }
    }
    
    func stop() {
        listener?.cancel()
        listener = nil
        DispatchQueue.main.async {
            self.isRunning = false
        }
    }
    
    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: queue)
        readRequest(connection: connection, accumulatedData: Data())
    }
    
    private func readRequest(connection: NWConnection, accumulatedData: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, context, isComplete, error in
            guard let self = self else { return }
            
            if let error = error {
                self.log("Connection error: \(error.localizedDescription)")
                connection.cancel()
                return
            }
            
            var newData = accumulatedData
            if let content = content {
                newData.append(content)
            }
            
            if let headerRange = self.findHeaderSeparator(in: newData) {
                let headerData = newData.subdata(in: 0..<headerRange.lowerBound)
                let bodyData = newData.subdata(in: headerRange.upperBound..<newData.count)
                
                if let headers = String(data: headerData, encoding: .utf8) {
                    let contentLength = self.parseContentLength(from: headers)
                    
                    if bodyData.count >= contentLength {
                        let finalBody = bodyData.subdata(in: 0..<contentLength)
                        self.processRequest(connection: connection, headerString: headers, bodyData: finalBody)
                    } else {
                        if isComplete {
                            self.processRequest(connection: connection, headerString: headers, bodyData: bodyData)
                        } else {
                            self.readRequest(connection: connection, accumulatedData: newData)
                        }
                    }
                } else {
                    self.sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Invalid Headers".data(using: .utf8)!)
                }
            } else {
                if isComplete {
                    if !newData.isEmpty {
                        self.log("TCP Stream closed before HTTP headers were complete.")
                    }
                    connection.cancel()
                } else {
                    self.readRequest(connection: connection, accumulatedData: newData)
                }
            }
        }
    }
    
    private func findHeaderSeparator(in data: Data) -> Range<Data.Index>? {
        let separator = Data([13, 10, 13, 10])
        return data.range(of: separator)
    }
    
    private func parseContentLength(from headers: String) -> Int {
        for line in headers.components(separatedBy: "\r\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, parts[0].lowercased() == "content-length" {
                return Int(parts[1]) ?? 0
            }
        }
        return 0
    }
    
    private func processRequest(connection: NWConnection, headerString: String, bodyData: Data) {
        let lines = headerString.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing Request Line".data(using: .utf8)!)
            return
        }
        
        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2 else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Invalid Request Line".data(using: .utf8)!)
            return
        }
        
        let method = String(parts[0])
        let urlString = String(parts[1])
        
        guard let url = URL(string: urlString) else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Invalid URL".data(using: .utf8)!)
            return
        }
        
        let path = url.path
        log("\(method) \(path) [Body: \(bodyData.count) bytes]")
        
        if method == "GET" && path == "/" {
            let html = getDashboardHTML()
            sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/html; charset=utf-8", body: html.data(using: .utf8)!)
        } else if path == "/dns-query" {
            var clientIP = "Unknown"
            if case .hostPort(let host, _) = connection.endpoint {
                switch host {
                case .name(let name, _): clientIP = name
                case .ipv4(let ipv4): clientIP = "\(ipv4)"
                case .ipv6(let ipv6): clientIP = "\(ipv6)"
                @unknown default: clientIP = "\(host)"
                }
            }
            
            if method == "GET" {
                if let queryItems = URLComponents(string: urlString)?.queryItems,
                   let dnsParam = queryItems.first(where: { $0.name == "dns" })?.value,
                   let queryData = decodeBase64Url(dnsParam) {
                    dnsServer?.processDoHQuery(data: queryData, clientIP: clientIP) { [weak self] responseData in
                        self?.sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "application/dns-message", body: responseData)
                    }
                } else {
                    sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Bad DoH Request".data(using: .utf8)!)
                }
            } else if method == "POST" {
                dnsServer?.processDoHQuery(data: bodyData, clientIP: clientIP) { [weak self] responseData in
                    self?.sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "application/dns-message", body: responseData)
                }
            } else {
                sendResponse(connection: connection, statusCode: 405, statusText: "Method Not Allowed", body: "Method Not Allowed".data(using: .utf8)!)
            }
        } else if method == "GET" && path == "/dns/config" {
            let running = dnsServer?.isRunning ?? false
            let blocked = Array(dnsServer?.customBlockedDomains ?? [])
            let blockedCount = dnsServer?.blockedCount ?? 0
            let whitelist = Array(dnsServer?.whitelistDomains ?? [])
            let subscriptions = dnsServer?.subscriptionURLs ?? []
            let upstream = dnsServer?.upstreamDNS ?? "1.1.1.1"
            let logs = dnsServer?.logs ?? []
            let isUpdating = dnsServer?.isUpdatingList ?? false
            let stats: [String: Any] = [
                "total": dnsServer?.totalQueries ?? 0,
                "blocked": dnsServer?.blockedQueries ?? 0,
                "allowed": dnsServer?.allowedQueries ?? 0,
                "blockedPercent": (dnsServer?.totalQueries ?? 0) > 0 ? (Double(dnsServer?.blockedQueries ?? 0) / Double(dnsServer?.totalQueries ?? 1) * 100.0) : 0.0
            ]
            let responseObj: [String: Any] = [
                "running": running,
                "blocked": blocked,
                "blockedCount": blockedCount,
                "whitelist": whitelist,
                "subscriptions": subscriptions,
                "upstream": upstream,
                "logs": logs,
                "stats": stats,
                "isUpdating": isUpdating
            ]
            if let jsonData = try? JSONSerialization.data(withJSONObject: responseObj, options: []) {
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "application/json", body: jsonData)
            } else {
                sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "JSON encoding failed".data(using: .utf8)!)
            }
        } else if method == "POST" && path == "/dns/block" {
            if let queryItems = URLComponents(string: urlString)?.queryItems,
               let domain = queryItems.first(where: { $0.name == "domain" })?.value {
                dnsServer?.block(domain: domain)
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Blocked \(domain)".data(using: .utf8)!)
            } else {
                sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing 'domain' query".data(using: .utf8)!)
            }
        } else if method == "POST" && path == "/dns/unblock" {
            if let queryItems = URLComponents(string: urlString)?.queryItems,
               let domain = queryItems.first(where: { $0.name == "domain" })?.value {
                dnsServer?.unblock(domain: domain)
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Unblocked \(domain)".data(using: .utf8)!)
            } else {
                sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing 'domain' query".data(using: .utf8)!)
            }
        } else if method == "POST" && path == "/dns/whitelist/add" {
            if let queryItems = URLComponents(string: urlString)?.queryItems,
               let domain = queryItems.first(where: { $0.name == "domain" })?.value {
                dnsServer?.whitelist(domain: domain)
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Whitelisted \(domain)".data(using: .utf8)!)
            } else {
                sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing 'domain' query".data(using: .utf8)!)
            }
        } else if method == "POST" && path == "/dns/whitelist/remove" {
            if let queryItems = URLComponents(string: urlString)?.queryItems,
               let domain = queryItems.first(where: { $0.name == "domain" })?.value {
                dnsServer?.unwhitelist(domain: domain)
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Unwhitelisted \(domain)".data(using: .utf8)!)
            } else {
                sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing 'domain' query".data(using: .utf8)!)
            }
        } else if method == "POST" && path == "/dns/sub/add" {
            if let queryItems = URLComponents(string: urlString)?.queryItems,
               let url = queryItems.first(where: { $0.name == "url" })?.value {
                dnsServer?.addSubscription(url: url)
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Added subscription".data(using: .utf8)!)
            } else {
                sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing 'url' query".data(using: .utf8)!)
            }
        } else if method == "POST" && path == "/dns/sub/remove" {
            if let queryItems = URLComponents(string: urlString)?.queryItems,
               let url = queryItems.first(where: { $0.name == "url" })?.value {
                dnsServer?.removeSubscription(url: url)
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Removed subscription".data(using: .utf8)!)
            } else {
                sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing 'url' query".data(using: .utf8)!)
            }
        } else if method == "POST" && path == "/dns/sub/refresh" {
            dnsServer?.updateBlocklists()
            sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Refreshed subscriptions".data(using: .utf8)!)
        } else if method == "POST" && path == "/dns/upstream" {
            if let queryItems = URLComponents(string: urlString)?.queryItems,
               let ip = queryItems.first(where: { $0.name == "ip" })?.value {
                dnsServer?.setUpstream(ip: ip)
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Updated upstream DNS".data(using: .utf8)!)
            } else {
                sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing 'ip' query".data(using: .utf8)!)
            }
        } else if method == "POST" && path == "/dns/stats/reset" {
            dnsServer?.resetStats()
            sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Reset stats".data(using: .utf8)!)
        } else if method == "POST" && path == "/dns/toggle" {
            if let dns = dnsServer {
                if dns.isRunning {
                    dns.stop()
                } else {
                    dns.start()
                }
                let running = dns.isRunning
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "application/json", body: "{\"running\": \(running)}".data(using: .utf8)!)
            } else {
                sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "DNS Server not bound".data(using: .utf8)!)
            }
        } else if method == "GET" && path == "/files" {
            let files = listDocumentsFiles()
            do {
                let jsonData = try JSONSerialization.data(withJSONObject: files, options: [])
                sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "application/json", body: jsonData)
            } catch {
                sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "JSON encoding failed".data(using: .utf8)!)
            }
        } else if method == "GET" && path == "/download" {
            if let queryItems = URLComponents(string: urlString)?.queryItems,
               let fileName = queryItems.first(where: { $0.name == "name" })?.value {
                sendFileDownload(connection: connection, fileName: fileName)
            } else {
                sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing 'name' query".data(using: .utf8)!)
            }
        } else if method == "POST" && path == "/upload" {
            handleUpload(connection: connection, headers: headerString, bodyData: bodyData)
        } else if method == "POST" && path == "/delete" {
            if let queryItems = URLComponents(string: urlString)?.queryItems,
               let fileName = queryItems.first(where: { $0.name == "name" })?.value {
                deleteFile(connection: connection, fileName: fileName)
            } else {
                sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Missing 'name' query".data(using: .utf8)!)
            }
        } else {
            sendResponse(connection: connection, statusCode: 404, statusText: "Not Found", body: "Path not found".data(using: .utf8)!)
        }
    }
    
    // MARK: - Generic HTTP Handler (WebSocket Relay support)
    
    func handleHTTP(method: String, path: String, query: String, body: Data, headers: [String: String] = [:], completion: @escaping (Int, String, Data, [String: String]) -> Void) {
        log("Tunnel Request: \(method) \(path)")
        
        if method == "GET" && path == "/" {
            let html = getDashboardHTML()
            completion(200, "text/html; charset=utf-8", html.data(using: .utf8)!, [:])
        } else if path == "/dns-query" {
            let clientIP = headers["x-forwarded-for"]?.components(separatedBy: ",").first?.trimmingCharacters(in: .whitespaces) ?? "Tunnel"
            
            if method == "GET" {
                let queryParams = parseQuery(query)
                if let dnsParam = queryParams["dns"],
                   let queryData = decodeBase64Url(dnsParam) {
                    dnsServer?.processDoHQuery(data: queryData, clientIP: clientIP) { responseData in
                        completion(200, "application/dns-message", responseData, ["Access-Control-Allow-Origin": "*"])
                    }
                } else {
                    completion(400, "text/plain", "Bad DoH Request".data(using: .utf8)!, [:])
                }
            } else if method == "POST" {
                dnsServer?.processDoHQuery(data: body, clientIP: clientIP) { responseData in
                    completion(200, "application/dns-message", responseData, ["Access-Control-Allow-Origin": "*"])
                }
            } else {
                completion(405, "text/plain", "Method Not Allowed".data(using: .utf8)!, [:])
            }
        } else if method == "GET" && path == "/dns/config" {
            let running = dnsServer?.isRunning ?? false
            let blocked = Array(dnsServer?.customBlockedDomains ?? [])
            let blockedCount = dnsServer?.blockedCount ?? 0
            let whitelist = Array(dnsServer?.whitelistDomains ?? [])
            let subscriptions = dnsServer?.subscriptionURLs ?? []
            let upstream = dnsServer?.upstreamDNS ?? "1.1.1.1"
            let logs = dnsServer?.logs ?? []
            let isUpdating = dnsServer?.isUpdatingList ?? false
            let stats: [String: Any] = [
                "total": dnsServer?.totalQueries ?? 0,
                "blocked": dnsServer?.blockedQueries ?? 0,
                "allowed": dnsServer?.allowedQueries ?? 0,
                "blockedPercent": (dnsServer?.totalQueries ?? 0) > 0 ? (Double(dnsServer?.blockedQueries ?? 0) / Double(dnsServer?.totalQueries ?? 1) * 100.0) : 0.0
            ]
            let responseObj: [String: Any] = [
                "running": running,
                "blocked": blocked,
                "blockedCount": blockedCount,
                "whitelist": whitelist,
                "subscriptions": subscriptions,
                "upstream": upstream,
                "logs": logs,
                "stats": stats,
                "isUpdating": isUpdating
            ]
            if let jsonData = try? JSONSerialization.data(withJSONObject: responseObj, options: []) {
                completion(200, "application/json", jsonData, [:])
            } else {
                completion(500, "text/plain", "JSON failed".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/dns/block" {
            let queryParams = parseQuery(query)
            if let domain = queryParams["domain"] {
                dnsServer?.block(domain: domain)
                completion(200, "text/plain", "Blocked \(domain)".data(using: .utf8)!, [:])
            } else {
                completion(400, "text/plain", "Missing domain".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/dns/unblock" {
            let queryParams = parseQuery(query)
            if let domain = queryParams["domain"] {
                dnsServer?.unblock(domain: domain)
                completion(200, "text/plain", "Unblocked \(domain)".data(using: .utf8)!, [:])
            } else {
                completion(400, "text/plain", "Missing domain".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/dns/whitelist/add" {
            let queryParams = parseQuery(query)
            if let domain = queryParams["domain"] {
                dnsServer?.whitelist(domain: domain)
                completion(200, "text/plain", "Whitelisted \(domain)".data(using: .utf8)!, [:])
            } else {
                completion(400, "text/plain", "Missing domain".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/dns/whitelist/remove" {
            let queryParams = parseQuery(query)
            if let domain = queryParams["domain"] {
                dnsServer?.unwhitelist(domain: domain)
                completion(200, "text/plain", "Unwhitelisted \(domain)".data(using: .utf8)!, [:])
            } else {
                completion(400, "text/plain", "Missing domain".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/dns/sub/add" {
            let queryParams = parseQuery(query)
            if let url = queryParams["url"] {
                dnsServer?.addSubscription(url: url)
                completion(200, "text/plain", "Added subscription".data(using: .utf8)!, [:])
            } else {
                completion(400, "text/plain", "Missing url".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/dns/sub/remove" {
            let queryParams = parseQuery(query)
            if let url = queryParams["url"] {
                dnsServer?.removeSubscription(url: url)
                completion(200, "text/plain", "Removed subscription".data(using: .utf8)!, [:])
            } else {
                completion(400, "text/plain", "Missing url".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/dns/sub/refresh" {
            dnsServer?.updateBlocklists()
            completion(200, "text/plain", "Refreshed subscriptions".data(using: .utf8)!, [:])
        } else if method == "POST" && path == "/dns/upstream" {
            let queryParams = parseQuery(query)
            if let ip = queryParams["ip"] {
                dnsServer?.setUpstream(ip: ip)
                completion(200, "text/plain", "Updated upstream DNS".data(using: .utf8)!, [:])
            } else {
                completion(400, "text/plain", "Missing ip".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/dns/stats/reset" {
            dnsServer?.resetStats()
            completion(200, "text/plain", "Reset stats".data(using: .utf8)!, [:])
        } else if method == "POST" && path == "/dns/toggle" {
            if let dns = dnsServer {
                if dns.isRunning {
                    dns.stop()
                } else {
                    dns.start()
                }
                let running = dns.isRunning
                completion(200, "application/json", "{\"running\": \(running)}".data(using: .utf8)!, [:])
            } else {
                completion(500, "text/plain", "DNS Server not bound".data(using: .utf8)!, [:])
            }
        } else if method == "GET" && path == "/files" {
            let files = listDocumentsFiles()
            if let jsonData = try? JSONSerialization.data(withJSONObject: files, options: []) {
                completion(200, "application/json", jsonData, [:])
            } else {
                completion(500, "text/plain", "JSON failed".data(using: .utf8)!, [:])
            }
        } else if method == "GET" && path == "/download" {
            let queryParams = parseQuery(query)
            if let fileName = queryParams["name"] {
                let fileManager = FileManager.default
                guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
                    completion(500, "text/plain", "Docs offline".data(using: .utf8)!, [:])
                    return
                }
                let fileURL = documentsURL.appendingPathComponent(fileName)
                if fileManager.fileExists(atPath: fileURL.path) {
                    if let fileData = try? Data(contentsOf: fileURL) {
                        let mime = mimeTypeForPath(path: fileName)
                        let headers = ["Content-Disposition": "attachment; filename=\"\(fileName)\""]
                        completion(200, mime, fileData, headers)
                    } else {
                        completion(500, "text/plain", "Read failed".data(using: .utf8)!, [:])
                    }
                } else {
                    completion(404, "text/plain", "File not found".data(using: .utf8)!, [:])
                }
            } else {
                completion(400, "text/plain", "Missing name".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/upload" {
            if let boundary = extractBoundary(fromBody: body) {
                let result = handleUploadData(body: body, boundary: boundary)
                if result.success {
                    completion(200, "text/plain", "Upload successful".data(using: .utf8)!, [:])
                } else {
                    completion(500, "text/plain", (result.error ?? "Upload failed").data(using: .utf8)!, [:])
                }
            } else {
                completion(400, "text/plain", "Could not extract boundary".data(using: .utf8)!, [:])
            }
        } else if method == "POST" && path == "/delete" {
            let queryParams = parseQuery(query)
            if let fileName = queryParams["name"] {
                let fileManager = FileManager.default
                guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
                    completion(500, "text/plain", "Docs offline".data(using: .utf8)!, [:])
                    return
                }
                let fileURL = documentsURL.appendingPathComponent(fileName)
                if fileManager.fileExists(atPath: fileURL.path) {
                    do {
                        try fileManager.removeItem(at: fileURL)
                        log("Deleted: \(fileName)")
                        DispatchQueue.main.async {
                            NotificationCenter.default.post(name: .fileListDidChange, object: nil)
                        }
                        completion(200, "text/plain", "Deleted".data(using: .utf8)!, [:])
                    } catch {
                        completion(500, "text/plain", "Delete failed".data(using: .utf8)!, [:])
                    }
                } else {
                    completion(404, "text/plain", "File not found".data(using: .utf8)!, [:])
                }
            } else {
                completion(400, "text/plain", "Missing name".data(using: .utf8)!, [:])
            }
        } else {
            completion(404, "text/plain", "Not found".data(using: .utf8)!, [:])
        }
    }
    
    private func parseQuery(_ query: String) -> [String: String] {
        var params: [String: String] = [:]
        for item in query.components(separatedBy: "&") {
            let parts = item.split(separator: "=", maxSplits: 1).map { String($0) }
            if parts.count == 2 {
                let key = parts[0].removingPercentEncoding ?? parts[0]
                let val = parts[1].removingPercentEncoding ?? parts[1]
                params[key] = val
            }
        }
        return params
    }
    
    private func extractBoundary(fromBody body: Data) -> String? {
        let doubleDash = Data([45, 45])
        guard body.starts(with: doubleDash) else { return nil }
        
        let crlf = Data([13, 10])
        guard let crlfRange = body.range(of: crlf) else { return nil }
        
        let boundaryData = body.subdata(in: 2..<crlfRange.lowerBound)
        return String(data: boundaryData, encoding: .utf8)
    }
    
    private func handleUploadData(body: Data, boundary: String) -> (success: Bool, error: String?) {
        let boundaryStr = "--" + boundary
        guard let boundaryData = boundaryStr.data(using: .utf8) else {
            return (false, "Invalid boundary")
        }
        
        guard let firstBoundaryRange = body.range(of: boundaryData) else {
            return (false, "Boundary not found")
        }
        
        let partStart = firstBoundaryRange.upperBound + 2
        guard partStart < body.count else {
            return (false, "Empty body")
        }
        
        let searchRange = partStart..<body.count
        guard let nextBoundaryRange = body.range(of: boundaryData, options: [], in: searchRange) else {
            return (false, "Closing boundary not found")
        }
        
        let partData = body.subdata(in: partStart..<nextBoundaryRange.lowerBound)
        let doubleCRLF = Data([13, 10, 13, 10])
        guard let separatorRange = partData.range(of: doubleCRLF) else {
            return (false, "Part header missing separator")
        }
        
        let partHeaderData = partData.subdata(in: 0..<separatorRange.lowerBound)
        let fileData = partData.subdata(in: separatorRange.upperBound..<(partData.count - 2))
        
        guard let partHeaders = String(data: partHeaderData, encoding: .utf8),
              let filename = extractFilename(from: partHeaders) else {
            return (false, "Could not extract filename")
        }
        
        let fileManager = FileManager.default
        guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return (false, "Docs folder offline")
        }
        
        let fileURL = documentsURL.appendingPathComponent(filename)
        
        do {
            try fileData.write(to: fileURL)
            log("Saved file: \(filename) (\(fileData.count) bytes)")
            
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: .fileListDidChange, object: nil)
            }
            return (true, nil)
        } catch {
            return (false, "Write failed: \(error.localizedDescription)")
        }
    }
    
    private func getBoundary(from headers: String) -> String? {
        for line in headers.components(separatedBy: "\r\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, parts[0].lowercased() == "content-type" {
                let contentType = parts[1]
                if contentType.contains("multipart/form-data") {
                    let subparts = contentType.components(separatedBy: ";")
                    for subpart in subparts {
                        let keyVal = subpart.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                        if keyVal.count == 2, keyVal[0].lowercased() == "boundary" {
                            return keyVal[1]
                        }
                    }
                }
            }
        }
        return nil
    }
    
    private func extractFilename(from partHeaders: String) -> String? {
        for line in partHeaders.components(separatedBy: "\r\n") {
            if line.lowercased().contains("content-disposition") {
                let params = line.components(separatedBy: ";")
                for param in params {
                    let kv = param.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if kv.count == 2, kv[0].lowercased() == "filename" {
                        var filename = kv[1]
                        if filename.hasPrefix("\"") && filename.hasSuffix("\"") {
                            filename = String(filename.dropFirst().dropLast())
                        }
                        return filename.removingPercentEncoding ?? filename
                    }
                }
            }
        }
        return nil
    }
    
    private func handleUpload(connection: NWConnection, headers: String, bodyData: Data) {
        guard let boundary = getBoundary(from: headers) else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "No boundary".data(using: .utf8)!)
            return
        }
        
        let boundaryStr = "--" + boundary
        guard let boundaryData = boundaryStr.data(using: .utf8) else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Invalid boundary".data(using: .utf8)!)
            return
        }
        
        guard let firstBoundaryRange = bodyData.range(of: boundaryData) else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Boundary not found".data(using: .utf8)!)
            return
        }
        
        let partStart = firstBoundaryRange.upperBound + 2
        guard partStart < bodyData.count else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Empty body".data(using: .utf8)!)
            return
        }
        
        let searchRange = partStart..<bodyData.count
        guard let nextBoundaryRange = bodyData.range(of: boundaryData, options: [], in: searchRange) else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Closing boundary not found".data(using: .utf8)!)
            return
        }
        
        let partData = bodyData.subdata(in: partStart..<nextBoundaryRange.lowerBound)
        let doubleCRLF = Data([13, 10, 13, 10])
        guard let separatorRange = partData.range(of: doubleCRLF) else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Part boundary missing separator".data(using: .utf8)!)
            return
        }
        
        let partHeaderData = partData.subdata(in: 0..<separatorRange.lowerBound)
        let fileData = partData.subdata(in: separatorRange.upperBound..<(partData.count - 2))
        
        guard let partHeaders = String(data: partHeaderData, encoding: .utf8),
              let filename = extractFilename(from: partHeaders) else {
            sendResponse(connection: connection, statusCode: 400, statusText: "Bad Request", body: "Could not read upload headers or filename".data(using: .utf8)!)
            return
        }
        
        let fileManager = FileManager.default
        guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "Docs folder offline".data(using: .utf8)!)
            return
        }
        
        let fileURL = documentsURL.appendingPathComponent(filename)
        
        do {
            try fileData.write(to: fileURL)
            log("Saved file: \(filename) (\(fileData.count) bytes)")
            
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: .fileListDidChange, object: nil)
            }
            
            sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Upload successful".data(using: .utf8)!)
        } catch {
            log("Write failed: \(error.localizedDescription)")
            sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "Failed to write file".data(using: .utf8)!)
        }
    }
    
    private func listDocumentsFiles() -> [[String: Any]] {
        let fileManager = FileManager.default
        guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return []
        }
        
        do {
            let fileURLs = try fileManager.contentsOfDirectory(at: documentsURL, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey], options: .skipsHiddenFiles)
            var filesList: [[String: Any]] = []
            let dateFormatter = ISO8601DateFormatter()
            
            for url in fileURLs {
                let resourceValues = try url.resourceValues(forKeys: [.fileSizeKey, .creationDateKey])
                filesList.append([
                    "name": url.lastPathComponent,
                    "size": resourceValues.fileSize ?? 0,
                    "created": dateFormatter.string(from: resourceValues.creationDate ?? Date())
                ])
            }
            
            return filesList.sorted {
                guard let d1 = $0["created"] as? String, let d2 = $1["created"] as? String else { return false }
                return d1 > d2
            }
        } catch {
            log("File listing error: \(error.localizedDescription)")
            return []
        }
    }
    
    private func sendFileDownload(connection: NWConnection, fileName: String) {
        let fileManager = FileManager.default
        guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "Docs folder unavailable".data(using: .utf8)!)
            return
        }
        
        let fileURL = documentsURL.appendingPathComponent(fileName)
        guard fileManager.fileExists(atPath: fileURL.path) else {
            sendResponse(connection: connection, statusCode: 404, statusText: "Not Found", body: "File not found".data(using: .utf8)!)
            return
        }
        
        do {
            let fileData = try Data(contentsOf: fileURL)
            let mimeType = mimeTypeForPath(path: fileName)
            
            let header = """
            HTTP/1.1 200 OK\r
            Content-Type: \(mimeType)\r
            Content-Length: \(fileData.count)\r
            Content-Disposition: attachment; filename="\(fileName)"\r
            Access-Control-Allow-Origin: *\r
            Connection: close\r
            \r\n
            """
            
            guard let headerData = header.data(using: .utf8) else {
                sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "Header error".data(using: .utf8)!)
                return
            }
            
            var responseData = Data()
            responseData.append(headerData)
            responseData.append(fileData)
            
            connection.send(content: responseData, completion: .contentProcessed { [weak self] error in
                if let error = error {
                    self?.log("Download connection error: \(error.localizedDescription)")
                }
                connection.cancel()
            })
        } catch {
            log("File read error: \(error.localizedDescription)")
            sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "Read failed".data(using: .utf8)!)
        }
    }
    
    private func deleteFile(connection: NWConnection, fileName: String) {
        let fileManager = FileManager.default
        guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "Docs folder offline".data(using: .utf8)!)
            return
        }
        
        let fileURL = documentsURL.appendingPathComponent(fileName)
        guard fileManager.fileExists(atPath: fileURL.path) else {
            sendResponse(connection: connection, statusCode: 404, statusText: "Not Found", body: "File not found".data(using: .utf8)!)
            return
        }
        
        do {
            try fileManager.removeItem(at: fileURL)
            log("Deleted file: \(fileName)")
            
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: .fileListDidChange, object: nil)
            }
            
            sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/plain", body: "Deleted".data(using: .utf8)!)
        } catch {
            log("Deletion failed: \(error.localizedDescription)")
            sendResponse(connection: connection, statusCode: 500, statusText: "Internal Error", body: "Failed to delete file".data(using: .utf8)!)
        }
    }
    
    private func mimeTypeForPath(path: String) -> String {
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        switch ext {
        case "html", "htm": return "text/html"
        case "css": return "text/css"
        case "js": return "application/javascript"
        case "json": return "application/json"
        case "png": return "image/png"
        case "jpg", "jpeg": return "image/jpeg"
        case "gif": return "image/gif"
        case "svg": return "image/svg+xml"
        case "pdf": return "application/pdf"
        case "txt": return "text/plain"
        case "zip": return "application/zip"
        default: return "application/octet-stream"
        }
    }
    
    private func sendResponse(connection: NWConnection, statusCode: Int, statusText: String, contentType: String = "text/plain", body: Data) {
        let header = """
        HTTP/1.1 \(statusCode) \(statusText)\r
        Content-Type: \(contentType)\r
        Content-Length: \(body.count)\r
        Access-Control-Allow-Origin: *\r
        Connection: close\r
        \r\n
        """
        
        guard let headerData = header.data(using: .utf8) else {
            connection.cancel()
            return
        }
        
        var responseData = Data()
        responseData.append(headerData)
        responseData.append(body)
        
        connection.send(content: responseData, completion: .contentProcessed { [weak self] error in
            if let error = error {
                self?.log("Response send failed: \(error.localizedDescription)")
            }
            connection.cancel()
        })
    }
    
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
    
    private func getDashboardHTML() -> String {
        return #"""
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>iOS Mini Server Portal</title>
            <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
            <style>
                :root {
                    --bg-color: #0b0f19;
                    --card-bg: rgba(20, 26, 46, 0.6);
                    --card-border: rgba(255, 255, 255, 0.08);
                    --primary: #8b5cf6;
                    --primary-glow: rgba(139, 92, 246, 0.4);
                    --success: #10b981;
                    --danger: #ef4444;
                    --text-main: #f3f4f6;
                    --text-muted: #9ca3af;
                }
                
                * {
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                    font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                }
                
                body {
                    background: radial-gradient(circle at top right, #1e1b4b, var(--bg-color));
                    color: var(--text-main);
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    padding: 2rem 1rem;
                    overflow-x: hidden;
                }

                .container {
                    width: 100%;
                    max-width: 900px;
                    display: flex;
                    flex-direction: column;
                    gap: 2rem;
                }

                header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    background: var(--card-bg);
                    border: 1px solid var(--card-border);
                    backdrop-filter: blur(16px);
                    padding: 1.5rem 2rem;
                    border-radius: 20px;
                    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
                }

                .logo-section h1 {
                    font-size: 1.5rem;
                    font-weight: 700;
                    background: linear-gradient(135deg, #a78bfa, #6366f1);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }

                .logo-section p {
                    font-size: 0.85rem;
                    color: var(--text-muted);
                    margin-top: 0.25rem;
                }

                .status-badge {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    background: rgba(16, 185, 129, 0.1);
                    color: var(--success);
                    padding: 0.5rem 1rem;
                    border-radius: 30px;
                    font-size: 0.85rem;
                    font-weight: 500;
                    border: 1px solid rgba(16, 185, 129, 0.2);
                }

                .status-dot {
                    width: 8px;
                    height: 8px;
                    background-color: var(--success);
                    border-radius: 50%;
                    animation: pulse 1.5s infinite;
                }

                @keyframes pulse {
                    0% { transform: scale(0.9); opacity: 0.6; }
                    50% { transform: scale(1.2); opacity: 1; }
                    100% { transform: scale(0.9); opacity: 0.6; }
                }

                .grid {
                    display: grid;
                    grid-template-columns: 1fr;
                    gap: 2rem;
                }

                @media (min-width: 768px) {
                    .grid {
                        grid-template-columns: 1fr 1.5fr;
                    }
                }

                .card {
                    background: var(--card-bg);
                    border: 1px solid var(--card-border);
                    backdrop-filter: blur(16px);
                    border-radius: 24px;
                    padding: 2rem;
                    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
                    transition: transform 0.3s ease, box-shadow 0.3s ease;
                }

                .card:hover {
                    box-shadow: 0 12px 40px 0 rgba(139, 92, 246, 0.1);
                }

                .card h2 {
                    font-size: 1.25rem;
                    margin-bottom: 1.5rem;
                    font-weight: 600;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }

                .upload-area {
                    border: 2px dashed rgba(139, 92, 246, 0.3);
                    border-radius: 16px;
                    padding: 2.5rem 1.5rem;
                    text-align: center;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    position: relative;
                    overflow: hidden;
                    background: rgba(139, 92, 246, 0.02);
                }

                .upload-area:hover, .upload-area.dragover {
                    border-color: var(--primary);
                    background: rgba(139, 92, 246, 0.05);
                    box-shadow: 0 0 20px var(--primary-glow);
                }

                .upload-icon {
                    font-size: 3rem;
                    margin-bottom: 1rem;
                    display: inline-block;
                    animation: float 3s ease-in-out infinite;
                }

                @keyframes float {
                    0% { transform: translateY(0px); }
                    50% { transform: translateY(-5px); }
                    100% { transform: translateY(0px); }
                }

                .upload-area p {
                    font-size: 0.95rem;
                    font-weight: 500;
                    margin-bottom: 0.5rem;
                }

                .upload-area span {
                    font-size: 0.8rem;
                    color: var(--text-muted);
                }

                #fileInput {
                    display: none;
                }

                .progress-container {
                    margin-top: 1.5rem;
                    display: none;
                }

                .progress-bar-bg {
                    background: rgba(255, 255, 255, 0.1);
                    height: 8px;
                    border-radius: 4px;
                    overflow: hidden;
                    margin-bottom: 0.5rem;
                }

                .progress-bar-fill {
                    background: linear-gradient(90deg, var(--primary), #6366f1);
                    width: 0%;
                    height: 100%;
                    border-radius: 4px;
                    transition: width 0.1s ease;
                    box-shadow: 0 0 8px var(--primary);
                }

                .progress-text {
                    font-size: 0.8rem;
                    color: var(--text-muted);
                    display: flex;
                    justify-content: space-between;
                }

                .files-table-wrapper {
                    overflow-x: auto;
                    margin-top: 1rem;
                }

                table {
                    width: 100%;
                    border-collapse: collapse;
                    text-align: left;
                }

                th {
                    padding: 1rem;
                    font-size: 0.8rem;
                    text-transform: uppercase;
                    color: var(--text-muted);
                    font-weight: 600;
                    border-bottom: 1px solid var(--card-border);
                }

                td {
                    padding: 1.2rem 1rem;
                    font-size: 0.9rem;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
                    white-space: nowrap;
                }

                tr:hover td {
                    background: rgba(255, 255, 255, 0.02);
                }

                .file-name {
                    font-weight: 500;
                    color: var(--text-main);
                    max-width: 250px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }

                .file-info {
                    font-size: 0.8rem;
                    color: var(--text-muted);
                }

                .actions {
                    display: flex;
                    gap: 0.75rem;
                }

                .btn-icon {
                    background: rgba(255, 255, 255, 0.05);
                    border: 1px solid var(--card-border);
                    width: 36px;
                    height: 36px;
                    border-radius: 10px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    cursor: pointer;
                    color: var(--text-main);
                    transition: all 0.2s ease;
                }

                .btn-icon:hover {
                    background: var(--primary);
                    border-color: var(--primary);
                    box-shadow: 0 0 10px var(--primary-glow);
                    transform: translateY(-2px);
                }

                .btn-icon.btn-delete:hover {
                    background: var(--danger);
                    border-color: var(--danger);
                    box-shadow: 0 0 10px rgba(239, 68, 68, 0.4);
                    transform: translateY(-2px);
                }

                .empty-state {
                    text-align: center;
                    padding: 4rem 2rem;
                    color: var(--text-muted);
                }

                .empty-icon {
                    font-size: 3rem;
                    margin-bottom: 1rem;
                    opacity: 0.5;
                }

                .toast-container {
                    position: fixed;
                    bottom: 2rem;
                    right: 2rem;
                    display: flex;
                    flex-direction: column;
                    gap: 0.75rem;
                    z-index: 1000;
                }

                .toast {
                    background: rgba(20, 26, 46, 0.9);
                    border: 1px solid var(--card-border);
                    backdrop-filter: blur(20px);
                    padding: 1rem 1.5rem;
                    border-radius: 14px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
                    display: flex;
                    align-items: center;
                    gap: 0.75rem;
                    color: var(--text-main);
                    min-width: 250px;
                    animation: slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
                    font-weight: 500;
                }

                @keyframes slideIn {
                    from { transform: translateX(120%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }

                .toast.success { border-left: 4px solid var(--success); }
                .toast.error { border-left: 4px solid var(--danger); }
                .toast.info { border-left: 4px solid var(--primary); }

                .svg-icon {
                    width: 18px;
                    height: 18px;
                    fill: currentColor;
                }

                /* Tabbed Navigation Styles */
                .tabs {
                    display: flex;
                    gap: 0.75rem;
                    margin-top: 1rem;
                    margin-bottom: 0.5rem;
                    width: 100%;
                    border-bottom: 1px solid var(--card-border);
                    padding-bottom: 0.5rem;
                }
                .tab {
                    padding: 0.6rem 1.2rem;
                    border-radius: 12px;
                    cursor: pointer;
                    font-weight: 600;
                    color: var(--text-muted);
                    transition: all 0.25s ease;
                    background: rgba(255, 255, 255, 0.02);
                    border: 1px solid var(--card-border);
                    font-size: 0.9rem;
                }
                .tab.active {
                    color: var(--text-main);
                    background: var(--primary);
                    border-color: var(--primary);
                    box-shadow: 0 0 15px var(--primary-glow);
                }
                .tab:hover:not(.active) {
                    background: rgba(255, 255, 255, 0.06);
                    color: var(--text-main);
                }
                .tab-content {
                    display: none;
                    width: 100%;
                    animation: fadeIn 0.3s ease;
                }
                .tab-content.active {
                    display: block;
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(5px); }
                    to { opacity: 1; transform: translateY(0); }
                }

                /* DNS Settings & Stats Styles */
                .dns-stats-grid {
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 1rem;
                    margin-bottom: 1.5rem;
                    width: 100%;
                }
                @media (min-width: 600px) {
                    .dns-stats-grid {
                        grid-template-columns: repeat(4, 1fr);
                    }
                }
                .stat-card {
                    background: rgba(255, 255, 255, 0.02);
                    border: 1px solid var(--card-border);
                    border-radius: 16px;
                    padding: 1.25rem 0.75rem;
                    text-align: center;
                }
                .stat-card-title {
                    font-size: 0.75rem;
                    color: var(--text-muted);
                    margin-bottom: 0.5rem;
                    font-weight: 600;
                    text-transform: uppercase;
                }
                .stat-card-val {
                    font-size: 1.4rem;
                    font-weight: 700;
                    color: var(--text-main);
                }
                .stat-card-val.blocked-num {
                    color: var(--danger);
                }
                .stat-card-val.allowed-num {
                    color: var(--success);
                }

                .badge {
                    padding: 0.3rem 0.85rem;
                    border-radius: 20px;
                    font-size: 0.8rem;
                    font-weight: 600;
                    display: inline-block;
                }
                .badge.success {
                    background: rgba(16, 185, 129, 0.1);
                    color: var(--success);
                    border: 1px solid rgba(16, 185, 129, 0.2);
                }
                .badge.danger {
                    background: rgba(239, 68, 68, 0.1);
                    color: var(--danger);
                    border: 1px solid rgba(239, 68, 68, 0.2);
                }
                .dns-status-panel {
                    background: rgba(0,0,0,0.15);
                    padding: 1.25rem;
                    border-radius: 16px;
                    border: 1px solid var(--card-border);
                }
                .status-row {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 1rem;
                    font-size: 0.95rem;
                }
                .btn-toggle {
                    flex: 1;
                    padding: 0.8rem;
                    border-radius: 12px;
                    border: none;
                    color: white;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    background: var(--primary);
                    box-shadow: 0 4px 12px var(--primary-glow);
                }
                .btn-toggle.running {
                    background: var(--danger);
                    box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
                }
                .btn-toggle:hover {
                    transform: translateY(-2px);
                }
                .dns-list-item {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 0.6rem 1rem;
                    background: rgba(255,255,255,0.02);
                    border-radius: 10px;
                    border: 1px solid rgba(255,255,255,0.04);
                    transition: background 0.2s;
                }
                .dns-list-item:hover {
                    background: rgba(255,255,255,0.05);
                }
                .dns-list-item span {
                    font-size: 0.9rem;
                    color: var(--text-main);
                    word-break: break-all;
                    padding-right: 0.5rem;
                }
                .btn-unblock {
                    background: transparent;
                    border: none;
                    color: var(--danger);
                    cursor: pointer;
                    font-weight: 600;
                    font-size: 0.85rem;
                    padding: 0.3rem 0.6rem;
                    border-radius: 6px;
                    transition: background 0.2s;
                }
                .btn-unblock:hover {
                    background: rgba(239, 68, 68, 0.1);
                }
                
                .dns-log-table {
                    width: 100%;
                    font-family: monospace;
                    font-size: 0.85rem;
                }
                .dns-log-table th {
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                    padding: 0.5rem;
                    font-size: 0.75rem;
                }
                .dns-log-table td {
                    padding: 0.6rem 0.5rem;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.02);
                }
                .dns-log-table tr:hover td {
                    background: rgba(255, 255, 255, 0.03);
                }
                .dns-status-badge {
                    font-weight: bold;
                    font-size: 0.75rem;
                    padding: 0.2rem 0.4rem;
                    border-radius: 4px;
                }
                .dns-status-badge.allowed {
                    background: rgba(16, 185, 129, 0.1);
                    color: var(--success);
                }
                .dns-status-badge.blocked {
                    background: rgba(239, 68, 68, 0.1);
                    color: var(--danger);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <div class="logo-section">
                        <h1>
                            <svg class="svg-icon" viewBox="0 0 24 24" style="width: 24px; height: 24px;"><path d="M19 13H5v-2h14v2zM5 5h14v2H5V5zm0 14h14v-2H5v2z"/></svg>
                            iOS Mini Server
                        </h1>
                        <p>Cổng chia sẻ dữ liệu không dây</p>
                    </div>
                    <div class="status-badge">
                        <div class="status-dot"></div>
                        <span>Hoạt động</span>
                    </div>
                </header>

                <div class="tabs">
                    <div class="tab active" onclick="switchTab('files-tab')">📁 Quản lý File</div>
                    <div class="tab" onclick="switchTab('dns-tab')">🛡️ DNS Ad-Blocker</div>
                </div>

                <div id="files-tab" class="tab-content active">
                    <div class="grid">
                        <div class="card">
                            <h2>Tải Lên Tệp Tin</h2>
                            <div class="upload-area" id="dropzone">
                                <div class="upload-icon">🚀</div>
                                <p>Kéo & Thả tệp tin vào đây</p>
                                <span>hoặc nhấn để chọn từ máy tính</span>
                                <input type="file" id="fileInput">
                            </div>
                            <div class="progress-container" id="progressContainer">
                                <div class="progress-bar-bg">
                                    <div class="progress-bar-fill" id="progressBar"></div>
                                </div>
                                <div class="progress-text">
                                    <span id="progressPercent">0%</span>
                                    <span id="progressFileName">file.txt</span>
                                </div>
                            </div>
                        </div>

                        <div class="card">
                            <h2>Tệp Tin Trên iPhone</h2>
                            <div class="files-table-wrapper">
                                <table id="filesTable">
                                    <thead>
                                        <tr>
                                            <th>Tên Tệp</th>
                                            <th>Kích Thước</th>
                                            <th>Hành Động</th>
                                        </tr>
                                    </thead>
                                    <tbody id="filesList">
                                        <!-- JS Populated -->
                                    </tbody>
                                </table>
                            </div>
                            <div id="emptyState" class="empty-state" style="display: none;">
                                <div class="empty-icon">📁</div>
                                <p>Chưa có tệp tin nào được tải lên</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div id="dns-tab" class="tab-content">
                    <!-- Stats Grid -->
                    <div class="dns-stats-grid">
                        <div class="stat-card">
                            <div class="stat-card-title">Tổng truy vấn</div>
                            <div class="stat-card-val" id="dnsStatTotal">0</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-card-title">Đã chặn</div>
                            <div class="stat-card-val blocked-num" id="dnsStatBlocked">0</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-card-title">Tỷ lệ chặn</div>
                            <div class="stat-card-val blocked-num" id="dnsStatPercent">0%</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-card-title">Bộ lọc đang hoạt động</div>
                            <div class="stat-card-val allowed-num" id="dnsStatActive">0</div>
                        </div>
                    </div>

                    <div class="grid">
                        <div class="card">
                            <h2>Trạng thái DNS</h2>
                            <div class="dns-status-panel">
                                <div class="status-row">
                                    <span>Trạng thái:</span>
                                    <span id="dnsRunningBadge" class="badge danger">Đã dừng</span>
                                </div>
                                <div style="display: flex; gap: 0.5rem; margin-top: 1rem; margin-bottom: 1rem;">
                                    <button id="btnToggleDNS" class="btn-toggle" onclick="toggleDNSServer()">Khởi động</button>
                                    <button onclick="resetDNSStats()" style="padding: 0.8rem 1rem; border-radius: 12px; background: rgba(255,255,255,0.05); border: 1px solid var(--card-border); color: #fff; cursor: pointer; font-weight: 600; font-size: 0.85rem;">Reset Stats</button>
                                </div>
                            </div>
                            
                            <div style="margin-top: 1.5rem; border-top: 1px solid var(--card-border); padding-top: 1.5rem;">
                                <h3>DNS Thượng Nguồn (Upstream)</h3>
                                <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
                                    <input type="text" id="upstreamInput" placeholder="Ví dụ: 1.1.1.1" style="flex: 1; padding: 0.75rem; border-radius: 10px; background: rgba(255,255,255,0.05); border: 1px solid var(--card-border); color: #fff; outline: none; font-size: 0.9rem;">
                                    <button onclick="setUpstreamDNS()" style="padding: 0.75rem 1.25rem; border-radius: 10px; background: var(--primary); color: #fff; border: none; font-weight: 600; cursor: pointer;">Lưu</button>
                                </div>
                            </div>
                        </div>

                        <div class="card">
                            <h2>Bảng Điều Khiển DNS</h2>
                            <div class="tabs" style="border-bottom: none; gap: 0.3rem; margin-top: 0; margin-bottom: 1rem; overflow-x: auto;">
                                <div class="tab active" id="subtab-logs" onclick="switchSubTab('logs')" style="padding: 0.5rem 0.75rem; font-size: 0.8rem; white-space: nowrap;">Query Logs</div>
                                <div class="tab" id="subtab-subs" onclick="switchSubTab('subs')" style="padding: 0.5rem 0.75rem; font-size: 0.8rem; white-space: nowrap;">Bộ lọc URL</div>
                                <div class="tab" id="subtab-list" onclick="switchSubTab('list')" style="padding: 0.5rem 0.75rem; font-size: 0.8rem; white-space: nowrap;">Chặn tùy chỉnh</div>
                                <div class="tab" id="subtab-white" onclick="switchSubTab('white')" style="padding: 0.5rem 0.75rem; font-size: 0.8rem; white-space: nowrap;">Danh sách trắng</div>
                            </div>
                            
                            <!-- Logs panel -->
                            <div id="dns-logs-panel" class="subtab-content">
                                <div style="height: 280px; overflow-y: auto; background: rgba(0,0,0,0.3); border-radius: 12px; border: 1px solid var(--card-border);">
                                    <table class="dns-log-table">
                                        <thead>
                                            <tr>
                                                <th style="width: 70px;">Giờ</th>
                                                <th style="width: 100px;">Thiết bị</th>
                                                <th>Tên miền</th>
                                                <th style="width: 80px;">T.Thái</th>
                                            </tr>
                                        </thead>
                                        <tbody id="dnsLogsList">
                                            <!-- Populate rows -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            
                            <!-- Subscriptions panel -->
                            <div id="dns-subs-panel" class="subtab-content" style="display: none;">
                                <div style="margin-bottom: 1rem; display: flex; gap: 0.5rem; justify-content: space-between; align-items: center;">
                                    <h4 style="font-size: 0.9rem; color: var(--text-muted);">Nguồn danh sách chặn (.hosts / adblock)</h4>
                                    <button onclick="refreshSubscriptions()" id="btnRefreshSubs" style="padding: 0.5rem 1rem; border-radius: 8px; background: var(--success); color: white; border: none; font-size: 0.8rem; font-weight: bold; cursor: pointer;">Cập nhật bộ lọc</button>
                                </div>
                                <div id="dnsSubsList" style="max-height: 160px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 1rem;">
                                    <!-- Subscription list -->
                                </div>
                                <div style="display: flex; gap: 0.5rem; border-top: 1px solid var(--card-border); padding-top: 1rem;">
                                    <input type="text" id="subInput" placeholder="Nhập URL bộ lọc (.hosts / adblock)" style="flex: 1; padding: 0.6rem; border-radius: 8px; background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: #fff; outline: none; font-size: 0.85rem;">
                                    <button onclick="addSubscription()" style="padding: 0.6rem 1rem; border-radius: 8px; background: var(--primary); color: #fff; border: none; font-weight: bold; cursor: pointer; font-size: 0.85rem;">Thêm</button>
                                </div>
                            </div>
                            
                            <!-- Custom blocklist panel -->
                            <div id="dns-list-panel" class="subtab-content" style="display: none;">
                                <div style="margin-bottom: 0.5rem; display: flex; gap: 0.5rem; justify-content: space-between;">
                                    <h4 style="font-size: 0.9rem; color: var(--text-muted);">Chặn thủ công</h4>
                                </div>
                                <div id="dnsBlockedList" style="max-height: 180px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 1rem;">
                                    <!-- Custom Blocked List -->
                                </div>
                                <div style="display: flex; gap: 0.5rem; border-top: 1px solid var(--card-border); padding-top: 1rem;">
                                    <input type="text" id="domainInput" placeholder="Ví dụ: ads.doubleclick.net" style="flex: 1; padding: 0.6rem; border-radius: 8px; background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: #fff; outline: none; font-size: 0.85rem;">
                                    <button onclick="blockDomain()" style="padding: 0.6rem 1rem; border-radius: 8px; background: var(--primary); color: #fff; border: none; font-weight: bold; cursor: pointer; font-size: 0.85rem;">Chặn</button>
                                </div>
                            </div>
                            
                            <!-- Whitelist panel -->
                            <div id="dns-white-panel" class="subtab-content" style="display: none;">
                                <div style="margin-bottom: 0.5rem; display: flex; gap: 0.5rem; justify-content: space-between;">
                                    <h4 style="font-size: 0.9rem; color: var(--text-muted);">Danh sách tên miền tin cậy</h4>
                                </div>
                                <div id="dnsWhiteList" style="max-height: 180px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 1rem;">
                                    <!-- Whitelist -->
                                </div>
                                <div style="display: flex; gap: 0.5rem; border-top: 1px solid var(--card-border); padding-top: 1rem;">
                                    <input type="text" id="whiteInput" placeholder="Ví dụ: google.com" style="flex: 1; padding: 0.6rem; border-radius: 8px; background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); color: #fff; outline: none; font-size: 0.85rem;">
                                    <button onclick="addWhitelist()" style="padding: 0.6rem 1rem; border-radius: 8px; background: var(--primary); color: #fff; border: none; font-weight: bold; cursor: pointer; font-size: 0.85rem;">Thêm</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="toast-container" id="toastContainer"></div>

            <script>
                const dropzone = document.getElementById('dropzone');
                const fileInput = document.getElementById('fileInput');
                const progressContainer = document.getElementById('progressContainer');
                const progressBar = document.getElementById('progressBar');
                const progressPercent = document.getElementById('progressPercent');
                const progressFileName = document.getElementById('progressFileName');
                const filesList = document.getElementById('filesList');
                const emptyState = document.getElementById('emptyState');
                const filesTable = document.getElementById('filesTable');
                const toastContainer = document.getElementById('toastContainer');

                fetchFiles();

                dropzone.addEventListener('click', () => fileInput.click());
                dropzone.addEventListener('dragover', (e) => {
                    e.preventDefault();
                    dropzone.classList.add('dragover');
                });
                dropzone.addEventListener('dragleave', () => {
                    dropzone.classList.remove('dragover');
                });
                dropzone.addEventListener('drop', (e) => {
                    e.preventDefault();
                    dropzone.classList.remove('dragover');
                    if (e.dataTransfer.files.length > 0) {
                        uploadFile(e.dataTransfer.files[0]);
                    }
                });

                fileInput.addEventListener('change', () => {
                    if (fileInput.files.length > 0) {
                        uploadFile(fileInput.files[0]);
                    }
                });

                function showToast(message, type = 'success') {
                    const toast = document.createElement('div');
                    toast.className = `toast ${type}`;
                    let icon = '✔️';
                    if (type === 'error') icon = '❌';
                    if (type === 'info') icon = 'ℹ️';
                    
                    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
                    toastContainer.appendChild(toast);
                    
                    setTimeout(() => {
                        toast.style.animation = 'slideIn 0.3s reverse forwards';
                        setTimeout(() => toast.remove(), 300);
                    }, 3000);
                }

                function formatBytes(bytes, decimals = 2) {
                    if (bytes === 0) return '0 Bytes';
                    const k = 1024;
                    const dm = decimals < 0 ? 0 : decimals;
                    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
                }

                function fetchFiles() {
                    fetch('/files')
                        .then(res => res.json())
                        .then(files => {
                            filesList.innerHTML = '';
                            if (files.length === 0) {
                                emptyState.style.display = 'block';
                                filesTable.style.display = 'none';
                                return;
                            }
                            
                            emptyState.style.display = 'none';
                            filesTable.style.display = 'table';
                            
                            files.forEach(file => {
                                const tr = document.createElement('tr');
                                tr.innerHTML = `
                                    <td>
                                        <div class="file-name" title="${file.name}">${file.name}</div>
                                        <div class="file-info">${new Date(file.created).toLocaleString()}</div>
                                    </td>
                                    <td>${formatBytes(file.size)}</td>
                                    <td>
                                        <div class="actions">
                                            <a class="btn-icon" href="/download?name=${encodeURIComponent(file.name)}" download title="Tải xuống">
                                                <svg class="svg-icon" viewBox="0 0 24 24"><path d="M5 20h14v-2H5v2zm0-10h4V4h6v6h4l-7 7-7-7z"/></svg>
                                            </a>
                                            <button class="btn-icon btn-delete" onclick="deleteFile('${file.name}')" title="Xóa">
                                                <svg class="svg-icon" viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                                            </button>
                                        </div>
                                    </td>
                                `;
                                filesList.appendChild(tr);
                            });
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Không thể lấy danh sách tệp tin', 'error');
                        });
                }

                function uploadFile(file) {
                    progressContainer.style.display = 'block';
                    progressFileName.innerText = file.name;
                    progressBar.style.width = '0%';
                    progressPercent.innerText = '0%';

                    const xhr = new XMLHttpRequest();
                    const formData = new FormData();
                    formData.append('file', file);

                    xhr.upload.addEventListener('progress', (e) => {
                        if (e.lengthComputable) {
                            const percent = Math.round((e.loaded / e.total) * 100);
                            progressBar.style.width = percent + '%';
                            progressPercent.innerText = percent + '%';
                        }
                    });

                    xhr.addEventListener('load', () => {
                        if (xhr.status === 200) {
                            showToast(`Đã tải lên: ${file.name}`);
                            fetchFiles();
                        } else {
                            showToast('Tải lên lỗi: ' + xhr.responseText, 'error');
                        }
                        setTimeout(() => {
                            progressContainer.style.display = 'none';
                        }, 1500);
                    });

                    xhr.addEventListener('error', () => {
                        showToast('Lỗi mạng khi tải lên tệp tin', 'error');
                        progressContainer.style.display = 'none';
                    });

                    xhr.open('POST', '/upload');
                    xhr.send(formData);
                }

                function deleteFile(name) {
                    if (!confirm(`Bạn có muốn xóa "${name}" không?`)) return;
                    
                    fetch(`/delete?name=${encodeURIComponent(name)}`, { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                showToast(`Đã xóa: ${name}`);
                                fetchFiles();
                            } else {
                                showToast('Lỗi xóa tệp tin', 'error');
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Lỗi mạng', 'error');
                        });
                }

                // DNS Tab Logic
                function switchTab(tabId) {
                    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
                    document.getElementById(tabId).classList.add('active');
                    
                    const tabs = document.querySelectorAll('.tabs > .tab');
                    if (tabId === 'files-tab') {
                        tabs[0].classList.add('active');
                        tabs[1].classList.remove('active');
                    } else {
                        tabs[0].classList.remove('active');
                        tabs[1].classList.add('active');
                        fetchDNSConfig();
                    }
                }

                function switchSubTab(type) {
                    document.querySelectorAll('.subtab-content').forEach(el => el.style.display = 'none');
                    document.querySelectorAll('.tab-content .tabs > .tab').forEach(el => {
                        if(el.id.startsWith('subtab-')) el.classList.remove('active');
                    });
                    
                    if (type === 'logs') {
                        document.getElementById('subtab-logs').classList.add('active');
                        document.getElementById('dns-logs-panel').style.display = 'block';
                    } else if (type === 'subs') {
                        document.getElementById('subtab-subs').classList.add('active');
                        document.getElementById('dns-subs-panel').style.display = 'block';
                    } else if (type === 'list') {
                        document.getElementById('subtab-list').classList.add('active');
                        document.getElementById('dns-list-panel').style.display = 'block';
                    } else if (type === 'white') {
                        document.getElementById('subtab-white').classList.add('active');
                        document.getElementById('dns-white-panel').style.display = 'block';
                    }
                }

                let dnsConfig = { running: false, blocked: [], whitelist: [], subscriptions: [], upstream: "1.1.1.1", logs: [], stats: { total: 0, blocked: 0, allowed: 0, blockedPercent: 0.0 }, isUpdating: false };

                function fetchDNSConfig() {
                    fetch('/dns/config')
                        .then(res => res.json())
                        .then(data => {
                            dnsConfig = data;
                            updateDNSUI();
                        })
                        .catch(err => {
                            console.error("Lỗi cấu hình DNS:", err);
                        });
                }

                function parseDNSLog(line) {
                    // Expect format: [HH:mm:ss] [ClientIP] Status - Domain
                    const match = line.match(/^\[(.*?)\]\s+\[(.*?)\]\s+(ALLOW.*?|BLOCKED.*?|✅ ALLOWED|❌ BLOCKED)\s+-\s+(.*?)$/);
                    if (match) {
                        const time = match[1];
                        const ip = match[2];
                        const status = match[3];
                        const domain = match[4];
                        const isBlocked = status.includes('BLOCKED') || status.includes('❌');
                        return { time, ip, domain, isBlocked, textStatus: isBlocked ? 'BLOCKED' : 'ALLOWED' };
                    }
                    
                    // Fallback for general logs: [HH:mm:ss] message
                    const fallbackMatch = line.match(/^\[(.*?)\]\s+(.*?)$/);
                    if (fallbackMatch) {
                        return { time: fallbackMatch[1], ip: 'System', domain: fallbackMatch[2], isBlocked: false, textStatus: 'INFO' };
                    }
                    
                    return { time: '', ip: 'System', domain: line, isBlocked: false, textStatus: 'INFO' };
                }

                function updateDNSUI() {
                    const runningBadge = document.getElementById('dnsRunningBadge');
                    const btnToggle = document.getElementById('btnToggleDNS');
                    const btnRefreshSubs = document.getElementById('btnRefreshSubs');
                    
                    if (dnsConfig.running) {
                        runningBadge.className = 'badge success';
                        runningBadge.innerText = 'Đang hoạt động';
                        btnToggle.className = 'btn-toggle running';
                        btnToggle.innerText = 'Dừng DNS Server';
                    } else {
                        runningBadge.className = 'badge danger';
                        runningBadge.innerText = 'Đã dừng';
                        btnToggle.className = 'btn-toggle';
                        btnToggle.innerText = 'Khởi động DNS Server';
                    }
                    
                    btnRefreshSubs.innerText = dnsConfig.isUpdating ? 'Đang cập nhật...' : 'Cập nhật bộ lọc';
                    btnRefreshSubs.disabled = dnsConfig.isUpdating;
                    
                    // Update stats
                    document.getElementById('dnsStatTotal').innerText = dnsConfig.stats.total;
                    document.getElementById('dnsStatBlocked').innerText = dnsConfig.stats.blocked;
                    document.getElementById('dnsStatPercent').innerText = dnsConfig.stats.blockedPercent.toFixed(1) + '%';
                    document.getElementById('dnsStatActive').innerText = (dnsConfig.blockedCount !== undefined ? dnsConfig.blockedCount : (dnsConfig.blocked ? dnsConfig.blocked.length : 0)) + ' tên miền';
                    
                    if(document.activeElement !== document.getElementById('upstreamInput')) {
                        document.getElementById('upstreamInput').value = dnsConfig.upstream;
                    }
                    
                    // Log table rows
                    const logsList = document.getElementById('dnsLogsList');
                    if (!dnsConfig.logs || dnsConfig.logs.length === 0) {
                        logsList.innerHTML = '<tr><td colspan="4" style="color: var(--text-muted); text-align: center; padding: 1.5rem;">Chưa có truy vấn nào được ghi nhận.</td></tr>';
                    } else {
                        logsList.innerHTML = dnsConfig.logs.map(logLine => {
                            const parsed = parseDNSLog(logLine);
                            const badgeClass = parsed.textStatus === 'BLOCKED' ? 'blocked' : (parsed.textStatus === 'ALLOWED' ? 'allowed' : '');
                            return `
                                <tr>
                                    <td>${parsed.time}</td>
                                    <td>${parsed.ip}</td>
                                    <td style="white-space: normal; word-break: break-all;">${parsed.domain}</td>
                                    <td><span class="dns-status-badge ${badgeClass}">${parsed.textStatus}</span></td>
                                </tr>
                            `;
                        }).reverse().join('');
                    }
                    
                    // Subscription source list
                    const subsList = document.getElementById('dnsSubsList');
                    if (!dnsConfig.subscriptions || dnsConfig.subscriptions.length === 0) {
                        subsList.innerHTML = '<div style="color: var(--text-muted); font-size: 0.9rem; text-align: center; padding: 1rem;">Chưa có nguồn bộ lọc nào.</div>';
                    } else {
                        subsList.innerHTML = dnsConfig.subscriptions.map(url => `
                            <div class="dns-list-item">
                                <span title="${url}">${url}</span>
                                <button class="btn-unblock" onclick="removeSubscription('${url}')">Xóa</button>
                            </div>
                        `).join('');
                    }
                    
                    // Custom blocked list
                    const blockedList = document.getElementById('dnsBlockedList');
                    if (!dnsConfig.blocked || dnsConfig.blocked.length === 0) {
                        blockedList.innerHTML = '<div style="color: var(--text-muted); font-size: 0.9rem; text-align: center; padding: 1rem;">Chưa chặn thủ công tên miền nào.</div>';
                    } else {
                        // Max show 100 manual domains to prevent browser freezing
                        const displayBlocked = dnsConfig.blocked.slice(0, 100);
                        blockedList.innerHTML = displayBlocked.map(domain => `
                            <div class="dns-list-item">
                                <span>${domain}</span>
                                <button class="btn-unblock" onclick="unblockDomain('${domain}')">Xóa</button>
                            </div>
                        `).join('') + (dnsConfig.blocked.length > 100 ? `<div style="text-align: center; font-size: 0.75rem; color: var(--text-muted);">...và ${dnsConfig.blocked.length - 100} tên miền khác</div>` : '');
                    }
                    
                    // Whitelist
                    const whitelistContainer = document.getElementById('dnsWhiteList');
                    if (!dnsConfig.whitelist || dnsConfig.whitelist.length === 0) {
                        whitelistContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 0.9rem; text-align: center; padding: 1rem;">Chưa cấu hình danh sách trắng.</div>';
                    } else {
                        whitelistContainer.innerHTML = dnsConfig.whitelist.map(domain => `
                            <div class="dns-list-item">
                                <span>${domain}</span>
                                <button class="btn-unblock" onclick="removeWhitelist('${domain}')">Xóa</button>
                            </div>
                        `).join('');
                    }
                }

                function toggleDNSServer() {
                    fetch('/dns/toggle', { method: 'POST' })
                        .then(res => res.json())
                        .then(data => {
                            dnsConfig.running = data.running;
                            showToast(data.running ? 'Đã khởi động DNS Server' : 'Đã dừng DNS Server', 'info');
                            fetchDNSConfig();
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Không thể thay đổi trạng thái DNS', 'error');
                        });
                }

                function blockDomain() {
                    const input = document.getElementById('domainInput');
                    const domain = input.value.trim();
                    if (!domain) return;
                    
                    fetch(`/dns/block?domain=${encodeURIComponent(domain)}`, { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                showToast(`Đã chặn: ${domain}`);
                                input.value = '';
                                fetchDNSConfig();
                            } else {
                                showToast('Chặn thất bại', 'error');
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Lỗi mạng', 'error');
                        });
                }

                function unblockDomain(domain) {
                    fetch(`/dns/unblock?domain=${encodeURIComponent(domain)}`, { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                showToast(`Đã bỏ chặn: ${domain}`);
                                fetchDNSConfig();
                            } else {
                                showToast('Bỏ chặn thất bại', 'error');
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Lỗi mạng', 'error');
                        });
                }
                
                function addWhitelist() {
                    const input = document.getElementById('whiteInput');
                    const domain = input.value.trim();
                    if (!domain) return;
                    
                    fetch(`/dns/whitelist/add?domain=${encodeURIComponent(domain)}`, { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                showToast(`Đã thêm whitelist: ${domain}`);
                                input.value = '';
                                fetchDNSConfig();
                            } else {
                                showToast('Thêm whitelist thất bại', 'error');
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Lỗi mạng', 'error');
                        });
                }
                
                function removeWhitelist(domain) {
                    fetch(`/dns/whitelist/remove?domain=${encodeURIComponent(domain)}`, { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                showToast(`Đã xóa whitelist: ${domain}`);
                                fetchDNSConfig();
                            } else {
                                showToast('Xóa whitelist thất bại', 'error');
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Lỗi mạng', 'error');
                        });
                }

                function addSubscription() {
                    const input = document.getElementById('subInput');
                    const url = input.value.trim();
                    if (!url) return;
                    
                    fetch(`/dns/sub/add?url=${encodeURIComponent(url)}`, { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                showToast('Đã thêm nguồn bộ lọc thành công');
                                input.value = '';
                                fetchDNSConfig();
                            } else {
                                showToast('Thêm nguồn thất bại', 'error');
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Lỗi mạng', 'error');
                        });
                }

                function removeSubscription(url) {
                    if (!confirm('Bạn có muốn xóa nguồn bộ lọc này không?')) return;
                    fetch(`/dns/sub/remove?url=${encodeURIComponent(url)}`, { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                showToast('Đã xóa nguồn bộ lọc');
                                fetchDNSConfig();
                            } else {
                                showToast('Xóa nguồn thất bại', 'error');
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Lỗi mạng', 'error');
                        });
                }

                function refreshSubscriptions() {
                    showToast('Đang tải và cập nhật các nguồn bộ lọc...', 'info');
                    fetch('/dns/sub/refresh', { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                fetchDNSConfig();
                            } else {
                                showToast('Cập nhật thất bại', 'error');
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Lỗi kết nối mạng', 'error');
                        });
                }

                function setUpstreamDNS() {
                    const ip = document.getElementById('upstreamInput').value.trim();
                    if (!ip) return;
                    fetch(`/dns/upstream?ip=${encodeURIComponent(ip)}`, { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                showToast('Đã lưu DNS thượng nguồn');
                                fetchDNSConfig();
                            } else {
                                showToast('Lỗi cấu hình Upstream', 'error');
                            }
                        })
                        .catch(err => {
                            console.error(err);
                            showToast('Lỗi mạng', 'error');
                        });
                }

                function resetDNSStats() {
                    if (!confirm('Bạn có muốn reset các số liệu thống kê không?')) return;
                    fetch('/dns/stats/reset', { method: 'POST' })
                        .then(res => {
                            if (res.ok) {
                                showToast('Đã reset thống kê');
                                fetchDNSConfig();
                            }
                        });
                }

                // Auto refresh DNS config/logs every 3 seconds if DNS tab active
                setInterval(() => {
                    const dnsTab = document.getElementById('dns-tab');
                    if (dnsTab && dnsTab.classList.contains('active')) {
                        fetchDNSConfig();
                    }
                }, 3000);
            </script>
        </body>
        </html>
        """#
    }
    
    private func decodeBase64Url(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        let mod = base64.count % 4
        if mod > 0 {
            base64 += String(repeating: "=", count: 4 - mod)
        }
        
        return Data(base64Encoded: base64)
    }
}
