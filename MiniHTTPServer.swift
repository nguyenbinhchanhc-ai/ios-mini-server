import Foundation
import Network
import Combine

extension Notification.Name {
    static let fileListDidChange = Notification.Name("FileListDidChange")
}

/// A lightweight, custom HTTP Server implemented using Network.framework.
class MiniHTTPServer: ObservableObject {
    
    @Published var isRunning = false
    @Published var logs: [String] = []
    
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "com.antigravity.miniserver.queue", qos: .userInitiated)
    let port: UInt16
    
    init(port: UInt16 = 8080) {
        self.port = port
    }
    
    /// Starts listening for incoming HTTP connections on the designated port.
    func start() {
        guard !isRunning else { return }
        
        do {
            let listener = try NWListener(using: .tcp, on: NWPort(rawValue: self.port)!)
            
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
    
    /// Stops the server listener.
    func stop() {
        listener?.cancel()
        listener = nil
        DispatchQueue.main.async {
            self.isRunning = false
        }
    }
    
    // MARK: - Connections & Reading
    
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
            
            // Look for the boundary between headers and body: \r\n\r\n
            if let headerRange = self.findHeaderSeparator(in: newData) {
                let headerData = newData.subdata(in: 0..<headerRange.lowerBound)
                let bodyData = newData.subdata(in: headerRange.upperBound..<newData.count)
                
                if let headers = String(data: headerData, encoding: .utf8) {
                    let contentLength = self.parseContentLength(from: headers)
                    
                    if bodyData.count >= contentLength {
                        // All content received!
                        let finalBody = bodyData.subdata(in: 0..<contentLength)
                        self.processRequest(connection: connection, headerString: headers, bodyData: finalBody)
                    } else {
                        // Need more data for the body
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
                // Headers not fully loaded yet, keep reading
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
        let separator = Data([13, 10, 13, 10]) // \r\n\r\n
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
    
    // MARK: - Request Routing & Processing
    
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
        
        // Output clean connection info
        log("\(method) \(path) [Body: \(bodyData.count) bytes]")
        
        if method == "GET" && path == "/" {
            let html = getDashboardHTML()
            sendResponse(connection: connection, statusCode: 200, statusText: "OK", contentType: "text/html; charset=utf-8", body: html.data(using: .utf8)!)
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
    
    // MARK: - Actions (Upload, Download, Delete, List)
    
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
                        // Handle URL decoding in case filename has escaped spaces etc.
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
        
        let partStart = firstBoundaryRange.upperBound + 2 // skip \r\n
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
        // File data ends before the ending \r\n (2 bytes) of the block preceding the next boundary
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
    
    // MARK: - HTML Portal Body
    
    private func getDashboardHTML() -> String {
        return """
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
            </script>
        </body>
        </html>
        """
    }
}
