import Foundation
import Combine

/// A client that establishes a WebSocket tunnel to a public relay server.
/// It forwards incoming HTTP requests from the relay to the local MiniHTTPServer and sends back responses.
class WebSocketTunnelClient: ObservableObject {
    @Published var isConnected = false
    @Published var publicURL: String = ""
    
    private var webSocketTask: URLSessionWebSocketTask?
    private let session = URLSession(configuration: .default)
    private var isRunning = false
    private var serverURL: URL?
    private let server: MiniHTTPServer
    
    init(server: MiniHTTPServer) {
        self.server = server
    }
    
    /// Connects to the WebSocket relay server using its public HTTP/HTTPS URL.
    func connect(to relayUrlString: String) {
        var urlComp = URLComponents(string: relayUrlString)
        
        // Convert HTTP/HTTPS to WS/WSS protocols
        if urlComp?.scheme == "https" {
            urlComp?.scheme = "wss"
        } else if urlComp?.scheme == "http" {
            urlComp?.scheme = "ws"
        } else if urlComp?.scheme == nil {
            urlComp?.scheme = "wss" // Default to secure websocket
        }
        
        urlComp?.path = "/tunnel"
        
        guard let url = urlComp?.url else { return }
        self.serverURL = url
        self.isRunning = true
        
        setupConnection()
    }
    
    /// Disconnects from the relay server.
    func disconnect() {
        self.isRunning = false
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        DispatchQueue.main.async {
            self.isConnected = false
            self.publicURL = ""
        }
    }
    
    private func setupConnection() {
        guard isRunning, let url = serverURL else { return }
        
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()
        
        DispatchQueue.main.async {
            self.isConnected = true
            
            // Format public URL for user display
            var displayComp = URLComponents(url: url, resolvingAgainstBaseURL: false)
            displayComp?.scheme = url.scheme == "wss" ? "https" : "http"
            displayComp?.path = ""
            self.publicURL = displayComp?.url?.absoluteString ?? ""
        }
        
        receiveMessage()
        sendPing()
    }
    
    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            guard let self = self, self.isRunning else { return }
            
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    self.handleIncomingMessage(text)
                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        self.handleIncomingMessage(text)
                    }
                @unknown default:
                    break
                }
                // Continue listening
                self.receiveMessage()
                
            case .failure(let error):
                print("WebSocket tunnel disconnected: \(error.localizedDescription)")
                DispatchQueue.main.async {
                    self.isConnected = false
                }
                
                // Retry connection after 3 seconds if still running
                DispatchQueue.global().asyncAfter(deadline: .now() + 3) { [weak self] in
                    self?.setupConnection()
                }
            }
        }
    }
    
    private func sendPing() {
        guard isRunning, let task = webSocketTask, task.state == .running else { return }
        
        let pingMessage = ["type": "ping"]
        if let data = try? JSONSerialization.data(withJSONObject: pingMessage),
           let string = String(data: data, encoding: .utf8) {
            task.send(.string(string)) { error in
                if let error = error {
                    print("Failed to send ping: \(error.localizedDescription)")
                }
            }
        }
        
        // Ping every 10 seconds to maintain connection
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) { [weak self] in
            self?.sendPing()
        }
    }
    
    private func handleIncomingMessage(_ text: String) {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String,
              type == "request",
              let requestId = json["id"] as? String,
              let method = json["method"] as? String,
              let path = json["path"] as? String else {
            return
        }
        
        let query = json["query"] as? String ?? ""
        let bodyBase64 = json["body"] as? String ?? ""
        let bodyData = Data(base64Encoded: bodyBase64) ?? Data()
        
        // Execute HTTP request locally
        server.handleHTTP(method: method, path: path, query: query, body: bodyData) { [weak self] statusCode, contentType, responseData, headers in
            guard let self = self else { return }
            
            // Format response payload
            var responsePayload: [String: Any] = [
                "type": "response",
                "id": requestId,
                "statusCode": statusCode,
                "headers": [
                    "Content-Type": contentType,
                    "Access-Control-Allow-Origin": "*"
                ]
            ]
            
            // Add custom headers (e.g. Content-Disposition for downloading)
            if var payloadHeaders = responsePayload["headers"] as? [String: String] {
                for (k, v) in headers {
                    payloadHeaders[k] = v
                }
                responsePayload["headers"] = payloadHeaders
            }
            
            if !responseData.isEmpty {
                responsePayload["body"] = responseData.base64EncodedString()
            }
            
            if let responseJSONData = try? JSONSerialization.data(withJSONObject: responsePayload),
               let responseString = String(data: responseJSONData, encoding: .utf8) {
                self.webSocketTask?.send(.string(responseString)) { error in
                    if let error = error {
                        print("Failed to send tunnel response: \(error.localizedDescription)")
                    }
                }
            }
        }
    }
}
