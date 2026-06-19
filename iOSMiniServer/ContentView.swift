import SwiftUI

struct FileItem: Identifiable {
    let id = UUID()
    let name: String
    let size: String
    let date: String
    let url: URL
}

struct ContentView: View {
    @StateObject private var dnsServer: MiniDNSServer
    @StateObject private var server: MiniHTTPServer
    @StateObject private var tunnelClient: WebSocketTunnelClient
    
    @State private var localIP: String? = nil
    @State private var files: [FileItem] = []
    @State private var selectedShareFile: FileItem? = nil
    @State private var relayURLString: String = "https://ios-mini-server.onrender.com/"
    
    init() {
        let dns = MiniDNSServer()
        let s = MiniHTTPServer(port: 8080)
        s.dnsServer = dns
        _dnsServer = StateObject(wrappedValue: dns)
        _server = StateObject(wrappedValue: s)
        _tunnelClient = StateObject(wrappedValue: WebSocketTunnelClient(server: s))
    }
    
    private var serverURLString: String {
        if let ip = localIP {
            return "http://\(ip):\(server.port)"
        }
        return "Không có Wi-Fi"
    }
    
    var body: some View {
        NavigationView {
            ZStack {
                // Background Gradient
                LinearGradient(
                    gradient: Gradient(colors: [Color(red: 0.05, green: 0.08, blue: 0.16), Color(red: 0.08, green: 0.05, blue: 0.12)]),
                    startPoint: .top,
                    endPoint: .bottom
                )
                .ignoresSafeArea()
                
                ScrollView {
                    VStack(spacing: 20) {
                        statusCard
                        dnsCard
                        logsCard
                        filesCard
                    }
                    .padding()
                }
            }
            .navigationTitle("Mini Server")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(action: refreshIP) {
                        Image(systemName: "wifi")
                            .foregroundColor(localIP != nil ? Color.green : Color.gray)
                    }
                }
            }
            .onAppear {
                refreshIP()
                refreshFiles()
            }
            .onReceive(NotificationCenter.default.publisher(for: .fileListDidChange)) { _ in
                refreshFiles()
            }
            .sheet(item: $selectedShareFile) { fileItem in
                ActivityView(activityItems: [fileItem.url])
            }
        }
        .preferredColorScheme(.dark)
    }
    
    // MARK: - Subviews
    
    @ViewBuilder
    private var statusCard: some View {
        VStack(spacing: 16) {
            // Local Server Control
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Máy chủ nội bộ (Wi-Fi)")
                        .font(.caption)
                        .foregroundColor(Color.gray)
                    
                    HStack(spacing: 8) {
                        Circle()
                            .fill(server.isRunning ? Color.green : Color.red)
                            .frame(width: 10, height: 10)
                            .shadow(color: server.isRunning ? Color.green : Color.red, radius: 4)
                        
                        Text(server.isRunning ? "ĐANG HOẠT ĐỘNG" : "ĐÃ DỪNG")
                            .font(.footnote)
                            .fontWeight(.bold)
                            .foregroundColor(server.isRunning ? Color.green : Color.red)
                    }
                }
                
                Spacer()
                
                Button(action: {
                    withAnimation(.spring()) {
                        if server.isRunning {
                            if tunnelClient.isConnected {
                                tunnelClient.disconnect()
                                BackgroundHelper.shared.stop()
                            }
                            server.stop()
                        } else {
                            refreshIP()
                            server.start()
                        }
                    }
                }) {
                    Text(server.isRunning ? "Dừng Server" : "Khởi Động")
                        .font(.subheadline)
                        .fontWeight(.semibold)
                        .foregroundColor(Color.white)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
                        .background(
                            RoundedRectangle(cornerRadius: 12)
                                .fill(server.isRunning ? Color.red : Color.blue)
                                .shadow(color: server.isRunning ? Color.red.opacity(0.4) : Color.blue.opacity(0.4), radius: 8)
                        )
                }
            }
            
            // Local IP Address
            if server.isRunning {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Địa chỉ Wi-Fi nội bộ:")
                        .font(.caption)
                        .foregroundColor(Color.gray)
                    
                    HStack {
                        Text(serverURLString)
                            .font(.subheadline)
                            .fontWeight(.medium)
                            .foregroundColor(Color.cyan)
                            .textSelection(.enabled)
                        
                        Spacer()
                        
                        Button(action: {
                            UIPasteboard.general.string = serverURLString
                        }) {
                            Image(systemName: "doc.on.doc")
                                .foregroundColor(Color.gray)
                                .padding(6)
                                .background(Color.white.opacity(0.05))
                                .cornerRadius(8)
                        }
                    }
                    .padding(10)
                    .background(Color.black.opacity(0.2))
                    .cornerRadius(10)
                }
            }
            
            Divider()
                .background(Color.white.opacity(0.1))
            
            // Public Cloud Tunnel Control
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Đường truyền đám mây (Internet)")
                            .font(.caption)
                            .foregroundColor(Color.gray)
                        
                        HStack(spacing: 8) {
                            Circle()
                                .fill(tunnelClient.isConnected ? Color.green : Color.orange)
                                .frame(width: 10, height: 10)
                                .shadow(color: tunnelClient.isConnected ? Color.green : Color.orange, radius: 4)
                            
                            Text(tunnelClient.isConnected ? "ĐẠT KẾT NỐI" : "CHƯA KẾT NỐI")
                                .font(.footnote)
                                .fontWeight(.bold)
                                .foregroundColor(tunnelClient.isConnected ? Color.green : Color.orange)
                        }
                    }
                    
                    Spacer()
                    
                    Button(action: {
                        withAnimation(.spring()) {
                            if tunnelClient.isConnected {
                                tunnelClient.disconnect()
                                BackgroundHelper.shared.stop()
                            } else {
                                if !server.isRunning {
                                    refreshIP()
                                    server.start()
                                }
                                BackgroundHelper.shared.start()
                                tunnelClient.connect(to: relayURLString)
                            }
                        }
                    }) {
                        Text(tunnelClient.isConnected ? "Ngắt Kết Nối" : "Kết Nối Cloud")
                            .font(.subheadline)
                            .fontWeight(.semibold)
                            .foregroundColor(Color.white)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                            .background(
                                RoundedRectangle(cornerRadius: 12)
                                    .fill(tunnelClient.isConnected ? Color.orange : Color.purple)
                                    .shadow(color: tunnelClient.isConnected ? Color.orange.opacity(0.4) : Color.purple.opacity(0.4), radius: 8)
                            )
                    }
                }
                
                if !tunnelClient.isConnected {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Nhập URL Server trung gian:")
                            .font(.caption2)
                            .foregroundColor(Color.gray)
                        
                        TextField("https://your-relay-domain.com", text: $relayURLString)
                            .textFieldStyle(PlainTextFieldStyle())
                            .font(.subheadline)
                            .foregroundColor(Color.white)
                            .padding(10)
                            .background(Color.white.opacity(0.05))
                            .cornerRadius(10)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                    }
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Địa chỉ truy cập Internet công cộng:")
                            .font(.caption)
                            .foregroundColor(Color.gray)
                        
                        HStack {
                            Text(tunnelClient.publicURL)
                                .font(.subheadline)
                                .fontWeight(.medium)
                                .foregroundColor(Color.purple)
                                .textSelection(.enabled)
                            
                            Spacer()
                            
                            Button(action: {
                                UIPasteboard.general.string = tunnelClient.publicURL
                            }) {
                                Image(systemName: "doc.on.doc")
                                    .foregroundColor(Color.gray)
                                    .padding(6)
                                    .background(Color.white.opacity(0.05))
                                    .cornerRadius(8)
                            }
                        }
                        .padding(10)
                        .background(Color.black.opacity(0.2))
                        .cornerRadius(10)
                    }
                }
            }
        }
        .padding()
        .background(Color.white.opacity(0.05))
        .cornerRadius(20)
        .overlay(
            RoundedRectangle(cornerRadius: 20)
                .stroke(Color.white.opacity(0.08), lineWidth: 1)
        )
    }
    
    @ViewBuilder
    private var dnsCard: some View {
        VStack(spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Trình Chặn Quảng Cáo DNS (Pi-hole)")
                        .font(.caption)
                        .foregroundColor(Color.gray)
                    
                    HStack(spacing: 8) {
                        Circle()
                            .fill(dnsServer.isRunning ? Color.green : Color.red)
                            .frame(width: 10, height: 10)
                            .shadow(color: dnsServer.isRunning ? Color.green : Color.red, radius: 4)
                        
                        Text(dnsServer.isRunning ? "ĐANG BẬT" : "ĐÃ TẮT")
                            .font(.footnote)
                            .fontWeight(.bold)
                            .foregroundColor(dnsServer.isRunning ? Color.green : Color.red)
                    }
                }
                
                Spacer()
                
                Button(action: {
                    withAnimation(.spring()) {
                        if dnsServer.isRunning {
                            dnsServer.stop()
                        } else {
                            dnsServer.start()
                        }
                    }
                }) {
                    Text(dnsServer.isRunning ? "Tắt DNS" : "Bật DNS")
                        .font(.subheadline)
                        .fontWeight(.semibold)
                        .foregroundColor(Color.white)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
                        .background(
                            RoundedRectangle(cornerRadius: 12)
                                .fill(dnsServer.isRunning ? Color.red : Color.green)
                                .shadow(color: dnsServer.isRunning ? Color.red.opacity(0.4) : Color.green.opacity(0.4), radius: 8)
                        )
                }
            }
            
            if dnsServer.isRunning {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Địa chỉ DNS trên thiết bị khác:")
                        .font(.caption)
                        .foregroundColor(Color.gray)
                    
                    HStack {
                        Text(localIP ?? "Cần kết nối Wi-Fi")
                            .font(.subheadline)
                            .fontWeight(.medium)
                            .foregroundColor(Color.cyan)
                            .textSelection(.enabled)
                        
                        Spacer()
                        
                        Button(action: {
                            UIPasteboard.general.string = localIP
                        }) {
                            Image(systemName: "doc.on.doc")
                                .foregroundColor(Color.gray)
                                .padding(6)
                                .background(Color.white.opacity(0.05))
                                .cornerRadius(8)
                        }
                    }
                    .padding(10)
                    .background(Color.black.opacity(0.2))
                    .cornerRadius(10)
                    
                    HStack {
                        Text("Số lượng chặn:")
                            .font(.footnote)
                            .foregroundColor(Color.gray)
                        Spacer()
                        Text("\(dnsServer.blockedCount) tên miền")
                            .font(.footnote)
                            .fontWeight(.bold)
                            .foregroundColor(Color.purple)
                    }
                }
            }
            
            Divider()
                .background(Color.white.opacity(0.1))
            
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Label("Nhật ký DNS", systemImage: "shield.text.feed")
                        .font(.subheadline)
                        .fontWeight(.semibold)
                        .foregroundColor(Color.white)
                    
                    Spacer()
                    
                    Button(action: { dnsServer.logs.removeAll() }) {
                        Text("Xóa log")
                            .font(.caption)
                            .foregroundColor(Color.gray)
                    }
                }
                
                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 6) {
                            if dnsServer.logs.isEmpty {
                                Text("Không có truy vấn DNS nào...")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundColor(Color.white.opacity(0.3))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            } else {
                                ForEach(dnsServer.logs, id: \.self) { log in
                                    Text(log)
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundColor(log.contains("❌") ? Color.red.opacity(0.9) : Color.green.opacity(0.9))
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .id(log)
                                }
                            }
                        }
                        .padding(10)
                    }
                    .frame(height: 120)
                    .background(Color.black.opacity(0.3))
                    .cornerRadius(12)
                    .onChange(of: dnsServer.logs) { newLogs in
                        if let lastLog = newLogs.last {
                            withAnimation {
                                proxy.scrollTo(lastLog, anchor: .bottom)
                            }
                        }
                    }
                }
            }
        }
        .padding()
        .background(Color.white.opacity(0.05))
        .cornerRadius(20)
        .overlay(
            RoundedRectangle(cornerRadius: 20)
                .stroke(Color.white.opacity(0.08), lineWidth: 1)
        )
    }
    
    @ViewBuilder
    private var logsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Nhật ký hệ thống", systemImage: "terminal")
                    .font(.headline)
                    .foregroundColor(Color.white)
                
                Spacer()
                
                Button(action: { server.logs.removeAll() }) {
                    Text("Xóa log")
                        .font(.caption)
                        .foregroundColor(Color.gray)
                }
            }
            
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        if server.logs.isEmpty {
                            Text("Không có log nào...")
                                .font(.system(.footnote, design: .monospaced))
                                .foregroundColor(Color.white.opacity(0.3))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        } else {
                            ForEach(server.logs, id: \.self) { log in
                                Text(log)
                                    .font(.system(.footnote, design: .monospaced))
                                    .foregroundColor(Color.green.opacity(0.9))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(log)
                            }
                        }
                    }
                    .padding(10)
                }
                .frame(height: 140)
                .background(Color.black.opacity(0.3))
                .cornerRadius(12)
                .onChange(of: server.logs) { newLogs in
                    if let lastLog = newLogs.last {
                        withAnimation {
                            proxy.scrollTo(lastLog, anchor: .bottom)
                        }
                    }
                }
            }
        }
        .padding()
        .background(Color.white.opacity(0.05))
        .cornerRadius(20)
        .overlay(
            RoundedRectangle(cornerRadius: 20)
                .stroke(Color.white.opacity(0.08), lineWidth: 1)
        )
    }
    
    @ViewBuilder
    private var filesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Tệp tin đã tải lên (\(files.count))", systemImage: "folder")
                    .font(.headline)
                    .foregroundColor(Color.white)
                
                Spacer()
                
                Button(action: { refreshFiles() }) {
                    Image(systemName: "arrow.clockwise")
                        .foregroundColor(Color.gray)
                }
            }
            
            if files.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "folder.badge.plus")
                        .font(.largeTitle)
                        .foregroundColor(Color.white.opacity(0.2))
                    Text("Chưa có tệp tin nào")
                        .font(.subheadline)
                        .foregroundColor(Color.white.opacity(0.4))
                    Text("Truy cập từ trình duyệt để tải file lên.")
                        .font(.caption)
                        .foregroundColor(Color.white.opacity(0.3))
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 30)
                .background(Color.black.opacity(0.15))
                .cornerRadius(12)
            } else {
                VStack(spacing: 8) {
                    ForEach(files) { file in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(file.name)
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                    .foregroundColor(Color.white)
                                    .lineLimit(1)
                                
                                HStack(spacing: 10) {
                                    Text(file.size)
                                    Text("•")
                                    Text(file.date)
                                }
                                .font(.caption2)
                                .foregroundColor(Color.gray)
                            }
                            
                            Spacer()
                            
                            HStack(spacing: 12) {
                                Button(action: {
                                    selectedShareFile = file
                                }) {
                                    Image(systemName: "square.and.arrow.up")
                                        .foregroundColor(Color.cyan)
                                        .padding(8)
                                        .background(Color.white.opacity(0.05))
                                        .cornerRadius(8)
                                }
                                
                                Button(action: {
                                    deleteFile(file)
                                }) {
                                    Image(systemName: "trash")
                                        .foregroundColor(Color.red)
                                        .padding(8)
                                        .background(Color.white.opacity(0.05))
                                        .cornerRadius(8)
                                }
                            }
                        }
                        .padding(12)
                        .background(Color.white.opacity(0.02))
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color.white.opacity(0.04), lineWidth: 1)
                        )
                    }
                }
            }
        }
        .padding()
        .background(Color.white.opacity(0.05))
        .cornerRadius(20)
        .overlay(
            RoundedRectangle(cornerRadius: 20)
                .stroke(Color.white.opacity(0.08), lineWidth: 1)
        )
    }
    
    // MARK: - Private Methods
    
    private func refreshIP() {
        localIP = IPAddressHelper.getWiFiIPAddress()
    }
    
    private func refreshFiles() {
        let fileManager = FileManager.default
        guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        
        do {
            let fileURLs = try fileManager.contentsOfDirectory(
                at: documentsURL,
                includingPropertiesForKeys: [.fileSizeKey, .creationDateKey],
                options: .skipsHiddenFiles
            )
            
            let formatter = DateFormatter()
            formatter.dateFormat = "dd/MM/yyyy HH:mm"
            
            var items: [FileItem] = []
            for url in fileURLs {
                let resourceValues = try url.resourceValues(forKeys: [.fileSizeKey, .creationDateKey])
                let sizeVal = resourceValues.fileSize ?? 0
                let dateVal = resourceValues.creationDate ?? Date()
                
                let sizeString = formatBytes(sizeVal)
                let dateString = formatter.string(from: dateVal)
                
                items.append(FileItem(
                    name: url.lastPathComponent,
                    size: sizeString,
                    date: dateString,
                    url: url
                ))
            }
            
            self.files = items.sorted { $0.url.lastPathComponent > $1.url.lastPathComponent }
        } catch {
            print("Failed to load files: \(error.localizedDescription)")
        }
    }
    
    private func deleteFile(_ item: FileItem) {
        do {
            try FileManager.default.removeItem(at: item.url)
            refreshFiles()
        } catch {
            print("Delete failed: \(error.localizedDescription)")
        }
    }
    
    private func formatBytes(_ bytes: Int) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useAll]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(bytes))
    }
}

// MARK: - Native Activity View for Sharing
struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]
    let applicationActivities: [UIActivity]?
    
    init(activityItems: [Any], applicationActivities: [UIActivity]? = nil) {
        self.activityItems = activityItems
        self.applicationActivities = applicationActivities
    }
    
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: applicationActivities)
    }
    
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
