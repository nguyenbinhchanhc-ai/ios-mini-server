import SwiftUI

struct FileItem: Identifiable {
    let id = UUID()
    let name: String
    let size: String
    let date: String
    let url: URL
}

struct ContentView: View {
    @StateObject private var server = MiniHTTPServer(port: 8080)
    @State private var localIP: String? = nil
    @State private var files: [FileItem] = []
    @State private var selectedShareFile: FileItem? = nil
    
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
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Trạng thái máy chủ")
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
            
            Divider()
                .background(Color.white.opacity(0.1))
            
            // Access URL Display
            if server.isRunning {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Địa chỉ truy cập trên trình duyệt:")
                        .font(.subheadline)
                        .foregroundColor(Color.white.opacity(0.8))
                    
                    HStack {
                        Text(serverURLString)
                            .font(.headline)
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
                    .padding(12)
                    .background(Color.black.opacity(0.2))
                    .cornerRadius(10)
                }
            } else {
                Text("Nhấn 'Khởi Động' để bắt đầu chạy máy chủ chia sẻ tệp.")
                    .font(.subheadline)
                    .foregroundColor(Color.white.opacity(0.5))
                    .multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
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
