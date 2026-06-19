# iOS Mini HTTP Server App (.IPA Build Pipeline)

Dự án này chứa mã nguồn của một ứng dụng iOS viết bằng SwiftUI đóng vai trò là máy chủ HTTP cục bộ giúp chia sẻ tệp tin qua mạng Wi-Fi. 

Đặc biệt, dự án đã được tích hợp sẵn **XcodeGen** và **GitHub Actions** để biên dịch trực tiếp ra tệp tin cài đặt `.ipa` hoàn toàn miễn phí trên Cloud mà không cần sử dụng máy Mac.

---

## 🛠️ Hướng dẫn lấy file `.ipa` từ GitHub Actions (Không cần Mac)

### Bước 1: Đẩy mã nguồn lên GitHub của bạn
Bạn chỉ cần đưa thư mục này lên một repository mới trên GitHub:
1. Tạo một Repository trống mới trên tài khoản GitHub của bạn (ví dụ tên: `ios-mini-server`).
2. Mở cửa sổ terminal/cmd tại thư mục này trên máy tính của bạn và chạy các lệnh sau:
   ```bash
   git init
   git add .
   git commit -m "Initialize iOS Mini Server"
   git branch -M main
   git remote add origin https://github.com/USERNAME/ios-mini-server.git
   git push -u origin main
   ```
   *(Thay `USERNAME` và `ios-mini-server` bằng thông tin tài khoản và repo của bạn).*

### Bước 2: Tải xuống tệp `.ipa` đã biên dịch
1. Ngay khi bạn đẩy code lên, truy cập vào trang GitHub của repository đó.
2. Chọn tab **Actions**. Bạn sẽ thấy một workflow có tên là `Build Unsigned IPA` đang tự động chạy.
3. Chờ khoảng 2-3 phút để máy chủ macOS của GitHub biên dịch và đóng gói ứng dụng.
4. Sau khi workflow chạy thành công (có tích xanh), bấm chọn vào job đó.
5. Kéo xuống phần **Artifacts** ở dưới cùng và nhấp chọn **`iOSMiniServer-Unsigned-IPA`** để tải về.
6. Sau khi tải về, giải nén file zip bạn sẽ nhận được tệp tin **`iOSMiniServer.ipa`**.

---

## 📲 Hướng dẫn cài đặt file `.ipa` lên iPhone từ Windows

Vì file `.ipa` này chưa được ký bản quyền (Unsigned), bạn cần dùng một công cụ ký bằng tài khoản Apple ID cá nhân của bạn để cài đặt lên iPhone. Các công cụ phổ biến bao gồm:

### Cách 1: Sử dụng Sideloadly (Khuyên dùng trên Windows - Rất đơn giản)
1. Tải và cài đặt **Sideloadly** trên máy tính Windows của bạn (tải tại [sideloadly.io](https://sideloadly.io/)).
2. Cài đặt **iTunes** và **iCloud** bản chính thức từ Apple (không dùng bản trên Microsoft Store) để máy tính nhận diện được iPhone.
3. Kết nối iPhone với máy tính bằng cáp USB. Chọn **Tin cậy máy tính này** (Trust this computer) trên màn hình iPhone nếu có.
4. Mở Sideloadly:
   - Kéo thả file `iOSMiniServer.ipa` vào ô **IPA** ở góc trái.
   - Nhập tài khoản **Apple ID** của bạn vào ô tương ứng.
   - Bấm **Start**.
   - Nếu chương trình yêu cầu nhập mật khẩu Apple ID hoặc mã xác thực 2 lớp (2FA), hãy nhập bình thường (Sideloadly gửi trực tiếp đến Apple để tạo chứng chỉ ký ứng dụng tạm thời).
5. Khi màn hình hiện chữ **Done**, ứng dụng sẽ xuất hiện trên màn hình iPhone của bạn.

### Cách 2: Sử dụng AltStore
1. Cài đặt **AltServer** trên máy tính Windows từ [altstore.io](https://altstore.io/).
2. Chạy AltServer và chọn cài đặt **AltStore** lên điện thoại iPhone của bạn.
3. Trên iPhone, mở AltStore, vào tab **My Apps**, nhấn dấu **+** ở góc trái và chọn file `iOSMiniServer.ipa` để tiến hành cài đặt và ký trực tiếp trên điện thoại qua Wi-Fi.

> [!IMPORTANT]
> **Kích hoạt Chế độ nhà phát triển (Developer Mode) trên iOS 16+**:
> Sau khi cài đặt ứng dụng bằng Sideloadly hoặc AltStore, nếu mở app bị báo lỗi bảo mật, bạn cần truy cập vào:
> **Cài đặt (Settings) > Quyền riêng tư & Bảo mật (Privacy & Security) > Chế độ nhà phát triển (Developer Mode)**, bật tính năng này lên và khởi động lại điện thoại theo yêu cầu.
>
> Ngoài ra, đối với tài khoản Apple ID cá nhân miễn phí, chứng chỉ ký ứng dụng sẽ có hiệu lực trong **7 ngày**. Sau 7 ngày, bạn chỉ cần cắm máy tính và nhấn ký lại (Resign/Refresh) trong Sideloadly hoặc AltStore để tiếp tục sử dụng.

---

## 📂 Cấu trúc thư mục dự án
- **`project.yml`**: Tệp cấu hình để sinh file dự án Xcode (`.xcodeproj`) tự động thông qua công cụ XcodeGen trên build runner.
- **`.github/workflows/build.yml`**: Tập lệnh CI/CD chạy trên đám mây của GitHub để tự động build file `.ipa`.
- **`iOSMiniServer/`**: Thư mục chứa toàn bộ mã nguồn Swift & SwiftUI của ứng dụng:
  - `iOSMiniServerApp.swift`: Tệp khởi chạy ứng dụng.
  - `ContentView.swift`: Giao diện điều khiển máy chủ, xem log và quản lý file.
  - `MiniHTTPServer.swift`: Lõi máy chủ HTTP xử lý upload/download.
  - `IPAddressHelper.swift`: Lấy địa chỉ IP Wi-Fi cục bộ.
