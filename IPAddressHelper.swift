import Foundation

/// A utility to retrieve the iPhone's current Wi-Fi IP address (IPv4).
struct IPAddressHelper {
    
    /// Returns the Wi-Fi IPv4 address of the device, or nil if not connected to Wi-Fi.
    static func getWiFiIPAddress() -> String? {
        var address: String?
        
        // Get list of all network interfaces on the device
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return nil }
        guard let firstAddr = ifaddr else { return nil }
        
        // Loop through linked list of interfaces
        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ptr.pointee
            
            // Check interface family: IPv4 (AF_INET is 2)
            let addrFamily = interface.ifa_addr.pointee.sa_family
            if addrFamily == UInt8(AF_INET) {
                
                // Check interface name: en0 is the Wi-Fi interface on iOS
                let name = String(cString: interface.ifa_name)
                if name == "en0" {
                    // Convert interface address to a human-readable IP string
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    let result = getnameinfo(
                        interface.ifa_addr,
                        socklen_t(interface.ifa_addr.pointee.sa_len),
                        &hostname,
                        socklen_t(hostname.count),
                        nil,
                        socklen_t(0),
                        NI_NUMERICHOST
                    )
                    
                    if result == 0 {
                        address = String(cString: hostname)
                        break
                    }
                }
            }
        }
        
        freeifaddrs(ifaddr)
        return address
    }
}
