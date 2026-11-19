import Foundation

/// What usually speaks on a well-known port, for the network map's details: "443 HTTPS". A port says what a
/// connection most likely is, not what it is (anything can listen anywhere), so the name is a hint next to the
/// number, never instead of it.
enum PortNames {
    static func name(_ port: Int) -> String? { table[port] }

    private static let table: [Int: String] = [
        20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
        143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTP over TLS", 500: "IPsec",
        514: "Syslog", 548: "AFP", 554: "RTSP", 587: "Mail submission", 631: "Printing (IPP)", 636: "LDAP over TLS",
        853: "DNS over TLS", 873: "rsync", 993: "IMAP over TLS", 995: "POP3 over TLS", 1194: "OpenVPN",
        1433: "SQL Server", 1701: "L2TP", 1723: "PPTP", 1883: "MQTT", 1900: "SSDP", 2049: "NFS", 3306: "MySQL",
        3389: "Remote Desktop", 3478: "STUN", 3479: "STUN", 4500: "IPsec NAT", 5060: "SIP", 5061: "SIP over TLS",
        5222: "XMPP", 5223: "Apple Push", 5228: "Google Push", 5353: "Bonjour", 5432: "PostgreSQL",
        5900: "Screen Sharing (VNC)", 6379: "Redis", 6443: "Kubernetes", 7000: "AirPlay", 8080: "HTTP (alternate)",
        8443: "HTTPS (alternate)", 8883: "MQTT over TLS", 9418: "Git", 11211: "Memcached", 27017: "MongoDB",
        51820: "WireGuard",
    ]
}
