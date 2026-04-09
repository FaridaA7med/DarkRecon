import socket
import concurrent.futures

# قائمة الموانئ الشائعة للفحص
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

def scan_port(host, port, timeout=3):
    """
    فحص منفذ واحد باستخدام TCP connect scan
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            return {"port": port, "state": "open", "service": service}
        else:
            return None
            
    except Exception:
        return None

def scan_ports(domain, ports=None, max_workers=50):
    """
    فحص الموانئ باستخدام threading
    """
    # أولاً نحصل على IP من domain
    try:
        host = socket.gethostbyname(domain)
        print(f"[*] Scanning {domain} ({host})")
    except:
        return {"error": f"Could not resolve {domain}"}
    
    # إذا لم يتم تحديد موانئ، استخدم القائمة الافتراضية
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    print(f"[*] Scanning {len(ports)} ports...")
    
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"[+] Port {result['port']} ({result['service']}) is OPEN")
    
    return {
        "host": host,
        "domain": domain,
        "open_ports": open_ports,
        "total_ports_scanned": len(ports),
        "open_count": len(open_ports)
    }
