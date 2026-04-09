import socket
import ssl

def grab_banner(host, port, timeout=5):
    """
    محاولة الحصول على banner من منفذ معين
    """
    try:
        # لو المنفذ 443 (HTTPS)، نحتاج SSL
        if port == 443:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # نرسل طلب HTTP بسيط
                    ssock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = ssock.recv(1024).decode('utf-8', errors='ignore')
                    return banner[:500]  # أول 500 حرف فقط
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                
                # نرسل طلب بسيط لبعض الخدمات
                if port == 80:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 22:
                    # SSH usually sends banner immediately
                    pass
                else:
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner[:500]
                
    except Exception as e:
        return f"Could not grab banner: {str(e)[:50]}"

def grab_all_banners(domain, open_ports):
    """
    الحصول على banners لجميع الموانئ المفتوحة
    """
    # نحصل على IP
    try:
        host = socket.gethostbyname(domain)
    except:
        return {"error": f"Could not resolve {domain}"}
    
    results = []
    
    for port_info in open_ports:
        port = port_info["port"]
        print(f"[*] Grabbing banner from port {port}...")
        
        banner = grab_banner(host, port)
        
        results.append({
            "port": port,
            "service": port_info["service"],
            "banner": banner
        })
    
    return results
