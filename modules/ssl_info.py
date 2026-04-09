import ssl
import socket

def check_https_support(domain, port=443):
    """التحقق من دعم HTTPS قبل محاولة استخراج الشهادة"""
    try:
        socket.create_connection((domain, port), timeout=5)
        return True
    except:
        return False

def get_ssl_info(domain, port=443):
    """
    استخراج معلومات SSL/TLS فقط إذا كان الموقع يدعم HTTPS
    """
    # أولاً: نتحقق إذا كان HTTPS شغال
    if not check_https_support(domain, port):
        return {
            "domain": domain,
            "status": "HTTPS not supported - site may be HTTP only",
            "is_wildcard": False,
            "subject_alt_names": []
        }
    
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
        result = {
            "domain": domain,
            "port": port,
            "status": "success",
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "version": cert.get("version"),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "subject_alt_names": [san[1] for san in cert.get("subjectAltName", [])],
            "is_wildcard": any("*" in san[1] for san in cert.get("subjectAltName", []))
        }
        
        return result
        
    except Exception as e:
        return {
            "domain": domain,
            "status": f"SSL error: {str(e)}",
            "is_wildcard": False,
            "subject_alt_names": []
        }
