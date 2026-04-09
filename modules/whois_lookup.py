import whois
import socket

def get_whois(domain):
    """
    استعلام WHOIS مع timeout أطول ومعالجة الأخطاء
    """
    try:
        # زيادة timeout
        socket.setdefaulttimeout(15)
        w = whois.whois(domain)
        
        if not w or not w.domain_name:
            return None
            
        result = {
            "domain": domain,
            "registrar": str(w.registrar) if w.registrar else "Not found",
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
            "org": str(w.org) if w.org else "Not found",
            "country": str(w.country) if w.country else "Not found",
            "emails": w.emails if w.emails else [],
            "privacy_protected": "privacy" in str(w.registrar).lower() if w.registrar else False
        }
        
        return result
        
    except Exception as e:
        # لو فشل، نرجع None بدل ما نوقف البرنامج
        return {
            "domain": domain,
            "error": str(e),
            "status": "WHOIS lookup failed - service may be rate limiting or domain has privacy protection"
        }
