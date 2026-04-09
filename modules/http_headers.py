import requests
from urllib3.exceptions import InsecureRequestWarning

# إيقاف تحذيرات SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def check_security_headers(headers):
    """
    تدقيق هيدرات الأمان حسب OWASP
    """
    security_headers = {
        "Strict-Transport-Security": {
            "attack": "يمنع هجمات SSL stripping",
            "remediation": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "risk": "MEDIUM"
        },
        "Content-Security-Policy": {
            "attack": "يمنع XSS و data injection",
            "remediation": "Content-Security-Policy: default-src 'self'",
            "risk": "HIGH"
        },
        "X-Frame-Options": {
            "attack": "يمنع clickjacking",
            "remediation": "X-Frame-Options: DENY",
            "risk": "MEDIUM"
        },
        "X-Content-Type-Options": {
            "attack": "يمنع MIME-type sniffing",
            "remediation": "X-Content-Type-Options: nosniff",
            "risk": "LOW"
        },
        "Referrer-Policy": {
            "attack": "تسريب معلومات referrer",
            "remediation": "Referrer-Policy: strict-origin-when-cross-origin",
            "risk": "LOW"
        }
    }
    
    audit = {}
    
    for header, info in security_headers.items():
        if header in headers:
            audit[header] = {
                "status": "PRESENT",
                "value": headers[header],
                "attack": info["attack"],
                "remediation": info["remediation"],
                "risk": info["risk"]
            }
        else:
            audit[header] = {
                "status": "MISSING",
                "attack": info["attack"],
                "remediation": info["remediation"],
                "risk": info["risk"]
            }
    
    return audit

def get_http_headers(domain):
    """
    جلب هيدرات HTTP - تجربة HTTP فقط لموقع testphp.vulnweb.com
    """
    result = {
        "url": "",
        "status_code": None,
        "server": "Not disclosed",
        "x_powered_by": "Not disclosed",
        "all_headers": {},
        "security_audit": {},
        "note": ""
    }
    
    # نستخدم HTTP مباشرة لأن الموقع لا يدعم HTTPS
    url = f"http://{domain}"
    result["url"] = url
    
    try:
        print(f"[*] Fetching headers from: {url}")
        response = requests.get(url, timeout=10, verify=False)
        
        result["status_code"] = response.status_code
        result["server"] = response.headers.get("Server", "Not disclosed")
        result["x_powered_by"] = response.headers.get("X-Powered-By", "Not disclosed")
        result["all_headers"] = dict(response.headers)
        result["security_audit"] = check_security_headers(response.headers)
        
        if response.status_code == 200:
            result["note"] = "Successfully connected via HTTP"
        
    except requests.exceptions.ConnectionError as e:
        result["note"] = f"Connection error: {str(e)[:80]}"
    except requests.exceptions.Timeout:
        result["note"] = "Request timed out"
    except Exception as e:
        result["note"] = f"Error: {str(e)[:80]}"
    
    return result
