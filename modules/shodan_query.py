import shodan
import socket
import os

def shodan_lookup(domain, api_key=None):
    """
    البحث في Shodan عن معلومات الـ IP المرتبط بالدومين
    """
    if api_key is None:
        api_key = os.environ.get('SHODAN_API_KEY')
    
    if not api_key:
        return {
            "status": "error",
            "message": "Shodan API key not found. Get one from https://account.shodan.io"
        }
    
    try:
        # الحصول على IP من الدومين
        ip = socket.gethostbyname(domain)
        print(f"[*] Looking up {domain} ({ip}) on Shodan...")
        
        api = shodan.Shodan(api_key)
        result = api.host(ip)
        
        return {
            "status": "success",
            "ip": ip,
            "domain": domain,
            "organization": result.get('org', 'Unknown'),
            "operating_system": result.get('os', 'Unknown'),
            "country": result.get('country_name', 'Unknown'),
            "open_ports": result.get('ports', []),
            "vulns": result.get('vulns', []),
            "hostnames": result.get('hostnames', [])
        }
        
    except shodan.APIError as e:
        return {
            "status": "error",
            "message": f"Shodan API error: {str(e)}"
        }
    except socket.gaierror:
        return {
            "status": "error",
            "message": f"Could not resolve domain: {domain}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
