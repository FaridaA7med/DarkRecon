import requests

def get_robots_txt(domain):
    """
    جلب وتحليل ملف robots.txt
    """
    result = {
        "domain": domain,
        "url": f"http://{domain}/robots.txt",
        "exists": False,
        "disallowed": [],
        "allowed": [],
        "sitemaps": [],
        "note": ""
    }
    
    try:
        response = requests.get(result["url"], timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        
        if response.status_code == 200:
            result["exists"] = True
            content = response.text
            
            for line in content.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line[9:].strip()
                    if path and path != "/":
                        result["disallowed"].append(path)
                elif line.lower().startswith("allow:"):
                    path = line[6:].strip()
                    if path:
                        result["allowed"].append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap = line[8:].strip()
                    if sitemap:
                        result["sitemaps"].append(sitemap)
            
            if result["disallowed"]:
                result["note"] = f"Found {len(result['disallowed'])} hidden paths in robots.txt"
            else:
                result["note"] = "robots.txt found but no disallowed paths"
        elif response.status_code == 404:
            result["note"] = "No robots.txt file found"
        else:
            result["note"] = f"HTTP {response.status_code}"
            
    except requests.exceptions.Timeout:
        result["note"] = "Timeout - robots.txt may not exist"
    except Exception as e:
        result["note"] = f"Error: {str(e)[:50]}"
    
    return result
