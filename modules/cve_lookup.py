import nvdlib
import socket

def search_cves_by_service(service_name, port=None):
    """
    البحث عن CVEs مرتبطة بخدمة معينة
    """
    keyword = service_name
    if port:
        keyword = f"{service_name} port {port}"
    
    try:
        results = nvdlib.searchCVE(
            keywordSearch=keyword,
            limit=5
        )
        
        cves = []
        for cve in results:
            cves.append({
                "id": cve.id,
                "description": cve.descriptions[0].value[:150] if cve.descriptions else "No description",
                "cvss_score": getattr(cve, 'v31score', None) or getattr(cve, 'v2score', None),
                "severity": getattr(cve, 'v31severity', None) or getattr(cve, 'v2severity', 'UNKNOWN'),
                "published": str(cve.published)[:10] if cve.published else "Unknown"
            })
        
        return {
            "status": "success",
            "service": service_name,
            "port": port,
            "total": len(cves),
            "cves": cves
        }
        
    except Exception as e:
        return {
            "status": "error",
            "service": service_name,
            "port": port,
            "message": str(e),
            "cves": []
        }


def get_cve_details(cve_id):
    """
    الحصول على تفاصيل CVE محدد
    """
    try:
        results = nvdlib.searchCVE(cveId=cve_id)
        if results:
            cve = results[0]
            return {
                "id": cve.id,
                "description": cve.descriptions[0].value if cve.descriptions else "No description",
                "cvss_score": getattr(cve, 'v31score', None) or getattr(cve, 'v2score', None),
                "severity": getattr(cve, 'v31severity', None) or getattr(cve, 'v2severity', 'UNKNOWN'),
                "published": str(cve.published)[:10] if cve.published else "Unknown",
                "references": [ref.url for ref in cve.references][:3] if cve.references else []
            }
        return {"status": "error", "message": f"CVE {cve_id} not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def analyze_open_ports(domain, open_ports):
    """
    تحليل CVEs لجميع الموانئ المفتوحة
    """
    results = {}
    
    for port_info in open_ports:
        port = port_info["port"]
        service = port_info["service"]
        print(f"[*] Searching CVEs for {service} (port {port})...")
        results[f"{service}_{port}"] = search_cves_by_service(service, port)
    
    return results
