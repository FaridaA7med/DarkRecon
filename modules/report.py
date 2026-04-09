import json
import os
from datetime import datetime

def save_report(domain, data):
    """حفظ التقرير بصيغة JSON و Markdown"""
    os.makedirs("reports", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # حفظ JSON
    json_file = f"reports/DarkRecon_{domain}_{timestamp}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"[+] JSON report saved: {json_file}")
    
    # حفظ Markdown عادي
    md_file = f"reports/DarkRecon_{domain}_{timestamp}.md"
    with open(md_file, "w", encoding="utf-8") as f:
        f.write(f"# DarkRecon Report - {domain}\n\n")
        f.write(f"**Scan Time:** {data['timestamp']}\n")
        f.write(f"**Mode:** {data['mode']}\n\n")
        f.write("---\n\n")
        f.write("```json\n")
        f.write(json.dumps(data, indent=2, default=str))
        f.write("\n```\n")
    
    # حفظ التقرير الاحترافي
    pro_file = f"reports/DarkRecon_{domain}_{timestamp}_PROFESSIONAL.md"
    generate_professional_report(domain, data, pro_file)
    print(f"[+] Professional report saved: {pro_file}")


def generate_professional_report(domain, data, filename):
    """توليد تقرير احترافي مع تقييم المخاطر"""
    with open(filename, "w", encoding="utf-8") as f:
        # Header
        f.write(f"# 🔐 Web Reconnaissance Report\n\n")
        f.write(f"**Target:** `{domain}`\n")
        f.write(f"**Scan Date:** {data['timestamp']}\n")
        f.write(f"**Scan Mode:** {data['mode']}\n\n")
        f.write("---\n\n")
        
        # Executive Summary
        f.write("## 📋 Executive Summary\n\n")
        f.write("This report presents the findings of an authorized web reconnaissance assessment. ")
        f.write("The assessment included both passive and active information gathering techniques ")
        f.write("to identify potential security weaknesses and exposed services.\n\n")
        
        # Risk Assessment Table
        f.write("## 🎯 Risk Assessment Summary\n\n")
        f.write("| Risk Level | Count | Description |\n")
        f.write("|------------|-------|-------------|\n")
        
        risks = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        if "active" in data and "http_headers" in data["active"]:
            headers = data["active"]["http_headers"]
            if "security_audit" in headers:
                for header, info in headers["security_audit"].items():
                    if info["status"] == "MISSING":
                        risks[info["risk"]] += 1
        
        if "active" in data and "port_scan" in data["active"]:
            open_count = data["active"]["port_scan"].get("open_count", 0)
            if open_count > 0:
                risks["MEDIUM"] += 1
        
        f.write(f"| 🔴 CRITICAL | {risks['CRITICAL']} | Immediate action required |\n")
        f.write(f"| 🟠 HIGH | {risks['HIGH']} | Address as priority |\n")
        f.write(f"| 🟡 MEDIUM | {risks['MEDIUM']} | Plan for remediation |\n")
        f.write(f"| 🟢 LOW | {risks['LOW']} | Best practice improvement |\n")
        f.write(f"| 🔵 INFO | {risks['INFO']} | Informational only |\n\n")
        
        # Open Ports
        if "active" in data and "port_scan" in data["active"]:
            f.write("## 🔌 Open Ports Discovered\n\n")
            f.write("| Port | Service | Risk |\n")
            f.write("|------|---------|------|\n")
            for port in data["active"]["port_scan"].get("open_ports", []):
                risk = "MEDIUM" if port["port"] in [21,23,3306,5432] else "INFO"
                f.write(f"| {port['port']} | {port['service']} | {risk} |\n")
            f.write("\n")
        
        # Missing Security Headers
        if "active" in data and "http_headers" in data["active"]:
            f.write("## ⚠️ Missing Security Headers\n\n")
            headers = data["active"]["http_headers"]
            if "security_audit" in headers:
                f.write("| Header | Risk | Attack Mitigated | Remediation |\n")
                f.write("|--------|------|------------------|-------------|\n")
                for header, info in headers["security_audit"].items():
                    if info["status"] == "MISSING":
                        f.write(f"| {header} | {info['risk']} | {info['attack']} | `{info['remediation']}` |\n")
            f.write("\n")
        
        # Google Dorks
        if "active" in data and "google_dorks" in data["active"]:
            f.write("## 🔍 OSINT Discovery (Google Dorks)\n\n")
            f.write("Use these Google search queries for further OSINT investigation:\n\n")
            dorks = data["active"]["google_dorks"].get("dorks", {})
            f.write("| Category | Dork |\n")
            f.write("|----------|------|\n")
            for category, dork in list(dorks.items())[:10]:
                f.write(f"| {category.replace('_', ' ').title()} | `{dork}` |\n")
            f.write("\n")
        
        # Shodan Results
                
        if "active" in data and "shodan" in data["active"]:
            f.write("## 🌐 Shodan Intelligence\n\n")
            shodan = data["active"]["shodan"]
            if shodan.get("status") == "success":
                f.write("| Property | Value |\n")
                f.write("|----------|-------|\n")
                f.write(f"| IP Address | `{shodan.get('ip', 'Unknown')}` |\n")
                f.write(f"| Organization | {shodan.get('organization', 'Unknown')} |\n")
                f.write(f"| Operating System | {shodan.get('operating_system', 'Unknown')} |\n")
                f.write(f"| Country | {shodan.get('country', 'Unknown')} |\n")
                f.write(f"| Open Ports (Shodan) | {', '.join(map(str, shodan.get('open_ports', [])))} |\n")
                if shodan.get("vulns"):
                    f.write(f"| Known Vulnerabilities | {', '.join(shodan.get('vulns', []))} |\n")
            else:
                f.write(f"*{shodan.get('message', 'Shodan lookup failed')}*\n")
            f.write("\n")
        
        # CVE Analysis Results
        if "active" in data and "cve_analysis" in data["active"]:
            f.write("## 🛡️ CVE Vulnerability Analysis\n\n")
            cve_analysis = data["active"]["cve_analysis"]
            
            if isinstance(cve_analysis, dict):
                for key, cve_data in cve_analysis.items():
                    if isinstance(cve_data, dict) and cve_data.get("status") == "success" and cve_data.get("cves"):
                        f.write(f"### {key}\n\n")
                        f.write("| CVE ID | Severity | Score | Description |\n")
                        f.write("|--------|----------|-------|-------------|\n")
                        for cve in cve_data["cves"][:5]:
                            severity = cve.get('severity', 'N/A')
                            score = cve.get('cvss_score', 'N/A')
                            desc = cve.get('description', '')[:80]
                            f.write(f"| {cve['id']} | {severity} | {score} | {desc}... |\n")
                        f.write("\n")
                    elif isinstance(cve_data, dict) and cve_data.get("status") == "error":
                        f.write(f"### {key}\n")
                        f.write(f"*Error: {cve_data.get('message', 'Unknown error')}*\n\n")
                    elif isinstance(cve_data, dict):
                        f.write(f"### {key}\n")
                        f.write("*No CVEs found for this service*\n\n")
                    else:
                        f.write(f"### {key}\n")
                        f.write(f"*{cve_data}*\n\n")
            else:
                f.write(f"*{cve_analysis}*\n\n")
        # WAF Results
        if "active" in data and "waf" in data["active"]:
            f.write("## 🛡️ WAF Detection Results\n\n")
            waf = data["active"]["waf"]
            if waf.get("has_waf"):
                f.write(f"| Property | Value |\n")
                f.write(f"|----------|-------|\n")
                f.write(f"| WAF Detected | ✅ Yes |\n")
                f.write(f"| WAF Name | **{waf.get('waf_name')}** |\n")
                f.write(f"| Confidence | {waf.get('confidence')} |\n")
                if waf.get("evidence"):
                    f.write(f"| Evidence | {', '.join(waf['evidence'][:3])} |\n")
            else:
                f.write(f"*No WAF detected or unknown WAF*\n")
            f.write("\n")
        
        # Email Extractor Results
        if "active" in data and "emails" in data["active"]:
            f.write("## 📧 Extracted Emails\n\n")
            emails = data["active"]["emails"]
            if emails.get("emails"):
                f.write("| Email |\n")
                f.write("|-------|\n")
                for email in emails["emails"][:10]:
                    f.write(f"| `{email}` |\n")
                if len(emails["emails"]) > 10:
                    f.write(f"| *... and {len(emails['emails']) - 10} more* |\n")
            else:
                f.write("*No emails found*\n")
            f.write("\n")
        
        # Recommendations
        f.write("## 📝 Recommendations\n\n")
        f.write("1. **Enable HSTS**: Add `Strict-Transport-Security` header to enforce HTTPS\n")
        f.write("2. **Add Referrer-Policy**: Implement `Referrer-Policy: strict-origin-when-cross-origin`\n")
        f.write("3. **Review robots.txt**: Ensure no sensitive paths are exposed\n")
        f.write("4. **Regular Scanning**: Conduct periodic reconnaissance to identify new exposures\n\n")
        
        # Footer
        f.write("---\n")
        f.write(f"*Report generated by DarkRecon Tool | {data['timestamp']}*\n")
