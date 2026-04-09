def generate_google_dorks(domain):
    """
    توليد Google Dorks للبحث عن معلومات حساسة
    """
    dorks = {
        "site_search": f"site:{domain}",
        "subdomains": f"site:*.{domain}",
        "admin_panels": f"site:{domain} intitle:admin OR intitle:login OR intitle:panel",
        "login_pages": f"site:{domain} inurl:login OR inurl:signin OR inurl:auth",
        "files": f"site:{domain} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:sql OR filetype:log",
        "config_files": f"site:{domain} filetype:conf OR filetype:config OR filetype:env",
        "backup_files": f"site:{domain} filetype:bak OR filetype:backup OR filetype:old",
        "database": f"site:{domain} filetype:sql OR inurl:database OR inurl:db",
        "passwords": f"site:{domain} intext:password OR intext:passwd OR intext:secret",
        "email_addresses": f"site:{domain} intext:@",
        "php_info": f"site:{domain} intitle:'phpinfo()'",
        "directory_listing": f"site:{domain} intitle:'index of'",
        "vulnerable_params": f"site:{domain} inurl:?id= OR inurl:?page= OR inurl:?q=",
        "api_endpoints": f"site:{domain} inurl:/api/ OR inurl:/v1/ OR inurl:/v2/",
        "git_repos": f"site:{domain} inurl:.git",
        "aws_buckets": f"site:s3.amazonaws.com {domain}",
        "google_sheets": f"site:docs.google.com/spreadsheets {domain}"
    }
    
    result = {
        "domain": domain,
        "total_dorks": len(dorks),
        "dorks": dorks,
        "usage": "Copy each dork and paste into Google search",
        "warning": "Google may block automated searches. Use manually for OSINT."
    }
    
    # إضافة dorks مخصصة للمنصات المختلفة
    if "admin" in domain or "login" in domain:
        result["note"] = "Target appears to have authentication pages"
    
    return result

def format_dorks_for_report(dorks_data):
    """
    تنسيق dorks للتقرير بشكل مقروء
    """
    if not dorks_data or "dorks" not in dorks_data:
        return ""
    
    formatted = "### 🔍 Google Dorks for OSINT\n\n"
    formatted += f"**Target:** {dorks_data['domain']}\n\n"
    formatted += "| Category | Google Dork |\n"
    formatted += "|----------|-------------|\n"
    
    for category, dork in dorks_data["dorks"].items():
        # تحويل اسم الفئة إلى اسم مقروء
        category_name = category.replace("_", " ").title()
        formatted += f"| {category_name} | `{dork}` |\n"
    
    formatted += f"\n**Note:** {dorks_data.get('warning', 'Use responsibly')}\n"
    
    return formatted
