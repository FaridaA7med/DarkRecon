import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# نمط الإيميل
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'


def extract_emails_from_text(text):
    """
    استخراج الإيميلات من نص
    """
    emails = re.findall(EMAIL_PATTERN, text)
    return list(set(emails))  # إزالة التكرار


def extract_emails_from_url(url, timeout=10, max_pages=10):
    """
    استخراج الإيميلات من صفحة واحدة
    """
    result = {
        "url": url,
        "emails": [],
        "status": "success"
    }
    
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        response.raise_for_status()
        
        emails = extract_emails_from_text(response.text)
        result["emails"] = emails
        result["count"] = len(emails)
        
    except requests.exceptions.Timeout:
        result["status"] = "timeout"
    except requests.exceptions.ConnectionError:
        result["status"] = "connection_error"
    except Exception as e:
        result["status"] = f"error: {str(e)}"
    
    return result


def crawl_and_extract_emails(start_url, max_pages=20, timeout=10):
    """
    الزحف على الموقع واستخراج الإيميلات من عدة صفحات
    """
    visited = set()
    to_visit = [start_url]
    all_emails = set()
    pages_visited = 0
    
    result = {
        "start_url": start_url,
        "pages_visited": 0,
        "emails_found": [],
        "email_sources": {},
        "status": "success"
    }
    
    while to_visit and pages_visited < max_pages:
        url = to_visit.pop(0)
        
        if url in visited:
            continue
        
        visited.add(url)
        
        try:
            response = requests.get(url, timeout=timeout, verify=False)
            response.raise_for_status()
            
            # استخراج الإيميلات من الصفحة الحالية
            emails = extract_emails_from_text(response.text)
            
            if emails:
                all_emails.update(emails)
                result["email_sources"][url] = emails
            
            # استخراج الروابط للزحف (لو عايزين نكمل)
            if pages_visited < max_pages - 1:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(url, link['href'])
                    if start_url in full_url and full_url not in visited:
                        to_visit.append(full_url)
            
            pages_visited += 1
            result["pages_visited"] = pages_visited
            
        except Exception as e:
            continue
    
    result["emails_found"] = list(all_emails)
    result["total_emails"] = len(all_emails)
    
    return result


def extract_emails_from_subdomains(domain, subdomains, timeout=10):
    """
    استخراج الإيميلات من الساب دومينز
    """
    results = {}
    all_emails = set()
    
    for sub in subdomains[:20]:  # حد أقصى 20 ساب دومين
        url = f"http://{sub}"
        try:
            response = requests.get(url, timeout=timeout, verify=False)
            emails = extract_emails_from_text(response.text)
            if emails:
                results[url] = emails
                all_emails.update(emails)
        except:
            continue
    
    return {
        "total_emails": len(all_emails),
        "emails": list(all_emails),
        "sources": results
    }
