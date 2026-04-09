#!/usr/bin/env python3
import argparse
from datetime import datetime
import json
import os
import sys

from colorama import init, Fore, Style, Back

from modules.alive_check import check_alive
from modules.banner_grab import grab_all_banners
from modules.cve_lookup import analyze_open_ports
from modules.dir_fuzz import dir_fuzz
from modules.dns_enum import get_dns_records
from modules.external_tools import run_all_external_tools
from modules.google_dorks import generate_google_dorks
from modules.http_headers import get_http_headers
from modules.port_scan import scan_ports
from modules.report import save_report
from modules.robots_txt import get_robots_txt
from modules.shodan_query import shodan_lookup
from modules.ssl_info import get_ssl_info
from modules.wayback import get_wayback_urls
from modules.whois_lookup import get_whois
from modules.waf_detection import detect_waf, test_waf_by_payload
from modules.email_extractor import extract_emails_from_url, crawl_and_extract_emails

# تهيئة الألوان
init(autoreset=True)

# تعريف ألوان قوية وظاهرة
RED = Fore.RED + Style.BRIGHT
GREEN = Fore.GREEN + Style.BRIGHT
YELLOW = Fore.YELLOW + Style.BRIGHT
CYAN = Fore.CYAN + Style.BRIGHT
WHITE = Fore.WHITE + Style.BRIGHT
RESET = Style.RESET_ALL


def ask_user(question, default="yes"):
    """تسأل المستخدم yes/no وتطلع True/False"""
    if default == "yes":
        prompt = f"\n{CYAN}┌─[?] {question}{RESET}\n└─ (Y/n): "
    else:
        prompt = f"\n{CYAN}┌─[?] {question}{RESET}\n└─ (y/N): "
    
    response = input(prompt).strip().lower()
    
    if default == "yes":
        return response != "n"
    else:
        return response == "y"


def print_banner():
    """طباعة البانر الرئيسي"""
    print(f"""
{YELLOW}╔═══════════════════════════════════════╗
║       {WHITE}DarkRecon Tool{YELLOW}               ║
║    {WHITE}Web Reconnaissance{YELLOW}            ║
╚═══════════════════════════════════════╝{RESET}
    """)


def print_success(msg):
    """طباعة رسالة نجاح"""
    print(f"{GREEN}[✓]{RESET} {msg}")


def print_info(msg):
    """طباعة رسالة معلومات"""
    print(f"{YELLOW}[*]{RESET} {msg}")


def print_error(msg):
    """طباعة رسالة خطأ"""
    print(f"{RED}[✗]{RESET} {msg}")


def print_title(msg):
    """طباعة عنوان رئيسي"""
    print(f"\n{YELLOW}{'═' * 50}{RESET}")
    print(f"{YELLOW}▶ {msg}{RESET}")
    print(f"{YELLOW}{'═' * 50}{RESET}")


def print_subtitle(msg):
    """طباعة عنوان فرعي"""
    print(f"\n{YELLOW}┌─[{msg}]{RESET}")


def print_finding(msg):
    """طباعة اكتشاف مهم"""
    print(f"{GREEN}[+] {msg}{RESET}")


def run_passive(domain, interactive=False):
    """تشغيل جميع موديولات passive recon"""
    print_title("PASSIVE RECONNAISSANCE")
    
    results = {}
    
    # WHOIS
    print_subtitle("WHOIS Module")
    if not interactive or ask_user("Run WHOIS lookup?"):
        print_info("Querying WHOIS database...")
        whois_data = get_whois(domain)
        results["whois"] = whois_data if whois_data else {"status": "unavailable"}
        if results["whois"] and results["whois"].get("status") != "unavailable":
            print_success("WHOIS data retrieved")
            if results["whois"].get("registrar"):
                print_finding(f"Registrar: {results['whois']['registrar']}")
    else:
        print_error("Skipping WHOIS lookup")
        results["whois"] = {"status": "skipped"}
    
    # DNS Records
    print_subtitle("DNS Module")
    if not interactive or ask_user("Run DNS enumeration?"):
        print_info("Enumerating DNS records...")
        results["dns_records"] = get_dns_records(domain)
        print_success("DNS enumeration completed")
        if results["dns_records"].get("A"):
            print_finding(f"IP Addresses: {', '.join(results['dns_records']['A'][:3])}")
    else:
        print_error("Skipping DNS enumeration")
        results["dns_records"] = {"status": "skipped"}
    
    # SSL Info
    print_subtitle("SSL/TLS Module")
    if not interactive or ask_user("Run SSL certificate analysis?"):
        print_info("Analyzing SSL certificate...")
        ssl_data = get_ssl_info(domain)
        results["ssl_info"] = ssl_data if ssl_data else {"status": "unavailable"}
        if results["ssl_info"] and results["ssl_info"].get("status") == "success":
            print_success("SSL certificate analyzed")
            if results["ssl_info"].get("subject_alt_names"):
                print_finding(f"SANs: {len(results['ssl_info']['subject_alt_names'])} domains found")
    else:
        print_error("Skipping SSL analysis")
        results["ssl_info"] = {"status": "skipped"}
    
    # External Tools (subfinder, amass, assetfinder) - PASSIVE
    print_subtitle("External Tools (subfinder, amass, assetfinder)")
    if not interactive or ask_user("Run passive subdomain enumeration with external tools?"):
        print_info("Running subfinder, amass, assetfinder...")
        results["passive_subdomains"] = run_all_external_tools(domain, interactive)
        if results["passive_subdomains"]:
            print_success(f"Found {len(results['passive_subdomains'])} subdomain(s)")
            for sub in results["passive_subdomains"][:5]:
                print_finding(sub)
            if len(results["passive_subdomains"]) > 5:
                print_info(f"... and {len(results['passive_subdomains']) - 5} more")
    else:
        print_error("Skipping external tools")
        results["passive_subdomains"] = []
    
    return results


def run_active(domain, wordlist, ports=None, interactive=False, shodan_key=None):
    """تشغيل جميع موديولات active recon"""
    print_title("ACTIVE RECONNAISSANCE")
    
    results = {}
    
    # Port Scan
    print_subtitle("Port Scanner")
    if not interactive or ask_user("Run port scan?"):
        print_info("Scanning for open ports...")
        if ports:
            results["port_scan"] = scan_ports(domain, ports)
        else:
            results["port_scan"] = scan_ports(domain)
        open_count = results["port_scan"].get("open_count", 0)
        if open_count > 0:
            print_success(f"Found {open_count} open port(s)")
            for port in results["port_scan"].get("open_ports", []):
                print_finding(f"Port {port['port']} ({port['service']}) is OPEN")
    else:
        print_error("Skipping port scan")
        results["port_scan"] = {"status": "skipped", "open_ports": []}
    
    # Banner Grabbing
    print_subtitle("Banner Grabbing")
    if not interactive or ask_user("Run banner grabbing?"):
        print_info("Grabbing service banners...")
        if "port_scan" in results and "open_ports" in results["port_scan"]:
            results["banners"] = grab_all_banners(domain, results["port_scan"]["open_ports"])
            print_success("Banners retrieved")
    else:
        print_error("Skipping banner grabbing")
        results["banners"] = {"status": "skipped"}
    
    # CVE Analysis
    print_subtitle("CVE Analysis")
    if not interactive or ask_user("Run CVE analysis?"):
        print_info("Checking for known vulnerabilities...")
        if "port_scan" in results and "open_ports" in results["port_scan"]:
            results["cve_analysis"] = analyze_open_ports(domain, results["port_scan"]["open_ports"])
            print_success("CVE analysis completed")
    else:
        print_error("Skipping CVE analysis")
        results["cve_analysis"] = {"status": "skipped"}
    
    # Shodan Lookup
    print_subtitle("Shodan Intelligence")
    if not interactive or ask_user("Run Shodan lookup? (requires API key)"):
        print_info("Querying Shodan database...")
        if shodan_key is None:
            shodan_key = os.environ.get('SHODAN_API_KEY')
        results["shodan"] = shodan_lookup(domain, shodan_key)
        if results["shodan"].get("status") == "success":
            print_success("Shodan data retrieved")
            if results["shodan"].get("open_ports"):
                print_finding(f"Open ports from Shodan: {', '.join(map(str, results['shodan']['open_ports']))}")
        else:
            print_error(f"Shodan: {results['shodan'].get('message', 'Failed')}")
    else:
        print_error("Skipping Shodan lookup")
        results["shodan"] = {"status": "skipped"}
    
    # Alive check (using subdomains from passive)
    print_subtitle("Alive Host Check")
    if not interactive or ask_user("Run alive host check on discovered subdomains?"):
        print_info("Checking alive hosts...")
        results["alive_hosts"] = check_alive([])  # Will be updated from passive results if available
        if results["alive_hosts"]:
            print_success(f"Found {len(results['alive_hosts'])} alive host(s)")
    else:
        print_error("Skipping alive host check")
        results["alive_hosts"] = []
    
    # Directory fuzzing
    print_subtitle("Directory Fuzzing")
    if not interactive or ask_user("Run directory fuzzing?"):
        print_info("Fuzzing for hidden directories...")
        results["directories"] = dir_fuzz(domain, wordlist)
        if results["directories"]:
            print_success(f"Found {len(results['directories'])} path(s)")
            for d in results["directories"][:5]:
                print_finding(f"{d['url']} ({d['status']})")
    else:
        print_error("Skipping directory fuzzing")
        results["directories"] = []
    
    # Wayback URLs
    print_subtitle("Wayback Machine")
    if not interactive or ask_user("Run Wayback Machine lookup?"):
        print_info("Fetching archived URLs...")
        results["wayback_urls"] = get_wayback_urls(domain)
        if results["wayback_urls"]:
            print_success(f"Found {len(results['wayback_urls'])} archived URLs")
    else:
        print_error("Skipping Wayback Machine lookup")
        results["wayback_urls"] = []
    
    # HTTP Headers
    print_subtitle("HTTP Headers Analysis")
    if not interactive or ask_user("Run HTTP headers analysis?"):
        print_info("Analyzing security headers...")
        results["http_headers"] = get_http_headers(domain)
        print_success("Headers analyzed")
    else:
        print_error("Skipping HTTP headers analysis")
        results["http_headers"] = {"status": "skipped"}
    
    # Robots.txt
    print_subtitle("Robots.txt")
    if not interactive or ask_user("Check robots.txt?"):
        print_info("Checking for robots.txt...")
        results["robots_txt"] = get_robots_txt(domain)
        if results["robots_txt"].get("exists"):
            print_success("robots.txt found")
    else:
        print_error("Skipping robots.txt check")
        results["robots_txt"] = {"status": "skipped"}
    
    # Google Dorks
    print_subtitle("OSINT - Google Dorks")
    if not interactive or ask_user("Generate Google dorks?"):
        print_info("Generating Google dork queries...")
        results["google_dorks"] = generate_google_dorks(domain)
        print_success(f"Generated {results['google_dorks'].get('total_dorks', 0)} dorks")
    else:
        print_error("Skipping Google dorks generation")
        results["google_dorks"] = {"status": "skipped"}
    
        # WAF Detection
    print_subtitle("WAF Detection")
    if not interactive or ask_user("Run WAF detection?"):
        print_info("Detecting Web Application Firewall...")
        results["waf"] = detect_waf(f"http://{domain}")
        if results["waf"].get("has_waf"):
            print_finding(f"WAF Detected: {results['waf']['waf_name']} (Confidence: {results['waf']['confidence']})")
        else:
            print_info("No WAF detected")
    else:
        print_error("Skipping WAF detection")
        results["waf"] = {"status": "skipped"}
    
    # Email Extractor
    print_subtitle("Email Extractor")
    if not interactive or ask_user("Run email extractor?"):
        print_info("Extracting emails from target...")
        results["emails"] = extract_emails_from_url(f"http://{domain}")
        if results["emails"].get("emails"):
            print_success(f"Found {results['emails']['count']} email(s)")
            for email in results["emails"]["emails"][:5]:
                print_finding(email)
    else:
        print_error("Skipping email extractor")
        results["emails"] = {"status": "skipped"}
    
    
    return results


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Web Reconnaissance Tool")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("--mode", choices=["passive", "active", "full"], 
                       default="full", help="Recon mode")
    parser.add_argument("--wordlist", default="wordlists/common.txt", 
                       help="Path to wordlist file")
    parser.add_argument("--ports", help="Comma-separated ports to scan (e.g., 80,443,8080)")
    parser.add_argument("--interactive", action="store_true", 
                       help="Run in interactive mode (ask before each module)")
    parser.add_argument("--shodan-key", help="Shodan API key (or set SHODAN_API_KEY env variable)")
    
    args = parser.parse_args()
    
    domain = args.target
    all_results = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "mode": args.mode
    }
    
    print_info(f"Target: {WHITE}{domain}{RESET}")
    print_info(f"Mode: {WHITE}{args.mode}{RESET}")
    
    if args.mode in ["passive", "full"]:
        all_results["passive"] = run_passive(domain, args.interactive)
    
    if args.mode in ["active", "full"]:
        if args.interactive:
            if not ask_user("\nPassive reconnaissance completed. Continue with active recon?"):
                print_error("Exiting as requested")
                print_success(f"Partial scan completed! Results saved to reports/")
                save_report(domain, all_results)
                return
        
        # جلب Shodan API key
        shodan_key = args.shodan_key if args.shodan_key else os.environ.get('SHODAN_API_KEY')
        
        if args.ports:
            ports_list = [int(p.strip()) for p in args.ports.split(",")]
            all_results["active"] = run_active(domain, args.wordlist, ports_list, args.interactive, shodan_key)
        else:
            all_results["active"] = run_active(domain, args.wordlist, interactive=args.interactive, shodan_key=shodan_key)
    
    # Save report
    save_report(domain, all_results)
    
    print(f"\n{GREEN}{'═' * 50}{RESET}")
    print_success(f"Scan completed! Results saved to reports/")
    print(f"{GREEN}{'═' * 50}{RESET}")


if __name__ == "__main__":
    main()
