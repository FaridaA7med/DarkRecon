#!/usr/bin/env python3
import argparse
from datetime import datetime
import json
import os

from modules.subdomain_enum import enumerate_subdomains
from modules.alive_check import check_alive
from modules.dir_fuzz import dir_fuzz
from modules.wayback import get_wayback_urls
from modules.whois_lookup import get_whois
from modules.dns_enum import get_dns_records
from modules.ssl_info import get_ssl_info
from modules.port_scan import scan_ports
from modules.banner_grab import grab_all_banners
from modules.robots_txt import get_robots_txt
from modules.google_dorks import generate_google_dorks
from modules.cve_lookup import analyze_open_ports
from modules.http_headers import get_http_headers
from modules.report import save_report

def run_passive(domain):
    """تشغيل جميع موديولات passive recon"""
    print("\n[+] Running PASSIVE reconnaissance...\n")
    
    results = {}
    
    # WHOIS
    print("[*] WHOIS lookup...")
    whois_data = get_whois(domain)
    results["whois"] = whois_data if whois_data else {"status": "unavailable"}
    
    # DNS Records
    print("[*] DNS enumeration...")
    results["dns_records"] = get_dns_records(domain)
    
    # SSL Info
    print("[*] SSL certificate analysis...")
    ssl_data = get_ssl_info(domain)
    results["ssl_info"] = ssl_data if ssl_data else {"status": "unavailable"}
    
    return results

def run_active(domain, wordlist):
    """تشغيل جميع موديولات active recon"""
    print("\n[+] Running ACTIVE reconnaissance...\n")
    
    results = {}
    # Port Scan
    print("[*] Port scanning...")
    results["port_scan"] = scan_ports(domain)
    # Banner Grabbing
    print("[*] Banner grabbing...")
    if "port_scan" in results and "open_ports" in results["port_scan"]:
        results["banners"] = grab_all_banners(domain, results["port_scan"]["open_ports"])
    else:
        results["banners"] = {"error": "No open ports found"}
    # Robots.txt
    print("[*] Checking robots.txt...")
    results["robots_txt"] = get_robots_txt(domain)
    
    # Google Dorks
    print("[*] Generating Google dorks...")
    results["google_dorks"] = generate_google_dorks(domain)    
    # CVE Analysis for open ports
    print("[*] Analyzing CVEs for open ports...")
    if "port_scan" in results and "open_ports" in results["port_scan"]:
        results["cve_analysis"] = analyze_open_ports(domain, results["port_scan"]["open_ports"])
    else:
        results["cve_analysis"] = {"error": "No open ports found"}
    # Subdomains
    print("[*] Subdomain enumeration...")
    results["subdomains"] = enumerate_subdomains(domain, wordlist)
    
    # Alive check
    print("[*] Checking alive hosts...")
    results["alive_hosts"] = check_alive(results["subdomains"])
    
    # Directory fuzzing
    print("[*] Directory fuzzing...")
    results["directories"] = dir_fuzz(domain, wordlist)
    
    # Wayback URLs
    print("[*] Wayback Machine URLs...")
    results["wayback_urls"] = get_wayback_urls(domain)
    
    # HTTP Headers
    print("[*] HTTP headers analysis...")
    results["http_headers"] = get_http_headers(domain)
    
    return results

def main():
    print("""
    ╔═══════════════════════════╗
    ║      DarkRecon Tool       ║
    ║   Web Reconnaissance      ║
    ╚═══════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(description="Web Reconnaissance Tool")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("--mode", choices=["passive", "active", "full"], 
                       default="full", help="Recon mode")
    parser.add_argument("--wordlist", default="wordlists/common.txt", 
                       help="Path to wordlist file")
    
    args = parser.parse_args()
    
    domain = args.target
    all_results = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "mode": args.mode
    }
    
    if args.mode in ["passive", "full"]:
        all_results["passive"] = run_passive(domain)
    
    if args.mode in ["active", "full"]:
        all_results["active"] = run_active(domain, args.wordlist)
    
    # Save report
    save_report(domain, all_results)
    
    print(f"\n[+] Scan completed! Results saved to reports/")

if __name__ == "__main__":
    main()
