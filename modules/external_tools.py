import subprocess
import os

def ask_user(question, default="yes"):
    """تسأل المستخدم yes/no وتطلع True/False"""
    if default == "yes":
        prompt = f"{question} (Y/n): "
    else:
        prompt = f"{question} (y/N): "
    
    response = input(prompt).strip().lower()
    
    if default == "yes":
        return response != "n"
    else:
        return response == "y"


def run_subfinder(domain):
    """تشغيل subfinder لجمع الساب دومينز"""
    output_file = f"/tmp/subfinder_{domain}.txt"
    try:
        print(f"[*] Running subfinder -d {domain}")
        cmd = f"subfinder -d {domain} -silent -o {output_file}"
        subprocess.run(cmd, shell=True, timeout=120, capture_output=True)
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subs = [line.strip() for line in f if line.strip()]
            os.remove(output_file)
            return subs
        return []
    except Exception as e:
        print(f"[!] subfinder error: {e}")
        return []


def run_assetfinder(domain):
    """تشغيل assetfinder لجمع الساب دومينز"""
    try:
        print(f"[*] Running assetfinder -subs-only {domain}")
        cmd = f"echo {domain} | assetfinder -subs-only"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        subs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return subs
    except Exception as e:
        print(f"[!] assetfinder error: {e}")
        return []


def run_amass(domain):
    """تشغيل amass لجمع الساب دومينز"""
    output_file = f"/tmp/amass_{domain}.txt"
    try:
        print(f"[*] Running amass enum -d {domain}")
        cmd = f"amass enum -d {domain} -silent -o {output_file}"
        subprocess.run(cmd, shell=True, timeout=180, capture_output=True)
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subs = [line.strip() for line in f if line.strip()]
            os.remove(output_file)
            return subs
        return []
    except Exception as e:
        print(f"[!] amass error: {e}")
        return []


def run_all_external_tools(domain, interactive=False):
    """تشغيل كل الأدوات الخارجية وجمع النتائج"""
    all_subs = set()
    
    # subfinder
    if not interactive or ask_user("[?] Run subfinder for passive subdomains?"):
        subs = run_subfinder(domain)
        print(f"[+] subfinder found {len(subs)} subdomains")
        all_subs.update(subs)
    else:
        print("[!] Skipping subfinder")
    
    # assetfinder
    if not interactive or ask_user("[?] Run assetfinder for passive subdomains?"):
        subs = run_assetfinder(domain)
        print(f"[+] assetfinder found {len(subs)} subdomains")
        all_subs.update(subs)
    else:
        print("[!] Skipping assetfinder")
    
    # amass
    if not interactive or ask_user("[?] Run amass for passive subdomains? (may take time)"):
        subs = run_amass(domain)
        print(f"[+] amass found {len(subs)} subdomains")
        all_subs.update(subs)
    else:
        print("[!] Skipping amass")
    
    return list(all_subs)
