import requests
import dns.resolver

# Passive (crt.sh)
def passive_subdomains(domain):
    print("[*] Passive Subdomains...")

    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        r = requests.get(url, timeout=10)
        data = r.json()

        subs = set()

        for entry in data:
            names = entry.get("name_value", "")
            for sub in names.split("\n"):
                subs.add(sub.strip())

        return list(subs)

    except:
        return []


# Active (Bruteforce)
def brute_subdomains(domain, wordlist):
    print("[*] Bruteforce Subdomains...")

    found = []

    with open(wordlist) as f:
        for word in f:
            sub = word.strip() + "." + domain

            try:
                dns.resolver.resolve(sub, "A")
                print(f"[+] Found: {sub}")
                found.append(sub)
            except:
                pass

    return found


# Merge
def enumerate_subdomains(domain, wordlist):
    passive = passive_subdomains(domain)
    active = brute_subdomains(domain, wordlist)

    return list(set(passive + active))
