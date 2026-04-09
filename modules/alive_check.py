import requests

def check_alive(subdomains):
    print("[*] Checking Alive Hosts...")

    alive = []

    for sub in subdomains:
        for proto in ["http://", "https://"]:
            url = proto + sub

            try:
                r = requests.get(url, timeout=3)

                print(f"[+] Alive: {url} ({r.status_code})")

                alive.append({
                    "url": url,
                    "status": r.status_code
                })

            except:
                pass

    return alive
