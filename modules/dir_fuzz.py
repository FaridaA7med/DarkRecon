import requests

def dir_fuzz(domain, wordlist):
    print("[*] Directory Fuzzing...")

    found = []

    with open(wordlist) as f:
        for word in f:
            word = word.strip()

            for ext in ["", ".php", ".html", ".bak"]:
                url = f"http://{domain}/{word}{ext}"

                try:
                    r = requests.get(url, timeout=3)

                    if r.status_code not in [404, 400]:
                        print(f"[+] Found: {url} ({r.status_code})")

                        found.append({
                            "url": url,
                            "status": r.status_code
                        })

                except:
                    pass

    return found
