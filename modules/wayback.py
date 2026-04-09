import requests

def get_wayback_urls(domain):
    print("[*] Getting Wayback URLs...")

    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json"

    try:
        r = requests.get(url, timeout=10)
        data = r.json()

        urls = [entry[0] for entry in data[1:]]

        return urls

    except:
        return []
