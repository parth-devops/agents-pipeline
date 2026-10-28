import requests

def get_status(url):
    return requests.get(url, timeout=5).status_code

if __name__ == "__main__":
    print(get_status("https://example.com"))