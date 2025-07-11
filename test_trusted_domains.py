import requests
import json

def normalize_url(url):
    """Ensure URL has a protocol"""
    if not url.startswith(('http://', 'https://')):
        return f'https://{url}'
    return url

def test_url(url):
    try:
        normalized_url = normalize_url(url)
        response = requests.post(
            'http://localhost:5001/predict',
            json={'url': normalized_url},
            headers={'Content-Type': 'application/json'}
        )
        result = response.json()
        print(f"\nTesting URL: {url} (normalized to: {normalized_url})")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(result, indent=2)}")
        return result
    except Exception as e:
        print(f"Error testing {url}: {str(e)}")
        return None

# Test cases
test_urls = [
    'www.google.com',
    'https://www.google.com',
    'http://www.google.com',
    'google.com',
    'https://google.com',
    'subdomain.google.com',
    'www.github.com',
    'github.com',
    'example.com',  # Should not be trusted
    'phishing-site.com'  # Should be marked as suspicious/phishing
]

if __name__ == "__main__":
    print("Testing trusted domains...")
    for url in test_urls:
        test_url(url)
