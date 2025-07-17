import requests
from termcolor import colored

def check_security_headers(url):
    """Check the security headers of a given URL."""
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        # List of critical security headers to check
        security_headers = {
            "Strict-Transport-Security": {
                "description": "Enforces secure (HTTPS) connections to the server.",
                "recommended": "max-age=31536000; includeSubDomains; preload",
                "severity": "high"
            },
            "X-Content-Type-Options": {
                "description": "Prevents MIME-sniffing attacks.",
                "recommended": "nosniff",
                "severity": "medium"
            },
            "X-Frame-Options": {
                "description": "Protects against clickjacking attacks.",
                "recommended": "DENY or SAMEORIGIN",
                "severity": "high"
            },
            "X-XSS-Protection": {
                "description": "Enables XSS filtering in older browsers.",
                "recommended": "1; mode=block",
                "severity": "medium"
            },
            "Content-Security-Policy": {
                "description": "Mitigates XSS, data injection, and other attacks.",
                "recommended": "A strict policy (e.g., default-src 'self')",
                "severity": "high"
            },
            "Referrer-Policy": {
                "description": "Controls how much referrer information is sent.",
                "recommended": "strict-origin-when-cross-origin",
                "severity": "low"
            },
            "Permissions-Policy": {
                "description": "Restricts browser features (e.g., geolocation, camera).",
                "recommended": "A restrictive policy (e.g., geolocation=())",
                "severity": "medium"
            }
        }

        print(colored(f"\n[+] Security Headers for: {url}", "blue", attrs=["bold"]))
        print(colored("=" * 50, "blue"))

        for header, details in security_headers.items():
            if header in headers:
                # Check if the header value matches the recommended configuration
                if header == "Strict-Transport-Security" and "max-age=31536000" in headers[header]:
                    print(colored(f"[✓] {header}: {headers[header]}", "green"))
                elif header == "X-Content-Type-Options" and headers[header].lower() == "nosniff":
                    print(colored(f"[✓] {header}: {headers[header]}", "green"))
                elif header == "X-Frame-Options" and headers[header].upper() in ["DENY", "SAMEORIGIN"]:
                    print(colored(f"[✓] {header}: {headers[header]}", "green"))
                elif header == "X-XSS-Protection" and headers[header] == "1; mode=block":
                    print(colored(f"[✓] {header}: {headers[header]}", "green"))
                elif header == "Content-Security-Policy" and headers[header]:
                    print(colored(f"[✓] {header}: {headers[header]}", "green"))
                elif header == "Referrer-Policy" and headers[header]:
                    print(colored(f"[✓] {header}: {headers[header]}", "green"))
                elif header == "Permissions-Policy" and headers[header]:
                    print(colored(f"[✓] {header}: {headers[header]}", "green"))
                else:
                    print(colored(f"[!] {header}: {headers[header]} (Weak configuration)", "yellow"))
                    print(colored(f"    Recommended: {details['recommended']}", "yellow"))
            else:
                print(colored(f"[✗] {header}: Missing", "red"))
                print(colored(f"    Description: {details['description']}", "red"))
                print(colored(f"    Recommended: {details['recommended']}", "red"))

    except requests.exceptions.RequestException as e:
        print(colored(f"[-] Failed to fetch headers: {e}", "red"))

def main():
    print(colored("=== Security Header Checker by learnwithaq.com ===", "cyan", attrs=["bold"]))
    url = input("Enter the URL to check (e.g., https://example.com): ")
    check_security_headers(url)

if __name__ == "__main__":
    main()
