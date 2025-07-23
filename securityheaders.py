# Security Headers Checker
# Copyright (C) 2025 Ahmed Qadir / learnwithaq.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import requests
from termcolor import colored
import re

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

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
                value = headers[header]
                if header == "Strict-Transport-Security" and "max-age=31536000" in value:
                    print(colored(f"[✓] {header}: {value}", "green"))
                elif header == "X-Content-Type-Options" and value.lower() == "nosniff":
                    print(colored(f"[✓] {header}: {value}", "green"))
                elif header == "X-Frame-Options" and value.upper() in ["DENY", "SAMEORIGIN"]:
                    print(colored(f"[✓] {header}: {value}", "green"))
                elif header == "X-XSS-Protection" and value == "1; mode=block":
                    print(colored(f"[✓] {header}: {value}", "green"))
                elif header in ["Content-Security-Policy", "Referrer-Policy", "Permissions-Policy"] and value:
                    print(colored(f"[✓] {header}: {value}", "green"))
                else:
                    print(colored(f"[!] {header}: {value} (Weak configuration)", "yellow"))
                    print(colored(f"    Recommended: {details['recommended']}", "yellow"))
            else:
                print(colored(f"[✗] {header}: Missing", "red"))
                print(colored(f"    Description: {details['description']}", "red"))
                print(colored(f"    Recommended: {details['recommended']}", "red"))

    except requests.exceptions.RequestException as e:
        print(colored(f"[-] Failed to fetch headers: {e}", "red"))

def is_valid_url(url):
    if not url.startswith("https://"):
        print(colored("[-] Error: URL must start with 'https://'", "red"))
        return False
    if not re.search(r"\.[a-z]{2,}$", url):
        print(colored("[-] Error: URL must contain a valid top-level domain (e.g., .com, .org)", "red"))
        return False
    return True

def main():
    print(colored(""" 
  #####                                               #     #                                           
 #     # ######  ####  #    # #####  # ##### #   #    #     # ######   ##   #####  ###### #####   ####  
 #       #      #    # #    # #    # #   #    # #     #     # #       #  #  #    # #      #    # #      
  #####  #####  #      #    # #    # #   #     #      ####### #####  #    # #    # #####  #    #  ####  
       # #      #      #    # #####  #   #     #      #     # #      ###### #    # #      #####       # 
 #     # #      #    # #    # #   #  #   #     #      #     # #      #    # #    # #      #   #  #    # 
  #####  ######  ####   ####  #    # #   #     #      #     # ###### #    # #####  ###### #    #  ####  
                                                                                                        
""", "red"))
    print(colored("=== Security Header Checker by learnwithaq.com ===\n", "cyan", attrs=["bold"]))

    while True:
        url = input(colored("Enter a URL (e.g., https://example.com) or type 'exit' to quit: ", "yellow"))

        if url.lower() == 'exit':
            print(colored("\n[+] Exiting... Stay Secure!\n", "green"))
            break

        if not is_valid_url(url):
            continue

        check_security_headers(url)
        print(colored("\n-----------------------------------------------\n", "cyan"))

if __name__ == "__main__":
    main()
