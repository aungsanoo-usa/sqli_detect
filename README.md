
# SQL Injection Detector with WAF Detection

## Overview
This script is a powerful tool for detecting **SQL Injection vulnerabilities** and identifying **Web Application Firewall (WAF) behavior** in web applications. Designed for both single URL and bulk URL testing from a `urls.txt` file, it provides detailed insights into the security posture of your application.

## Features
- **SQL Injection Detection**:
  - Comprehensive payloads for error-based, union-based, and logical SQL injection techniques.
  - Tracks significant changes in response length and detects error messages.
  
- **Web Application Firewall (WAF) Detection**:
  - Identifies WAF behavior by observing HTTP status codes (`403`, `406`, etc.) and content changes.

- **Flexible Scanning**:
  - Test a single URL or scan multiple URLs from a `urls.txt` file.

- **User-Friendly Output**:
  - Color-coded results for vulnerabilities, WAF detection, and safe responses.

## Requirements
- Python 3.6 or later
- Libraries: `requests`, `colorama`

Install the required libraries using:
```bash
pip install requests colorama
```

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/aungsanoo-usa/sqli_detect.git
   cd sqli_detect
   ```
2. Run the script:
   ```bash
   python sqli_detect.py
   ```
3. Choose your scan type:
   - Enter `1` for a single URL scan.
   - Enter `2` to scan multiple URLs from a file (e.g., `urls.txt`).

4. Review the results in the terminal.

## Input Format
### Single URL
When prompted, enter a URL with a parameter:
```
http://example.com/page.php?id=
```

### Bulk URLs
Create a `urls.txt` file with one URL per line:
```
http://example.com/page.php?id=
http://test.com/item.php?item_id=
http://vulnerable-site.com/index.php?product_id=
```

## Example Output
### Vulnerable Target
```text
[*] Starting SQL Injection scan for: http://example.com/page.php?id=
[+] SQL Injection Found with payload: ' OR 1=1; --
[!] WAF Detected: Payload '' caused HTTP 403
[+] SQL Injection Found with payload: ' UNION SELECT NULL,NULL,NULL--

[!] Scan complete.
[!!!] The target might be VULNERABLE to SQL Injection.
```

### Secure Target
```text
[*] Starting SQL Injection scan for: http://example.com/page.php?id=
[-] No vulnerability with payload: '
[-] No vulnerability with payload: ' OR 1=1; --
[!] WAF behavior detected: Response length changed with payload: ' UNION SELECT NULL,NULL,NULL--

[!] Scan complete.
[+] The target is NOT vulnerable to SQL Injection.
```

### Bulk URLs Summary
```text
[*] Starting SQL Injection scan for: http://example.com/page.php?id=
[+] SQL Injection Found with payload: ' OR '1'='1
[!] WAF Detected: Payload '' caused HTTP 406
[*] Starting SQL Injection scan for: http://secure-site.com/index.php?item_id=
[-] No vulnerability with payload: '

[!] Scan complete.
Summary:
http://example.com/page.php?id= -> VULNERABLE
http://secure-site.com/index.php?item_id= -> NOT VULNERABLE
```

## Payloads Used
The script tests a wide variety of SQL injection payloads, including:
- `'`
- `''`
- `' OR 1=1; --`
- `' UNION SELECT NULL,NULL,NULL--`
- And many more...

For the full list, refer to the `scan()` function in the script.

## Contributions
Contributions are welcome! If you'd like to improve the tool, feel free to fork the repository, make your changes, and submit a pull request.

## Disclaimer
This tool is intended for **educational purposes** and **authorized penetration testing** only. Ensure you have permission to test any target. The developers are not responsible for any misuse of this tool.

