
# SQL Injection Detection Tool

## Overview
This script is designed to detect SQL injection vulnerabilities in web applications. It uses a comprehensive set of payloads and analyzes responses for error messages, response length changes, and WAF detection behavior.

## Features
- **Comprehensive Payloads**: Includes a variety of SQL injection payloads for error-based, union-based, and logical injection techniques.
- **Error Detection**: Identifies SQL errors in HTTP responses from MySQL, SQL Server, Oracle, PostgreSQL, and other databases.
- **WAF Detection**: Tests for Web Application Firewalls (WAF) and detects blocking behavior.
- **Response Length Analysis**: Flags significant changes in response length as a potential vulnerability indicator.
- **Color-Coded Output**: Displays results with intuitive color coding for vulnerabilities, errors, and safe results.

## Installation
1. Ensure you have Python 3 installed.
2. Install the required libraries:
   ```bash
   pip install requests colorama
   ```

## Usage
1. Run the script:
   ```bash
   python sqli_detector.py
   ```
2. Enter the target URL:
   ```
   http://example.com/page.php?id=
   ```

3. Review the results in the terminal.

## Example Output
### If Vulnerable
```text
[*] Starting SQL Injection scan for: http://example.com/page.php?id=
[-] No vulnerability with payload: '
[!] Response length changed significantly with payload: ' OR '1'='1
[+] SQL Injection Found with payload: ' UNION SELECT NULL,NULL,NULL--

[!] SQL Injection scan complete.
[!!!] The target is VULNERABLE to SQL Injection.
```

### If Not Vulnerable
```text
[*] Starting SQL Injection scan for: http://example.com/page.php?id=
[-] No vulnerability with payload: '
[-] No vulnerability with payload: ' OR '1'='1
[-] No vulnerability with payload: ' UNION SELECT NULL,NULL,NULL--

[!] SQL Injection scan complete.
[+] The target is NOT vulnerable to SQL Injection.
```

## Payloads Used
The script uses a wide variety of payloads, including:
- `'`
- `''`
- `' OR 1=1; --`
- `' UNION SELECT NULL,NULL,NULL--`
- And many more...

Refer to the script for the full list of payloads.

## Contributions
Contributions are welcome! Feel free to fork this repository and submit pull requests.

