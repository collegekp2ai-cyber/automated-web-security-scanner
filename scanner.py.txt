
import json
import re
from datetime import datetime
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "Helps enforce HTTPS connections."
    ),
    "Content-Security-Policy": (
        "Helps control which resources a page can load."
    ),
    "X-Content-Type-Options": (
        "Helps prevent MIME-type sniffing."
    ),
    "X-Frame-Options": (
        "Helps reduce clickjacking risks."
    ),
    "Referrer-Policy": (
        "Controls referrer information sent by browsers."
    ),
    "Permissions-Policy": (
        "Controls access to browser features."
    ),
}


def normalize_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Please enter a website address.")

    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme != "https":
        raise ValueError(
            "Only HTTPS websites are allowed by this scanner."
        )

    if not parsed.hostname:
        raise ValueError("The website address is invalid.")

    if parsed.username or parsed.password:
        raise ValueError(
            "Website addresses containing login credentials are not allowed."
        )

    host = parsed.hostname.lower()

    # Avoid scanning local/private targets.
    if (
        host == "localhost"
        or host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
        or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)
    ):
        raise ValueError(
            "Local hostnames and IP-address targets are not allowed."
        )

    return raw_url


def scan_website(url):
    print("\nConnecting to website...")

    response = requests.get(
        url,
        timeout=15,
        allow_redirects=True,
        verify=True,
        headers={"User-Agent": "Educational-Web-Security-Scanner/1.0"},
    )

    final_url = response.url
    final_scheme = urlparse(final_url).scheme.lower()

    report = {
        "scan_time": datetime.now().astimezone().isoformat(),
        "requested_url": url,
        "final_url": final_url,
        "http_status": response.status_code,
        "https_used": final_scheme == "https",
        "security_headers": {},
        "cookies": [],
        "notes": [
            "This is a basic educational configuration check, "
            "not a complete security audit."
        ],
    }

    print("\n" + "=" * 58)
    print("          AUTOMATED WEB SECURITY SCANNER")
    print("=" * 58)
    print("Requested URL:", url)
    print("Final URL:    ", final_url)
    print("HTTP status:  ", response.status_code)
    print("HTTPS used:   ", report["https_used"])

    print("\n--- SECURITY HEADER CHECK ---")

    headers_lower = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    for header, description in SECURITY_HEADERS.items():
        value = headers_lower.get(header.lower())

        if value:
            status = "PRESENT"
            print(f"[+] {header}: {status}")
        else:
            status = "MISSING"
            print(f"[-] {header}: {status}")

        report["security_headers"][header] = {
            "status": status,
            "value": value,
            "purpose": description,
        }

    print("\n--- COOKIE SECURITY CHECK ---")

    set_cookie_headers = response.raw.headers.getlist("Set-Cookie")

    if not set_cookie_headers:
        print("No Set-Cookie headers were returned.")
    else:
        for cookie_line in set_cookie_headers:
            parts = [
                part.strip()
                for part in cookie_line.split(";")
            ]

            cookie_name = parts[0].split("=", 1)[0].strip()
            attributes = {
                part.split("=", 1)[0].strip().lower()
                for part in parts[1:]
                if part
            }

            cookie_report = {
                "name": cookie_name,
                "secure": "secure" in attributes,
                "httponly": "httponly" in attributes,
                "samesite": next(
                    (
                        part.split("=", 1)[1].strip()
                        for part in parts[1:]
                        if part.lower().startswith("samesite=")
                    ),
                    None,
                ),
            }

            report["cookies"].append(cookie_report)

            print(f"Cookie: {cookie_name}")
            print("  Secure:  ", cookie_report["secure"])
            print("  HttpOnly:", cookie_report["httponly"])
            print("  SameSite:", cookie_report["samesite"])

    with open(
        "scan_report.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(report, file, indent=4)

    print("\n" + "=" * 58)
    print("Scan completed.")
    print("Report saved as: scan_report.json")
    print("=" * 58)


def main():
    print("Educational Web Security Scanner")
    print("Scan only websites you own or have permission to test.")

    raw_url = input(
        "\nEnter an HTTPS website (e.g. https://example.com): "
    )

    try:
        url = normalize_url(raw_url)
        scan_website(url)

    except ValueError as error:
        print("\nInput error:", error)

    except requests.exceptions.SSLError:
        print(
            "\nConnection failed because TLS/SSL verification failed."
        )

    except requests.exceptions.Timeout:
        print("\nConnection timed out. Try again later.")

    except requests.exceptions.RequestException as error:
        print("\nWebsite request failed:", error)

    except OSError as error:
        print("\nCould not save the report:", error)


if __name__ == "__main__":
    main()
