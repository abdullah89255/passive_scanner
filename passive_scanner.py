#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import re
import time
from collections import deque
from dataclasses import dataclass, asdict
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib import robotparser

import requests

DEFAULT_TIMEOUT = 10
DEFAULT_DELAY = 0.75  # seconds between requests
MAX_URLS = 75         # global cap per target
MAX_DEPTH = 2         # crawl depth limit

USER_AGENT = "BugBountyPassiveScanner/1.0 (+respecting-robots; ethical; non-intrusive)"

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
]

TECH_LEAK_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-runtime",
]

@dataclass
class Finding:
    category: str
    severity: str
    message: str
    url: str = ""
    evidence: dict = None

@dataclass
class PageReport:
    url: str
    status: int
    final_url: str
    https: bool
    headers: dict
    cookies: list
    findings: list

class LinkFormParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            href = attrs.get("href", "").strip()
            if href:
                resolved = urljoin(self.base_url, href)
                self.links.add(resolved)
        elif tag == "form":
            self.current_form = {
                "action": urljoin(self.base_url, attrs.get("action", "") or self.base_url),
                "method": (attrs.get("method", "GET") or "GET").upper(),
                "inputs": []
            }
        elif tag in ("input", "select", "textarea") and self.current_form is not None:
            name = attrs.get("name") or ""
            t = attrs.get("type", "text").lower()
            self.current_form["inputs"].append({"name": name, "type": t})

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

def is_in_scope_url(root_netloc, url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc == root_netloc
    except Exception:
        return False

def polite_get(session, url):
    try:
        resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        return resp
    except requests.RequestException:
        return None

def analyze_security_headers(url, headers):
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}

    for h in SECURITY_HEADERS:
        if h not in lower:
            findings.append(Finding(
                category="Security Headers",
                severity="Medium",
                message=f"Missing {h} header",
                url=url
            ))
    # CSP quality check
    csp = lower.get("content-security-policy")
    if csp:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            findings.append(Finding(
                category="Content Security Policy",
                severity="Low",
                message="CSP contains unsafe directives (unsafe-inline/unsafe-eval)",
                url=url,
                evidence={"csp": csp}
            ))
    # X-Frame-Options check
    xfo = lower.get("x-frame-options", "")
    if xfo and xfo.lower() not in ("deny", "sameorigin"):
        findings.append(Finding(
            category="Clickjacking",
            severity="Low",
            message="X-Frame-Options present but not DENY or SAMEORIGIN",
            url=url,
            evidence={"x-frame-options": xfo}
        ))
    return findings

def analyze_cookies(url, response):
    findings = []
    cookie_reports = []
    for c in response.cookies:
        cr = {
            "name": c.name,
            "secure": c.secure,
            "httponly": getattr(c, "has_nonstandard_attr", lambda x: False)("httponly") or "HttpOnly" in str(c._rest).lower(),
            "samesite": getattr(c, "get", lambda k, d=None: None)("samesite") if hasattr(c, "get") else None
        }
        cookie_reports.append(cr)
        if not cr["secure"] and urlparse(response.url).scheme == "https":
            findings.append(Finding(
                category="Cookie Security",
                severity="Medium",
                message=f"Cookie '{c.name}' missing Secure flag over HTTPS",
                url=response.url
            ))
        if not cr["httponly"]:
            findings.append(Finding(
                category="Cookie Security",
                severity="Low",
                message=f"Cookie '{c.name}' missing HttpOnly flag",
                url=response.url
            ))
        if (cr["samesite"] or "").lower() not in ("lax", "strict"):
            findings.append(Finding(
                category="Cookie Security",
                severity="Low",
                message=f"Cookie '{c.name}' missing SameSite or set to None",
                url=response.url
            ))
    return cookie_reports, findings

def analyze_mixed_content(base_url, html):
    findings = []
    if not html or not base_url.startswith("https://"):
        return findings
    # Simple heuristic: look for http:// resources in src/href
    unsafe = set(re.findall(r'''(?:src|href)\s*=\s*["']http://[^"']+["']''', html, re.IGNORECASE))
    if unsafe:
        findings.append(Finding(
            category="Mixed Content",
            severity="Medium",
            message="HTTPS page loads HTTP resources",
            url=base_url,
            evidence={"examples": list(unsafe)[:5]}
        ))
    return findings

def analyze_server_banners(url, headers):
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}
    leaks = {}
    for h in TECH_LEAK_HEADERS:
        if h in lower:
            leaks[h] = lower[h]
    if leaks:
        findings.append(Finding(
            category="Fingerprinting",
            severity="Low",
            message="Server/technology banners exposed in response headers",
            url=url,
            evidence=leaks
        ))
    return findings

def analyze_forms(url, forms):
    findings = []
    sensitive_keywords = {"password", "pass", "secret", "token", "otp", "credit", "card", "ssn"}
    for f in forms:
        method = f.get("method", "GET")
        action = f.get("action", url)
        inputs = f.get("inputs", [])
        names = {i.get("name", "").lower() for i in inputs}
        if method == "GET" and names & sensitive_keywords:
            findings.append(Finding(
                category="Form Posture",
                severity="Low",
                message="Sensitive fields may be submitted via GET (URL query)",
                url=url,
                evidence={"action": action, "method": method, "fields": list(names & sensitive_keywords)}
            ))
    return findings

def analyze_hsts(url, headers):
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}
    sts = lower.get("strict-transport-security")
    if not sts and url.startswith("https://"):
        findings.append(Finding(
            category="Transport Security",
            severity="Medium",
            message="Missing HSTS on HTTPS endpoint",
            url=url
        ))
    return findings

def load_robots(session, base_url):
    rp = robotparser.RobotFileParser()
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        resp = session.get(robots_url, timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200:
            rp.parse(resp.text.splitlines())
        else:
            rp.set_url(robots_url)
            rp.read()  # may fail silently; we treat unknown as allowed
    except Exception:
        pass
    return rp

def check_security_txt(session, base_url):
    sec_url = urljoin(base_url, "/.well-known/security.txt")
    resp = polite_get(session, sec_url)
    if resp and resp.status_code == 200 and "security" in resp.text.lower():
        return Finding(
            category="Metadata",
            severity="Informational",
            message="Found security.txt",
            url=resp.url
        )
    return None

def crawl_target(start_url, max_urls=MAX_URLS, max_depth=MAX_DEPTH, delay=DEFAULT_DELAY):
    parsed = urlparse(start_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    robots = load_robots(session, root)

    visited = set()
    q = deque([(start_url, 0)])
    reports = []
    global_count = 0

    meta_findings = []
    stxt = check_security_txt(session, root)
    if stxt:
        meta_findings.append(stxt)

    while q and global_count < max_urls:
        url, depth = q.popleft()
        if url in visited or depth > max_depth:
            continue
        if robots and not robots.can_fetch(USER_AGENT, url):
            # Respect robots.txt: skip disallowed
            visited.add(url)
            continue

        time.sleep(delay)

        resp = polite_get(session, url)
        visited.add(url)
        if not resp:
            continue

        status = resp.status_code
        final_url = resp.url
        https = final_url.startswith("https://")
        headers = dict(resp.headers)
        body = resp.text if ("text/html" in resp.headers.get("Content-Type", "")) else ""

        findings = []
        findings += analyze_security_headers(final_url, headers)
        findings += analyze_server_banners(final_url, headers)
        findings += analyze_hsts(final_url, headers)
        _, cookie_findings = analyze_cookies(final_url, resp)
        findings += cookie_findings
        findings += analyze_mixed_content(final_url, body)

        page = PageReport(
            url=url,
            status=status,
            final_url=final_url,
            https=https,
            headers=headers,
            cookies=[c.name for c in resp.cookies],
            findings=[asdict(f) for f in findings]
        )
        reports.append(page)

        # Parse links & forms (for reporting only; no submissions)
        if body:
            parser = LinkFormParser(final_url)
            try:
                parser.feed(body)
            except Exception:
                parser.close()
            form_findings = analyze_forms(final_url, parser.forms)
            if form_findings:
                page.findings.extend([asdict(f) for f in form_findings])

            # Queue same-host links
            for link in parser.links:
                if is_in_scope_url(parsed.netloc, link) and link not in visited:
                    q.append((link, depth + 1))
                    global_count += 1
                    if global_count >= max_urls:
                        break

    # Assemble final report
    return {
        "target": start_url,
        "summary": {
            "pages_scanned": len(reports),
            "findings_count": sum(len(p.findings) for p in reports),
        },
        "metadata_findings": [asdict(f) for f in meta_findings],
        "pages": [asdict(r) for r in reports],
        "tool": {
            "name": "Passive Web Recon Scanner",
            "version": "1.0",
            "agent": USER_AGENT,
            "limits": {"max_urls": max_urls, "max_depth": max_depth, "delay_seconds": delay}
        }
    }

def main():
    ap = argparse.ArgumentParser(description="Passive, robots-aware reconnaissance for bug bounty programs.")
    ap.add_argument("target", help="Target URL (e.g., https://example.com)")
    ap.add_argument("--max-urls", type=int, default=MAX_URLS, help="Max URLs to scan per target")
    ap.add_argument("--max-depth", type=int, default=MAX_DEPTH, help="Max crawl depth")
    ap.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests (seconds)")
    ap.add_argument("--output", default="report.json", help="Output JSON file")
    args = ap.parse_args()

    report = crawl_target(args.target, args.max_urls, args.max_depth, args.delay)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Report written to {args.output}")

if __name__ == "__main__":
    main()
