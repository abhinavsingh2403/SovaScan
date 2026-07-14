"""threat_scraper.py — scrapes Reddit and RSS feeds for CVE/exploit mentions."""

import re
import time
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, UTC

import httpx

logger = logging.getLogger("sovascan.scraper")
logging.basicConfig(level=logging.INFO)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

KEYWORDS = [
    "CVE-", "0day", "zero-day", "PoC", "exploit",
    "RCE", "SQLi", "XSS", "vulnerability", "critical patch",
    "remote code execution", "privilege escalation", "buffer overflow",
]

SUBREDDITS = ["netsec", "cybersecurity"]

RSS_FEEDS = [
    ("HackerNews",   "https://feeds.feedburner.com/TheHackersNews"),
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
    ("PortSwigger",  "https://portswigger.net/daily-swig/rss"),
    ("Krebs",        "https://krebsonsecurity.com/feed/"),
]

WATCH_PACKAGES = [
    ("requests",   "PyPI"),
    ("django",     "PyPI"),
    ("flask",      "PyPI"),
    ("numpy",      "PyPI"),
    ("pillow",     "PyPI"),
    ("pyyaml",     "PyPI"),
    ("sqlalchemy", "PyPI"),
    ("lodash",     "npm"),
    ("express",    "npm"),
    ("axios",      "npm"),
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


@dataclass
class ThreatLead:
    source: str
    cve_ids: list[str]
    text: str
    url: str
    found_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ── Reddit ────────────────────────────────────────────────────────────────────

def scrape_reddit(limit: int = 25) -> list[ThreatLead]:
    """Scrape Reddit security subreddits via RSS."""
    leads: list[ThreatLead] = []
    seen_urls: set[str] = set()

    with httpx.Client(headers=HEADERS, timeout=10, follow_redirects=True) as client:
        for sub in SUBREDDITS:
            url = f"https://www.reddit.com/r/{sub}/new.rss?limit={limit}"
            for attempt in range(3):
                try:
                    response = client.get(url)
                    if response.status_code == 429:
                        wait = (attempt + 1) * 10
                        logger.warning("Rate limited on r/%s, waiting %ds...", sub, wait)
                        time.sleep(wait)
                        continue

                    root = ET.fromstring(response.text)
                    ns = {"atom": "http://www.w3.org/2005/Atom"}
                    entries = root.findall("atom:entry", ns)

                    for entry in entries:
                        title = entry.findtext("atom:title", default="", namespaces=ns)
                        content = entry.findtext("atom:content", default="", namespaces=ns)
                        link = entry.find("atom:link", ns)
                        permalink = link.attrib.get("href", "") if link is not None else ""

                        if permalink in seen_urls:
                            continue
                        seen_urls.add(permalink)

                        combined = f"{title} {content}"
                        if not any(kw.lower() in combined.lower() for kw in KEYWORDS):
                            continue

                        cve_ids = list({c.upper() for c in CVE_PATTERN.findall(combined)})
                        leads.append(ThreatLead(
                            source=f"r/{sub}",
                            cve_ids=cve_ids,
                            text=combined[:500],
                            url=permalink,
                        ))
                    break

                except Exception as exc:
                    logger.warning("Failed on r/%s (attempt %d): %s", sub, attempt + 1, exc)

            time.sleep(10)

    logger.info("Reddit: found %d leads", len(leads))
    return leads


# ── RSS Feeds ─────────────────────────────────────────────────────────────────

def scrape_rss_feeds() -> list[ThreatLead]:
    """Scrape HackerNews and BleepingComputer RSS feeds."""
    leads: list[ThreatLead] = []
    seen_urls: set[str] = set()

    with httpx.Client(headers=HEADERS, timeout=10, follow_redirects=True) as client:
        for source_name, feed_url in RSS_FEEDS:
            try:
                response = client.get(feed_url)
                root = ET.fromstring(response.text)
                items = root.findall(".//item")
                count = 0

                for item in items:
                    title = item.findtext("title") or ""
                    description = item.findtext("description") or ""
                    link = item.findtext("link") or ""

                    if link in seen_urls:
                        continue
                    seen_urls.add(link)

                    combined = f"{title} {description}"
                    if not any(kw.lower() in combined.lower() for kw in KEYWORDS):
                        continue

                    cve_ids = list({c.upper() for c in CVE_PATTERN.findall(combined)})
                    leads.append(ThreatLead(
                        source=source_name,
                        cve_ids=cve_ids,
                        text=combined[:500],
                        url=link,
                    ))
                    count += 1

                logger.info("%s: found %d leads", source_name, count)

            except Exception as exc:
                logger.warning("Failed on %s: %s", source_name, exc)

            time.sleep(2)

    return leads


# ── OSV Lookup ────────────────────────────────────────────────────────────────

def lookup_osv(cve_id: str) -> list[dict]:
    """Query OSV API for affected packages given a CVE ID."""
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"

    try:
        with httpx.Client(timeout=10) as client:
            response = client.get(url)
            if response.status_code == 404:
                logger.info("No OSV entry for %s", cve_id)
                return []
            data = response.json()
    except Exception as exc:
        logger.warning("OSV lookup failed for %s: %s", cve_id, exc)
        return []

    results = []
    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")

        ranges = []
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                ranges.append(event)

        versions = affected.get("versions", [])

        if name:
            results.append({
                "cve_id": cve_id,
                "package": name,
                "ecosystem": ecosystem,
                "ranges": ranges,
                "versions": versions[:5],
                "severity": data.get("database_specific", {}).get("severity", "UNKNOWN"),
                "summary": data.get("summary", ""),
            })

    return results

def check_watched_packages() -> list[dict]:
    """Query OSV for any known vulns in watched packages."""
    results = []
    url = "https://api.osv.dev/v1/query"

    with httpx.Client(timeout=10) as client:
        for pkg_name, ecosystem in WATCH_PACKAGES:
            try:
                payload = {
                    "package": {
                        "name": pkg_name,
                        "ecosystem": ecosystem,
                    }
                }
                response = client.post(url, json=payload)
                data = response.json()
                vulns = data.get("vulns", [])

                if vulns:
                    results.append({
                        "package": pkg_name,
                        "ecosystem": ecosystem,
                        "vuln_count": len(vulns),
                        "vuln_ids": [v["id"] for v in vulns[:5]],
                    })
                    logger.info("%s (%s): %d known vulns", pkg_name, ecosystem, len(vulns))

            except Exception as exc:
                logger.warning("Package check failed for %s: %s", pkg_name, exc)

            time.sleep(0.5)

    return results

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    print("\n" + "="*60)
    print("REDDIT LEADS")
    print("="*60)
    reddit_leads = scrape_reddit()
    for lead in reddit_leads:
        print(f"\n[{lead.source}] {lead.found_at.strftime('%Y-%m-%d %H:%M')}")
        print(f"CVEs : {lead.cve_ids or 'none'}")
        print(f"URL  : {lead.url}")
        print(f"Text : {lead.text[:150]}")

    print("\n" + "="*60)
    print("RSS FEED LEADS")
    print("="*60)
    rss_leads = scrape_rss_feeds()
    for lead in rss_leads:
        print(f"\n[{lead.source}] {lead.found_at.strftime('%Y-%m-%d %H:%M')}")
        print(f"CVEs : {lead.cve_ids or 'none'}")
        print(f"URL  : {lead.url}")
        print(f"Text : {lead.text[:150]}")

    all_leads = reddit_leads + rss_leads
    all_cves = {cve for lead in all_leads for cve in lead.cve_ids}

    print("\n" + "="*60)
    print(f"OSV PACKAGE LOOKUPS ({len(all_cves)} unique CVEs found)")
    print("="*60)
    for cve_id in all_cves:
        print(f"\n[{cve_id}]")
        packages = lookup_osv(cve_id)
        if not packages:
            print("  No OSV package data (likely firmware/hardware CVE)")
        for pkg in packages:
            print(f"  Package  : {pkg['package']} ({pkg['ecosystem']})")
            print(f"  Severity : {pkg['severity']}")
            print(f"  Summary  : {pkg['summary']}")
            print(f"  Ranges   : {pkg['ranges']}")
    # ── Watched Package Check
    print("\n" + "="*60)
    print("WATCHED PACKAGE VULNERABILITY CHECK")
    print("="*60)
    watched_results = check_watched_packages()
    if not watched_results:
        print("\nNo vulnerabilities found in watched packages.")
    for result in watched_results:
        print(f"\n{result['package']} ({result['ecosystem']})")
        print(f"  Known vulns : {result['vuln_count']}")
        print(f"  IDs (top 5) : {result['vuln_ids']}")    