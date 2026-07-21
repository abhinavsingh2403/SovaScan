import logging
import re
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# Pattern to normalize and match CVE IDs
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class ThreatIntelRecord:
    cve_id: str
    known_exploited: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    priority: str = "monitor"
    sources: list[str] = field(default_factory=list)
    summary: str = ""
    remediation_urgency: str = ""


class ThreatIntelEnricher:
    # URL feeds
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"

    # Thread-safe in-memory cache for CISA KEV catalog lookup
    _cisa_kev_cache: dict[str, dict] | None = None

    def __init__(self):
        pass

    def _load_cisa_kev_cache(self) -> dict[str, dict]:
        """Loads and caches the CISA KEV catalog in memory using httpx."""
        if ThreatIntelEnricher._cisa_kev_cache is not None:
            return ThreatIntelEnricher._cisa_kev_cache

        cache = {}
        try:
            logger.info("Fetching CISA KEV catalog...")
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                res = client.get(self.CISA_KEV_URL)
                if res.status_code == 200:
                    data = res.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    for vuln in vulnerabilities:
                        cve = vuln.get("cveID")
                        if cve:
                            cache[cve.upper()] = vuln
                    logger.info(f"Loaded {len(cache)} KEV records into cache.")
                else:
                    logger.warning(f"CISA KEV fetch returned status code: {res.status_code}")
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV catalog: {e}")

        # Cache even if empty to prevent repeated fail requests in same execution
        ThreatIntelEnricher._cisa_kev_cache = cache
        return cache

    def _fetch_epss_scores(self, cve_ids: list[str]) -> dict[str, dict]:
        """Queries the FIRST EPSS API for scores of given CVE list."""
        scores = {}
        if not cve_ids:
            return scores

        # Batch queries when possible (API allows comma separated values)
        cve_query = ",".join(cve_ids)
        try:
            logger.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
            with httpx.Client(timeout=10.0) as client:
                res = client.get(self.EPSS_API_URL, params={"cve": cve_query})
                if res.status_code == 200:
                    data = res.json()
                    records = data.get("data", [])
                    for rec in records:
                        cve = rec.get("cve")
                        if cve:
                            scores[cve.upper()] = rec
                else:
                    logger.warning(f"EPSS API fetch returned status code: {res.status_code}")
        except Exception as e:
            logger.error(f"Failed to query EPSS scores: {e}")

        return scores

    def _build_priority(
        self,
        cve_id: str,
        known_exploited: bool,
        epss_score: float | None,
        cvss_score: float | None = None
    ) -> tuple[str, str]:
        """Calculates remediation priority and urgency string based on CISA KEV status,

        EPSS probability, and CVSS score.
        """
        score_epss = epss_score if epss_score is not None else 0.0
        score_cvss = cvss_score if cvss_score is not None else 0.0

        # Immediate: KEV is true OR EPSS >= 0.70
        if known_exploited or score_epss >= 0.70:
            return "immediate", "Patch immediately or isolate affected component."

        # High: EPSS >= 0.30 OR CVSS >= 8.0
        if score_epss >= 0.30 or score_cvss >= 8.0:
            return "high", "Plan patch for the next scheduled deployment window."

        # Scheduled: EPSS >= 0.05 OR CVSS >= 5.0
        if score_epss >= 0.05 or score_cvss >= 5.0:
            return "scheduled", "Remediate as part of routine maintenance."

        # Monitor: Everything else
        return "monitor", "Monitor for changes in threat status."

    def enrich_cves(
        self,
        cve_ids: list[str],
        cvss_scores: dict[str, float] | None = None
    ) -> dict[str, ThreatIntelRecord]:
        """Enriches a list of CVE IDs with CISA KEV and EPSS intelligence data."""
        enriched = {}
        if not cve_ids:
            return enriched

        # Normalize inputs
        normalized_cves = [c.strip().upper() for c in cve_ids if CVE_PATTERN.match(c.strip())]
        normalized_cves = list(set(normalized_cves))

        if not normalized_cves:
            return enriched

        cvss_map = {k.upper(): v for k, v in (cvss_scores or {}).items()}

        # Load CISA KEV Cache
        kev_cache = self._load_cisa_kev_cache()

        # Load EPSS scores
        epss_map = self._fetch_epss_scores(normalized_cves)

        for cve in normalized_cves:
            record = ThreatIntelRecord(cve_id=cve)
            record.sources = []

            # 1. CISA KEV Check
            kev_data = kev_cache.get(cve)
            if kev_data:
                record.known_exploited = True
                record.summary = kev_data.get("shortDescription") or f"Known exploited vulnerability affecting {kev_data.get('product', 'unknown')}."
                record.sources.append("CISA KEV")
            else:
                record.known_exploited = False
                record.summary = "No active CISA exploitation record found."

            # 2. EPSS Check
            epss_data = epss_map.get(cve)
            if epss_data:
                try:
                    record.epss_score = float(epss_data.get("epss", 0.0))
                    record.epss_percentile = float(epss_data.get("percentile", 0.0))
                    record.sources.append("FIRST EPSS")
                except ValueError:
                    pass

            # 3. Calculate Priority
            cvss_val = cvss_map.get(cve)
            priority, urgency = self._build_priority(
                cve,
                record.known_exploited,
                record.epss_score,
                cvss_val
            )
            record.priority = priority
            record.remediation_urgency = urgency

            enriched[cve] = record

        return enriched
