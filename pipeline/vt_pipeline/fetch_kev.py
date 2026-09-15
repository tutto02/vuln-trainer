"""CISA Known Exploited Vulnerabilities – ein JSON-Download, täglich gecacht."""
from __future__ import annotations

import json

from .http import cached_json, get_bytes

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_kev(refresh: bool = False) -> dict[str, dict]:
    """Gibt {cve_id: {date_added, ransomware, name, vendor, product, required_action}} zurück."""
    def fetch():
        raw = json.loads(get_bytes(KEV_URL))
        out = {}
        for v in raw["vulnerabilities"]:
            out[v["cveID"]] = {
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                "name": v.get("vulnerabilityName"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "required_action": v.get("requiredAction"),
            }
        return {"catalog_version": raw.get("catalogVersion"), "date_released": raw.get("dateReleased"), "items": out}
    data = cached_json("kev", fetch, max_age_days=0 if refresh else 1)
    return data
