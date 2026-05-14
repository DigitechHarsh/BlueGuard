"""
BlueGuard CVE Intelligence Fetcher
====================================
Fetches last 5 years of CVE data from NVD API v2.0
Stores into MongoDB: blueguard_db.cve_intelligence

NOTE: NVD API v2.0 limits each request to a 120-day window.
      This script automatically chunks the date range.

Usage: python fetch_nvd_cve.py
Estimated time: ~45-60 minutes for ~100,000 CVEs
"""

import requests
import pymongo
import os
import time
import math
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# ─── Config ───────────────────────────────────────────────────────────────────
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE    = 2000          # Max per NVD page
CHUNK_DAYS   = 120           # NVD v2.0 max date range per request
DELAY_SEC    = 0.65          # With API key: 50 req/30s → safe at 0.65s
YEARS_BACK   = 5

# ─── MongoDB ──────────────────────────────────────────────────────────────────
client  = pymongo.MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
db      = client.blueguard_db
col     = db.cve_intelligence

col.create_index("cve_id", unique=True)
col.create_index("severity")
col.create_index([("cwe_ids", pymongo.ASCENDING)])
col.create_index("cvss_score")

# ─── Date chunks ──────────────────────────────────────────────────────────────
end_dt   = datetime.utcnow()
start_dt = end_dt - timedelta(days=365 * YEARS_BACK)

def build_chunks():
    """Split the total range into 120-day windows."""
    chunks = []
    cur = start_dt
    while cur < end_dt:
        nxt = min(cur + timedelta(days=CHUNK_DAYS), end_dt)
        chunks.append((cur, nxt))
        cur = nxt
    return chunks

HEADERS = {}
if NVD_API_KEY:
    HEADERS["apiKey"] = NVD_API_KEY
    print(f"✅ Using NVD API Key (high rate limit: 50 req/30s)")
else:
    print("⚠️  No API key — rate limited to 5 req/30s (very slow)")
    DELAY_SEC = 6.5

# ─── Helper: Extract one CVE ──────────────────────────────────────────────────
def extract_cve(item: dict) -> dict | None:
    try:
        cve_data    = item.get("cve", {})
        cve_id      = cve_data.get("id", "")
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        metrics     = cve_data.get("metrics", {})
        cvss_score  = 0.0
        cvss_vector = ""
        severity    = "Unknown"

        for ver in ["cvssMetricV31", "cvssMetricV30"]:
            if ver in metrics and metrics[ver]:
                m = metrics[ver][0].get("cvssData", {})
                cvss_score  = float(m.get("baseScore", 0.0))
                cvss_vector = m.get("vectorString", "")
                severity    = m.get("baseSeverity", "Unknown").capitalize()
                break

        if cvss_score == 0.0 and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            m = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score  = float(m.get("baseScore", 0.0))
            cvss_vector = m.get("vectorString", "")
            if   cvss_score >= 7.0: severity = "High"
            elif cvss_score >= 4.0: severity = "Medium"
            else:                   severity = "Low"

        cwe_ids = []
        for weakness in cve_data.get("weaknesses", []):
            for wd in weakness.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-") and val not in cwe_ids:
                    cwe_ids.append(val)

        published = cve_data.get("published", "")[:10]
        modified  = cve_data.get("lastModified", "")[:10]

        return {
            "cve_id"        : cve_id,
            "description"   : description[:500],
            "cvss_score"    : round(cvss_score, 1),
            "cvss_vector"   : cvss_vector,
            "severity"      : severity,
            "cwe_ids"       : cwe_ids,
            "published_date": published,
            "last_modified" : modified,
            "fetched_at"    : datetime.utcnow()
        }
    except Exception:
        return None


def upsert_batch(batch: list) -> int:
    if not batch:
        return 0
    ops = [
        pymongo.UpdateOne({"cve_id": d["cve_id"]}, {"$set": d}, upsert=True)
        for d in batch if d
    ]
    try:
        r = col.bulk_write(ops, ordered=False)
        return r.upserted_count + r.modified_count
    except Exception as e:
        print(f"  DB error: {e}")
        return 0


def fetch_chunk(pub_start: str, pub_end: str, start_index: int) -> dict | None:
    """Fetch one page within a date chunk."""
    params = {
        "pubStartDate"   : pub_start,
        "pubEndDate"     : pub_end,
        "startIndex"     : start_index,
        "resultsPerPage" : PAGE_SIZE,
    }
    for attempt in range(3):
        try:
            r = requests.get(NVD_BASE_URL, headers=HEADERS, params=params, timeout=30)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 429:
                wait = 35 * (attempt + 1)
                print(f"  ⏳ Rate limited — waiting {wait}s...")
                time.sleep(wait)
            else:
                print(f"  ⚠️  HTTP {r.status_code} (attempt {attempt+1}) | {r.text[:80]}")
                time.sleep(5)
        except Exception as e:
            print(f"  ⚠️  Error: {e} (attempt {attempt+1})")
            time.sleep(5)
    return None


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    chunks = build_chunks()
    total_saved = 0

    # ── Resume: count already saved CVEs ─────────────────────────────────────
    try:
        already = col.count_documents({})
        if already > 0:
            print(f"\n  ⏩ RESUME MODE: {already:,} CVEs already in DB — skipping completed chunks\n")
    except Exception:
        already = 0

    print("=" * 62)
    print("  🛡️  BlueGuard CVE Intelligence Fetcher")
    print(f"  📅  Range : {start_dt.strftime('%Y-%m-%d')} → {end_dt.strftime('%Y-%m-%d')}")
    print(f"  📦  Chunks: {len(chunks)} x {CHUNK_DAYS}-day windows")
    print("=" * 62)

    for ci, (c_start, c_end) in enumerate(chunks, 1):
        ps = c_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        pe = c_end.strftime("%Y-%m-%dT%H:%M:%S.000")

        # ── Resume: check if this chunk is already fully saved ────────────────
        try:
            chunk_in_db = col.count_documents({
                "published_date": {
                    "$gte": c_start.strftime("%Y-%m-%d"),
                    "$lte": c_end.strftime("%Y-%m-%d")
                }
            })
        except Exception:
            chunk_in_db = 0

        # Fetch first page to get total for this chunk
        first = fetch_chunk(ps, pe, 0)
        if not first:
            print(f"  ❌ Chunk {ci}/{len(chunks)} failed — skipping")
            continue

        chunk_total = first.get("totalResults", 0)
        pages       = math.ceil(chunk_total / PAGE_SIZE) if chunk_total else 1

        # If chunk already fully fetched, skip it
        if chunk_in_db >= chunk_total and chunk_total > 0:
            print(f"  ⏩ Chunk {ci:2}/{len(chunks)}: {c_start.strftime('%Y-%m-%d')} → {c_end.strftime('%Y-%m-%d')} | Already saved ({chunk_in_db}) — SKIPPING")
            total_saved += chunk_in_db
            time.sleep(0.3)
            continue

        print(f"\n  📅 Chunk {ci:2}/{len(chunks)}: {c_start.strftime('%Y-%m-%d')} → {c_end.strftime('%Y-%m-%d')} | {chunk_total} CVEs | {pages} page(s)")

        # Save first page
        batch = [extract_cve(v) for v in first.get("vulnerabilities", [])]
        saved = upsert_batch([b for b in batch if b])
        total_saved += saved

        # Remaining pages in this chunk
        for pg in range(1, pages):
            time.sleep(DELAY_SEC)
            data = fetch_chunk(ps, pe, pg * PAGE_SIZE)
            if not data:
                continue
            batch = [extract_cve(v) for v in data.get("vulnerabilities", [])]
            pg_saved = upsert_batch([b for b in batch if b])
            saved += pg_saved
            total_saved += pg_saved

        print(f"     ✅ Chunk saved: {saved} | Total so far: {total_saved:,}")
        time.sleep(DELAY_SEC)

    # ── Final count from DB (most accurate) ──────────────────────────────────
    try:
        final_count = col.count_documents({})
    except Exception:
        final_count = total_saved

    print("\n" + "=" * 62)
    print(f"  ✅ COMPLETE! {final_count:,} CVEs in MongoDB")
    print(f"  🗄️  Collection : blueguard_db.cve_intelligence")
    print(f"  🧠 BlueGuard AI will now use real NVD data!")
    print("=" * 62)


if __name__ == "__main__":
    main()
