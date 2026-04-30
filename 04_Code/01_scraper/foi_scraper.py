"""
foi_scraper.py
--------------
Targeted scraper for FOI (Totalförsvarets forskningsinstitut) reports.
https://www.foi.se/rapporter.html

Strategy:
  1. Use Playwright (headless Chromium) to paginate through the JS-rendered
     search results and collect report IDs (e.g. "FOI-R--5931--SE").
  2. Use the public REST endpoint https://www.foi.se/rest-api/report/{id}
     which directly serves the PDF — no extra page load needed.
  3. Filter to 2020+ only (pre-NIS2 baseline + NIS2 preparation).
  4. Stop when TARGET_PDFS (default 100) have been successfully downloaded
     and processed.

Output: appends to the same collection_log.csv / metadata_fields.csv used
        by collector.py, so results appear in one place.

Usage:
  cd 04_Code/01_scraper
  source .venv/bin/activate
  python foi_scraper.py               # collect 100 PDFs (default)
  python foi_scraper.py --target 50   # collect 50 PDFs
  python foi_scraper.py --dry-run     # find URLs but do not download
  python foi_scraper.py --year-from 2022 --year-to 2025
"""

import os
import re
import csv
import sys
import json
import time
import random
import hashlib
import logging
import argparse
import tempfile
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, unquote

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

# ─────────────────────────────────────────────────────────────────────────────
# Paths  (mirrors collector.py layout)
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR   = SCRIPT_DIR.parent.parent       # PDFMETA/
DATA_DIR   = BASE_DIR / "03_Data"

COLLECTION_LOG = DATA_DIR / "collection_log.csv"
METADATA_CSV   = DATA_DIR / "metadata_fields.csv"
ERROR_LOG      = DATA_DIR / "crawl_errors.log"

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

AUTHORITY_NAME    = "Totalförsvarets forskningsinstitut"
AUTHORITY_NAME_EN = "Swedish Defence Research Agency (FOI)"
AUTHORITY_TIER    = 1

FOI_SEARCH_URL = "https://www.foi.se/rapporter.html"
FOI_REST_BASE  = "https://www.foi.se/rest-api/report/"

# How long to wait after page load before extracting links (ms)
POST_LOAD_WAIT_MS = 4_000

# Temporal periods — must match collector.py
PERIOD_PRE_NIS2  = "2020-2023"
PERIOD_NIS2_PREP = "2024-2025"
PERIOD_POST_LAW  = "post-2026"

MIN_SLEEP = 2.0   # seconds between HTTP requests (polite)
MAX_SLEEP = 4.0

# How long Playwright should wait for the results list to render (ms)
PAGE_RENDER_TIMEOUT_MS = 20_000

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(ERROR_LOG), mode="a", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Data structures (mirrors collector.py)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PDFRecord:
    authority_name: str
    authority_name_en: str
    tier: int
    pdf_url: str
    source_page_url: str
    sha256: str
    file_size_bytes: int
    temporal_period: str
    year_from_url: Optional[int]
    year_from_pdf: Optional[int]
    year_used: Optional[int]
    collection_timestamp: str
    exiftool_ok: bool
    notes: str = ""


@dataclass
class MetadataField:
    authority_name: str
    tier: int
    pdf_url: str
    sha256: str
    temporal_period: str
    field_name: str
    field_value: str


_LOG_FIELDNAMES  = list(PDFRecord.__dataclass_fields__.keys())
_META_FIELDNAMES = list(MetadataField.__dataclass_fields__.keys())

_SKIP_EXIFTOOL_FIELDS = {
    "SourceFile", "ExifToolVersion", "Directory",
    "FileModifyDate", "FileAccessDate", "FileInodeChangeDate",
    "FilePermissions", "FileType", "FileTypeExtension", "MIMEType",
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────

def polite_sleep():
    time.sleep(random.uniform(MIN_SLEEP, MAX_SLEEP))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def classify_year(year: Optional[int]) -> Optional[str]:
    if year is None:
        return None
    if 2020 <= year <= 2023:
        return PERIOD_PRE_NIS2
    if 2024 <= year <= 2025:
        return PERIOD_NIS2_PREP
    if year >= 2026:
        return PERIOD_POST_LAW
    return "pre-2020"


def year_from_exiftool(meta: dict) -> Optional[int]:
    for key in ("CreateDate", "ModifyDate", "MetadataDate", "XMP:CreateDate"):
        val = meta.get(key, "")
        if not val:
            continue
        m = re.search(r"(\d{4})", str(val))
        if m:
            y = int(m.group(1))
            if 2010 <= y <= 2030:
                return y
    return None


def run_exiftool(filepath: Path) -> dict:
    try:
        result = subprocess.run(
            ["exiftool", "-json", "-all:all", "-charset", "utf8", str(filepath)],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
        if result.returncode != 0:
            log.warning(f"exiftool non-zero exit: {result.stderr[:200]}")
            return {}
        data = json.loads(result.stdout)
        return data[0] if data else {}
    except FileNotFoundError:
        log.error("exiftool not found — install with: brew install exiftool")
        return {}
    except Exception as e:
        log.warning(f"exiftool failed: {e}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# CSV I/O
# ─────────────────────────────────────────────────────────────────────────────

def _open_csv(path: Path, fieldnames: list) -> tuple:
    write_header = not path.exists()
    f = open(path, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    if write_header:
        writer.writeheader()
    return f, writer


def append_record(record: PDFRecord):
    f, w = _open_csv(COLLECTION_LOG, _LOG_FIELDNAMES)
    w.writerow(asdict(record))
    f.close()


def append_metadata(fields: list):
    if not fields:
        return
    f, w = _open_csv(METADATA_CSV, _META_FIELDNAMES)
    for mf in fields:
        w.writerow(asdict(mf))
    f.close()


def load_seen_urls() -> set:
    seen = set()
    if not COLLECTION_LOG.exists():
        return seen
    with open(COLLECTION_LOG, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            url = row.get("pdf_url", "").strip()
            if url:
                seen.add(url)
    return seen


def load_period_counts() -> dict:
    counts = {PERIOD_PRE_NIS2: 0, PERIOD_NIS2_PREP: 0, PERIOD_POST_LAW: 0}
    if not COLLECTION_LOG.exists():
        return counts
    with open(COLLECTION_LOG, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("authority_name") == AUTHORITY_NAME:
                p = row.get("temporal_period", "")
                if p in counts:
                    counts[p] += 1
    return counts


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Playwright: scrape report IDs from paginated search results
# ─────────────────────────────────────────────────────────────────────────────

def scrape_report_ids_playwright(
    year_from: int,
    year_to: int,
    max_ids: int,
) -> list[dict]:
    """
    Use headless Chromium to paginate through the FOI JS-rendered search results.

    The page structure (confirmed via browser inspection):
      - Report links use the query parameter: ?reportNo=FOI-R--5838--SE
        e.g. href="/rapporter/rapportsammanfattning.html?reportNo=FOI-R--5838--SE"
      - Direct download: https://www.foi.se/rest-api/report/FOI-R--5838--SE
      - Memo format also exists: "FOI Memo 9145" (with a space)

    Returns a list of dicts: { "report_no": str, "year": int|None, "title": str }
    """
    # FOI search URL parameters (0-indexed pages)
    search_url_tpl = (
        f"{FOI_SEARCH_URL}"
        f"?yearFrom={year_from}&yearTo={year_to}"
        f"&sort=PublishDate&direction=Desc&page={{page}}"
    )

    # Regex: extract reportNo value from hrefs like
    #   /rapporter/rapportsammanfattning.html?reportNo=FOI-R--5838--SE
    #   or  /rest-api/report/FOI-R--5838--SE
    # Character class [^&\s] stops at & or whitespace (avoids quote conflicts)
    REPORT_NO_RE = re.compile(
        r"reportNo=([^&\s]+)|rest-api/report/([^&\s]+)",
        re.IGNORECASE,
    )

    results  = []
    seen_ids = set()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            locale="sv-SE",
        )
        page = context.new_page()
        page_num = 0
        consecutive_empty = 0

        while len(results) < max_ids:
            url = search_url_tpl.format(page=page_num)
            log.info(f"  [Playwright] Loading page {page_num}: {url}")

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            except PWTimeout:
                if results:
                    log.warning(f"  [Playwright] Timeout on page {page_num} — using {len(results)} IDs collected so far")
                else:
                    log.error(f"  [Playwright] Timeout loading page {page_num} — stopping")
                break

            # Accept cookie banner on first page
            if page_num == 0:
                try:
                    btn = page.locator(
                        "button:has-text('Acceptera'), "
                        "button:has-text('Godkänn'), "
                        "button:has-text('OK')"
                    )
                    if btn.count() > 0:
                        btn.first.click(timeout=5_000)
                        page.wait_for_timeout(1_000)
                        log.info("  [Playwright] Accepted cookie banner")
                except Exception:
                    pass

            # Wait for at least one reportNo link to appear
            try:
                page.wait_for_selector(
                    "a[href*='reportNo=']",
                    timeout=PAGE_RENDER_TIMEOUT_MS,
                )
            except PWTimeout:
                content = page.content()
                if "inga träffar" in content.lower() or "0 rapporter" in content.lower():
                    log.info(f"  [Playwright] No results on page {page_num} — done")
                    break
                log.warning(f"  [Playwright] No report links on page {page_num}")
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    log.error("  [Playwright] 3 consecutive empty pages — stopping")
                    break
                page_num += 1
                time.sleep(2)
                continue

            # Extra wait for all cards to render fully
            page.wait_for_timeout(POST_LOAD_WAIT_MS)
            consecutive_empty = 0

            # Grab ALL anchor hrefs from the rendered DOM
            all_hrefs = page.evaluate(
                """() => [...document.querySelectorAll('a[href]')]
                         .map(a => ({href: a.href, text: a.innerText.trim()}))"""
            )

            page_ids_found = 0
            for item in all_hrefs:
                href = item.get("href", "")
                text = item.get("text", "")
                m = REPORT_NO_RE.search(href)
                if not m:
                    continue

                report_no = (m.group(1) or m.group(2) or "").strip()
                if not report_no:
                    continue

                # URL-decode spaces (%20) in "FOI%20Memo%209145"
                from urllib.parse import unquote as _unquote
                report_no = _unquote(report_no)

                if report_no in seen_ids:
                    continue
                seen_ids.add(report_no)
                page_ids_found += 1

                # Year: look for a 20xx year in surrounding card text via JS
                year = None
                try:
                    parent_text = page.evaluate(
                        f"""() => {{
                            const a = [...document.querySelectorAll('a[href]')]
                              .find(el => el.href.includes({repr(report_no.replace("'", "'"))}))
                            return a ? a.closest('li, article, section, div')?.innerText || '' : ''
                        }}"""
                    )
                    m_year = re.search(r"\b(20\d{2})\b", parent_text)
                    if m_year:
                        year = int(m_year.group(1))
                except Exception:
                    pass

                results.append({
                    "report_no":   report_no,
                    "year":        year,
                    "title":       text,
                    "source_page": url,
                })

                if len(results) >= max_ids:
                    break

            log.info(
                f"  [Playwright] Page {page_num}: +{page_ids_found} IDs "
                f"(total: {len(results)})"
            )

            if page_ids_found == 0:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    log.info("  [Playwright] 3 pages with no new IDs — reached end")
                    break
            else:
                consecutive_empty = 0

            page_num += 1
            time.sleep(random.uniform(1.5, 3.0))

        browser.close()

    log.info(f"  [Playwright] Collected {len(results)} report IDs across {page_num} pages")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Download one PDF via the REST endpoint
# ─────────────────────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (compatible; AcademicResearchBot/1.0; "
        "Stockholm University CYFO Research 2026; "
        "Legal basis: Offentlighetsprincipen; "
        "+https://www.su.se)"
    ),
    "Accept": "application/pdf,*/*",
    "Referer": "https://www.foi.se/rapporter.html",
})
SESSION.verify = False


def download_foi_pdf(
    report_info: dict,
    seen_urls: set,
    period_counts: dict,
    quota_per_period: int,
    dry_run: bool = False,
) -> Optional[PDFRecord]:
    """
    Download a single FOI report PDF via the REST API endpoint.
    Returns a PDFRecord on success, None otherwise.
    """
    report_no  = report_info["report_no"]
    hint_year  = report_info.get("year")
    source_url = report_info.get("source_page", FOI_SEARCH_URL)
    # URL-encode the report number (handles "FOI Memo 9158" → "FOI%20Memo%209158")
    from urllib.parse import quote as _quote
    pdf_url    = FOI_REST_BASE + _quote(report_no, safe="-.")

    if pdf_url in seen_urls:
        log.debug(f"  [SKIP] Already collected: {pdf_url}")
        return None

    # Quick pre-filter: if we know the year and quota is already full, skip
    if hint_year is not None:
        period = classify_year(hint_year)
        if period == "pre-2020":
            log.debug(f"  [SKIP] pre-2020 ({hint_year}): {report_no}")
            return None
        if period and period_counts.get(period, 0) >= quota_per_period:
            log.debug(f"  [SKIP] Quota full for {period}: {report_no}")
            return None

    if dry_run:
        log.info(f"  [DRY-RUN] Would download: {pdf_url}")
        seen_urls.add(pdf_url)
        return None

    polite_sleep()

    # ── Download ──────────────────────────────────────────────────────────────
    tmp_path: Optional[Path] = None
    try:
        resp = SESSION.get(pdf_url, stream=True, timeout=45)

        if resp.status_code == 404:
            log.debug(f"  [404] Report not available as PDF: {report_no}")
            seen_urls.add(pdf_url)
            return None

        resp.raise_for_status()

        ct = resp.headers.get("Content-Type", "")
        if ct and "pdf" not in ct.lower() and "octet-stream" not in ct.lower():
            log.debug(f"  [SKIP] Non-PDF content-type '{ct}': {report_no}")
            seen_urls.add(pdf_url)
            return None

        content_length = int(resp.headers.get("Content-Length", 0))
        if content_length > 52_428_800:  # 50 MB cap
            log.info(f"  [SKIP] Too large ({content_length // 1_048_576} MB): {report_no}")
            seen_urls.add(pdf_url)
            return None

        with tempfile.NamedTemporaryFile(
            suffix=".pdf", delete=False, dir=DATA_DIR
        ) as tmp:
            tmp_path = Path(tmp.name)
            for chunk in resp.iter_content(chunk_size=65536):
                tmp.write(chunk)

    except requests.RequestException as e:
        log.warning(f"  [HTTP error] {pdf_url}: {e}")
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()
        return None

    # ── Verify PDF magic bytes ────────────────────────────────────────────────
    try:
        with open(tmp_path, "rb") as f:
            if f.read(5) != b"%PDF-":
                log.debug(f"  [SKIP] Not a real PDF: {report_no}")
                tmp_path.unlink()
                seen_urls.add(pdf_url)
                return None
    except OSError:
        pass

    file_size = tmp_path.stat().st_size
    sha256    = sha256_file(tmp_path)

    # ── ExifTool ──────────────────────────────────────────────────────────────
    meta        = run_exiftool(tmp_path)
    exiftool_ok = bool(meta)
    pdf_year    = year_from_exiftool(meta) if meta else None

    # ── Determine year & period ───────────────────────────────────────────────
    year_used = hint_year or pdf_year
    period    = classify_year(year_used) or "unknown"

    if period == "pre-2020":
        log.debug(f"  [SKIP] pre-2020 after metadata check: {report_no}")
        tmp_path.unlink()
        seen_urls.add(pdf_url)
        return None

    # Enforce quota (checked again after real year is known)
    if period in (PERIOD_PRE_NIS2, PERIOD_NIS2_PREP, PERIOD_POST_LAW):
        if period_counts.get(period, 0) >= quota_per_period:
            log.debug(f"  [SKIP] Quota full for {period} (post-download check): {report_no}")
            tmp_path.unlink()
            seen_urls.add(pdf_url)
            return None

    # ── Save to final location ────────────────────────────────────────────────
    year_str  = str(year_used) if year_used else "unknown_year"
    final_dir = DATA_DIR / "01_raw_pdfs" / year_str / "FOI"
    final_dir.mkdir(parents=True, exist_ok=True)

    safe_id   = report_no.replace("/", "-").replace(" ", "_")
    filename  = f"{sha256[:8]}_{safe_id}.pdf"
    final_path = final_dir / filename

    try:
        tmp_path.rename(final_path)
    except OSError as e:
        log.warning(f"  Could not move {tmp_path} → {final_path}: {e}")

    # ── Build record ──────────────────────────────────────────────────────────
    notes = ""
    if meta and meta.get("Linearized") == "No":
        notes = "check_incremental"

    record = PDFRecord(
        authority_name    = AUTHORITY_NAME,
        authority_name_en = AUTHORITY_NAME_EN,
        tier              = AUTHORITY_TIER,
        pdf_url           = pdf_url,
        source_page_url   = source_url,
        sha256            = sha256,
        file_size_bytes   = file_size,
        temporal_period   = period,
        year_from_url     = None,
        year_from_pdf     = pdf_year,
        year_used         = year_used,
        collection_timestamp = datetime.utcnow().isoformat() + "Z",
        exiftool_ok       = exiftool_ok,
        notes             = notes,
    )

    # ── Metadata rows ─────────────────────────────────────────────────────────
    meta_rows = [
        MetadataField(
            authority_name  = AUTHORITY_NAME,
            tier            = AUTHORITY_TIER,
            pdf_url         = pdf_url,
            sha256          = sha256,
            temporal_period = period,
            field_name      = k,
            field_value     = str(v),
        )
        for k, v in meta.items()
        if k not in _SKIP_EXIFTOOL_FIELDS and str(v).strip()
    ]

    append_record(record)
    append_metadata(meta_rows)

    period_counts[period] = period_counts.get(period, 0) + 1
    seen_urls.add(pdf_url)

    log.info(
        f"  [OK] {sha256[:8]}… | {file_size // 1024:>5} KB | "
        f"year={year_used} ({period}) | fields={len(meta_rows)} | {report_no}"
    )
    return record


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Targeted FOI scraper — collects PDFs from foi.se/rapporter.html"
    )
    parser.add_argument("--target",   type=int, default=100,
                        help="Total PDFs to collect (default: 100)")
    parser.add_argument("--year-from", type=int, default=2020,
                        help="Search from year (default: 2020)")
    parser.add_argument("--year-to",   type=int, default=2025,
                        help="Search to year (default: 2025)")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Find report IDs but do not download")
    parser.add_argument("--quota",     type=int, default=50,
                        help="Max PDFs per temporal period (default: 50)")
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    log.info("=" * 60)
    log.info("FOI Targeted Scraper")
    log.info(f"Target: {args.target} PDFs | Years: {args.year_from}–{args.year_to}")
    log.info(f"Quota per period: {args.quota} | Dry-run: {args.dry_run}")
    log.info("=" * 60)

    # Resume state
    seen_urls     = load_seen_urls()
    period_counts = load_period_counts()
    log.info(f"Resume: {len(seen_urls)} URLs already collected")
    log.info(f"Period counts for FOI: {period_counts}\n")

    # ── Step 1: collect report IDs via Playwright ─────────────────────────────
    # We fetch more IDs than the target in case some 404 or are pre-2020
    fetch_ids_target = args.target * 3   # generous buffer
    log.info(f"[Step 1] Scraping up to {fetch_ids_target} report IDs from FOI search…")

    report_ids = scrape_report_ids_playwright(
        year_from  = args.year_from,
        year_to    = args.year_to,
        max_ids    = fetch_ids_target,
    )

    if not report_ids:
        log.error("No report IDs found — check if the page structure has changed.")
        sys.exit(1)

    log.info(f"[Step 1] Done. Found {len(report_ids)} report IDs.\n")

    # ── Step 2: download PDFs ─────────────────────────────────────────────────
    log.info("[Step 2] Downloading PDFs…")
    downloaded = 0
    skipped    = 0

    for i, report_info in enumerate(report_ids, 1):
        # Check if overall target is met
        if downloaded >= args.target:
            log.info(f"Target of {args.target} PDFs reached — stopping.")
            break

        # Check if all relevant quotas are full
        pre  = period_counts.get(PERIOD_PRE_NIS2,  0)
        prep = period_counts.get(PERIOD_NIS2_PREP, 0)
        post = period_counts.get(PERIOD_POST_LAW,  0)
        if pre >= args.quota and prep >= args.quota and post >= args.quota:
            log.info("All period quotas full — stopping.")
            break

        log.info(f"  [{i}/{len(report_ids)}] {report_info['report_no']}")

        record = download_foi_pdf(
            report_info     = report_info,
            seen_urls       = seen_urls,
            period_counts   = period_counts,
            quota_per_period= args.quota,
            dry_run         = args.dry_run,
        )

        if record:
            downloaded += 1
        else:
            skipped += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    log.info("\n" + "=" * 60)
    log.info("FOI Scraper — Complete")
    log.info(f"  Downloaded : {downloaded}")
    log.info(f"  Skipped    : {skipped}")
    log.info(f"  Period counts: {period_counts}")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
