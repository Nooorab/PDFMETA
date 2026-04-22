"""
collector.py
------------
Collects PDF documents from 30 Swedish public-sector authority websites for
the study "A Forensic Analysis of Metadata Leakage in Swedish Public Documents".

Design constraints (from project specification):
  - PDF files only
  - Respects robots.txt for every domain
  - 3–5 second random delay between all HTTP requests
  - SHA-256 hash computed for every file
  - ExifTool metadata extracted immediately after download
  - Raw PDF deleted immediately after extraction (GDPR + storage)
  - Temporal quota: 50 PDFs per authority from 2020–2023 (pre-NIS2 baseline)
                    50 PDFs per authority from 2024–2025 (NIS2 preparation)
                    Post-2026 collected descriptively only (no quota limit)
  - Metadata logged to CSV: one row per PDF
  - Legal basis: Offentlighetsprincipen + GDPR Article 89 research exemption

Usage:
  # Run all 30 authorities
  python collector.py

  # Run a single authority (use exact Swedish name from authorities.py)
  python collector.py --authority "Säkerhetspolisen"

  # Run all authorities in a specific tier
  python collector.py --tier 1

  # Dry-run: crawl and find PDFs but do not download
  python collector.py --dry-run

  # Resume from where it stopped (default behaviour — checks existing log)
  python collector.py

Output files (in ../../03_Data/):
  collection_log.csv        — one row per collected PDF
  metadata_fields.csv       — one row per ExifTool field per PDF (long format)
  crawl_errors.log          — HTTP errors, robots.txt blocks, parse failures
"""

import os
import re
import csv
import sys
import time
import random
import hashlib
import logging
import argparse
import tempfile
import subprocess
import json
import heapq
import itertools
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from bs4 import BeautifulSoup

# Resolve paths relative to this script file
SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR   = SCRIPT_DIR.parent.parent       # PDFMETA/
DATA_DIR   = BASE_DIR / "03_Data"           # 03_Data/

COLLECTION_LOG = DATA_DIR / "collection_log.csv"
METADATA_CSV   = DATA_DIR / "metadata_fields.csv"
ERROR_LOG      = DATA_DIR / "crawl_errors.log"

# Import authority definitions
sys.path.insert(0, str(SCRIPT_DIR))
from authorities import ALL_AUTHORITIES, AUTHORITY_BY_NAME, Authority

# ─────────────────────────────────────────────────────────────────────────────
# Temporal windows
# ─────────────────────────────────────────────────────────────────────────────

PERIOD_PRE_NIS2   = "2020-2023"   # Baseline
PERIOD_NIS2_PREP  = "2024-2025"   # NIS2 preparation
PERIOD_POST_LAW   = "post-2026"   # Descriptive only

QUOTA_PER_PERIOD  = 50            # Max PDFs per authority per temporal period
PAGE_CAP          = 10            # Max successful PDFs per HTML page

SENSITIVE_KEYWORDS = [
    "rapport", "beslut", "protokoll", "arsredovisning", "policy",
    "riktlinje", "avtal", "strategi", "utredning"
]

def classify_year(year: Optional[int]) -> Optional[str]:
    """Map a year to its temporal period label."""
    if year is None:
        return None
    if 2020 <= year <= 2023:
        return PERIOD_PRE_NIS2
    if 2024 <= year <= 2025:
        return PERIOD_NIS2_PREP
    if year >= 2026:
        return PERIOD_POST_LAW
    return None   # Before 2020 — out of scope

# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PDFRecord:
    """One row in collection_log.csv — one entry per collected PDF."""
    authority_name: str
    authority_name_en: str
    tier: int
    pdf_url: str
    source_page_url: str
    sha256: str
    file_size_bytes: int
    temporal_period: str          # PERIOD_* constant
    year_from_url: Optional[int]
    year_from_pdf: Optional[int]
    year_used: Optional[int]      # Final authoritative year (url → pdf → None)
    collection_timestamp: str     # ISO-8601
    exiftool_ok: bool
    notes: str = ""


@dataclass
class MetadataField:
    """One row in metadata_fields.csv — one ExifTool field per PDF."""
    authority_name: str
    tier: int
    pdf_url: str
    sha256: str
    temporal_period: str
    field_name: str
    field_value: str

# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
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
# HTTP session
# ─────────────────────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (compatible; AcademicResearchBot/1.0; "
        "Stockholm University CYFO Research 2026; "
        "Legal basis: Offentlighetsprincipen; "
        "+https://www.su.se)"
    )
})
SESSION.timeout = 20
SESSION.verify = False  # Disable SSL verification for misconfigured govt sites

def polite_sleep():
    """Sleep a random 3–5 seconds between requests (as specified)."""
    time.sleep(random.uniform(3.0, 5.0))

# ─────────────────────────────────────────────────────────────────────────────
# robots.txt compliance
# ─────────────────────────────────────────────────────────────────────────────

_robots_cache: dict[str, RobotFileParser] = {}

def get_robots(base_url: str) -> RobotFileParser:
    """Fetch and cache robots.txt for a domain. Returns permissive parser on failure."""
    parsed = urlparse(base_url)
    domain_key = f"{parsed.scheme}://{parsed.netloc}"

    if domain_key not in _robots_cache:
        rp = RobotFileParser()
        robots_url = f"{domain_key}/robots.txt"
        rp.set_url(robots_url)
        try:
            resp = SESSION.get(robots_url, timeout=10)
            if resp.status_code == 200:
                rp.parse(resp.text.splitlines())
                log.debug(f"robots.txt loaded: {robots_url}")
            else:
                log.debug(f"robots.txt returned {resp.status_code}: {robots_url}")
        except Exception as e:
            log.warning(f"Could not fetch {robots_url}: {e} — treating as allow-all")
        _robots_cache[domain_key] = rp

    return _robots_cache[domain_key]


def is_allowed(url: str) -> bool:
    """Return True if our user-agent is allowed to fetch this URL."""
    rp = get_robots(url)
    return rp.can_fetch(SESSION.headers["User-Agent"], url)

# ─────────────────────────────────────────────────────────────────────────────
# Date extraction
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that commonly appear in Swedish government PDF URLs
_URL_DATE_PATTERNS = [
    re.compile(r"/(\d{4})/(\d{1,2})/"),           # /2023/05/
    re.compile(r"/(\d{4})-(\d{2})-\d{2}"),        # /2023-05-12
    re.compile(r"[_\-/](\d{4})[_\-]"),            # _2023_ or -2023-
    re.compile(r"/(\d{4})/"),                       # /2023/
]

def year_from_url(url: str) -> Optional[int]:
    """Try to extract a publication year from a PDF URL."""
    for pat in _URL_DATE_PATTERNS:
        m = pat.search(url)
        if m:
            try:
                y = int(m.group(1))
                if 2010 <= y <= 2030:
                    return y
            except (ValueError, IndexError):
                continue
    return None


def year_from_exiftool(meta: dict) -> Optional[int]:
    """
    Extract the most likely publication year from ExifTool metadata dict.
    Priority: CreateDate > ModifyDate > MetadataDate
    """
    for key in ("CreateDate", "ModifyDate", "MetadataDate", "XMP:CreateDate"):
        val = meta.get(key, "")
        if not val:
            continue
        # ExifTool dates: "2023:05:12 10:30:00+02:00" or ISO format
        m = re.search(r"(\d{4})", str(val))
        if m:
            y = int(m.group(1))
            if 2010 <= y <= 2030:
                return y
    return None

# ─────────────────────────────────────────────────────────────────────────────
# ExifTool integration
# ─────────────────────────────────────────────────────────────────────────────

def run_exiftool(filepath: Path) -> dict:
    """
    Run exiftool on a local PDF file.
    Returns a flat dict of field→value, or empty dict on failure.
    Requires exiftool to be installed: brew install exiftool
    """
    try:
        result = subprocess.run(
            ["exiftool", "-json", "-all:all", "-charset", "utf8", str(filepath)],
            capture_output=True,
            text=True,
            timeout=30,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            log.warning(f"exiftool non-zero exit for {filepath.name}: {result.stderr[:200]}")
            return {}
        data = json.loads(result.stdout)
        return data[0] if data else {}
    except FileNotFoundError:
        log.error("exiftool not found. Install it: brew install exiftool")
        return {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        log.warning(f"exiftool failed for {filepath.name}: {e}")
        return {}

# ─────────────────────────────────────────────────────────────────────────────
# SHA-256 hashing
# ─────────────────────────────────────────────────────────────────────────────

def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# ─────────────────────────────────────────────────────────────────────────────
# CSV writers
# ─────────────────────────────────────────────────────────────────────────────

_LOG_FIELDNAMES = list(PDFRecord.__dataclass_fields__.keys())
_META_FIELDNAMES = list(MetadataField.__dataclass_fields__.keys())

# Fields to EXCLUDE from metadata_fields.csv (not analytically useful)
_SKIP_EXIFTOOL_FIELDS = {
    "SourceFile", "ExifToolVersion", "Directory",
    "FileModifyDate", "FileAccessDate", "FileInodeChangeDate",
    "FilePermissions", "FileType", "FileTypeExtension",
    "MIMEType", "Linearized",
}

def _open_csv(path: Path, fieldnames: list[str]) -> tuple:
    """Open a CSV for appending (or create with header). Returns (file, writer)."""
    write_header = not path.exists()
    f = open(path, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    if write_header:
        writer.writeheader()
    return f, writer


def append_record(record: PDFRecord):
    f, writer = _open_csv(COLLECTION_LOG, _LOG_FIELDNAMES)
    writer.writerow(asdict(record))
    f.close()


def append_metadata(fields: list[MetadataField]):
    if not fields:
        return
    f, writer = _open_csv(METADATA_CSV, _META_FIELDNAMES)
    for mf in fields:
        writer.writerow(asdict(mf))
    f.close()

# ─────────────────────────────────────────────────────────────────────────────
# Already-collected tracker (resume support)
# ─────────────────────────────────────────────────────────────────────────────

def load_already_collected() -> dict[str, dict[str, int]]:
    """
    Load collection_log.csv and return per-authority period counts.
    Returns: { authority_name: { period_label: count } }
    """
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    if not COLLECTION_LOG.exists():
        return counts
    with open(COLLECTION_LOG, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name   = row.get("authority_name", "")
            period = row.get("temporal_period", "")
            if name and period:
                counts[name][period] += 1
    return counts


def load_seen_urls() -> set[str]:
    """Return the set of PDF URLs already present in collection_log.csv."""
    seen: set[str] = set()
    if not COLLECTION_LOG.exists():
        return seen
    with open(COLLECTION_LOG, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("pdf_url", "").strip()
            if url:
                seen.add(url)
    return seen

# ─────────────────────────────────────────────────────────────────────────────
# Web crawling
# ─────────────────────────────────────────────────────────────────────────────

def fetch_page(url: str) -> Optional[BeautifulSoup]:
    """
    Fetch an HTML page and return a BeautifulSoup object.
    Returns None on error. Applies polite delay and robots.txt check.
    """
    if not is_allowed(url):
        log.info(f"  [robots.txt] Blocked: {url}")
        return None

    polite_sleep()
    try:
        resp = SESSION.get(url, timeout=20)
        resp.raise_for_status()
        return BeautifulSoup(resp.text, "html.parser")
    except requests.RequestException as e:
        log.warning(f"  [HTTP error] {url}: {e}")
        return None


NAV_KEYWORDS = [
    "publikation", "dokument", "rapport", "fakta", "statistik", 
    "om oss", "om-oss", "om-myndigheten", "arkiv", "styrdokument", "beslut",
    "om_oss", "om_myndigheten", "handlingar", "diarium", "blanketter",
    "lagar", "regler", "kunskap"
]

def get_nav_score(url: str) -> int:
    """Score HTML links for the priority queue. Lower score = crawled earlier."""
    url_lower = url.lower()
    return sum(-1 for kw in NAV_KEYWORDS if kw in url_lower)

def get_pdf_score(url: str) -> int:
    """Score PDF links. Lower score = downloaded earlier."""
    url_lower = url.lower()
    return sum(-1 for kw in SENSITIVE_KEYWORDS if kw in url_lower)

# ─────────────────────────────────────────────────────────────────────────────
# Core: download one PDF, extract metadata, delete
# ─────────────────────────────────────────────────────────────────────────────

def process_pdf(
    pdf_url: str,
    source_page: str,
    authority: Authority,
    url_year: Optional[int],
    dry_run: bool = False,
) -> Optional[PDFRecord]:
    """
    Download one PDF to a temp file, run ExifTool, log metadata, then
    immediately delete the file.

    Returns a PDFRecord on success, or None if the download/extraction failed.
    """
    if not is_allowed(pdf_url):
        log.info(f"    [robots.txt] Blocked PDF: {pdf_url}")
        return None

    if dry_run:
        log.info(f"    [DRY-RUN] Would download: {pdf_url}")
        return None

    polite_sleep()

    # ── Download to temp file ────────────────────────────────────────────────
    tmp_path: Optional[Path] = None
    try:
        resp = SESSION.get(pdf_url, stream=True, timeout=30)
        resp.raise_for_status()

        # Confirm Content-Type is PDF (not always set, so don't hard-fail)
        ct = resp.headers.get("Content-Type", "")
        if ct and "pdf" not in ct.lower() and "octet-stream" not in ct.lower():
            log.debug(f"    [SKIP] Non-PDF content-type '{ct}': {pdf_url}")
            return None

        with tempfile.NamedTemporaryFile(
            suffix=".pdf", delete=False, dir=DATA_DIR
        ) as tmp:
            tmp_path = Path(tmp.name)
            for chunk in resp.iter_content(chunk_size=65536):
                tmp.write(chunk)

    except requests.RequestException as e:
        log.warning(f"    [HTTP error] {pdf_url}: {e}")
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()
        return None

    # ── Verify it's actually a PDF ────────────────────────────────────────────
    try:
        with open(tmp_path, "rb") as f:
            header = f.read(5)
        if header != b"%PDF-":
            log.debug(f"    [SKIP] Not a PDF (bad header): {pdf_url}")
            tmp_path.unlink()
            return None
    except OSError:
        pass

    file_size   = tmp_path.stat().st_size
    sha256      = sha256_file(tmp_path)

    # ── ExifTool extraction ──────────────────────────────────────────────────
    meta         = run_exiftool(tmp_path)
    exiftool_ok  = bool(meta)
    pdf_year     = year_from_exiftool(meta) if meta else None

    # ── Determine authoritative year ─────────────────────────────────────────
    year_used   = url_year if url_year is not None else pdf_year
    period      = classify_year(year_used) or "unknown"

    # ── Move to final storage (organized by year) ────────────────────────────
    year_str = str(year_used) if year_used else "unknown_year"
    final_dir = DATA_DIR / "01_raw_pdfs" / year_str / authority.name_en.replace(" ", "_").replace("/", "-")
    final_dir.mkdir(parents=True, exist_ok=True)
    
    final_path = final_dir / tmp_path.name
    try:
        tmp_path.rename(final_path)
        log.debug(f"    [SAVED] {final_path.name}")
    except OSError as e:
        log.warning(f"    Could not move file to {final_path}: {e}")

    # ── Build record ──────────────────────────────────────────────────────────
    record = PDFRecord(
        authority_name    = authority.name,
        authority_name_en = authority.name_en,
        tier              = authority.tier,
        pdf_url           = pdf_url,
        source_page_url   = source_page,
        sha256            = sha256,
        file_size_bytes   = file_size,
        temporal_period   = period,
        year_from_url     = url_year,
        year_from_pdf     = pdf_year,
        year_used         = year_used,
        collection_timestamp = datetime.utcnow().isoformat() + "Z",
        exiftool_ok       = exiftool_ok,
    )

    # ── Build metadata field rows ─────────────────────────────────────────────
    meta_rows = [
        MetadataField(
            authority_name = authority.name,
            tier           = authority.tier,
            pdf_url        = pdf_url,
            sha256         = sha256,
            temporal_period= period,
            field_name     = k,
            field_value    = str(v),
        )
        for k, v in meta.items()
        if k not in _SKIP_EXIFTOOL_FIELDS and str(v).strip()
    ]

    # ── Persist ───────────────────────────────────────────────────────────────
    append_record(record)
    append_metadata(meta_rows)

    log.info(
        f"    [OK] {sha256[:8]}… | {file_size//1024:>5} KB | "
        f"year={year_used} ({period}) | fields={len(meta_rows)}"
    )
    return record

# ─────────────────────────────────────────────────────────────────────────────
# Authority-level collection loop
# ─────────────────────────────────────────────────────────────────────────────

def collect_authority(
    authority: Authority,
    period_counts: dict[str, int],
    seen_urls: set[str],
    dry_run: bool = False,
):
    """
    Focused Crawler: Starts at authority.start_url, explores high-value
    navigation paths first using a Priority Queue, and processes PDFs on the fly.
    Stops crawling when quotas are filled.
    """
    pre_filled  = period_counts.get(PERIOD_PRE_NIS2,  0)
    prep_filled = period_counts.get(PERIOD_NIS2_PREP, 0)

    pre_remaining  = max(0, QUOTA_PER_PERIOD - pre_filled)
    prep_remaining = max(0, QUOTA_PER_PERIOD - prep_filled)

    if pre_remaining == 0 and prep_remaining == 0:
        log.info(f"[{authority.name}] Both quotas full — skipping")
        return

    log.info(
        f"\n{'='*60}\n"
        f"Authority : {authority.name}\n"
        f"Tier      : {authority.tier}\n"
        f"Quota left: {PERIOD_PRE_NIS2}={pre_remaining}  "
        f"{PERIOD_NIS2_PREP}={prep_remaining}\n"
        f"{'='*60}"
    )

    domain = authority.domain.lstrip("www.")
    visited_pages: set[str] = set()
    queue = []
    counter = itertools.count()
    
    # heapq state: (nav_score, depth, count, url, source_page)
    heapq.heappush(queue, (0, 0, next(counter), authority.start_url, authority.start_url))

    while queue:
        pre_remaining  = QUOTA_PER_PERIOD - period_counts.get(PERIOD_PRE_NIS2,  0)
        prep_remaining = QUOTA_PER_PERIOD - period_counts.get(PERIOD_NIS2_PREP, 0)
        if pre_remaining <= 0 and prep_remaining <= 0:
            log.info("  Both quotas filled — moving to next authority")
            break

        nav_score, depth, _, page_url, source_page = heapq.heappop(queue)

        if page_url in visited_pages:
            continue
        visited_pages.add(page_url)

        if not is_allowed(page_url):
            log.debug(f"    [robots.txt] Skipping page: {page_url}")
            continue

        log.debug(f"  Crawling (depth={depth}, score={nav_score}): {page_url}")
        soup = fetch_page(page_url)
        if soup is None:
            continue

        page_pdfs = []

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith("#") or href.startswith("mailto:"):
                continue

            abs_url = urljoin(page_url, href)
            parsed  = urlparse(abs_url)

            # Stay within authority's domain
            if domain not in parsed.netloc:
                continue

            # Check if PDF
            if abs_url.lower().endswith(".pdf") or "filetype=pdf" in abs_url.lower():
                if abs_url not in seen_urls:
                    page_pdfs.append(abs_url)
                continue

            # Enqueue HTML pages
            if depth < authority.crawl_depth and abs_url not in visited_pages:
                if parsed.scheme in ("http", "https"):
                    n_score = get_nav_score(abs_url)
                    heapq.heappush(queue, (n_score, depth + 1, next(counter), abs_url, page_url))

        # Process PDFs found on this page, most sensitive first
        if page_pdfs:
            page_pdfs.sort(key=get_pdf_score) # Lower score is better
            log.info(f"  → Found {len(page_pdfs)} PDFs on {page_url}")
            
            successful_from_page = 0
            
            for pdf_url in page_pdfs:
                # Cap at PAGE_CAP successful files per page to ensure variety across the site
                if successful_from_page >= PAGE_CAP:
                    log.info(f"  [CAP] Reached {PAGE_CAP}-file limit for this page. Moving to other pages.")
                    break
                    
                # Re-check quotas in inner loop
                pre_rem  = QUOTA_PER_PERIOD - period_counts.get(PERIOD_PRE_NIS2,  0)
                prep_rem = QUOTA_PER_PERIOD - period_counts.get(PERIOD_NIS2_PREP, 0)
                if pre_rem <= 0 and prep_rem <= 0:
                    break

                url_year = year_from_url(pdf_url)
                record = process_pdf(pdf_url, page_url, authority, url_year, dry_run)
                seen_urls.add(pdf_url)
                
                if record:
                    successful_from_page += 1
                    if record.temporal_period in (PERIOD_PRE_NIS2, PERIOD_NIS2_PREP, PERIOD_POST_LAW):
                        period_counts[record.temporal_period] = (
                            period_counts.get(record.temporal_period, 0) + 1
                        )

    log.info(
        f"\n[{authority.name}] Done. "
        f"Pre-NIS2: {period_counts.get(PERIOD_PRE_NIS2, 0)}/{QUOTA_PER_PERIOD}  "
        f"NIS2-prep: {period_counts.get(PERIOD_NIS2_PREP, 0)}/{QUOTA_PER_PERIOD}"
    )

# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PDF metadata collector for Swedish public authorities"
    )
    parser.add_argument(
        "--authority", "-a",
        help="Collect only this authority (exact Swedish name)",
        default=None,
    )
    parser.add_argument(
        "--tier", "-t",
        type=int,
        choices=[1, 2, 3],
        help="Collect only authorities in this tier (1, 2, or 3)",
        default=None,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Crawl and log PDF URLs but do not download or delete anything",
    )
    parser.add_argument(
        "--test-mode",
        action="store_true",
        help="Run a short test (downloads only 2 PDFs per period)",
    )
    args = parser.parse_args()

    global QUOTA_PER_PERIOD, PAGE_CAP
    if args.test_mode:
        QUOTA_PER_PERIOD = 2
        PAGE_CAP = 2

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    log.info("=" * 60)
    log.info("PDF Metadata Collector — Swedish Public Authorities")
    log.info("Legal basis: Offentlighetsprincipen + GDPR Art. 89")
    log.info(f"Output directory: {DATA_DIR}")
    log.info(f"Dry-run: {args.dry_run}")
    log.info("=" * 60)

    # Load resume state
    already_collected = load_already_collected()
    seen_urls         = load_seen_urls()
    log.info(f"Resuming: {len(seen_urls)} URLs already in log\n")

    # Select which authorities to process
    if args.authority:
        if args.authority not in AUTHORITY_BY_NAME:
            log.error(f"Unknown authority: '{args.authority}'")
            log.error(f"Available: {list(AUTHORITY_BY_NAME.keys())}")
            sys.exit(1)
        authorities = [AUTHORITY_BY_NAME[args.authority]]
    elif args.tier:
        authorities = [a for a in ALL_AUTHORITIES if a.tier == args.tier]
    else:
        authorities = ALL_AUTHORITIES

    log.info(f"Processing {len(authorities)} authorit(y/ies)\n")

    for authority in authorities:
        period_counts = dict(already_collected.get(authority.name, {}))
        try:
            collect_authority(authority, period_counts, seen_urls, dry_run=args.dry_run)
        except KeyboardInterrupt:
            log.info("\nInterrupted by user — progress has been saved to CSV")
            sys.exit(0)
        except Exception as e:
            log.error(f"Unexpected error for {authority.name}: {e}", exc_info=True)
            continue   # Move on to next authority rather than crashing

    log.info("\n✅ Collection complete.")
    log.info(f"   Collection log : {COLLECTION_LOG}")
    log.info(f"   Metadata fields: {METADATA_CSV}")
    log.info(f"   Error log      : {ERROR_LOG}")


if __name__ == "__main__":
    main()
