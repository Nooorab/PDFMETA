"""
authorities.py
--------------
Configuration for all 30 Swedish public-sector authorities in the study.

Structure: 3 tiers × 10 authorities × max 100 PDFs each (50 pre-NIS2 + 50 NIS2-prep)

Tier 1 (Red)   — High Security Sensitivity
Tier 2 (Orange)— Operational & Infrastructure Risk
Tier 3 (Yellow)— Data Exposure & High Volume
"""

from dataclasses import dataclass


@dataclass
class Authority:
    """Represents one Swedish public authority in the corpus."""
    name: str                        # Official Swedish name
    name_en: str                     # English name (for logging)
    tier: int                        # 1, 2, or 3
    domain: str                      # e.g. "www.sakerhetspolisen.se"
    start_url: str                   # The root homepage to start crawling from
    crawl_depth: int = 4             # How many link-hops from the homepage
    notes: str = ""                  # Any crawl-specific notes


# ─────────────────────────────────────────────────────────────────────────────
# TIER 1 — High Security Sensitivity (Critical Impact)
# ─────────────────────────────────────────────────────────────────────────────

TIER1 = [
    Authority(
        name="Regeringskansliet",
        name_en="Government Offices of Sweden",
        tier=1,
        domain="www.regeringen.se",
        start_url="https://www.regeringen.se/",
    ),
    Authority(
        name="Säkerhetspolisen",
        name_en="Swedish Security Service (SÄPO)",
        tier=1,
        domain="www.sakerhetspolisen.se",
        start_url="https://www.sakerhetspolisen.se/",
    ),
    Authority(
        name="Polismyndigheten",
        name_en="Swedish Police Authority",
        tier=1,
        domain="polisen.se",
        start_url="https://polisen.se/",
    ),
    Authority(
        name="Åklagarmyndigheten",
        name_en="Swedish Prosecution Authority",
        tier=1,
        domain="www.aklagare.se",
        start_url="https://www.aklagare.se/",
    ),
    Authority(
        name="Försvarsmakten",
        name_en="Swedish Armed Forces",
        tier=1,
        domain="www.forsvarsmakten.se",
        start_url="https://www.forsvarsmakten.se/",
        notes="May block scrapers — check robots.txt carefully",
    ),
    Authority(
        name="Försvarets radioanstalt",
        name_en="National Defence Radio Establishment (FRA)",
        tier=1,
        domain="www.fra.se",
        start_url="https://www.fra.se/",
    ),
    Authority(
        name="Tullverket",
        name_en="Swedish Customs",
        tier=1,
        domain="www.tullverket.se",
        start_url="https://www.tullverket.se/",
    ),
    Authority(
        name="Myndigheten för samhällsskydd och beredskap",
        name_en="Swedish Civil Contingencies Agency (MSB)",
        tier=1,
        domain="www.msb.se",
        start_url="https://www.msb.se/",
    ),
    Authority(
        name="Totalförsvarets forskningsinstitut",
        name_en="Swedish Defence Research Agency (FOI)",
        tier=1,
        domain="www.foi.se",
        start_url="https://www.foi.se/",
    ),
    Authority(
        name="Säkerhets- och integritetsskyddsnämnden",
        name_en="Security and Integrity Protection Board (SIN)",
        tier=1,
        domain="www.sakint.se",
        start_url="https://www.sakint.se/",
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# TIER 2 — Operational & Infrastructure Risk (Systems Exposure)
# ─────────────────────────────────────────────────────────────────────────────

TIER2 = [
    Authority(
        name="Myndigheten för digital förvaltning",
        name_en="Agency for Digital Government (DIGG)",
        tier=2,
        domain="www.digg.se",
        start_url="https://www.digg.se/",
    ),
    Authority(
        name="Post- och telestyrelsen",
        name_en="Swedish Post and Telecom Authority (PTS)",
        tier=2,
        domain="www.pts.se",
        start_url="https://www.pts.se/",
    ),
    Authority(
        name="Trafikverket",
        name_en="Swedish Transport Administration",
        tier=2,
        domain="www.trafikverket.se",
        start_url="https://www.trafikverket.se/",
    ),
    Authority(
        name="Transportstyrelsen",
        name_en="Swedish Transport Agency",
        tier=2,
        domain="www.transportstyrelsen.se",
        start_url="https://www.transportstyrelsen.se/",
    ),
    Authority(
        name="Affärsverket svenska kraftnät",
        name_en="Swedish National Grid (Svenska Kraftnät)",
        tier=2,
        domain="www.svk.se",
        start_url="https://www.svk.se/",
    ),
    Authority(
        name="Energimyndigheten",
        name_en="Swedish Energy Agency",
        tier=2,
        domain="www.energimyndigheten.se",
        start_url="https://www.energimyndigheten.se/",
    ),
    Authority(
        name="E-hälsomyndigheten",
        name_en="eHealth Agency",
        tier=2,
        domain="www.ehalsomyndigheten.se",
        start_url="https://www.ehalsomyndigheten.se/",
    ),
    Authority(
        name="Lantmäteriet",
        name_en="Swedish Mapping, Cadastral and Land Registration Authority",
        tier=2,
        domain="www.lantmateriet.se",
        start_url="https://www.lantmateriet.se/",
    ),
    Authority(
        name="Ekobrottsmyndigheten",
        name_en="Swedish Economic Crime Authority",
        tier=2,
        domain="www.ekobrottsmyndigheten.se",
        start_url="https://www.ekobrottsmyndigheten.se/",
    ),
    Authority(
        name="Integritetsskyddsmyndigheten",
        name_en="Swedish Authority for Privacy Protection (IMY)",
        tier=2,
        domain="www.imy.se",
        start_url="https://www.imy.se/",
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# TIER 3 — Data Exposure & High Volume (Indirect Risk)
# ─────────────────────────────────────────────────────────────────────────────

TIER3 = [
    Authority(
        name="Skatteverket",
        name_en="Swedish Tax Agency",
        tier=3,
        domain="www.skatteverket.se",
        start_url="https://www.skatteverket.se/",
    ),
    Authority(
        name="Försäkringskassan",
        name_en="Swedish Social Insurance Agency",
        tier=3,
        domain="www.forsakringskassan.se",
        start_url="https://www.forsakringskassan.se/",
    ),
    Authority(
        name="Pensionsmyndigheten",
        name_en="Swedish Pensions Agency",
        tier=3,
        domain="www.pensionsmyndigheten.se",
        start_url="https://www.pensionsmyndigheten.se/",
    ),
    Authority(
        name="Statistiska centralbyrån",
        name_en="Statistics Sweden (SCB)",
        tier=3,
        domain="www.scb.se",
        start_url="https://www.scb.se/",
    ),
    Authority(
        name="Bolagsverket",
        name_en="Swedish Companies Registration Office",
        tier=3,
        domain="www.bolagsverket.se",
        start_url="https://www.bolagsverket.se/",
    ),
    Authority(
        name="Socialstyrelsen",
        name_en="National Board of Health and Welfare",
        tier=3,
        domain="www.socialstyrelsen.se",
        start_url="https://www.socialstyrelsen.se/",
    ),
    Authority(
        name="Folkhälsomyndigheten",
        name_en="Public Health Agency of Sweden",
        tier=3,
        domain="www.folkhalsomyndigheten.se",
        start_url="https://www.folkhalsomyndigheten.se/",
    ),
    Authority(
        name="Karolinska institutet",
        name_en="Karolinska Institute",
        tier=3,
        domain="ki.se",
        start_url="https://ki.se/",
    ),
    Authority(
        name="Stockholm universitet",
        name_en="Stockholm University",
        tier=3,
        domain="www.su.se",
        start_url="https://www.su.se/",
    ),
    Authority(
        name="Lunds universitet",
        name_en="Lund University",
        tier=3,
        domain="www.lu.se",
        start_url="https://www.lu.se/",
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# Combined registry — used by collector.py
# ─────────────────────────────────────────────────────────────────────────────

ALL_AUTHORITIES: list[Authority] = TIER1 + TIER2 + TIER3

AUTHORITY_BY_NAME: dict[str, Authority] = {a.name: a for a in ALL_AUTHORITIES}
