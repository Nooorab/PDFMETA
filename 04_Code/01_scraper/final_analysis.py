"""
final_analysis.py — Complete analysis with corrected numbers.
Includes: R0-R3 classification, chi-square tests, linearization correction,
both Approach A (Skrauča) and Approach B (enhanced), and visualization data.
"""
import csv, re, os, json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent.parent
DATA_DIR = BASE_DIR / "03_Data"
REPORT_DIR = BASE_DIR / "06_Report" / "analysis_output"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

VALID_PERIODS = {"2020-2023", "2024-2025", "post-2026", "unknown"}

# ── Software keywords ──
SW_KW = ["microsoft","word","excel","powerpoint","office","adobe","acrobat",
    "indesign","illustrator","photoshop","libreoffice","openoffice","writer",
    "latex","tex","chromium","chrome","pdfcreator","pdf-xchange","foxit",
    "nitro","print to pdf","distiller","ghostscript","aspose","itext",
    "scribus","canva","stratsys","esri","arcgis","xerox","toshiba",
    "inkscape","pagemaker","ibooks","pscript","dpuscan","designer ",
    "primopdf","pdf code"]

# ── Authority names (R0) ──
AUTH_NAMES = {
    "folkhälsomyndigheten","försäkringskassan","polismyndigheten","bolagsverket",
    "transportstyrelsen","säkerhetspolisen","socialstyrelsen","lantmäteriet",
    "myndigheten för digital förvaltning","tullverket","skatteverket",
    "energimyndigheten","digg","lunds universitet","finansinspektionen",
    "integritetsskyddsmyndigheten (imy)","integritetsskyddsmyndigheten",
    "svenska kraftnät","åklagarmyndigheten","stockholms universitet",
    "stockholm universitet","myndigheten för civilt försvar","msb","fra",
    "försvarsmakten","trafikverket","regeringskansliet","karolinska institutet",
    "ekobrottsmyndigheten","pensionsmyndigheten","e-hälsomyndigheten",
    "totalförsvarets forskningsinstitut","foi","post- och telestyrelsen","pts",
    "försvarets radioanstalt","myndigheten för samhällsskydd och beredskap",
    "myndigheten för säkerhets- och integritetsskydd",
    "säkerhets- och integritetsskyddsnämnden",
    "nct nationellt centrum för terrorhotbedömning",
    "nct national centre for terrorist threat assessment",
    "digg myndigheten för digital förvaltning","affärsverket svenska kraftnät",
    "public health agency of sweden","folkhälsomyndigeten","juridiska fakulteten",
    "författare",
}
NOT_USER = {"oecd","nct","pds","mcf","msb","fra","foi","imy","digg","pts",
    "list","word","pdf","admin","user","root","säpo","nato","edqm"}
ORG_KW = ["myndighet","departement","styrels","verket","institut","universitet",
    "kommun","region ","riksdag","hovrätt","tingsrätt","länsstyrels",
    "inspektionen","nämnd","centrum för terrorhotbedömning"]

_USERNAME_RE = re.compile(r"^[a-z]{2,8}\d{0,6}$")
_ID_RE = re.compile(r"^[a-z]\d{4,8}$")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PATH_RE = re.compile(r"[A-Z]:\\|/home/|/Users/|\\\\[A-Za-z]")

SKIP_FIELDS = {"FileName","FileSize","Directory"}
R3_NAMES = {"PrinterName","C_Owner_WorkUnitPath","C_WorkUnitPath",
    "C_Owner_WorkUnit","C_WorkUnit","C_Owner_WorkUnit_ExternalId",
    "CdpWorkPlace","CdpCompany","TemplateUrl","Xd_ProgID","C_Owner_UserName",
    "ArticulatePath", "ArticulateGUID", "CloudStatistics_StoryID",
    "ClassificationContentMarkingHeaderText"}
R3_PFX = ["MSIP_Label_","Stc3"]
R2_NAMES = {"Author","Creator","LastModifiedBy","C_Owner","C_Owner_Email",
    "C_Owner_FamilyName","C_Owner_GivenName","C_Owners",
    "C_CreatedBy","C_Reviewers","C_Approvers","Tag_AuthorEmail",
    "Tag_AuthorEmailDisplayName","Tag_EmailSubject","Stc3_pr_FirstName",
    "Stc3_pr_LastName","Stc3_pr_EMail","Stc3Pr_FirstName","Stc3Pr_LastName",
    "Stc3Ts_ProcessedBy","Stc3Ts_ProcessedOwner","AM_Ansvarig","Aktor",
    "C_Form_INFORMATIONSKLASSNING","Personuppgifter","Sekretess",
    "Klassifisering","CdpEmail", "GrammarlyDocumentId", 
    "Mendeley_Unique_User_Id_1", "Mendeley0020Unique0020User0020Id_1"}
R1_NAMES = {"Producer","CreatorTool","PDFVersion","XMPToolkit","Linearized",
    "HasXFA","Software","GTS_PDFXVersion","GTS_PDFAVersion","Trapped"}

def classify_author_value(val):
    vl = val.lower().strip()
    if not vl: return "empty"
    if _PATH_RE.search(val): return "path"
    if _EMAIL_RE.search(val): return "email"
    if any(k in vl for k in SW_KW): return "software"
    if vl in AUTH_NAMES: return "organization"
    if vl not in NOT_USER and (_USERNAME_RE.match(vl) or _ID_RE.match(vl)):
        return "username"
    if vl in ("microsoft office user","user","admin","administrator"):
        return "software"
    if any(k in vl for k in ORG_KW): return "organization"
    if ";" in val:  # semi-colon separated = multiple names
        return "personal_name"
    words = val.strip().split()
    if len(words) >= 2 and all(w[0].isupper() and w.replace("-","").replace(".","").isalpha() for w in words if len(w)>1):
        return "personal_name"
    if "," in val:
        parts = [p.strip() for p in val.split(",")]
        if len(parts)==2 and all(p and p[0].isupper() for p in parts):
            return "personal_name"
        if any(p and p[0].isupper() for p in parts[:2]):
            return "personal_name"  # name + dept code
    if "['" in val: return "personal_name"  # raw debug data
    if "(" in val and ")" in val and any(c.isupper() for c in val.split("(")[0]):
        return "personal_name"
    return "unknown"

def classify_field(fn, fv):
    if fn in R3_NAMES: return "R3"
    for p in R3_PFX:
        if fn.startswith(p): return "R3"
    if _PATH_RE.search(str(fv)): return "R3"
    if fn in R2_NAMES:
        if fn in ("Author","Creator","LastModifiedBy"):
            vt = classify_author_value(fv)
            if vt == "software": return "R1"
            if vt == "organization": return "R0"
            if vt == "username": return "R3"
            if vt in ("personal_name","email"): return "R2"
            if vt == "path": return "R3"
            return "R2"  # conservative: unknown → R2
        return "R2"
    if _EMAIL_RE.search(str(fv)): return "R2"
    if fn in R1_NAMES: return "R1"
    return "R0"

def chi_square_2x2(a,b,c,d):
    """Simple 2x2 chi-square without scipy."""
    n = a+b+c+d
    if n == 0: return 0, 1.0
    e1 = (a+b)*(a+c)/n; e2 = (a+b)*(b+d)/n
    e3 = (c+d)*(a+c)/n; e4 = (c+d)*(b+d)/n
    if any(e==0 for e in [e1,e2,e3,e4]): return 0, 1.0
    chi2 = (a-e1)**2/e1 + (b-e2)**2/e2 + (c-e3)**2/e3 + (d-e4)**2/e4
    # Approximate p-value using chi2 with df=1
    import math
    p = math.exp(-chi2/2) if chi2 < 30 else 0.0
    return chi2, p

def main():
    print("Loading data...")
    # Load collection log
    sha_rec = {}
    with open(DATA_DIR/"collection_log.csv","r",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("temporal_period") in VALID_PERIODS:
                sha_rec[row["sha256"]] = row
    print(f"  {len(sha_rec)} PDFs in collection log")

    # Load hidden changes
    hidden = {}
    with open(DATA_DIR/"hidden_changes_log.csv","r",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            hidden[row["sha256"]] = row

    # Classify all metadata fields
    doc_risks = defaultdict(list)  # sha -> [risk levels]
    doc_r2_approach_a = set()  # Approach A: any Author/Creator field present
    author_types = Counter()
    field_risk_counter = Counter()
    total_fields = 0
    r3_findings = []

    with open(DATA_DIR/"metadata_fields.csv","r",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            fn = row.get("field_name","")
            fv = row.get("field_value","")
            sha = row.get("sha256","")
            if fn in SKIP_FIELDS: continue
            risk = classify_field(fn, fv)
            if risk == "R3":
                r3_findings.append({"sha256": sha, "field_name": fn, "field_value": fv})
            doc_risks[sha].append(risk)
            field_risk_counter[risk] += 1
            total_fields += 1
            # Approach A tracking
            if fn in ("Author","Creator","LastModifiedBy") and fv.strip():
                doc_r2_approach_a.add(sha)
                author_types[classify_author_value(fv)] += 1

    # Document-level risk
    doc_max_risk = {}
    risk_order = {"R3":3,"R2":2,"R1":1,"R0":0}
    for sha, risks in doc_risks.items():
        max_r = max(risks, key=lambda r: risk_order.get(r,0))
        doc_max_risk[sha] = max_r

    # ── Build report ──
    L = []
    L.append("="*75)
    L.append("FINAL FORENSIC METADATA ANALYSIS REPORT")
    L.append(f"Skrauča (2026) R0–R3 Taxonomy | Generated: {datetime.now().isoformat()}")
    L.append("="*75)

    # Overview
    L.append(f"\nTotal PDFs: {len(sha_rec)}")
    L.append(f"Total metadata fields classified: {total_fields}")

    # Field-level
    L.append("\n─── FIELD-LEVEL RISK DISTRIBUTION ───")
    for r in ["R3","R2","R1","R0"]:
        c = field_risk_counter.get(r,0)
        L.append(f"  {r}: {c:>6} ({100*c/total_fields:.1f}%)")

    # Doc-level
    L.append("\n─── DOCUMENT-LEVEL RISK (highest field wins) ───")
    doc_counter = Counter(doc_max_risk.values())
    total_docs = len(doc_max_risk)
    for r in ["R3","R2","R1","R0"]:
        c = doc_counter.get(r,0)
        L.append(f"  {r}: {c:>5} docs ({100*c/total_docs:.1f}%)")

    # Approach A vs B
    L.append("\n─── APPROACH A (Skrauča) vs APPROACH B (Enhanced) ───")
    L.append(f"  Approach A: {len(doc_r2_approach_a)}/{len(sha_rec)} docs have Author/Creator = R2 ({100*len(doc_r2_approach_a)/len(sha_rec):.1f}%)")
    r2_approach_b = sum(1 for r in doc_max_risk.values() if r in ("R2","R3"))
    L.append(f"  Approach B: {r2_approach_b}/{len(sha_rec)} docs have R2+ risk ({100*r2_approach_b/len(sha_rec):.1f}%)")

    # Author value breakdown
    L.append("\n─── AUTHOR/CREATOR VALUE TYPES ───")
    total_av = sum(author_types.values())
    for vt, cnt in author_types.most_common():
        L.append(f"  {vt:20s}: {cnt:>5} ({100*cnt/total_av:.1f}%)")

    # Tier comparison
    L.append("\n─── TIER COMPARISON ───")
    tier_data = defaultdict(lambda: Counter())
    for sha, risk in doc_max_risk.items():
        rec = sha_rec.get(sha)
        if rec:
            tier_data[rec["tier"]][risk] += 1

    tier_labels = {"1":"Strategic & Sovereign Risk","2":"Systemic & Structural Risk","3":"Societal & Privacy Risk"}
    L.append(f"{'Tier':<40s} {'R3':>8} {'R2':>8} {'R1':>8} {'R0':>8} {'Total':>8}")
    for t in ["1","2","3"]:
        c = tier_data[t]
        total = sum(c.values())
        parts = [f"Tier {t}: {tier_labels.get(t,'')}"]
        for r in ["R3","R2","R1","R0"]:
            cnt = c.get(r,0)
            parts.append(f"{cnt:>4}({100*cnt/total:3.0f}%)" if total else "0")
        parts.append(f"{total:>6}")
        L.append(f"  {'  '.join(parts)}")

    # Temporal comparison
    L.append("\n─── TEMPORAL COMPARISON ───")
    period_data = defaultdict(lambda: Counter())
    for sha, risk in doc_max_risk.items():
        rec = sha_rec.get(sha)
        if rec:
            period_data[rec["temporal_period"]][risk] += 1

    for p in ["2020-2023","2024-2025","post-2026"]:
        c = period_data[p]
        total = sum(c.values())
        if total == 0: continue
        parts = [f"{p:35s}"]
        for r in ["R3","R2","R1","R0"]:
            cnt = c.get(r,0)
            parts.append(f"{cnt:>4}({100*cnt/total:3.0f}%)")
        parts.append(f"{total:>6}")
        L.append(f"  {'  '.join(parts)}")

    # ── Linearization-corrected incremental updates ──
    L.append("\n─── INCREMENTAL UPDATES (LINEARIZATION-CORRECTED) ───")
    total_h = len(hidden)
    raw_inc = sum(1 for h in hidden.values() if h.get("has_incremental")=="True")
    ambiguous = sum(1 for h in hidden.values() 
                    if h.get("is_linearized")=="True" and int(h.get("version_count",0))==2)
    confirmed = raw_inc - ambiguous
    L.append(f"  Total PDFs scanned: {total_h}")
    L.append(f"  Raw incremental count (%%EOF>1): {raw_inc} ({100*raw_inc/total_h:.1f}%)")
    L.append(f"  Ambiguous (linearized + vc=2): {ambiguous}")
    L.append(f"  CONFIRMED incremental saves: {confirmed} ({100*confirmed/total_h:.1f}%)")
    L.append(f"  (Conservative: excludes linearized files with exactly 2 %%EOF markers)")

    # ── Chi-Square Tests ──
    L.append("\n─── CHI-SQUARE STATISTICAL TESTS ───")

    # Test 1: Tier 1 vs Tier 2 R2 exposure
    t1_r2 = tier_data["1"].get("R2",0) + tier_data["1"].get("R3",0)
    t1_not = sum(tier_data["1"].values()) - t1_r2
    t2_r2 = tier_data["2"].get("R2",0) + tier_data["2"].get("R3",0)
    t2_not = sum(tier_data["2"].values()) - t2_r2
    chi2, p = chi_square_2x2(t1_r2, t1_not, t2_r2, t2_not)
    L.append(f"\n  Test 1: Tier 1 vs Tier 2 — R2+ exposure")
    L.append(f"    Tier 1: {t1_r2}/{t1_r2+t1_not} ({100*t1_r2/(t1_r2+t1_not):.1f}%)")
    L.append(f"    Tier 2: {t2_r2}/{t2_r2+t2_not} ({100*t2_r2/(t2_r2+t2_not):.1f}%)")
    L.append(f"    χ² = {chi2:.2f}, p ≈ {p:.4f} {'***' if p<0.001 else '**' if p<0.01 else '*' if p<0.05 else 'ns'}")

    # Test 2: Tier 1 vs Tier 3
    t3_r2 = tier_data["3"].get("R2",0) + tier_data["3"].get("R3",0)
    t3_not = sum(tier_data["3"].values()) - t3_r2
    chi2, p = chi_square_2x2(t1_r2, t1_not, t3_r2, t3_not)
    L.append(f"\n  Test 2: Tier 1 vs Tier 3 — R2+ exposure")
    L.append(f"    Tier 1: {t1_r2}/{t1_r2+t1_not} ({100*t1_r2/(t1_r2+t1_not):.1f}%)")
    L.append(f"    Tier 3: {t3_r2}/{t3_r2+t3_not} ({100*t3_r2/(t3_r2+t3_not):.1f}%)")
    L.append(f"    χ² = {chi2:.2f}, p ≈ {p:.4f} {'***' if p<0.001 else '**' if p<0.01 else '*' if p<0.05 else 'ns'}")

    # Test 3: Pre-NIS2 vs NIS2-prep R2 exposure
    p1_r2 = period_data["2020-2023"].get("R2",0) + period_data["2020-2023"].get("R3",0)
    p1_not = sum(period_data["2020-2023"].values()) - p1_r2
    p2_r2 = period_data["2024-2025"].get("R2",0) + period_data["2024-2025"].get("R3",0)
    p2_not = sum(period_data["2024-2025"].values()) - p2_r2
    chi2, p = chi_square_2x2(p1_r2, p1_not, p2_r2, p2_not)
    L.append(f"\n  Test 3: 2020-2023 vs 2024-2025 — R2+ exposure")
    L.append(f"    2020-2023: {p1_r2}/{p1_r2+p1_not} ({100*p1_r2/(p1_r2+p1_not):.1f}%)")
    L.append(f"    2024-2025: {p2_r2}/{p2_r2+p2_not} ({100*p2_r2/(p2_r2+p2_not):.1f}%)")
    L.append(f"    χ² = {chi2:.2f}, p ≈ {p:.4f} {'***' if p<0.001 else '**' if p<0.01 else '*' if p<0.05 else 'ns'}")

    # ── Software distribution ──
    L.append("\n─── SOFTWARE DISTRIBUTION ───")
    sw_counter = Counter()
    with open(DATA_DIR/"metadata_fields.csv","r",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("field_name") == "Producer":
                val = row.get("field_value","").strip()
                if not val: continue
                vl = val.lower()
                if "microsoft" in vl: sw_counter["Microsoft Office"] += 1
                elif "adobe" in vl or "acrobat" in vl: sw_counter["Adobe"] += 1
                elif "libreoffice" in vl: sw_counter["LibreOffice"] += 1
                elif "latex" in vl or "tex" in vl: sw_counter["LaTeX"] += 1
                elif "foxit" in vl: sw_counter["Foxit"] += 1
                elif "chromium" in vl or "chrome" in vl: sw_counter["Chromium"] += 1
                else: sw_counter["Other"] += 1

    total_sw = sum(sw_counter.values())
    for sw, cnt in sw_counter.most_common():
        L.append(f"  {sw:25s}: {cnt:>5} ({100*cnt/total_sw:.1f}%)")

    # ── Save report ──
    report = "\n".join(L)
    with open(REPORT_DIR/"final_report.txt","w",encoding="utf-8") as f:
        f.write(report)

    # ── Save visualization data as JSON ──
    viz_data = {
        "tier_comparison": {t: dict(tier_data[t]) for t in ["1","2","3"]},
        "temporal_comparison": {p: dict(period_data[p]) for p in ["2020-2023","2024-2025","post-2026"]},
        "software_distribution": dict(sw_counter),
        "author_value_types": dict(author_types),
        "doc_risk_distribution": dict(doc_counter),
        "incremental_updates": {
            "total": total_h, "raw": raw_inc,
            "ambiguous_linearized": ambiguous, "confirmed": confirmed
        }
    }
    with open(REPORT_DIR/"viz_data.json","w") as f:
        json.dump(viz_data, f, indent=2)

    # ── Export R3 Findings ──
    with open(REPORT_DIR/"r3_findings.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["sha256", "field_name", "field_value"])
        writer.writeheader()
        writer.writerows(r3_findings)

    print(f"\n✅ Final report: {REPORT_DIR/'final_report.txt'}")
    print(f"✅ Viz data: {REPORT_DIR/'viz_data.json'}")
    print(f"✅ R3 Findings: {REPORT_DIR/'r3_findings.csv'}")
    print("\n" + report)

if __name__ == "__main__":
    main()
