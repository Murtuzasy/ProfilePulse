"""
Risk Ledger & Integrity Trust Score
------------------------------------
Proof-of-Concept fraud triage tool for C2C / IT staffing pipelines.

Every pillar ATTEMPTS a real, live check first. If — and only if — the
live check fails (network drop, bot-block, timeout, unparsable response),
the app falls back to a clearly labeled SIMULATED state built from a
static reference dataset. Nothing simulated is ever displayed as if it
were live. This distinction is shown in the UI on every metric.
"""

import io
import re
import socket
import datetime
from dataclasses import dataclass, field

import requests
import streamlit as st
from bs4 import BeautifulSoup
import pdfplumber
from pypdf import PdfReader

# --------------------------------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="Integrity Trust Score | C2C Fraud Shield",
    page_icon="🛡️",
    layout="wide",
)

USCIS_ENDPOINT = "https://egov.uscis.gov/cs/services/case-status"
REQUEST_TIMEOUT = 8  # seconds

# --------------------------------------------------------------------------
# STATIC REFERENCE DATA (used only as an offline fallback / heuristic base,
# never presented as a live database record)
# --------------------------------------------------------------------------

# Well-documented mass registered-agent / mail-drop addresses. Presence of
# one of these strings in a petitioner/employer block is a real, publicly
# known signal of a shell-heavy jurisdiction -- not a guarantee of fraud,
# but a legitimate heuristic input.
KNOWN_SHELL_HUB_ADDRESSES = [
    "1209 orange street",           # Wilmington, DE — CT Corp / Corporation Trust Center
    "1013 centre road",             # Wilmington, DE — Corporation Service Company
    "251 little falls drive",       # Wilmington, DE — Corporation Trust Company
    "8 the green",                  # Dover, DE — common registered-agent mill
    "16192 coastal highway",        # Lewes, DE — Harvard Business Services registered agent hub
    "2711 centerville road",        # Wilmington, DE
    "1201 north market street",     # Wilmington, DE
]

GENERIC_VENDOR_TOKENS = [
    "solutions", "technologies", "technology", "consulting", "consultancy",
    "global", "systems", "info tech", "infotech", "it services",
    "software solutions", "enterprise", "ventures", "group llc",
]

HIGH_RISK_SUFFIX_ONLY_PATTERN = re.compile(
    r"^\s*[a-z]{1,3}\s+(inc|llc|corp)\.?\s*$", re.IGNORECASE
)

# Simulated USCIS response bank — used ONLY if the live POST request to
# USCIS fails or is blocked. Structurally mirrors real case-status text so
# the UI can be exercised end-to-end, but is always tagged SIMULATED.
SIMULATED_USCIS_RESPONSES = {
    "default": {
        "status_header": "Case Status Unavailable — Manual Verification Required",
        "status_description": (
            "The live USCIS case status service did not return a parsable "
            "response (this is common when automated requests are made from "
            "a cloud data-center IP, which USCIS's bot-mitigation layer "
            "frequently blocks). This is SIMULATED placeholder text, not a "
            "real case result. Verify this receipt number manually at "
            "https://egov.uscis.gov/casestatus/landing.do"
        ),
    }
}


# --------------------------------------------------------------------------
# DATA MODEL
# --------------------------------------------------------------------------
@dataclass
class PillarResult:
    name: str
    is_live: bool
    risk_score: int  # 0 (no risk) - 100 (critical risk)
    headline: str
    details: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


# --------------------------------------------------------------------------
# PILLAR 1 — PDF TEXT EXTRACTION + RECEIPT NUMBER ISOLATION
# --------------------------------------------------------------------------
def extract_pdf_text(file_bytes: bytes) -> str:
    """Extracts all text from the uploaded PDF using pdfplumber."""
    text_chunks = []
    try:
        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text() or ""
                text_chunks.append(page_text)
    except Exception as e:
        st.warning(f"pdfplumber text extraction failed ({e}); attempting pypdf fallback.")
        try:
            reader = PdfReader(io.BytesIO(file_bytes))
            for page in reader.pages:
                text_chunks.append(page.extract_text() or "")
        except Exception as e2:
            st.error(f"Both PDF text extraction engines failed: {e2}")
    return "\n".join(text_chunks)


def extract_receipt_number(text: str) -> str | None:
    """
    Isolates a 13-character USCIS receipt number.
    Format: 3 letters (service center prefix) + 10 digits.
    Valid prefixes: LIN, SRC, EAC, WAC, IOE, NBC, MSC, YSC, TSC, VSC, WOO, IOE
    """
    pattern = re.compile(
        r"\b(LIN|SRC|EAC|WAC|IOE|NBC|MSC|YSC|TSC|VSC|WOO)\d{10}\b",
        re.IGNORECASE,
    )
    match = pattern.search(text.replace(" ", ""))
    if match:
        return match.group(0).upper()

    # Secondary pass: numbers may have stray spaces inserted by PDF text layers
    compact = re.sub(r"\s+", "", text)
    match = pattern.search(compact)
    if match:
        return match.group(0).upper()

    return None


# --------------------------------------------------------------------------
# PILLAR 1 — LIVE USCIS CASE STATUS SCRAPE
# --------------------------------------------------------------------------
def check_uscis_status(receipt_number: str) -> PillarResult:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        "Origin": "https://egov.uscis.gov",
        "Referer": "https://egov.uscis.gov/casestatus/landing.do",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    payload = {"appReceiptNum": receipt_number}

    try:
        response = requests.post(
            USCIS_ENDPOINT,
            data=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        container = soup.find("div", class_="rows text-center")

        if container is None:
            # Try a slightly looser match in case class ordering differs
            container = soup.find("div", class_=lambda c: c and "text-center" in c and "rows" in c)

        if container is None:
            raise ValueError("Expected DOM container ('div.rows.text-center') not found in response.")

        header_tag = container.find("h1")
        desc_tag = container.find("p")

        if header_tag is None or desc_tag is None:
            raise ValueError("Status <h1>/<p> elements not present — page structure may have changed or request was blocked.")

        status_header = header_tag.get_text(strip=True)
        status_description = desc_tag.get_text(strip=True)

        risk_score = 10
        warnings = []
        lowered = status_header.lower()
        if "denied" in lowered or "rejected" in lowered or "revoked" in lowered:
            risk_score = 95
            warnings.append("USCIS status indicates a negative case outcome.")
        elif "request for evidence" in lowered or "rfe" in lowered:
            risk_score = 55
            warnings.append("Case is under additional evidentiary review.")
        elif "approved" in lowered or "issued" in lowered or "received" in lowered:
            risk_score = 10

        return PillarResult(
            name="USCIS Live Case Status",
            is_live=True,
            risk_score=risk_score,
            headline=status_header,
            details={
                "receipt_number": receipt_number,
                "status_header": status_header,
                "status_description": status_description,
                "http_status_code": response.status_code,
                "source": USCIS_ENDPOINT,
            },
            warnings=warnings,
        )

    except (requests.exceptions.RequestException, ValueError, Exception) as e:
        sim = SIMULATED_USCIS_RESPONSES["default"]
        return PillarResult(
            name="USCIS Live Case Status",
            is_live=False,
            risk_score=0,  # cannot score risk on a failed live call — do not fabricate a risk level
            headline=sim["status_header"],
            details={
                "receipt_number": receipt_number,
                "status_header": sim["status_header"],
                "status_description": sim["status_description"],
                "error": str(e),
                "source": USCIS_ENDPOINT,
            },
            warnings=[
                "LIVE USCIS CHECK FAILED — this pillar could not be verified automatically. "
                "Manually confirm the case status before making a decision."
            ],
        )


# --------------------------------------------------------------------------
# PILLAR 2 — PDF METADATA / CRYPTOGRAPHIC FORENSICS
# --------------------------------------------------------------------------
EDITING_SOFTWARE_SIGNATURES = [
    "canva", "photoshop", "illustrator", "gimp", "quartz pdfcontext",
    "macos quartz", "microsoft word", "pdf-xchange editor", "foxit phantompdf",
    "smallpdf", "sejda", "pdfescape", "inkscape",
]


def extract_pdf_metadata(file_bytes: bytes) -> dict:
    reader = PdfReader(io.BytesIO(file_bytes))
    meta = reader.metadata or {}

    def clean(v):
        return str(v) if v is not None else "Not Present"

    return {
        "producer": clean(meta.get("/Producer")),
        "creator": clean(meta.get("/Creator")),
        "creation_date_raw": clean(meta.get("/CreationDate")),
        "mod_date_raw": clean(meta.get("/ModDate")),
        "author": clean(meta.get("/Author")),
        "title": clean(meta.get("/Title")),
        "num_pages": len(reader.pages),
    }


def parse_pdf_date(raw: str) -> datetime.datetime | None:
    """Parses PDF date strings of the form D:YYYYMMDDHHmmSS(+/-HH'mm')."""
    if not raw or raw == "Not Present":
        return None
    cleaned = raw.replace("D:", "").strip()
    cleaned = re.sub(r"[Zz]$", "", cleaned)
    cleaned = re.split(r"[+-]\d{2}'?\d{2}'?$", cleaned)[0]

    length_to_format = {14: "%Y%m%d%H%M%S", 12: "%Y%m%d%H%M", 8: "%Y%m%d"}
    for length, fmt in length_to_format.items():
        candidate = cleaned[:length]
        if len(candidate) < length:
            continue
        try:
            return datetime.datetime.strptime(candidate, fmt)
        except ValueError:
            continue
    return None


def evaluate_metadata_risk(meta: dict) -> PillarResult:
    warnings = []
    risk_score = 5  # baseline low risk for a clean, unremarkable PDF

    producer = meta["producer"].lower()
    creator = meta["creator"].lower()

    matched_signatures = [
        sig for sig in EDITING_SOFTWARE_SIGNATURES
        if sig in producer or sig in creator
    ]
    if matched_signatures:
        risk_score = 90
        warnings.append(
            f"Editing/design software fingerprint detected in metadata: "
            f"{', '.join(matched_signatures)}. Official USCIS-issued PDFs are "
            f"normally generated by government document systems, not consumer "
            f"design or editing tools."
        )

    creation_dt = parse_pdf_date(meta["creation_date_raw"])
    mod_dt = parse_pdf_date(meta["mod_date_raw"])

    if creation_dt and mod_dt:
        delta = abs((mod_dt - creation_dt).total_seconds())
        if delta > 60:  # more than a minute apart suggests post-creation editing
            risk_score = max(risk_score, 80)
            warnings.append(
                f"CreationDate ({creation_dt}) and ModDate ({mod_dt}) do not match "
                f"(difference: {delta:,.0f} seconds). This is consistent with the "
                f"document being re-saved or altered after initial generation."
            )
    elif meta["mod_date_raw"] == "Not Present" and meta["creation_date_raw"] == "Not Present":
        risk_score = max(risk_score, 40)
        warnings.append("No timestamp metadata present at all — unusual for an authentic government-issued PDF.")

    if risk_score >= 80:
        headline = "CRITICAL RISK / POSSIBLE FORGED DOCUMENT"
    elif risk_score >= 40:
        headline = "ELEVATED RISK — Anomalies Detected"
    else:
        headline = "No Structural Anomalies Detected"

    return PillarResult(
        name="PDF Metadata Forensics",
        is_live=True,  # this is a real, local read of the actual uploaded file — always "live"
        risk_score=risk_score,
        headline=headline,
        details=meta,
        warnings=warnings,
    )


# --------------------------------------------------------------------------
# PILLAR 3 — C2C VENDOR / EMPLOYER HEURISTIC AUDIT
# --------------------------------------------------------------------------
def check_domain_liveness(vendor_name: str) -> dict:
    """
    Attempts a REAL live check of whether a plausible domain for this vendor
    name resolves and responds. This is a best-effort heuristic (we are
    guessing the domain from the name), not an authoritative registry match.
    """
    slug = re.sub(r"[^a-z0-9]", "", vendor_name.lower())
    slug = re.sub(r"(llc|inc|corp|corporation|ltd|technologies|tech|solutions)$", "", slug)
    if not slug:
        return {"attempted": False, "reason": "Vendor name produced an empty domain slug."}

    candidate_domain = f"{slug}.com"
    try:
        socket.setdefaulttimeout(5)
        socket.gethostbyname(candidate_domain)
        resolves = True
    except socket.error:
        resolves = False

    http_reachable = False
    status_code = None
    if resolves:
        try:
            r = requests.get(f"https://{candidate_domain}", timeout=REQUEST_TIMEOUT, headers={
                "User-Agent": "Mozilla/5.0 (compatible; FraudShieldPoC/1.0)"
            })
            http_reachable = True
            status_code = r.status_code
        except requests.exceptions.RequestException:
            http_reachable = False

    return {
        "attempted": True,
        "candidate_domain": candidate_domain,
        "dns_resolves": resolves,
        "http_reachable": http_reachable,
        "http_status_code": status_code,
    }


def evaluate_vendor_heuristics(vendor_name: str, petitioner_text_block: str) -> PillarResult:
    warnings = []
    risk_score = 20  # baseline: unknown vendor, moderate default caution
    vendor_lower = vendor_name.lower().strip()

    if HIGH_RISK_SUFFIX_ONLY_PATTERN.match(vendor_name):
        risk_score += 25
        warnings.append("Vendor name is an unusually short, generic string plus a bare corporate suffix (e.g. 'XY Inc') — a common shell-naming pattern.")

    generic_hits = [tok for tok in GENERIC_VENDOR_TOKENS if tok in vendor_lower]
    if len(generic_hits) >= 2:
        risk_score += 15
        warnings.append(f"Vendor name stacks multiple generic staffing buzzwords ({', '.join(generic_hits)}), common in low-substance C2C shells.")

    shell_hub_hits = [addr for addr in KNOWN_SHELL_HUB_ADDRESSES if addr in petitioner_text_block.lower()]
    if shell_hub_hits:
        risk_score += 35
        warnings.append(
            f"Document text references a known mass registered-agent / mail-drop address "
            f"({shell_hub_hits[0].title()}), commonly used by high-volume shell entity registrations."
        )

    domain_check = check_domain_liveness(vendor_name)
    is_live_component = domain_check.get("attempted", False)
    if domain_check.get("attempted") and not domain_check.get("dns_resolves"):
        risk_score += 20
        warnings.append(
            f"No DNS record found for the most plausible corporate domain "
            f"({domain_check.get('candidate_domain')}). Legitimate staffing vendors "
            f"almost always have a resolvable web presence."
        )
    elif domain_check.get("attempted") and domain_check.get("dns_resolves") and not domain_check.get("http_reachable"):
        risk_score += 10
        warnings.append(
            f"Domain {domain_check.get('candidate_domain')} resolves in DNS but did not "
            f"respond to an HTTPS request — could indicate a parked or defunct domain."
        )

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        headline = "HIGH RISK VENDOR PROFILE"
    elif risk_score >= 40:
        headline = "MODERATE RISK — Recommend Manual Verification"
    else:
        headline = "LOW RISK — No Strong Shell Indicators"

    return PillarResult(
        name="C2C Vendor Heuristic Audit",
        is_live=is_live_component,
        risk_score=risk_score,
        headline=headline,
        details={
            "vendor_name": vendor_name,
            "generic_token_hits": generic_hits,
            "shell_hub_address_hits": shell_hub_hits,
            "domain_check": domain_check,
        },
        warnings=warnings,
    )


# --------------------------------------------------------------------------
# TRUST SCORE AGGREGATION
# --------------------------------------------------------------------------
def compute_trust_score(pillars: list[PillarResult]) -> int:
    """
    Weighted aggregate: metadata forensics and USCIS status carry more
    weight than the vendor heuristic layer, since the former are direct
    document/government checks and the latter is inferential.
    """
    weights = {
        "USCIS Live Case Status": 0.35,
        "PDF Metadata Forensics": 0.40,
        "C2C Vendor Heuristic Audit": 0.25,
    }
    total_risk = 0.0
    for p in pillars:
        w = weights.get(p.name, 1 / len(pillars))
        total_risk += p.risk_score * w
    trust_score = max(0, 100 - round(total_risk))
    return trust_score


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------
st.title("🛡️ Risk Ledger & Integrity Trust Score")
st.caption(
    "C2C candidate-proxy fraud triage — Proof of Concept. "
    "Live checks are attempted first; any pillar that could not be verified live is clearly labeled **SIMULATED / MANUAL VERIFICATION REQUIRED** — it is never shown as a confirmed live result."
)

st.info(
    "⚠️ **This tool does not make a hiring or legal determination.** It surfaces "
    "document, USCIS-status, and vendor-naming signals for a human recruiter to "
    "investigate further. Clean metadata does not prove authenticity, and a "
    "USCIS block does not indicate fraud.",
    icon="⚠️",
)

col_upload, col_vendor = st.columns([1.3, 1])

with col_upload:
    uploaded_file = st.file_uploader(
        "Upload Candidate I-797 / EAD PDF",
        type=["pdf"],
        help="The recruiter uploads the document received from the candidate.",
    )

with col_vendor:
    vendor_name = st.text_input(
        "C2C Vendor / Employer Name",
        placeholder="e.g. Alpine Tech Solutions LLC",
        help="The staffing vendor name provided alongside the candidate submission.",
    )

run_analysis = st.button("🔍 Run Forensic Analysis", type="primary", use_container_width=True)

if run_analysis:
    if uploaded_file is None:
        st.error("Please upload a PDF document before running the analysis.")
    elif not vendor_name.strip():
        st.error("Please enter the C2C Vendor / Employer name before running the analysis.")
    else:
        file_bytes = uploaded_file.read()

        with st.spinner("Extracting document text..."):
            doc_text = extract_pdf_text(file_bytes)

        if not doc_text.strip():
            st.error(
                "No extractable text was found in this PDF. It may be a scanned "
                "image without an OCR text layer. Metadata forensics will still run."
            )

        with st.spinner("Isolating USCIS receipt number..."):
            receipt_number = extract_receipt_number(doc_text)

        with st.spinner("Reading PDF structural metadata..."):
            try:
                raw_meta = extract_pdf_metadata(file_bytes)
                pillar_meta = evaluate_metadata_risk(raw_meta)
            except Exception as e:
                st.error(f"Metadata extraction failed: {e}")
                pillar_meta = PillarResult(
                    name="PDF Metadata Forensics",
                    is_live=False,
                    risk_score=50,
                    headline="Metadata Read Failed",
                    warnings=[f"Could not parse PDF structure: {e}"],
                )

        if receipt_number:
            with st.spinner(f"Submitting live case-status request to USCIS for {receipt_number}..."):
                pillar_uscis = check_uscis_status(receipt_number)
        else:
            pillar_uscis = PillarResult(
                name="USCIS Live Case Status",
                is_live=False,
                risk_score=0,
                headline="No Receipt Number Found",
                warnings=[
                    "Could not isolate a 13-character USCIS receipt number "
                    "(LIN/SRC/EAC/WAC/IOE/NBC/MSC/YSC/TSC/VSC/WOO + 10 digits) "
                    "from the extracted document text."
                ],
            )

        with st.spinner("Auditing vendor entity signals..."):
            pillar_vendor = evaluate_vendor_heuristics(vendor_name, doc_text)

        all_pillars = [pillar_uscis, pillar_meta, pillar_vendor]
        trust_score = compute_trust_score(all_pillars)

        st.divider()
        st.subheader("Integrity Trust Score")

        score_col, badge_col = st.columns([1, 2])
        with score_col:
            if trust_score >= 75:
                st.metric("Overall Trust Score", f"{trust_score} / 100", delta="Low Risk", delta_color="normal")
            elif trust_score >= 45:
                st.metric("Overall Trust Score", f"{trust_score} / 100", delta="Elevated Risk", delta_color="off")
            else:
                st.metric("Overall Trust Score", f"{trust_score} / 100", delta="Critical Risk", delta_color="inverse")

        with badge_col:
            live_count = sum(1 for p in all_pillars if p.is_live)
            st.write(f"**{live_count} / {len(all_pillars)} pillars returned LIVE data.** Pillars that could not be verified live are flagged below and excluded from being treated as confirmed.")

        st.divider()
        st.subheader("Risk Ledger — Pillar Breakdown")

        c1, c2, c3 = st.columns(3)

        for col, pillar in zip([c1, c2, c3], all_pillars):
            with col:
                live_tag = "🟢 LIVE" if pillar.is_live else "🟡 SIMULATED / MANUAL VERIFY"
                st.markdown(f"**{pillar.name}**")
                st.caption(live_tag)

                if pillar.risk_score >= 70:
                    st.error(pillar.headline)
                elif pillar.risk_score >= 40:
                    st.warning(pillar.headline)
                else:
                    st.success(pillar.headline)

                st.metric("Pillar Risk Score", f"{pillar.risk_score} / 100")

                if pillar.warnings:
                    for w in pillar.warnings:
                        st.write(f"⚠️ {w}")

                with st.expander("Raw details"):
                    st.json(pillar.details)

        st.divider()
        st.subheader("Extracted Document Preview")
        with st.expander("View extracted PDF text"):
            st.text(doc_text[:5000] if doc_text else "No text extracted.")

        st.caption(
            f"Analysis run at {datetime.datetime.utcnow().isoformat()}Z | "
            f"Receipt number used: {receipt_number or 'N/A'} | "
            f"Vendor evaluated: {vendor_name}"
        )
else:
    st.write("Upload a document and enter the vendor name, then click **Run Forensic Analysis**.")
