"""Engagement runners and PDF report generation for the SpyTV C2.

Two engagements are supported:

* **AuditEngagement** — scan → dry-run checks → exploit send → connection
  teardown → client details → Red Team audit report (PDF).
* **PatchEngagement** — patch every device → client details → remediation
  report (PDF) proving what was patched and why anything was not.

Both reports are branded **Authenticated, Inc.** and follow industry
pentest-report structure (cover, contents, executive summary, scope &
methodology, inventory, findings, risk, remediation/attestation,
recommendations, appendices, sign-off).
"""
import datetime
import hashlib
import inspect
import io
import json
import os
import threading
import uuid
import xml.sax.saxutils as xesc

from c2_ops import utc_now_iso

# ---------------------------------------------------------------------------
# constants / client details
# ---------------------------------------------------------------------------

COMPANY = "Authenticated, Inc."
CLIENT_FIELDS = ("company", "name", "address", "phone", "email", "website")
ARCHIVE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "c2_data", "audits")

# Authorization form (Rules of Engagement) document parameters
AUTH_VERSION = "1.0"
AUTH_VALID_DAYS = 30

_SEV_COLORS = {
    "CRITICAL": "#B91C1C",
    "HIGH": "#C2410C",
    "MEDIUM": "#A16207",
    "LOW": "#15803D",
}
_STATUS_COLORS = {
    "patched": "#15803D",
    "partial": "#A16207",
    "failed": "#B91C1C",
    "error": "#B91C1C",
    "not-applicable": "#6B7280",
    "success": "#15803D",
}


def new_report_id(prefix="RPT"):
    stamp = datetime.datetime.now().strftime("%Y%m%d")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:6].upper()}"


def validate_client(data):
    """Validate the shared client-details form. Returns (client, errors).

    ``name`` is the authorized representative; ``company`` is their legal
    entity — both feed the authorization form and the final report.
    """
    data = data or {}
    client = {f: str(data.get(f, "") or "").strip() for f in CLIENT_FIELDS}
    errors = []
    if not client["company"]:
        errors.append("Client company name is required.")
    if not client["name"]:
        errors.append("Authorized representative name is required.")
    if not client["address"]:
        errors.append("Client address is required.")
    phone_digits = "".join(ch for ch in client["phone"] if ch.isdigit())
    if len(phone_digits) < 7:
        errors.append("A valid phone number is required.")
    if "@" not in client["email"] or "." not in client["email"].rsplit("@", 1)[-1]:
        errors.append("A valid email address is required.")
    if not client["website"]:
        errors.append("Client website is required.")
    return client, errors


# ---------------------------------------------------------------------------
# PDF primitives
# ---------------------------------------------------------------------------

def _pdf_libs():
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (HRFlowable, KeepTogether, PageBreak,
                                    Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)
    from reportlab.platypus.tableofcontents import TableOfContents
    return locals()


def _build_styles(L):
    colors = L["colors"]
    ParagraphStyle = L["ParagraphStyle"]
    TA_CENTER, TA_JUSTIFY = L["TA_CENTER"], L["TA_JUSTIFY"]

    brand = colors.HexColor("#111827")
    accent = colors.HexColor("#0F766E")
    muted = colors.HexColor("#6B7280")
    body_c = colors.HexColor("#1F2937")

    s = {
        "brand": ParagraphStyle("Brand", fontName="Helvetica-Bold", fontSize=22,
                                textColor=brand, alignment=TA_CENTER, spaceAfter=2),
        "brandsub": ParagraphStyle("BrandSub", fontName="Helvetica", fontSize=10,
                                   textColor=accent, alignment=TA_CENTER,
                                   spaceAfter=2, letterSpacing=2),
        "cover": ParagraphStyle("CoverTitle", fontName="Helvetica-Bold",
                                fontSize=24, textColor=brand, alignment=TA_CENTER,
                                spaceBefore=18, spaceAfter=6, leading=28),
        "coversub": ParagraphStyle("CoverSub", fontName="Helvetica", fontSize=12,
                                   textColor=accent, alignment=TA_CENTER,
                                   spaceAfter=4),
        "h1": ParagraphStyle("H1", fontName="Helvetica-Bold", fontSize=14,
                             textColor=brand, spaceBefore=14, spaceAfter=7,
                             leading=17),
        "h2": ParagraphStyle("H2", fontName="Helvetica-Bold", fontSize=11,
                             textColor=accent, spaceBefore=9, spaceAfter=5,
                             leading=14),
        "body": ParagraphStyle("Body", fontName="Helvetica", fontSize=9.5,
                               textColor=body_c, alignment=TA_JUSTIFY,
                               leading=13.5, spaceAfter=6),
        "bullet": ParagraphStyle("BulletItem", fontName="Helvetica", fontSize=9.5,
                                 textColor=body_c, leading=13, leftIndent=12,
                                 bulletIndent=2, spaceAfter=3),
        "small": ParagraphStyle("Small", fontName="Helvetica", fontSize=8,
                                textColor=muted, alignment=TA_CENTER, leading=11),
        "th": ParagraphStyle("TH", fontName="Helvetica-Bold", fontSize=8.5,
                             textColor=colors.white, leading=11),
        "cell": ParagraphStyle("Cell", fontName="Helvetica", fontSize=8.5,
                               textColor=body_c, leading=11),
        "cellb": ParagraphStyle("CellB", fontName="Helvetica-Bold", fontSize=8.5,
                                textColor=body_c, leading=11),
        "cellmuted": ParagraphStyle("CellMuted", fontName="Helvetica", fontSize=8,
                                    textColor=muted, leading=10),
        "toc1": ParagraphStyle("TOC1", fontName="Helvetica-Bold", fontSize=10.5,
                               textColor=brand, spaceBefore=7, leading=14),
        "toc2": ParagraphStyle("TOC2", fontName="Helvetica", fontSize=9.5,
                               textColor=body_c, leftIndent=16, leading=12),
        "sign": ParagraphStyle("Sign", fontName="Helvetica", fontSize=9.5,
                               textColor=body_c, leading=16),
        "sig": ParagraphStyle("Sig", fontName="Times-Italic", fontSize=15,
                              textColor=brand, spaceBefore=4, spaceAfter=3),
        "sigsmall": ParagraphStyle("SigSmall", fontName="Times-Italic",
                                   fontSize=12, textColor=body_c,
                                   spaceBefore=2, spaceAfter=2),
        "clause": ParagraphStyle("Clause", fontName="Helvetica", fontSize=9.5,
                                 textColor=body_c, alignment=TA_JUSTIFY,
                                 leading=13.5, spaceAfter=5, leftIndent=10),
        "tochead": ParagraphStyle("TOCHead", fontName="Helvetica-Bold",
                                  fontSize=16, textColor=brand,
                                  spaceBefore=4, spaceAfter=8, leading=20),
        "doctitle": ParagraphStyle("DocTitle", fontName="Helvetica-Bold",
                                   fontSize=16, textColor=brand,
                                   alignment=TA_CENTER, leading=20,
                                   spaceBefore=6, spaceAfter=2),
        "docsub": ParagraphStyle("DocSub", fontName="Helvetica", fontSize=10.5,
                                 textColor=accent, alignment=TA_CENTER,
                                 leading=14, spaceAfter=4),
    }
    return s


def _esc(text):
    return xesc.escape(str(text if text is not None else ""))


def _sev(text):
    key = str(text or "").upper()
    color = _SEV_COLORS.get(key)
    if not color:
        return _esc(key or "—")
    return f'<font color="{color}"><b>{_esc(key)}</b></font>'


def _status(text):
    key = str(text or "")
    color = _STATUS_COLORS.get(key, "#1F2937")
    label = key.upper().replace("-", " ") or "—"
    return f'<font color="{color}"><b>{_esc(label)}</b></font>'


def _table(L, rows, widths, header=True, zebra=True):
    """rows: list of lists (strings are wrapped in cell Paragraphs)."""
    Paragraph = L["Paragraph"]
    Table = L["Table"]
    TableStyle = L["TableStyle"]
    colors = L["colors"]
    mm = L["mm"]
    s = _styles()

    out = []
    for r_i, row in enumerate(rows):
        styled = []
        for cell in row:
            if isinstance(cell, str):
                style = s["th"] if (header and r_i == 0) else s["cell"]
                styled.append(Paragraph(cell, style))
            else:
                styled.append(cell)
        out.append(styled)
    table = Table(out, colWidths=[w * mm for w in widths],
                  repeatRows=1 if header else 0, hAlign="LEFT")
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")))
    if zebra:
        for i in range(1 if header else 0, len(out)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i),
                              colors.HexColor("#F3F4F6")))
    table.setStyle(TableStyle(style))
    return table


def _kv_table(L, pairs, label_width=42, value_width=132):
    """Key/value block used on covers and metadata sections."""
    Paragraph = L["Paragraph"]
    Table = L["Table"]
    TableStyle = L["TableStyle"]
    colors = L["colors"]
    mm = L["mm"]
    s = _styles()

    rows = [[Paragraph(f"<b>{_esc(k)}</b>", s["cell"]),
             Paragraph(_esc(v), s["cell"])] for k, v in pairs]
    table = Table(rows, colWidths=[label_width * mm, value_width * mm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


_styles_cache = None


def _styles():
    global _styles_cache
    if _styles_cache is None:
        L = _pdf_libs()
        _styles_cache = _build_styles(L)
    return _styles_cache


def _page_callbacks(title, report_id):
    """Header/footer/metadata callbacks for cover and later pages."""
    L = _pdf_libs()
    colors, A4, mm = L["colors"], L["A4"], L["mm"]
    brand = colors.HexColor("#111827")
    muted = colors.HexColor("#6B7280")

    def _meta(canvas, doc):
        canvas.setTitle(f"{title} — {report_id}")
        canvas.setAuthor(COMPANY)
        canvas.setSubject(f"{title} prepared by {COMPANY}")
        canvas.setCreator(COMPANY)

    def _footer(canvas, doc):
        w, h = A4
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D1D5DB"))
        canvas.setLineWidth(0.5)
        canvas.line(doc.leftMargin, 15 * mm, w - doc.rightMargin, 15 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(muted)
        canvas.drawString(doc.leftMargin, 11 * mm,
                          f"Confidential — prepared by {COMPANY} for the named client")
        canvas.drawRightString(w - doc.rightMargin, 11 * mm,
                               f"{report_id}  ·  Page {doc.page}")
        canvas.restoreState()

    def on_cover(canvas, doc):
        _meta(canvas, doc)
        _footer(canvas, doc)

    def on_later(canvas, doc):
        _meta(canvas, doc)
        w, h = A4
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(brand)
        canvas.drawString(doc.leftMargin, h - 14 * mm, COMPANY.upper())
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(muted)
        canvas.drawRightString(w - doc.rightMargin, h - 14 * mm, title)
        canvas.setStrokeColor(colors.HexColor("#D1D5DB"))
        canvas.line(doc.leftMargin, h - 16 * mm, w - doc.rightMargin, h - 16 * mm)
        canvas.restoreState()
        _footer(canvas, doc)

    return on_cover, on_later


def _cover_story(L, title, subtitle, client, report_id, engagement_type):
    Paragraph, Spacer, PageBreak, HRFlowable = (L["Paragraph"], L["Spacer"],
                                                L["PageBreak"], L["HRFlowable"])
    mm = L["mm"]
    s = _styles()

    story = [
        Spacer(1, 6 * mm),
        Paragraph(COMPANY, s["brand"]),
        Paragraph("OFFICE OF SECURITY ASSESSMENTS", s["brandsub"]),
        HRFlowable(width="100%", thickness=1.2, color=L["colors"].HexColor("#0F766E"),
                   spaceBefore=4, spaceAfter=4),
        Spacer(1, 16 * mm),
        Paragraph(title, s["cover"]),
        Paragraph(subtitle, s["coversub"]),
        Spacer(1, 12 * mm),
        _kv_table(L, [
            ("Client", client["name"]),
            ("Address", client["address"]),
            ("Phone", client["phone"]),
            ("Email", client["email"]),
            ("Website", client["website"]),
            ("Report ID", report_id),
            ("Engagement type", engagement_type),
            ("Date issued", datetime.date.today().isoformat()),
            ("Classification", "Confidential"),
            ("Prepared by", COMPANY),
        ]),
        Spacer(1, 10 * mm),
        Paragraph(
            f"This report was prepared by <b>{_esc(COMPANY)}</b> for the named "
            "client and documents the results of an authorized security "
            "assessment engagement. It contains confidential information and may "
            "not be reproduced or distributed without written permission.",
            s["small"]),
        PageBreak(),
    ]
    return story


def _contents_story(L, entries=None):
    """Table of contents page (populated during multiBuild)."""
    Paragraph, Spacer, PageBreak = L["Paragraph"], L["Spacer"], L["PageBreak"]
    TableOfContents = L["TableOfContents"]
    mm = L["mm"]
    s = _styles()
    toc = TableOfContents()
    toc.levelStyles = [s["toc1"], s["toc2"]]
    toc.dotsMinLevel = 0
    return [Paragraph("Contents", _styles()["tochead"]), Spacer(1, 2 * mm), toc,
            PageBreak()]


def _section(L, number, heading):
    Paragraph = L["Paragraph"]
    s = _styles()
    return Paragraph(f"{number}. {_esc(heading)}", s["h1"])


def _subsection(L, number, heading):
    Paragraph = L["Paragraph"]
    s = _styles()
    return Paragraph(f"{number} {_esc(heading)}", s["h2"])


def _para(L, text):
    return L["Paragraph"](text, _styles()["body"])


def _bullets(L, items):
    from reportlab.platypus import ListFlowable, ListItem
    s = _styles()
    return ListFlowable([ListItem(L["Paragraph"](t, s["body"]), leftIndent=14)
                         for t in items], bulletType="bullet", start="•",
                        leftIndent=10)


def _signoff(L):
    Paragraph, Spacer, Table, TableStyle = (L["Paragraph"], L["Spacer"],
                                            L["Table"], L["TableStyle"])
    mm, colors = L["mm"], L["colors"]
    s = _styles()
    rows = [
        [Paragraph("<b>Prepared by</b>", s["cell"]),
         Paragraph(_esc(COMPANY), s["cell"]),
         Paragraph("<b>Date</b>", s["cell"]),
         Paragraph(datetime.date.today().isoformat(), s["cell"])],
        [Paragraph("<b>Assessment lead</b>", s["cell"]),
         Paragraph("Ian — Authenticated, Inc.", s["cell"]),
         Paragraph("<b>Signature</b>", s["cell"]),
         Paragraph("________________________", s["cell"])],
    ]
    t = Table(rows, colWidths=[34 * mm, 56 * mm, 24 * mm, 60 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F3F4F6")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return [Spacer(1, 4 * mm), t]


def _render_pdf(story, title, report_id):
    """Render a flowable story to PDF bytes with headers/footers/TOC."""
    L = _pdf_libs()
    SimpleDocTemplate, A4, mm = L["SimpleDocTemplate"], L["A4"], L["mm"]

    class _Doc(SimpleDocTemplate):
        def afterFlowable(self, flowable):
            if isinstance(flowable, L["Paragraph"]):
                name = getattr(flowable.style, "name", "")
                text = flowable.getPlainText()
                if name == "H1":
                    self.notify("TOCEntry", (0, text, self.page))
                elif name == "H2":
                    self.notify("TOCEntry", (1, text, self.page))

    buf = io.BytesIO()
    doc = _Doc(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
               topMargin=22 * mm, bottomMargin=20 * mm)
    on_cover, on_later = _page_callbacks(title, report_id)
    doc.multiBuild(story, onFirstPage=on_cover, onLaterPages=on_later)
    return buf.getvalue()


def _appendix(L, cve_rows, metadata_pairs):
    Paragraph, Spacer, PageBreak = L["Paragraph"], L["Spacer"], L["PageBreak"]
    mm = L["mm"]
    s = _styles()
    story = [PageBreak(),
             _section(L, "Appendix A", "CVE References")]
    if cve_rows:
        rows = [["CVE", "Severity", "Component", "Fixed in", "NVD Advisory"]]
        for c in cve_rows:
            rows.append([
                f'<b>{_esc(c.get("id", ""))}</b>',
                _sev(c.get("severity")),
                _esc(c.get("component", "—")),
                _esc(c.get("fixed_in", "—")),
                f'<link href="https://nvd.nist.gov/vuln/detail/{_esc(c.get("id", ""))}" color="#0F766E">'
                f'nvd.nist.gov/vuln/detail/{_esc(c.get("id", ""))}</link>',
            ])
        story.append(_table(L, rows, [30, 20, 40, 34, 50]))
    else:
        story.append(_para(L, "No CVEs were matched during this engagement."))
    story += [
        Spacer(1, 4 * mm),
        _section(L, "Appendix B", "Report Metadata"),
        _kv_table(L, metadata_pairs),
        Spacer(1, 6 * mm),
        _para(L, f"End of report — {_esc(COMPANY)}."),
    ]
    return story


def _pdf_bytes(story, title, report_id):
    return _render_pdf(story, title, report_id)


# ---------------------------------------------------------------------------
# Authorization to Perform Security Assessment & Rules of Engagement
#
# Industry-standard security-testing authorization instrument: numbered
# clauses, parties, authorization statement, scope / out-of-scope, rules of
# engagement, confidentiality, disclaimer & liability, ESIGN/UETA
# electronic-signature clause, provider pre-signature block, client
# e-signature block, tamper-evident SHA-256 record hash and an execution
# audit trail. Saved locally under c2_data/audits/<auth_id>/.
# ---------------------------------------------------------------------------

PROVIDER_ASSESSOR = "Ian"
PROVIDER_ASSESSOR_TITLE = "Assessment Lead"
AUTH_TITLE = "ASSESSMENT AUTHORIZATION AND RULES OF ENGAGEMENT"


def _utc_stamp(dt=None):
    dt = dt or datetime.datetime.now(datetime.timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def authorization_record_hash(auth_id, client, signature=None, signed_at=None):
    """SHA-256 over the canonical execution record.

    Embedded in the PDF audit-trail table and the ``authorization.json``
    sidecar so either party can later prove the executed instrument was
    not altered (tamper evidence).
    """
    payload = json.dumps(
        {
            "auth_id": str(auth_id),
            "client": {k: str((client or {}).get(k, "")) for k in CLIENT_FIELDS},
            "signature_sha256": hashlib.sha256(signature or b"").hexdigest(),
            "signed_at": str(signed_at or ""),
            "document": f"SpyTV Assessment Authorization v{AUTH_VERSION}",
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _sig_block_client(L, client, signature_png, signed_at, signer_ip):
    """Right-hand client signature cell (signed or pending)."""
    Paragraph = L["Paragraph"]
    mm = L["mm"]
    s = _styles()
    rep = _esc(client.get("name", ""))
    org = _esc(client.get("company", ""))
    flows = [Paragraph("CLIENT — AUTHORIZED REPRESENTATIVE", s["cellb"])]

    drawn = None
    if signature_png:
        try:
            from reportlab.lib.utils import ImageReader
            from reportlab.platypus import Image as _RLImage
            reader = ImageReader(io.BytesIO(signature_png))
            iw, ih = reader.getSize()
            if iw and ih:
                width = 58 * mm
                height = width * (ih / float(iw))
                if height > 26 * mm:
                    scale = (26 * mm) / height
                    width *= scale
                    height = 26 * mm
                drawn = _RLImage(io.BytesIO(signature_png), width=width,
                                 height=height)
        except Exception:
            drawn = None
    if drawn is not None:
        flows.append(drawn)
    else:
        flows.append(Paragraph(
            f"/s/ {rep}" if signed_at else "/s/ ______________________",
            s["sig"]))

    flows += [
        Paragraph(f"Printed name: {rep or '—'}", s["cell"]),
        Paragraph("Title: Authorized Representative", s["cell"]),
        Paragraph(f"Company: {org or '—'}", s["cell"]),
        Paragraph(f"Date (UTC): {_esc(signed_at) if signed_at else '— pending —'}",
                  s["cell"]),
    ]
    if signed_at and signer_ip:
        flows.append(Paragraph(f"Signed from IP: {_esc(signer_ip)}", s["cellmuted"]))
    if signed_at:
        flows.append(Paragraph(
            '<font color="#15803D"><b>STATUS — SIGNED (ELECTRONIC)</b></font>',
            s["cell"]))
    else:
        flows.append(Paragraph(
            '<font color="#A16207"><b>STATUS — PENDING CLIENT E-SIGNATURE</b></font>',
            s["cell"]))
    return flows


def _sig_block_provider(L, issued_s):
    """Left-hand provider block — pre-signed by Authenticated, Inc."""
    Paragraph = L["Paragraph"]
    s = _styles()
    return [
        Paragraph("SERVICE PROVIDER", s["cellb"]),
        Paragraph(f"/s/ {PROVIDER_ASSESSOR}", s["sig"]),
        Paragraph(f"Name: {PROVIDER_ASSESSOR}", s["cell"]),
        Paragraph(f"Title: {PROVIDER_ASSESSOR_TITLE}", s["cell"]),
        Paragraph(f"Entity: {_esc(COMPANY)}", s["cell"]),
        Paragraph(f"Pre-signed (UTC): {issued_s}", s["cell"]),
        Paragraph(f'<font color="#15803D"><b>STATUS — PRE-SIGNED BY '
                  f"{_esc(COMPANY)}</b></font>", s["cell"]),
    ]


def build_authorization_pdf(client, auth_id, signature_png=None,
                            signer_ip=None, signed_at=None,
                            record_hash=None):
    """Render the Authorization to Perform a Security Assessment & Rules of
    Engagement document (returns PDF bytes).

    Without ``signature_png``/``signed_at`` the client block renders as
    *pending* (the unsigned form presented for e-signature). With them the
    executed instrument is rendered including the drawn signature and the
    execution audit trail.
    """
    L = _pdf_libs()
    Paragraph, Spacer, PageBreak = L["Paragraph"], L["Spacer"], L["PageBreak"]
    HRFlowable, Table, TableStyle = (L["HRFlowable"], L["Table"],
                                     L["TableStyle"])
    mm, colors = L["mm"], L["colors"]
    s = _styles()

    signed = bool(signature_png) or bool(signed_at)
    issued = datetime.datetime.now(datetime.timezone.utc)
    expires = issued + datetime.timedelta(days=AUTH_VALID_DAYS)
    issued_s = _utc_stamp(issued)
    expires_s = _utc_stamp(expires)
    if record_hash is None:
        record_hash = authorization_record_hash(auth_id, client,
                                                signature_png, signed_at)

    def _cl(num, text):
        return Paragraph(f"<b>{num}</b>&nbsp;&nbsp;{text}", s["clause"])

    client_rows = [
        ["Client detail", "As recorded"],
        ["Legal entity", _esc(client.get("company", ""))],
        ["Authorized representative", _esc(client.get("name", ""))],
        ["Address", _esc(client.get("address", ""))],
        ["Telephone", _esc(client.get("phone", ""))],
        ["Email", _esc(client.get("email", ""))],
        ["Website", _esc(client.get("website", ""))],
    ]

    story = [
        Spacer(1, 4 * mm),
        Paragraph(COMPANY, s["brand"]),
        Paragraph("OFFICE OF SECURITY ASSESSMENTS", s["brandsub"]),
        HRFlowable(width="100%", thickness=1.2,
                   color=colors.HexColor("#0F766E"), spaceBefore=4,
                   spaceAfter=6),
        Spacer(1, 4 * mm),
        Paragraph("AUTHORIZATION TO PERFORM A SECURITY ASSESSMENT",
                  s["doctitle"]),
        Paragraph("AND RULES OF ENGAGEMENT", s["docsub"]),
        _kv_table(L, [
            ("Document ID", auth_id),
            ("Version", AUTH_VERSION),
            ("Issued (UTC)", issued_s),
            ("Effective", "Upon execution by the Client representative"),
            ("Expires (UTC)", expires_s),
            ("Classification", "Confidential — Legally Binding"),
            ("Provider", COMPANY),
            ("Prepared by", f"{COMPANY} — Office of Security Assessments"),
        ]),
        Spacer(1, 4 * mm),
        _para(L,
              "This Authorization and Rules of Engagement (the “Instrument”) "
              "governs the security assessment to be performed by the Provider "
              "for the Client. It is executed electronically; both parties "
              "intend that it be legally binding. Testing will not commence "
              "until this Instrument has been pre-signed by the Provider and "
              "countersigned by the Client."),
        _section(L, "1", "Parties"),
        _cl("1.1", f"<b>Provider.</b> {_esc(COMPANY)}, through its Office of "
                   f"Security Assessments (the “Provider”), acting by "
                   f"{PROVIDER_ASSESSOR}, {PROVIDER_ASSESSOR_TITLE}. "
                   "Contact for this engagement is available through the "
                   "SpyTV C2 dashboard and the contact details on record."),
        _cl("1.2", "<b>Client.</b> The Client identified below, acting by its "
                   "authorized representative whose name and company appear in "
                   "the execution block:"),
        _table(L, client_rows, [50, 124]),
        Spacer(1, 3 * mm),
        _section(L, "2", "Authorization Statement"),
        _cl("2.1", "The Client hereby authorizes the Provider to conduct the "
                   "security assessment described in Section 3 against the "
                   "Client’s television and streaming (TV/OTT) devices on the "
                   "Client’s premises network, including active discovery, "
                   "vulnerability verification and controlled exploitation as "
                   "set out in this Instrument."),
        _cl("2.2", "The Client warrants that it owns, or has obtained written "
                   "permission from the owner of, every system within scope, "
                   "and that such permission is a material condition of this "
                   "Instrument. The Client confirms it has the legal authority "
                   "to grant this authorization."),
        _cl("2.3", "The Client acknowledges that the assessment includes active "
                   "testing that may generate security alerts, scan traffic and "
                   "transient device activity on the Client’s network, and "
                   "accepts such activity in writing by executing this "
                   "Instrument. The Provider shall not commence testing before "
                   "both signatures are in place."),
        _section(L, "3", "Scope of Work"),
        _cl("3.1", "<b>In-scope systems.</b> Television and streaming devices "
                   "reachable from the SpyTV C2 host on the Client’s local "
                   "network (the exact address range is determined by the "
                   "discovery scan at engagement start and recorded in the "
                   "engagement record)."),
        _cl("3.2", "<b>Phases.</b> The assessment is performed in the following "
                   "ordered phases:"),
        _bullets(L, [
            "<b>Phase 1 — Discovery:</b> scan the Client’s network for "
            "vulnerable TV devices and fingerprint their make, model and "
            "firmware.",
            "<b>Phase 2 — Dry-run verification:</b> evaluate applicable exploit "
            "modules against each device <i>without transmitting payloads</i> "
            "to confirm exploitability and severity.",
            "<b>Phase 3 — Controlled exploitation:</b> transmit exploit "
            "payloads to confirmed devices solely to demonstrate impact under "
            "supervised conditions.",
            "<b>Phase 4 — Teardown:</b> terminate all sessions and connections "
            "opened by the assessment and verify that no channels remain open.",
            "<b>Phase 5 — Reporting:</b> deliver a written report of findings, "
            "risk ratings and remediation guidance to the Client.",
        ]),
        _cl("3.3", "<b>Methods.</b> Network and port probing, service and "
                   "firmware fingerprinting, CVE database matching, controlled "
                   "exploit execution, session teardown and (at the Client’s "
                   "separate request) remediation/patch execution with "
                   "verification."),
        _section(L, "4", "Out of Scope"),
        _cl("4.1", "The following are expressly excluded from this Instrument:"),
        _bullets(L, [
            "Denial-of-service, stress, flood or availability-degrading "
            "testing of any kind.",
            "Social engineering, phishing, pretexting or physical intrusion.",
            "Testing of third-party, cloud or carrier-managed systems not "
            "owned by the Client and not on the Client’s local network.",
            "Destructive testing, data deletion or permanent modification of "
            "devices (remediation is applied only when separately requested "
            "by the Client).",
            "Any system the Client does not own or have written permission to "
            "test.",
            "Application, web or source-code testing not related to the "
            "television device environment.",
        ]),
        _section(L, "5", "Rules of Engagement"),
        _cl("5.1", "<b>Testing window.</b> Activity is limited to the five "
                   "phases in Section 3.2 and runs from execution of this "
                   "Instrument until the report is delivered or this "
                   "Instrument expires, whichever occurs first."),
        _cl("5.2", "<b>Emergency stop.</b> The Client may pause or terminate "
                   "the assessment at any time by contacting the Provider at "
                   "the telephone or email recorded in Section 1.2. The "
                   "Provider will immediately halt all activity and tear down "
                   "all sessions upon such a request."),
        _cl("5.3", "<b>Data handling.</b> Any media or telemetry captured from "
                   "in-scope devices during testing is stored only in the "
                   "local SpyTV C2 repository on the Client-designated host, "
                   "is made available to the Client, and is destroyed within "
                   "seven (7) days of a written request."),
        _cl("5.4", "<b>Artifacts and remediation.</b> Controlled exploitation "
                   "may install temporary test implants on in-scope devices "
                   "solely to demonstrate impact; these are removed through "
                   "the C2 Remove control or on the Client’s request. Patching "
                   "or configuration changes are performed only under the "
                   "Client’s separate Patch instruction and are documented in "
                   "a remediation report."),
        _cl("5.5", "<b>Disclosure.</b> Findings are disclosed to the Client "
                   "only. Publication or coordinated disclosure to third "
                   "parties requires the Client’s prior written consent, "
                   "except where disclosure is required by law."),
        _cl("5.6", "<b>Communication.</b> Day-to-day coordination occurs via "
                   "the SpyTV C2 dashboard. Any material change to scope or "
                   "method requires a written amendment to this Instrument."),
        _section(L, "6", "Confidentiality and Data Protection"),
        _cl("6.1", "Each party shall keep confidential all non-public "
                   "information disclosed in connection with this engagement, "
                   "using at least the degree of care it uses for its own "
                   "confidential information and no less than reasonable "
                   "care."),
        _cl("6.2", "This obligation survives termination for twenty-four (24) "
                   "months, or until the information enters the public domain "
                   "through no fault of the receiving party, or longer where "
                   "required by law. Independently developed information and "
                   "information lawfully received from a third party are "
                   "excluded."),
        _cl("6.3", "A party compelled by law to disclose confidential "
                   "information shall, where legally permitted, promptly "
                   "notify the other party and disclose only the minimum "
                   "portion legally required."),
        _section(L, "7", "Disclaimer and Limitation of Liability"),
        _cl("7.1", "Findings and deliverables are provided “as is” without "
                   "warranty of any kind, including completeness or accuracy "
                   "of vulnerability identification. Security testing is "
                   "inherently imperfect; a clean result does not guarantee "
                   "the absence of vulnerabilities."),
        _cl("7.2", "Testing may cause transient disruption, security alerts "
                   "or device reboots. To the maximum extent permitted by "
                   "law, the Provider is liable only for direct loss proven "
                   "to result from the Provider’s gross negligence, and is "
                   "not liable for indirect, consequential or incidental "
                   "loss, or for loss arising from the Client’s use of the "
                   "findings."),
        _cl("7.3", "The Client remains solely responsible for remediation "
                   "prioritization and for any business impact of its "
                   "remediation decisions."),
        _section(L, "8", "Electronic Signatures and Records"),
        _cl("8.1", "The parties agree to conduct this transaction electronically "
                   "and consent to the use of electronic signatures and "
                   "electronic records. Signatures executed under this "
                   "Instrument — including drawn signatures and “/s/” "
                   "signatures — are intended to be legally binding and have "
                   "the same force and effect as handwritten signatures, in "
                   "accordance with the federal ESIGN Act (15 U.S.C. §7001) "
                   "and the Uniform Electronic Transactions Act (UETA) as "
                   "enacted in the applicable jurisdiction."),
        _cl("8.2", "<b>Integrity.</b> Execution of this Instrument assigns the "
                   "Document ID shown above and a SHA-256 Record Hash computed "
                   "over the client details, signature and execution "
                   "timestamp. Either party may recompute that hash against "
                   "its retained copy; any alteration of the executed document "
                   "produces a different hash."),
        _cl("8.3", "<b>Audit trail.</b> The execution timestamp (UTC) and the "
                   "source IP address of the signing request are recorded "
                   "with the document and reproduced in the audit trail "
                   "below. The Provider retains the executed record locally "
                   "as evidence of the Client’s authorization."),
        _section(L, "9", "Term, Amendment and Termination"),
        _cl("9.1", "This Instrument is effective upon execution by the Client "
                   f"and, if not executed, expires on {expires_s}. Delivery of "
                   "the final assessment report closes the engagement."),
        _cl("9.2", "Either party may revoke this Instrument at any time by "
                   "written notice (email suffices). Upon revocation the "
                   "Provider immediately ceases testing and tears down all "
                   "sessions. Clauses 6, 7 and 8 survive revocation or "
                   "expiration."),
        _cl("9.3", "Amendments are valid only when recorded in writing and "
                   "accepted by both parties."),
        PageBreak(),
        _section(L, "10", "Execution"),
        _cl("10.1", "The parties execute this Instrument by electronic "
                    "signature below. The Provider block is pre-signed; the "
                    "Client block is executed by the authorized representative "
                    "through the SpyTV C2 dashboard signature pad."),
        Spacer(1, 3 * mm),
    ]

    sig_table = Table(
        [[_sig_block_provider(L, issued_s),
          _sig_block_client(L, client, signature_png, signed_at, signer_ip)]],
        colWidths=[85 * mm, 85 * mm], hAlign="LEFT")
    sig_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#9CA3AF")),
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#F3F4F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(sig_table)

    story += [
        Spacer(1, 6 * mm),
        _subsection(L, "10.2", "Execution audit trail"),
        _kv_table(L, [
            ("Document ID", auth_id),
            ("Document version", AUTH_VERSION),
            ("Provider pre-signature (UTC)", issued_s),
            ("Client signature (UTC)",
             _esc(signed_at) if signed_at else "Pending — not yet executed"),
            ("Signer source IP", _esc(signer_ip) if signer_ip else "n/a"),
            ("Signature status",
             "EXECUTED — BOTH PARTIES" if signed
             else "AWAITING CLIENT E-SIGNATURE"),
            ("Record SHA-256", record_hash),
        ]),
        Spacer(1, 6 * mm),
        _para(L, f"End of Instrument — {_esc(COMPANY)}. Retain a copy for your "
                 "records; the Record SHA-256 above verifies that this "
                 "document has not been altered."),
    ]

    return _render_pdf(story, AUTH_TITLE, auth_id)


# ---------------------------------------------------------------------------
# engagement state machines
# ---------------------------------------------------------------------------

class Engagement:
    """Base state machine shared by the audit and patch-all flows."""

    kind = "engagement"
    prefix = "RPT"
    title = "Report"
    subtitle = ""
    engagement_type = ""

    def __init__(self, **kw):
        self.report_id = new_report_id(self.prefix)
        self.phase = "created"
        self.progress = 0
        self.log = []
        self.phases = []
        self.results = {}
        self.client = None
        self.report_path = None
        self.error = None
        self.started_at = utc_now_iso()
        self.finished_at = None
        self._thread = None
        self._lock = threading.Lock()
        self.configure(**kw)

    # -- configuration hooks ------------------------------------------------
    def configure(self, **kw):
        pass

    # -- state --------------------------------------------------------------
    def say(self, msg):
        with self._lock:
            self.log.append({"at": utc_now_iso(), "msg": str(msg)})
            self.log = self.log[-500:]

    def set_phase(self, phase, progress):
        with self._lock:
            self.phase = phase
            self.progress = max(0, min(100, int(progress)))
            self.phases.append({"phase": phase, "at": utc_now_iso()})
        self.say(f"[{phase}] {progress}%")

    def set_progress(self, progress, log=False):
        """Move the bar WITHOUT recording a phase transition.

        Long steps used to jump5% → 25% only once the whole step finished, so
        a slow network discovery made the banner look frozen (or dead). Callers
        now push intermediate percentages through here while the work runs.
        Returns True when the value actually changed.
        """
        pct = max(0, min(100, int(progress)))
        with self._lock:
            changed = pct != self.progress
            if changed:
                self.progress = pct
        if changed and log:
            self.say(f"[{self.phase}] {pct}%")
        return changed

    def snapshot(self):
        with self._lock:
            return {
                "kind": self.kind,
                "report_id": self.report_id,
                "phase": self.phase,
                "progress": self.progress,
                "log": self.log[-100:],
                "phases": self.phases,
                "results": self.results,
                "client": self.client,
                "report_ready": bool(self.report_path),
                "report_url": f"/api/{self.kind}/report.pdf" if self.report_path else None,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "error": self.error,
            }

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        self._thread = threading.Thread(target=self._safe_run, daemon=True,
                                        name=f"{self.kind}-engagement")
        self._thread.start()

    def _safe_run(self):
        try:
            self.run()
        except Exception as e:  # noqa: BLE001 — keep the state machine alive
            self.error = str(e)
            self.set_phase("error", self.progress)
            self.say(f"Engagement failed: {e}")

    def run(self):
        raise NotImplementedError

    # -- reporting ----------------------------------------------------------
    def render(self, client):
        """Validate client details, build the PDF, archive both to disk."""
        self.client = client
        self.set_phase("rendering", 95)
        story = self.build_story(client)
        pdf = _pdf_bytes(story, self.title, self.report_id)

        out_dir = os.path.join(ARCHIVE_ROOT, self.report_id)
        os.makedirs(out_dir, exist_ok=True)
        pdf_path = os.path.join(out_dir, "report.pdf")
        with open(pdf_path, "wb") as f:
            f.write(pdf)
        with open(os.path.join(out_dir, "engagement.json"), "w",
                  encoding="utf-8") as f:
            json.dump(self.snapshot(), f, indent=2, default=str)

        self.report_path = pdf_path
        self.finished_at = utc_now_iso()
        self.set_phase("done", 100)
        self.say(f"Report {self.report_id} rendered: {len(pdf)} bytes")
        return pdf_path

    def build_story(self, client):
        raise NotImplementedError

    # -- shared story pieces ------------------------------------------------
    def _cover(self, L, client, title=None, subtitle=None):
        return _cover_story(L, title or self.title, subtitle or self.subtitle,
                            client, self.report_id, self.engagement_type)

    def _cve_universe(self):
        """All CVE dicts seen across the engagement (for appendix + risk)."""
        seen = {}
        for check in self.results.get("checks", []):
            for c in check.get("cves", []):
                if c.get("id"):
                    seen[c["id"]] = c
        for target in self.results.get("scan", {}).get("targets", []):
            for c in target.get("cves", []):
                if c.get("id"):
                    seen[c["id"]] = c
        return list(seen.values())

    @staticmethod
    def _max_severity(cves):
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        best = None
        for c in cves:
            sev = str(c.get("severity") or "").upper()
            if sev in order and (best is None or order.index(sev) > order.index(best)):
                best = sev
        return best


class AuditEngagement(Engagement):
    """Red Team audit: scan → check (no send) → send → teardown → report."""

    kind = "audit"
    prefix = "AUD"
    title = "RED TEAM VULNERABILITY AUDIT REPORT"
    subtitle = "Network television security assessment — findings and exploitation results"
    engagement_type = "Red Team Vulnerability Audit (network scan, dry-run verification, controlled exploitation, teardown)"

    def configure(self, cidr=None, scan_fn=None, check_fn=None, exploit_fn=None,
                  kill_fn=None, client=None):
        self.cidr = cidr
        self.scan_fn = scan_fn
        self.check_fn = check_fn
        self.exploit_fn = exploit_fn
        self.kill_fn = kill_fn
        self.client = client  # collected up-front with the signed authorization
        self.results = {"scan": {}, "checks": [], "exploits": [],
                        "connections": {}}

    # -- discovery progress -------------------------------------------------
    def _scan_progress(self, fraction):
        """Map the scan's 0.0 → 1.0 onto the scanning phase's5% → 25% slice."""
        frac = max(0.0, min(1.0, float(fraction)))
        pct = 5 + int(20 * frac)
        # Log on 5-point steps only, so the banner log stays readable; the bar
        # itself still advances on every update it receives.
        self.set_progress(pct, log=(pct % 5 == 0))

    def _run_scan(self):
        """Run the wired scan_fn, passing a progress callback when it takes one.

        Callables wired with the older ``lambda cidr: ...`` shape accept only
        one argument — detect that from the signature instead of catching
        TypeError, which would re-run a scan that actually failed inside for
        an unrelated reason.
        """
        cb = self._scan_progress
        try:
            params = list(inspect.signature(self.scan_fn).parameters.values())
        except (TypeError, ValueError):
            params = []
        accepts_progress = (
            any(p.kind == p.VAR_KEYWORD for p in params) or
            sum(1 for p in params
                if p.kind in (p.POSITIONAL_ONLY,
                              p.POSITIONAL_OR_KEYWORD)) >= 2
        )
        if accepts_progress:
            return self.scan_fn(self.cidr, cb) or []
        return self.scan_fn(self.cidr) or []

    def run(self):
        # Phase 1 — scan for vulnerable TVs
        self.set_phase("scanning", 5)
        self.say(f"Scanning {self.cidr or 'local network'} for vulnerable TVs...")
        findings = self._run_scan()
        targets = [f for f in findings
                   if f.get("vulnerable") and f.get("tv_type")]
        self.results["scan"] = {
            "cidr": self.cidr or "auto",
            "discovered": len(findings),
            "vulnerable": len(targets),
            "targets": targets,
        }
        self.say(f"Scan complete: {len(findings)} host(s), "
                 f"{len(targets)} vulnerable TV(s)")

        # Phase 2 — check every exploit WITHOUT sending it
        self.set_phase("checking", 25)
        for t in targets:
            try:
                check = self.check_fn(t["ip"])
            except Exception as e:  # noqa: BLE001
                check = {"ip": t["ip"], "reachable": False, "error": str(e)}
            self.results["checks"].append(check)
            verdict = "vulnerable" if check.get("vulnerable") else "not confirmed"
            self.say(f"Checked {t['ip']} ({t.get('name') or t.get('tv_type')}): "
                     f"{verdict} — no payloads sent")
        self.say(f"Exploit pre-checks complete for {len(self.results['checks'])} "
                 "target(s) (dry-run only)")

        # Phase 3 — send the exploits
        self.set_phase("exploiting", 55)
        for t in targets:
            entry = {
                "ip": t["ip"],
                "tv_type": t.get("tv_type"),
                "name": t.get("name") or t.get("device_type"),
                "cves": t.get("cve_ids") or [c.get("id") for c in t.get("cves", [])],
            }
            try:
                entry.update(self.exploit_fn(t.get("tv_type"), t["ip"]))
            except Exception as e:  # noqa: BLE001
                entry.update({"attempted": True, "success": False, "error": str(e)})
            self.results["exploits"].append(entry)
            outcome = "succeeded" if entry.get("success") else \
                f"failed ({entry.get('error') or 'not confirmed'})"
            self.say(f"Exploit {entry['ip']} ({entry.get('tv_type')}): {outcome}")

        # Phase 4 — kill every connection opened during the engagement
        self.set_phase("tearing_down", 85)
        ips = [t["ip"] for t in targets]
        conn = self.kill_fn(ips) or {}
        self.results["connections"] = conn
        self.say(f"Connection teardown: {conn.get('detail', 'complete')}")

        if self.client:
            # Client details were captured with the signed authorization —
            # render the report automatically now that the audit is complete.
            self.say("Audit complete — generating the report from the "
                     "authorized client details...")
            self.render(self.client)
        else:
            self.set_phase("awaiting_client", 100)
            self.say("Audit complete — client details required to render the report.")

    # -- report -------------------------------------------------------------
    def build_story(self, client):
        L = _pdf_libs()
        Spacer, PageBreak = L["Spacer"], L["PageBreak"]
        mm = L["mm"]
        s = _styles()

        scan = self.results.get("scan", {})
        checks = self.results.get("checks", [])
        exploits = self.results.get("exploits", [])
        conn = self.results.get("connections", {})
        targets = scan.get("targets", [])
        cves = self._cve_universe()
        succeeded = [e for e in exploits if e.get("success")]
        failed = [e for e in exploits if e.get("attempted") and not e.get("success")]
        max_sev = self._max_severity(cves)
        risk_label = {"CRITICAL": "Critical", "HIGH": "High",
                      "MEDIUM": "Moderate", "LOW": "Low"}.get(max_sev,
                                                               "Informational")

        story = self._cover(L, client)
        story += _contents_story(L)

        # 1 — Executive Summary
        story += [_section(L, "1", "Executive Summary"),
                  _para(L, (
                      f"{COMPANY} performed an authorized Red Team vulnerability "
                      f"audit of the client's television network environment. "
                      f"The engagement identified <b>{scan.get('vulnerable', 0)}</b> "
                      f"vulnerable smart TV device(s) out of <b>{scan.get('discovered', 0)}</b> "
                      f"host(s) discovered, matching <b>{len(cves)}</b> known CVE(s). "
                      f"All identified exploits were verified in dry-run mode before "
                      f"controlled execution: <b>{len(succeeded)}</b> succeeded and "
                      f"<b>{len(failed)}</b> failed or could not be confirmed. Every "
                      f"connection opened during the engagement was subsequently "
                      f"terminated and verified. The overall risk rating for this "
                      f"engagement is <b>{_esc(risk_label)}</b>.")),
                  _table(L, [
                      ["Metric", "Result"],
                      ["Hosts discovered", str(scan.get("discovered", 0))],
                      ["Vulnerable TV devices", str(scan.get("vulnerable", 0))],
                      ["Distinct CVEs matched", str(len(cves))],
                      ["Exploit pre-checks (dry-run)", str(len(checks))],
                      ["Exploits executed", str(len([e for e in exploits if e.get('attempted')]))],
                      ["Exploits successful", str(len(succeeded))],
                      ["Connections verified closed",
                       str("Yes" if conn.get("verified") else "No")],
                      ["Overall risk rating", _esc(risk_label)],
                  ], [74, 100]),
                  Spacer(1, 3 * mm)]

        # 2 — Scope & Methodology
        story += [_section(L, "2", "Scope & Methodology"),
                  _para(L, "The engagement executed the following phases in order. "
                           "Exploit verification was performed without transmitting "
                           "payloads; exploitation was only executed after every "
                           "pre-check passed."),
                  _bullets(L, [
                      "<b>Discovery</b> — TCP service probing across generic TV "
                      "ports and every CVE-family signature port, with device "
                      "family identification and CVE database matching.",
                      "<b>Dry-run verification</b> — each exploit module's "
                      "vulnerability check executed without sending an exploit "
                      "payload (version/banner confirmation only).",
                      "<b>Controlled exploitation</b> — exploit modules executed "
                      "against confirmed targets with per-attempt outcome capture.",
                      "<b>Teardown</b> — tracked sockets closed, spawned "
                      "operator tools terminated, and remaining connections to "
                      "engagement targets verified.",
                  ]),
                  Spacer(1, 2 * mm),
                  _table(L,
                         [["Phase", "Status", "Timestamp (UTC)"]] +
                         [[_esc(p["phase"]), "completed", _esc(p["at"])]
                          for p in self.phases],
                         [56, 34, 84]),
                  Spacer(1, 3 * mm)]

        # 3 — Target Inventory
        story += [_section(L, "3", "Target Inventory")]
        if targets:
            rows = [["#", "IP Address", "Device", "Family", "Open Ports", "CVEs", "Severity"]]
            for i, t in enumerate(targets, 1):
                sev = t.get("severity") or self._max_severity(t.get("cves", []))
                rows.append([
                    str(i), _esc(t.get("ip", "")),
                    _esc(t.get("name") or t.get("device_type") or "—"),
                    _esc(t.get("tv_type", "—")),
                    _esc(", ".join(str(p) for p in (t.get("open_ports") or [])) or "—"),
                    str(len(t.get("cves") or [])),
                    _sev(sev),
                ])
            story.append(_table(L, rows, [8, 26, 34, 30, 44, 14, 18]))
        else:
            story.append(_para(L, "No vulnerable television devices were discovered "
                                  "during the scan phase."))
        story.append(Spacer(1, 3 * mm))

        # 4 — Findings & exploitation results
        story += [_section(L, "4", "Findings & Exploitation Results")]
        if not targets:
            story.append(_para(L, "No findings to report — the network scan "
                                  "identified no devices matching known vulnerable "
                                  "television families."))
        by_ip_exploit = {e.get("ip"): e for e in exploits}
        for i, t in enumerate(targets, 1):
            ip = t.get("ip")
            check = next((c for c in checks if c.get("ip") == ip), {})
            exploit = by_ip_exploit.get(ip, {})
            block = [
                _subsection(L, f"4.{i}",
                            f"{ip} — {t.get('name') or t.get('device_type') or 'TV'} "
                            f"({t.get('tv_type', 'unknown family')})"),
            ]
            cve_list = t.get("cves") or []
            if cve_list:
                rows = [["CVE", "Severity", "CVSS", "Component", "Fixed in"]]
                for c in cve_list:
                    rows.append([
                        f'<b>{_esc(c.get("id", ""))}</b>', _sev(c.get("severity")),
                        _esc(c.get("score", "—")),
                        _esc(c.get("component", "—")),
                        _esc(c.get("fixed_in", "—")),
                    ])
                block.append(_table(L, rows, [32, 20, 16, 56, 50]))
                block.append(Spacer(1, 2 * mm))
            dry = check.get("dry_run") or {}
            if dry.get("available"):
                if dry.get("timeout") or dry.get("error"):
                    verdict = f"dry-run check inconclusive: {dry.get('error')}"
                elif dry.get("vulnerable"):
                    verdict = (f"dry-run check CONFIRMED the target vulnerable to "
                               f"{', '.join(dry.get('cves') or []) or 'matched CVEs'}"
                               + (f" (version {dry['version']})"
                                  if dry.get("version") and dry["version"] != "Unknown" else ""))
                else:
                    verdict = "dry-run check did not confirm exploitation conditions"
            else:
                verdict = dry.get("reason") or "no dry-run check available"
            block.append(_para(L, f"<b>Pre-check (no payload sent):</b> {_esc(verdict)}"))
            if exploit:
                ok = bool(exploit.get("success"))
                outcome = "SUCCEEDED" if ok else "FAILED / NOT CONFIRMED"
                detail = exploit.get("error") or ""
                extra = f" — {_esc(detail)}" if detail and not ok else ""
                dur = f" ({exploit.get('duration_s')}s)" if exploit.get("duration_s") is not None else ""
                color = "#15803D" if ok else "#B91C1C"
                block.append(_para(
                    L,
                    f'<b>Exploitation:</b> <font color="{color}"><b>{outcome}</b>'
                    f"</font>{_esc(dur)}{extra}"))
            else:
                block.append(_para(L, "<b>Exploitation:</b> not attempted"))
            story.extend(block)
            story.append(Spacer(1, 2 * mm))

        # 5 — Risk assessment
        story += [_section(L, "5", "Risk Assessment"),
                  _para(L, "Severity ratings follow CVSS v3.1 qualitative "
                           "ratings as published in the NVD advisories listed in "
                           "Appendix A.")]
        sev_counts = {}
        for c in cves:
            key = str(c.get("severity") or "UNKNOWN").upper()
            sev_counts[key] = sev_counts.get(key, 0) + 1
        rows = [["Severity", "Count", "Rating guide"]]
        guide = {"CRITICAL": "Immediate action — exploitable with full impact",
                 "HIGH": "Urgent action — significant impact likely",
                 "MEDIUM": "Schedule remediation — limited impact",
                 "LOW": "Track and remediate in normal cycle"}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            rows.append([_sev(sev), str(sev_counts.get(sev, 0)),
                         _esc(guide[sev])])
        story += [_table(L, rows, [30, 20, 124]), Spacer(1, 3 * mm)]

        # 6 — Teardown verification
        story += [_section(L, "6", "Connection Teardown Verification"),
                  _table(L, [
                      ["Check", "Result"],
                      ["Tracked sockets closed", str(conn.get("sockets_closed", 0))],
                      ["Operator tools terminated",
                       _esc(", ".join(conn.get("tools_terminated") or []) or "none")],
                      ["Established connections remaining",
                       str(conn.get("remaining_established", "—"))],
                      ["Verified (no remaining sessions)",
                       "Yes" if conn.get("verified") else "No"],
                      ["Verified at (UTC)", _esc(conn.get("verified_at", "—"))],
                      ["Detail", _esc(conn.get("detail", "—"))],
                  ], [74, 100]), Spacer(1, 3 * mm)]

        # 7 — Recommendations
        story += [_section(L, "7", "Recommendations"),
                  _bullets(L, [
                      "Apply vendor firmware updates to every device listed in "
                      "Section 3; fixed versions are given per CVE in Section 4 "
                      "and Appendix A.",
                      "Use the C2 Patch controls to execute the device family's "
                      "remediation commands and re-run this audit to confirm "
                      "remediation.",
                      "Segment television devices onto a dedicated VLAN with "
                      "egress filtering to limit command-and-control reachability.",
                      "Disable developer/debug interfaces (sdb, ADB, SSH) on all "
                      "production televisions.",
                      "Re-assess quarterly or after any firmware change.",
                  ])]

        # 8 — Conclusion + sign-off
        story += [_section(L, "8", "Conclusion"),
                  _para(L, (
                      f"The engagement confirmed {scan.get('vulnerable', 0)} "
                      f"vulnerable television device(s) and executed the "
                      f"corresponding exploit modules under authorization, with "
                      f"{len(succeeded)} successful outcome(s). All connections "
                      f"opened during testing were terminated and verified "
                      f"{'and no sessions remain open' if conn.get('verified') else 'with the exceptions noted in Section 6'}. "
                      f"{COMPANY} recommends prompt remediation per Section 7. "
                      "This assessment should be repeated after remediation to "
                      "confirm closure.")),
                  Spacer(1, 4 * mm)]
        story += _signoff(L)
        story += _appendix(L, cves, [
            ("Report ID", self.report_id),
            ("Engagement type", self.engagement_type),
            ("Started (UTC)", self.started_at),
            ("Completed (UTC)", self.finished_at or utc_now_iso()),
            ("Client", client["name"]),
            ("Prepared by", COMPANY),
            ("Tooling", "SpyTV C2 — network scanner, CVE database, exploit modules"),
            ("CVE source", "NVD (NIST) via the C2 CVE feed"),
        ])
        return story


class PatchEngagement(Engagement):
    """Patch-all: remediate every device, then render the proof report."""

    kind = "patch"
    prefix = "PAT"
    title = "VULNERABILITY PATCH & REMEDIATION REPORT"
    subtitle = "Attestation of remediation results — verified per device and CVE"
    engagement_type = "Full-network vulnerability remediation (patch-all) with attestation report"

    def configure(self, targets_fn=None, patch_fn=None):
        self.targets_fn = targets_fn
        self.patch_fn = patch_fn
        self.results = {"targets": [], "devices": [], "summary": {}}

    @staticmethod
    def _classify(result):
        """Turn raw patch results into a status + human-readable reason."""
        if result.get("error"):
            return "error", result["error"]
        total = result.get("total", 0)
        ok = result.get("ok", 0)
        if total == 0:
            return ("not-applicable",
                    "No remediation commands are defined for this device "
                    "family — manual vendor firmware update required.")
        if ok == total:
            return "patched", None
        failures = [p for p in result.get("patches", [])
                    if p.get("status") not in ("ok", "executed")]
        detail = "; ".join(
            f"{p.get('status')}: {p.get('output') or p.get('command')}"
            for p in failures[:3]) or "unknown failure"
        if ok == 0:
            return "failed", f"All {total} remediation command(s) failed — {detail}"
        return ("partial",
                f"{ok}/{total} remediation commands succeeded — {detail}")

    def run(self):
        self.set_phase("patching", 10)
        targets = self.targets_fn() or []
        self.results["targets"] = targets
        self.say(f"Patch-all started for {len(targets)} device(s)")

        devices = []
        for i, t in enumerate(targets, 1):
            ip, tv_type = t.get("ip"), t.get("tv_type")
            entry = {
                "ip": ip, "tv_type": tv_type, "name": t.get("name") or tv_type,
                "source": t.get("source", "scan"),
                "device_id": t.get("device_id"),
            }
            if not ip or not tv_type:
                entry.update(status="not-applicable",
                             reason="Device has no identifiable TV family — "
                                    "cannot map remediation commands.",
                             total=0, ok=0, cves_fixed=[], patches=[])
            else:
                self.say(f"[{i}/{len(targets)}] Patching {ip} ({tv_type})...")
                try:
                    result = self.patch_fn(ip, tv_type)
                except Exception as e:  # noqa: BLE001
                    result = {"error": str(e), "total": 0, "ok": 0,
                              "patches": [], "cves_fixed": []}
                status, reason = self._classify(result)
                entry.update({
                    "status": status,
                    "reason": reason,
                    "total": result.get("total", 0),
                    "ok": result.get("ok", 0),
                    "cves_fixed": result.get("cves_fixed", []),
                    "patches": result.get("patches", []),
                })
                self.say(f"  {ip}: {status.upper().replace('-', ' ')}"
                         + (f" — {reason}" if reason else ""))
            devices.append(entry)
            self.results["devices"] = devices
            progress = 10 + int(80 * (i / max(1, len(targets))))
            self.set_phase("patching", progress)

        summary = {
            "total": len(devices),
            "patched": sum(1 for d in devices if d["status"] == "patched"),
            "partial": sum(1 for d in devices if d["status"] == "partial"),
            "failed": sum(1 for d in devices if d["status"] in ("failed", "error")),
            "not_applicable": sum(1 for d in devices
                                  if d["status"] == "not-applicable"),
        }
        summary["exceptions"] = summary["total"] - summary["patched"]
        self.results["summary"] = summary
        self.say(f"Patch-all complete: {summary['patched']}/{summary['total']} "
                 f"devices fully patched ({summary['exceptions']} exception(s))")
        self.set_phase("awaiting_client", 100)
        self.say("Client details required to render the remediation report.")

    # -- report -------------------------------------------------------------
    def build_story(self, client):
        L = _pdf_libs()
        Spacer, PageBreak = L["Spacer"], L["PageBreak"]
        mm = L["mm"]

        devices = self.results.get("devices", [])
        summary = self.results.get("summary", {})
        exceptions = [d for d in devices if d["status"] != "patched"]
        cves = []
        seen = set()
        for d in devices:
            for c in d.get("cves_fixed") or []:
                if c and c not in seen:
                    seen.add(c)
                    cves.append({"id": c, "severity": None, "component": None,
                                 "fixed_in": None})
        # Enrich appendix CVEs from the CVE database when available.
        try:
            from core.cve_scanner import TV_CVE_DATABASE
            db_cves = {c["id"]: c for info in TV_CVE_DATABASE.values()
                       for c in info.get("cves", [])}
            cves = [dict(db_cves.get(c["id"], c)) for c in cves]
        except Exception:
            pass

        all_clear = summary.get("total", 0) > 0 and not exceptions

        story = self._cover(
            L, client,
            subtitle="Patch verification — all device vulnerabilities confirmed "
                     "remediated, or documented with cause")
        story += _contents_story(L)

        # 1 — Executive summary
        story += [_section(L, "1", "Executive Summary"),
                  _para(L, (
                      f"{COMPANY} executed a full-network vulnerability remediation "
                      f"engagement against the client's television environment, "
                      f"patching every device with known CVE exposures. "
                      f"<b>{summary.get('patched', 0)}</b> of "
                      f"<b>{summary.get('total', 0)}</b> targeted device(s) were "
                      f"<b>fully patched and verified</b>." + (
                          " All identified device vulnerabilities were "
                          "successfully patched; no exceptions were recorded."
                          if all_clear else
                          f" <b>{summary.get('exceptions', 0)}</b> device(s) "
                          "could not be fully patched or had no applicable "
                          "remediation — each exception and its cause is "
                          "documented in Section 4." if summary.get("exceptions") else
                          ""))),
                  _table(L, [
                      ["Metric", "Result"],
                      ["Devices targeted", str(summary.get("total", 0))],
                      ["Fully patched & verified", str(summary.get("patched", 0))],
                      ["Partially patched", str(summary.get("partial", 0))],
                      ["Failed / could not patch", str(summary.get("failed", 0))],
                      ["No remediation defined", str(summary.get("not_applicable", 0))],
                      ["Exceptions requiring action", str(summary.get("exceptions", 0))],
                      ["Overall remediation status",
                       _status("patched" if all_clear else
                               ("partial" if summary.get("patched") else "failed"))],
                  ], [74, 100]),
                  Spacer(1, 3 * mm)]

        # 2 — Scope & methodology
        story += [_section(L, "2", "Scope & Methodology"),
                  _para(L, "Remediation was executed with the SpyTV C2 patch "
                           "pipeline: each device family's documented remediation "
                           "commands were run against every identified television, "
                           "capturing per-command output and return codes. A device "
                           "is attested as PATCHED only when every remediation "
                           "command for its family completed successfully."),
                  _bullets(L, [
                      "<b>Targeting</b> — devices collected from registered "
                      "implants and the latest network scan (family → CVE mapping).",
                      "<b>Execution</b> — family remediation commands executed "
                      "sequentially per device with 45 s per-command timeout.",
                      "<b>Classification</b> — PATCHED (all commands ok), "
                      "PARTIAL (some ok), FAILED (none ok), NOT APPLICABLE "
                      "(no commands defined) with reason capture.",
                      "<b>Attestation</b> — results summarized per device and "
                      "CVE below, with failure causes for every exception.",
                  ]),
                  Spacer(1, 3 * mm)]

        # 3 — Remediation status overview
        story += [_section(L, "3", "Device Inventory & Remediation Status")]
        if devices:
            rows = [["#", "IP Address", "Device / Family", "Source",
                     "CVEs", "Commands", "Status"]]
            for i, d in enumerate(devices, 1):
                rows.append([
                    str(i), _esc(d.get("ip", "")),
                    _esc(f"{d.get('name', '—')} ({d.get('tv_type', '—')})"),
                    _esc(d.get("source", "—")),
                    str(len(d.get("cves_fixed") or [])),
                    f"{d.get('ok', 0)}/{d.get('total', 0)}",
                    _status(d.get("status")),
                ])
            story.append(_table(L, rows, [8, 26, 46, 20, 14, 20, 40]))
        else:
            story.append(_para(L, "No devices were identified for remediation — "
                                  "the network scan and device registry were empty."))
        story.append(Spacer(1, 3 * mm))

        # 4 — Detailed results (+ reasons for anything not patched)
        story += [_section(L, "4", "Detailed Remediation Results")]
        if not devices:
            story.append(_para(L, "No per-device results to report."))
        for i, d in enumerate(devices, 1):
            block = [
                _subsection(L, f"4.{i}",
                            f"{d.get('ip')} — {d.get('name')} "
                            f"({d.get('tv_type', 'family unknown')})"),
                _para(L, "<b>Status:</b> " + _status(d.get("status")) +
                       (" &nbsp;&nbsp;<b>Commands successful:</b> "
                        f"{d.get('ok', 0)}/{d.get('total', 0)}"
                        if d.get("total") else "")),
            ]
            if d.get("cves_fixed"):
                block.append(_para(
                    L, "<b>CVEs addressed:</b> "
                    + ", ".join(_esc(c) for c in d["cves_fixed"])))
            if d.get("status") != "patched":
                block.append(_para(
                    L, "<b>Reason not fully patched:</b> "
                    f'<font color="#B91C1C">{_esc(d.get("reason") or "see command output below")}</font>'))
            if d.get("patches"):
                rows = [["Remediation command", "Status", "Output / evidence"]]
                for p in d["patches"]:
                    st = p.get("status")
                    color = "#15803D" if st in ("ok", "executed") else \
                        "#A16207" if st in ("skipped", "timeout") else "#B91C1C"
                    rows.append([
                        _esc(p.get("command", "")),
                        f'<font color="{color}"><b>{_esc(str(st).upper())}</b></font>',
                        _esc(p.get("output") or "—"),
                    ])
                block.append(_table(L, rows, [72, 22, 80]))
            story.extend(block)
            story.append(Spacer(1, 2 * mm))

        # 5 — Verification & attestation
        story += [_section(L, "5", "Verification & Attestation")]
        if all_clear:
            statement = (
                f"{COMPANY} attests that all {summary.get('patched', 0)} "
                f"identified television device(s) were remediated successfully: "
                "every documented remediation command for each device family "
                "completed without error, closing the matched CVE exposures. "
                "No device vulnerabilities remain unpatched from this engagement.")
        elif not devices:
            statement = ("No vulnerable devices were present at the time of the "
                         "engagement; nothing required remediation.")
        else:
            names = ", ".join(f"{d.get('ip')} ({d.get('status').upper().replace('-', ' ')})"
                              for d in exceptions)
            statement = (
                f"Of {summary.get('total', 0)} device(s) targeted, "
                f"{summary.get('patched', 0)} were fully patched and verified. "
                f"The following device(s) were <b>not</b> fully patched: "
                f"<b>{_esc(names)}</b>. Per-device causes are documented in "
                "Section 4 and summarized in the exceptions table below; these "
                "devices remain exposed until the listed cause is resolved and "
                "remediation is re-run.")
        story.append(_para(L, statement))
        if exceptions:
            rows = [["IP Address", "Status", "Reason / cause"]]
            for d in exceptions:
                rows.append([_esc(d.get("ip", "")), _status(d.get("status")),
                             _esc(d.get("reason") or "—")])
            story.append(_table(L, rows, [30, 34, 110]))
            story.append(Spacer(1, 3 * mm))

        # 6 — Recommendations
        recs = []
        if exceptions:
            recs.append("Resolve each exception in Section 5: install missing "
                        "operator tooling, reach the device, or perform the "
                        "vendor firmware update manually, then re-run Patch.")
            recs.append("Re-run this remediation engagement after correcting "
                        "exceptions and attach the updated report as evidence "
                        "of closure.")
        recs += [
            "Schedule a follow-up audit (C2 → Audit) to confirm the patched "
            "devices no longer match vulnerable signatures.",
            "Maintain a regular firmware-update cadence for all television "
            "devices and re-scan monthly.",
        ]
        story += [_section(L, "6", "Recommendations"), _bullets(L, recs)]
        story += [Spacer(1, 4 * mm)]
        story += _signoff(L)
        story += _appendix(L, cves, [
            ("Report ID", self.report_id),
            ("Engagement type", self.engagement_type),
            ("Started (UTC)", self.started_at),
            ("Completed (UTC)", self.finished_at or utc_now_iso()),
            ("Client", client["name"]),
            ("Prepared by", COMPANY),
            ("Tooling", "SpyTV C2 — patch pipeline (family remediation commands)"),
            ("Devices covered", str(summary.get("total", 0))),
        ])
        return story
