"""
Helper utilities: PDF report generation, formatting, badge renderers,
and cybersecurity report exporter using fpdf2.
"""

import io
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from fpdf import FPDF

    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


def format_timestamp(iso_str: Optional[str]) -> str:
    """Format ISO timestamp into readable format."""
    if not iso_str:
        return "N/A"
    try:
        clean_str = iso_str.replace("Z", "")
        dt = datetime.fromisoformat(clean_str)
        return dt.strftime("%b %d, %Y - %H:%M:%S UTC")
    except Exception:
        return str(iso_str)


def get_risk_color(risk_level: str) -> str:
    """Return hex color for a risk level or prediction outcome."""
    level = str(risk_level).upper()
    if "CRITICAL" in level or "SUSPICIOUS" in level or "FAKE" in level:
        return "#EF4444"
    elif "HIGH" in level:
        return "#F87171"
    elif "MEDIUM" in level:
        return "#F59E0B"
    elif "LOW" in level or "GENUINE" in level:
        return "#10B981"
    elif "INSUFFICIENT" in level:
        return "#3B82F6"
    return "#3B82F6"


def render_risk_badge_html(risk_level: str, risk_score: float) -> str:
    """Generates an HTML badge for risk level."""
    level = str(risk_level).upper()
    cls_name = "risk-badge-low"
    icon = "🛡️"

    if "CRITICAL" in level:
        cls_name = "risk-badge-critical"
        icon = "🚨"
    elif "HIGH" in level:
        cls_name = "risk-badge-high"
        icon = "⚠️"
    elif "MEDIUM" in level:
        cls_name = "risk-badge-medium"
        icon = "⚡"
    elif "LOW" in level:
        cls_name = "risk-badge-low"
        icon = "✅"

    return f"""
    <span class="risk-badge {cls_name}">
        <span>{icon}</span> {level} RISK &bull; {risk_score:.0f}/100
    </span>
    """


class CybersecurityReportPDF(FPDF):
    """Custom PDF generator for professional Cybersecurity Job Threat Reports."""

    def __init__(self, report_id: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.report_id = report_id
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        # Header banner
        self.set_fill_color(17, 24, 39)
        self.rect(0, 0, 210, 20, "F")

        self.set_font("Helvetica", "B", 11)
        self.set_text_color(0, 240, 255)
        self.set_xy(10, 6)
        self.cell(0, 5, "INTELLIGENT FAKE JOB & RECRUITMENT SCAM DETECTION SYSTEM")

        self.set_font("Helvetica", "", 8)
        self.set_text_color(148, 163, 184)
        self.set_xy(10, 12)
        self.cell(0, 4, f"CYBERSECURITY INCIDENT & THREAT REPORT | REF: {self.report_id}")
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.cell(
            0,
            10,
            f"Page {self.page_no()} | Academic Cybersecurity Project | Decision-Support System - Not Legal Advice",
            align="C",
        )


def _clean_for_pdf(text: Any) -> str:
    """Sanitizes unicode characters (like em-dashes and smart quotes) for Latin-1 core fonts."""
    if text is None:
        return ""
    s = str(text)
    s = s.replace("—", " - ").replace("–", " - ").replace("“", '"').replace("”", '"').replace("’", "'").replace("‘", "'")
    s = s.replace("•", "*").replace("…", "...").replace("™", "").replace("®", "")
    return s.encode("latin-1", "replace").decode("latin-1")


def generate_pdf_report(analysis_record: Dict[str, Any]) -> Optional[bytes]:
    """Generates an executive cybersecurity PDF report for an analyzed job posting."""
    if not HAS_FPDF:
        return None

    try:
        report_id = _clean_for_pdf(analysis_record.get("id", "REPORT")[:8]).upper()
        pdf = CybersecurityReportPDF(report_id)
        pdf.add_page()
        pdf.set_margins(12, 12, 12)

        # Title
        pdf.set_y(26)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 8, "EXECUTIVE THREAT ASSESSMENT REPORT")
        pdf.ln(8)

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(71, 85, 105)
        created_time = _clean_for_pdf(format_timestamp(analysis_record.get("created_at")))
        pdf.cell(0, 5, f"Generated: {created_time} | Assessment Engine: v2.4 (ML + Hybrid Rules)")
        pdf.ln(8)

        # Job Summary Table Box
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(226, 232, 240)
        pdf.rect(12, pdf.get_y(), 186, 32, "FD")

        job_info = analysis_record.get("job_data", {})
        title = _clean_for_pdf(job_info.get("title", "N/A"))[:45]
        company = _clean_for_pdf(job_info.get("company", "N/A"))[:40]
        location = _clean_for_pdf(job_info.get("location", "N/A"))[:30]
        salary = _clean_for_pdf(job_info.get("salary", "Not Disclosed"))[:30]

        pdf.set_xy(16, pdf.get_y() + 3)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(35, 6, "Target Job Title:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(60, 6, title)

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(30, 6, "Claimed Company:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(50, 6, company)
        pdf.ln(6)

        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(35, 6, "Location:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(60, 6, location)

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(30, 6, "Offered Salary:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(50, 6, salary)
        pdf.ln(6)

        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(35, 6, "Application Link:")
        pdf.set_font("Helvetica", "", 9)
        url = _clean_for_pdf(job_info.get("url") or "None Provided")[:70]
        pdf.cell(140, 6, url)
        pdf.ln(6)

        pdf.ln(6)

        # Verdict Summary Card
        pred = _clean_for_pdf(analysis_record.get("prediction", "UNKNOWN"))
        risk_score = float(analysis_record.get("risk_score", 0.0))
        risk_level = _clean_for_pdf(analysis_record.get("risk_level", "UNKNOWN"))
        confidence = float(analysis_record.get("confidence", 0.0))

        # Color fill based on outcome
        if "Suspicious" in pred or "CRITICAL" in risk_level or "HIGH" in risk_level:
            pdf.set_fill_color(254, 242, 242)
            pdf.set_draw_color(239, 68, 68)
            pdf.set_text_color(185, 28, 28)
        elif "Insufficient" in pred:
            pdf.set_fill_color(239, 246, 255)
            pdf.set_draw_color(59, 130, 246)
            pdf.set_text_color(29, 78, 216)
        elif "MEDIUM" in risk_level:
            pdf.set_fill_color(255, 251, 235)
            pdf.set_draw_color(245, 158, 11)
            pdf.set_text_color(180, 83, 9)
        else:
            pdf.set_fill_color(240, 253, 244)
            pdf.set_draw_color(16, 185, 129)
            pdf.set_text_color(4, 120, 87)

        y_verdict = pdf.get_y()
        pdf.rect(12, y_verdict, 186, 24, "FD")
        pdf.set_xy(16, y_verdict + 3)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(100, 7, f"CLASSIFICATION: {pred.upper()} ({risk_level} RISK)")

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(75, 7, f"SCORE: {risk_score:.0f}/100 | CONF: {confidence:.1f}%", align="R")
        pdf.ln(7)

        pdf.set_xy(16, y_verdict + 11)
        pdf.set_font("Helvetica", "", 8.5)
        raw_cats = ", ".join(analysis_record.get("scam_categories", [])) or "None Identified"
        cats = _clean_for_pdf(raw_cats)[:90]
        pdf.cell(175, 5, f"Primary Scam Categories: {cats}")
        pdf.ln(5)

        pdf.set_xy(16, y_verdict + 16)
        pdf.set_font("Helvetica", "I", 7.5)
        pdf.cell(175, 5, "Disclaimer: Decision-support evaluation based on documented indicators. None is a guarantee of authenticity or fraud.")
        pdf.ln(6)

        pdf.ln(8)

        # Red Flags
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, "DETECTED RED FLAGS & RISK INDICATORS:")
        pdf.ln(6)
        pdf.set_font("Helvetica", "", 9)
        red_flags = analysis_record.get("red_flags", [])
        if red_flags:
            for flag in red_flags[:6]:
                pdf.set_text_color(220, 38, 38)
                pdf.cell(5, 5, "[X]")
                pdf.set_text_color(51, 65, 85)
                pdf.cell(0, 5, f" {_clean_for_pdf(flag)[:85]}")
                pdf.ln(5)
        else:
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 5, "No critical red flags detected.")
            pdf.ln(5)

        pdf.ln(4)

        # Trust Indicators
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, "POSITIVE TRUST & INTEGRITY INDICATORS:")
        pdf.ln(6)
        pdf.set_font("Helvetica", "", 9)
        trust_flags = analysis_record.get("trust_indicators", [])
        if trust_flags:
            for flag in trust_flags[:5]:
                pdf.set_text_color(16, 185, 129)
                pdf.cell(5, 5, "[+]")
                pdf.set_text_color(51, 65, 85)
                pdf.cell(0, 5, f" {_clean_for_pdf(flag)[:85]}")
                pdf.ln(5)
        else:
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 5, "No positive trust indicators detected.")
            pdf.ln(5)

        pdf.ln(4)

        # URL and Company Summary
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, "SEPARATED VERIFICATION DIMENSIONS:")
        pdf.ln(6)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(51, 65, 85)

        ml_prob_val = analysis_record.get("ml_result", {}).get("fraud_probability", 0.0)
        pdf.cell(0, 5, f"- Dimension 1 (ML Text Model): Fraud Probability {ml_prob_val*100:.1f}%")
        pdf.ln(5)

        url_analysis = analysis_record.get("url_analysis", {})
        url_validity_str = _clean_for_pdf(url_analysis.get("url_validity", "No URL provided"))
        pdf.cell(0, 5, f"- Dimension 2 (URL Validity): {url_validity_str}")
        pdf.ln(5)

        company_verif = analysis_record.get("company_verification", {})
        comp_status_str = _clean_for_pdf(company_verif.get("verification_status", "UNVERIFIED"))
        comp_summary = _clean_for_pdf(company_verif.get("summary", "Company verification inconclusive."))[:65]
        pdf.cell(0, 5, f"- Dimension 3 (Company Identity): {comp_status_str} ({comp_summary}...)")
        pdf.ln(5)

        pdf.ln(4)

        # Explainable AI findings
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, "EXPLAINABILITY & FEATURE INFLUENCE:")
        pdf.ln(6)
        pdf.set_font("Helvetica", "", 9)
        explanation = analysis_record.get("explanation", {})
        summary_text = _clean_for_pdf(explanation.get("summary", "Analysis completed based on NLP and rule matching."))
        pdf.multi_cell(186, 5, f"- {summary_text}")

        pdf.ln(4)

        # Recommended Action Box
        pdf.set_fill_color(241, 245, 249)
        pdf.set_draw_color(203, 213, 225)
        y_act = pdf.get_y()
        pdf.rect(12, y_act, 186, 22, "FD")
        pdf.set_xy(16, y_act + 2)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 5, "RECOMMENDED SECURITY ACTIONS:")
        pdf.ln(5)

        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(51, 65, 85)
        action = _clean_for_pdf(analysis_record.get("recommended_action", "Proceed with standard verification precautions."))
        pdf.set_x(16)
        pdf.multi_cell(175, 4.5, action)

        return bytes(pdf.output())
    except Exception as e:
        return None
