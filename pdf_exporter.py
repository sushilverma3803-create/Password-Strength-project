import io
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def generate_pdf_report(
    analysis_data: Dict[str, Any],
    password_preview: str = "••••••••••••",
    operator_name: str = "Anonymous Operator",
    recommendations: List[Dict[str, Any]] = None
) -> bytes:
    """
    Generate an enterprise-grade cybersecurity password strength audit report PDF.
    Returns: PDF file bytes buffer.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    story = []
    styles = getSampleStyleSheet()

    # Custom Color Palette
    c_primary = colors.HexColor("#060913")
    c_navy = colors.HexColor("#0a1024")
    c_cyan = colors.HexColor("#00a8b5")
    c_emerald = colors.HexColor("#008f51")
    c_amber = colors.HexColor("#b37400")
    c_crimson = colors.HexColor("#d61a4c")
    c_light_bg = colors.HexColor("#f1f5f9")
    c_text_dark = colors.HexColor("#0f172a")
    c_text_muted = colors.HexColor("#475569")

    # Custom Typography Styles
    style_header_title = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=c_navy
    )
    style_header_sub = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=c_cyan
    )
    style_meta = ParagraphStyle(
        'MetaText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=c_text_muted
    )
    style_h2 = ParagraphStyle(
        'Heading2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=c_navy,
        spaceBefore=10,
        spaceAfter=6
    )
    style_body = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=c_text_dark
    )
    style_code = ParagraphStyle(
        'Code',
        parent=styles['Normal'],
        fontName='Courier-Bold',
        fontSize=10,
        leading=13,
        textColor=c_navy
    )
    style_rec_title = ParagraphStyle(
        'RecTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=c_navy
    )
    style_rec_desc = ParagraphStyle(
        'RecDesc',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=c_text_muted
    )

    # 1. Header & Branding Banner
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = f"CYB-{int(datetime.now().timestamp())}"

    header_table_data = [
        [
            Paragraph("<b>CYBERGUARD // SENTINEL AUDIT</b><br/><font color='#00a8b5'>CRYPTOGRAPHIC SECURITY EVALUATION</font>", style_header_title),
            Paragraph(f"<b>REPORT ID:</b> {report_id}<br/><b>DATE:</b> {now_utc}<br/><b>OPERATOR:</b> {operator_name}", style_meta)
        ]
    ]
    t_header = Table(header_table_data, colWidths=[330, 210])
    t_header.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8)
    ]))
    story.append(t_header)

    story.append(HRFlowable(width="100%", thickness=1.5, color=c_cyan, spaceBefore=4, spaceAfter=14))

    # 2. Executive Summary & Resilience Scorecard
    score = analysis_data.get('score', 0)
    status = analysis_data.get('status', 'Weak')
    entropy = analysis_data.get('entropy', 0.0)
    length = analysis_data.get('length', len(password_preview))
    is_breached = analysis_data.get('is_breached', False)
    breach_count = analysis_data.get('breach_info', {}).get('count', 0) if analysis_data.get('breach_info') else 0

    score_color = c_crimson
    if score >= 80: score_color = c_emerald
    elif score >= 55: score_color = c_cyan
    elif score >= 25: score_color = c_amber

    breach_text = f"<font color='#d61a4c'><b>BREACH DETECTED ({breach_count:,} leaks)</b></font>" if is_breached else "<font color='#008f51'><b>CLEAN (Zero Known Breaches)</b></font>"

    story.append(Paragraph("<b>1. EXECUTIVE SUMMARY &amp; METRIC SCORECARD</b>", style_h2))

    summary_table_data = [
        [
            Paragraph(f"<b>Target Evaluated:</b> {password_preview}", style_code),
            Paragraph(f"<b>Security Rating:</b> <font color='{score_color.hexval()}'><b>{status.upper()}</b></font>", style_body),
            Paragraph(f"<b>Overall Score:</b> <b>{score} / 100</b>", style_body)
        ],
        [
            Paragraph(f"<b>Character Length:</b> {length} chars", style_body),
            Paragraph(f"<b>Shannon Entropy:</b> {round(entropy, 2)} bits", style_body),
            Paragraph(f"<b>Breach Integrity:</b> {breach_text}", style_body)
        ]
    ]
    t_summary = Table(summary_table_data, colWidths=[180, 180, 180])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_light_bg),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 14))

    # 3. Brute-Force Attack Scenario Breakdown
    story.append(Paragraph("<b>2. BRUTE-FORCE RESILIENCE SIMULATION</b>", style_h2))
    scenarios = analysis_data.get('attack_scenarios', {})
    cluster_time = scenarios.get('gpu_cluster', {}).get('time', 'Instant')
    single_gpu = scenarios.get('single_gpu', {}).get('time', 'Instant')
    online_fast = scenarios.get('online_fast', {}).get('time', 'Instant')
    online_throttled = scenarios.get('online_throttled', {}).get('time', 'Instant')

    entropy_metrics = analysis_data.get('entropy_metrics', {})
    difficulty = entropy_metrics.get('difficulty_rating', 'Trivial')
    combinations = entropy_metrics.get('combinations_display', '0')
    charset_pool = entropy_metrics.get('pool_size', 0)

    attack_table_data = [
        ["Attack Scenario", "Estimated Compute Rate", "Crack Time Resistance", "Threat Severity"],
        ["Modern GPU Cluster (10x RTX 4090)", "100 Billion Guesses / sec", cluster_time, "High Rigor"],
        ["Consumer Single GPU", "1 Billion Guesses / sec", single_gpu, "Moderate"],
        ["Online Web Unthrottled", "100 Requests / sec", online_fast, "Low Rigor"],
        ["Online Throttled / Cloudflare Rate-Limit", "10 Requests / sec", online_throttled, "Network Throttled"],
        ["Search Space Combinations", f"2^{round(entropy, 1)} ({combinations})", f"Charset Pool: {charset_pool} chars", f"Tier: {difficulty}"]
    ]
    t_attack = Table(attack_table_data, colWidths=[160, 140, 130, 110])
    t_attack.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
    ]))
    story.append(t_attack)
    story.append(Spacer(1, 14))

    # 4. Complexity Criteria Matrix
    story.append(Paragraph("<b>3. CRYPTOGRAPHIC COMPLEXITY COMPLIANCE</b>", style_h2))
    crit = analysis_data.get('criteria', {})
    
    crit_table_data = [
        [
            f"<b>Length >= 8:</b> {'[PASS]' if length >= 8 else '[FAIL]'}",
            f"<b>Length >= 12:</b> {'[PASS]' if length >= 12 else '[FAIL]'}",
            f"<b>Uppercase (A-Z):</b> {'[PASS]' if crit.get('has_upper') else '[FAIL]'}"
        ],
        [
            f"<b>Lowercase (a-z):</b> {'[PASS]' if crit.get('has_lower') else '[FAIL]'}",
            f"<b>Numerical (0-9):</b> {'[PASS]' if crit.get('has_digit') else '[FAIL]'}",
            f"<b>Symbols (!@#$):</b> {'[PASS]' if crit.get('has_symbol') else '[FAIL]'}"
        ]
    ]
    t_crit = Table([[Paragraph(c, style_body) for c in row] for row in crit_table_data], colWidths=[180, 180, 180])
    t_crit.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_light_bg),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_crit)
    story.append(Spacer(1, 14))

    # 5. Security Recommendations
    story.append(Paragraph("<b>4. TAILORED SECURITY RECOMMENDATIONS &amp; REMEDIATION</b>", style_h2))
    recs_list = recommendations or []
    if not recs_list:
        raw_recs = analysis_data.get('recommendations', [])
        recs_list = [{'title': 'Heuristic Advisory', 'message': r, 'action': 'Harden credentials.'} for r in raw_recs]

    rec_table_rows = []
    for r in recs_list[:5]:
        sev = r.get('severity', 'INFO')
        title = r.get('title', 'Recommendation')
        msg = r.get('message', '')
        act = r.get('action', '')

        badge_color = c_cyan
        if sev == 'CRITICAL': badge_color = c_crimson
        elif sev == 'WARNING': badge_color = c_amber
        elif sev == 'OPTIMAL': badge_color = c_emerald

        rec_table_rows.append([
            Paragraph(f"<font color='{badge_color.hexval()}'><b>[{sev}]</b></font>", style_body),
            Paragraph(f"<b>{title}</b><br/>{msg}<br/><i>Action: {act}</i>", style_rec_desc)
        ])

    if rec_table_rows:
        t_recs = Table(rec_table_rows, colWidths=[80, 460])
        t_recs.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, c_light_bg]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t_recs)

    # 6. Confidentiality Signoff Footer
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceBefore=10, spaceAfter=8))
    footer_text = Paragraph(
        "<b>CONFIDENTIALITY NOTICE:</b> This cryptographic security evaluation is generated locally by CyberGuard Sentinel. "
        "No plaintext credentials are transmitted or stored without cryptographic hashing. Adheres to NIST SP 800-63B standards.",
        style_meta
    )
    story.append(footer_text)

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
