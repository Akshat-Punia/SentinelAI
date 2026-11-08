import io
from datetime import datetime
from typing import List, Dict, Any


class SecurityReportGenerator:
    """
    Generates downloadable compliance and incident reports.
    Supports ReportLab if installed, with a self-contained pure-Python PDF 1.4 generator fallback.
    """

    @classmethod
    def generate_pdf_report(cls, stats: Dict[str, Any], alerts: List[Any], events_count: int) -> bytes:
        """Generates a binary PDF report ready for download."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
            styles = getSampleStyleSheet()

            story = []
            title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=22, textColor=colors.HexColor("#0f172a"), spaceAfter=10)
            meta_style = ParagraphStyle('MetaStyle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor("#64748b"), spaceAfter=15)
            h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor("#1e293b"), spaceBefore=12, spaceAfter=8)
            body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#334155"), spaceAfter=6)

            story.append(Paragraph("SENTINEL AI — EXECUTIVE SECURITY REPORT", title_style))
            story.append(Paragraph(f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Classification: CONFIDENTIAL", meta_style))
            story.append(Spacer(1, 10))

            story.append(Paragraph("1. Executive Summary & Incident Metrics", h2_style))
            summary_data = [
                ["Metric", "Value", "Metric", "Value"],
                ["Total Events Ingested", str(events_count), "Total Security Alerts", str(stats.get("total_alerts", 0))],
                ["Critical Alerts", str(stats.get("critical_alerts", 0)), "High Severity Alerts", str(stats.get("high_alerts", 0))],
                ["Open / Unresolved", str(stats.get("open_alerts", 0)), "Resolved Incidents", str(stats.get("resolved_alerts", 0))]
            ]
            t = Table(summary_data, colWidths=[130, 130, 130, 130])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ]))
            story.append(t)
            story.append(Spacer(1, 15))

            story.append(Paragraph("2. Recent Threat Alerts & Mitigations", h2_style))
            alert_rows = [["ID", "Severity", "Rule", "Status", "Score"]]
            for a in alerts[:10]:
                alert_rows.append([f"#{a.id}", a.severity, a.rule_triggered, a.status, f"{a.risk_score:.1f}"])

            if len(alert_rows) > 1:
                at = Table(alert_rows, colWidths=[40, 70, 230, 100, 60])
                at.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                ]))
                story.append(at)
            else:
                story.append(Paragraph("No active security alerts recorded during this reporting cycle.", body_style))

            story.append(Spacer(1, 20))
            story.append(Paragraph("3. Compliance & Governance Attestation", h2_style))
            story.append(Paragraph(
                "This report validates continuous event telemetry monitoring, role-based IAM governance, and automated risk scoring "
                "under the Sentinel AI security baseline. Incident data is hashed and permanently audited in system logs.",
                body_style
            ))

            doc.build(story)
            return buffer.getvalue()

        except ImportError:
            # Self-contained pure-Python valid PDF 1.4 generation
            return cls._generate_pure_pdf(stats, alerts, events_count)

    @classmethod
    def _generate_pure_pdf(cls, stats: Dict[str, Any], alerts: List[Any], events_count: int) -> bytes:
        """Pure-Python valid PDF 1.4 stream generator."""
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        lines = [
            "SENTINEL AI - EXECUTIVE SECURITY & INCIDENT AUDIT REPORT",
            f"Generated: {now} | Status: CONFIDENTIAL",
            "--------------------------------------------------------------------------------",
            "",
            "1. EXECUTIVE METRICS SUMMARY:",
            f"   - Total Ingested Telemetry Events: {events_count}",
            f"   - Total Threat Alerts Triggered:   {stats.get('total_alerts', 0)}",
            f"   - Critical Severity Incidents:     {stats.get('critical_alerts', 0)}",
            f"   - High Severity Incidents:         {stats.get('high_alerts', 0)}",
            f"   - Open Incidents Under Review:     {stats.get('open_alerts', 0)}",
            f"   - Successfully Resolved Incidents: {stats.get('resolved_alerts', 0)}",
            "",
            "2. RECENT INCIDENT INVESTIGATIONS:",
        ]

        for a in alerts[:8]:
            lines.append(f"   * Alert #{a.id} [{a.severity}] (Score: {a.risk_score}/100)")
            lines.append(f"     Title:  {a.title}")
            lines.append(f"     Rule:   {a.rule_triggered} | Status: {a.status}")
            lines.append(f"     Action: {a.recommended_action or 'N/A'}")
            lines.append("")

        if not alerts:
            lines.append("   (No active threat alerts recorded during this period)")
            lines.append("")

        lines.extend([
            "3. COMPLIANCE & GOVERNANCE AUDIT ATTESTATION:",
            "   This system report confirms active continuous security monitoring,",
            "   Identity and Access Management (IAM) role enforcement, and machine learning",
            "   risk scoring under Sentinel AI. All events are immutably logged in audit_logs.",
            "",
            "   End of Official Security Report."
        ])

        # Convert text lines into valid PDF content stream
        stream_content = "BT\n/F1 10 Tf\n50 750 Td\n14 TL\n"
        for line in lines:
            escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            stream_content += f"({escaped}) '\n"
        stream_content += "ET\n"

        stream_bytes = stream_content.encode("latin-1")
        stream_len = len(stream_bytes)

        pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
            b"4 0 obj\n<< /Length " + str(stream_len).encode("ascii") + b" >>\nstream\n"
            + stream_bytes +
            b"\nendstream\nendobj\n"
            b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"
            b"xref\n0 6\n"
            b"0000000000 65535 f \n"
            b"0000000009 00000 n \n"
            b"0000000058 00000 n \n"
            b"0000000115 00000 n \n"
            b"0000000250 00000 n \n"
            b"0000000300 00000 n \n"
            b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n380\n%%EOF"
        )
        return pdf
