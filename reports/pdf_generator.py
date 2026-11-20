import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether

from config import Config
from database.models import AlertModel, FlowModel
from database.db import query_db, execute_db

class PDFReportGenerator:
    @staticmethod
    def generate_incident_report(report_title="Executive Security Investigation Report", incident_id=None, analyst_user="SecOps Analyst"):
        """
        Builds a comprehensive, professional enterprise PDF report
        using ReportLab and returns the file path.
        """
        os.makedirs(Config.REPORT_DIR, exist_ok=True)
        timestamp_slug = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"NetSentry_Report_{timestamp_slug}.pdf"
        file_path = os.path.join(Config.REPORT_DIR, filename)

        doc = SimpleDocTemplate(
            file_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom professional typography styles
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a')
        )

        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor('#475569')
        )

        section_heading = ParagraphStyle(
            'SectionHeading',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1e40af'),
            spaceBefore=14,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor('#1e293b')
        )

        table_header = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#ffffff')
        )

        table_cell = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor('#1e293b')
        )

        badge_critical = ParagraphStyle('Crit', parent=table_cell, textColor=colors.HexColor('#dc2626'), fontName='Helvetica-Bold')
        badge_high = ParagraphStyle('High', parent=table_cell, textColor=colors.HexColor('#ea580c'), fontName='Helvetica-Bold')
        badge_med = ParagraphStyle('Med', parent=table_cell, textColor=colors.HexColor('#d97706'), fontName='Helvetica-Bold')
        badge_low = ParagraphStyle('Low', parent=table_cell, textColor=colors.HexColor('#16a34a'), fontName='Helvetica-Bold')

        elements = []

        # 1. Header Banner
        elements.append(Paragraph("NETSENTRY AI – ENTERPRISE SECURITY REPORT", subtitle_style))
        elements.append(Paragraph(report_title, title_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Lead Analyst: {analyst_user} | Classification: SOC CONFIDENTIAL", subtitle_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceBefore=4, spaceAfter=14))

        # 2. Executive Summary Metrics
        total_flows = FlowModel.get_count()
        alerts = AlertModel.get_recent(50)
        total_alerts = len(alerts)
        exfil_alerts = sum(1 for a in alerts if 'Exfiltration' in a['alert_type'])
        critical_alerts = sum(1 for a in alerts if a['severity'] == 'Critical')
        avg_risk = round(sum(a['risk_score'] for a in alerts) / max(1, total_alerts), 1) if total_alerts > 0 else 0.0

        summary_data = [
            [
                Paragraph("<b>Total Network Flows</b>", table_cell),
                Paragraph("<b>Flagged Alerts</b>", table_cell),
                Paragraph("<b>Potential Exfiltration</b>", table_cell),
                Paragraph("<b>Critical Incidents</b>", table_cell),
                Paragraph("<b>Mean Risk Score</b>", table_cell)
            ],
            [
                Paragraph(f"<font size=13><b>{total_flows:,}</b></font>", table_cell),
                Paragraph(f"<font size=13><b>{total_alerts}</b></font>", table_cell),
                Paragraph(f"<font size=13 color='#dc2626'><b>{exfil_alerts}</b></font>", table_cell),
                Paragraph(f"<font size=13 color='#dc2626'><b>{critical_alerts}</b></font>", table_cell),
                Paragraph(f"<font size=13 color='#1e40af'><b>{avg_risk}/100</b></font>", table_cell)
            ]
        ]
        summary_table = Table(summary_data, colWidths=[108, 108, 108, 108, 108])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        # 3. Detection Engine Methodology Brief
        elements.append(Paragraph("1. Adaptive AI Detection Methodology", section_heading))
        elements.append(Paragraph(
            "NetSentry AI operates a dual-layer machine learning pipeline. An unsupervised <b>Isolation Forest</b> continuously benchmarks high-dimensional flow features (outbound byte velocity, asymmetric transfer ratios, and connection durations) to isolate statistical anomalies. Concurrently, a multi-class <b>Random Forest classifier</b> assesses egress telemetry against established behavioral baselines. Suspicious indicators are synthesized through a dynamic 0–100 risk scoring engine weighted with destination threat intelligence.",
            body_style
        ))
        elements.append(Spacer(1, 10))

        # 4. Key Security Incidents Table
        elements.append(Paragraph("2. Prioritized Security Incidents & Potential Exfiltration Events", section_heading))

        if not alerts:
            elements.append(Paragraph("<i>No suspicious network events or exfiltration attempts currently recorded.</i>", body_style))
        else:
            table_rows = [
                [
                    Paragraph("Time", table_header),
                    Paragraph("Source IP", table_header),
                    Paragraph("Destination IP", table_header),
                    Paragraph("Protocol", table_header),
                    Paragraph("Bytes Sent", table_header),
                    Paragraph("AI Classification", table_header),
                    Paragraph("Risk", table_header),
                    Paragraph("Status", table_header)
                ]
            ]

            for alert_row in alerts[:12]: # Top 12 incidents
                a = dict(alert_row)
                sev = a['severity']
                b_style = badge_critical if sev == 'Critical' else (badge_high if sev == 'High' else (badge_med if sev == 'Medium' else badge_low))
                time_str = str(a['timestamp']).split('.')[0][-8:]
                table_rows.append([
                    Paragraph(time_str, table_cell),
                    Paragraph(f"<b>{a['src_ip']}</b>", table_cell),
                    Paragraph(a['dst_ip'], table_cell),
                    Paragraph(a.get('protocol', 'TCP'), table_cell),
                    Paragraph(f"{a.get('bytes_sent', 0):,} B", table_cell),
                    Paragraph(a.get('alert_type', 'Suspicious Flow'), table_cell),
                    Paragraph(f"{a['risk_score']:.0f} ({sev})", b_style),
                    Paragraph(a.get('status', 'New'), table_cell)
                ])

            incidents_table = Table(table_rows, colWidths=[55, 80, 85, 45, 65, 120, 50, 40])
            incidents_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#f1f5f9')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#ffffff'), colors.HexColor('#f8fafc')]),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(incidents_table)

        elements.append(Spacer(1, 14))

        # 5. Explainable AI & Investigation Recommendations
        elements.append(Paragraph("3. Explainable AI Attribution & SOC Recommended Remediation", section_heading))
        recs_text = [
            "<b>Host Containment:</b> For events classified with Critical or High severity, initiate network micro-segmentation on originating internal IP to halt active egress.",
            "<b>Egress Validation:</b> Verify if large outbound transfers correspond to scheduled corporate backups, remote deployments, or unauthorized cloud storage syncs.",
            "<b>Threat Intel Pivot:</b> Examine external destination IPs and ASN ownership for recent threat reports, dynamic DNS indicators, or Tor exit registration.",
            "<b>Adaptive Learning Feedback:</b> If a flagged transfer represents authorized business operations, mark the alert as 'Legitimate / False Positive' in the NetSentry console to adapt the device baseline."
        ]
        for r in recs_text:
            elements.append(Paragraph(f"• {r}", body_style))
            elements.append(Spacer(1, 3))

        elements.append(Spacer(1, 12))

        # 6. Safety & Compliance Disclaimer
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#cbd5e1'), spaceBefore=8, spaceAfter=8))
        disclaimer = (
            "<b>NOTICE:</b> NetSentry AI performs statistical anomaly detection and behavioral machine learning. "
            "Flagged transfers and high-risk scores indicate anomalous network patterns warranting SOC review and do not "
            "constitute conclusive forensic evidence of malicious intent or data compromise."
        )
        elements.append(Paragraph(disclaimer, ParagraphStyle('Disc', parent=body_style, fontSize=8, leading=10, textColor=colors.HexColor('#64748b'))))

        # Build Document
        doc.build(elements)

        # Record in DB
        report_id = execute_db('''
        INSERT INTO generated_reports (title, report_type, file_path, total_incidents, avg_risk_score)
        VALUES (?, ?, ?, ?, ?)
        ''', (report_title, "Executive Incident Summary", file_path, total_alerts, avg_risk))

        print(f"[NetSentry AI] Generated PDF report: {file_path} (ID: {report_id})")
        return report_id, file_path, filename
