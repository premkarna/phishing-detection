from fpdf import FPDF
import datetime
import os
import unicodedata

class SOCReport(FPDF):
    def header(self):
        # Professional Header with Blue/Dark Theme
        self.set_fill_color(30, 41, 59) # Dark Slate
        self.rect(0, 0, 210, 40, 'F')
        
        self.set_font('Arial', 'B', 20)
        self.set_text_color(255, 255, 255)
        self.cell(0, 15, 'SENTINEL GUARDIAN', 0, 1, 'C')
        
        self.set_font('Arial', 'B', 12)
        self.set_text_color(59, 130, 246) # Blue
        self.cell(0, 10, 'SOC FORENSIC INTELLIGENCE REPORT', 0, 1, 'C')
        
        self.ln(10)

    def footer(self):
        self.set_y(-20)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)
        self.cell(0, 10, f'Confidential SOC Report - ID: SG-{int(datetime.datetime.now().timestamp())} - Page {self.page_no()}', 0, 0, 'C')

def _safe(text):
    """Sanitize text to Latin-1 safe string for fpdf v1."""
    if not isinstance(text, str):
        text = str(text)
    text = unicodedata.normalize('NFKD', text)
    return text.encode('latin-1', errors='replace').decode('latin-1')

def generate_pdf_report(scan_data):
    pdf = SOCReport()
    pdf.add_page()
    
    # 1. Summary Box
    risk = scan_data.get('calculated_risk', 0)
    threat_status = "BENIGN"
    color = (16, 185, 129) # Green

    if risk >= 70:
        color = (239, 68, 68) # Red
        threat_status = "CRITICAL THREAT"
    elif risk >= 30:
        color = (245, 158, 11) # Orange
        threat_status = "SUSPICIOUS"
        
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 15, f'  FINAL VERDICT: {threat_status} (Risk Score: {risk}/100)', 0, 1, 'L', True)
    pdf.ln(5)
    
    # 2. Forensic Metadata (Table-like structure)
    pdf.set_text_color(30, 41, 59)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '1. FORENSIC METADATA & INFRASTRUCTURE', 0, 1, 'L')
    
    pdf.set_font('Arial', 'B', 10)
    pdf.set_fill_color(241, 245, 249)
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")
    target = _safe(str(scan_data.get('target_url', scan_data.get('payload', 'Unknown Target'))))
    if len(target) > 60: target = target[:57] + "..."
    
    metadata = [
        ("Scan Timestamp", timestamp),
        ("Target Payload", target),
        ("Source IP Address", _safe(scan_data.get('server_ip_loc', '127.0.0.1 (Internal/Hidden)'))),
        ("Domain Longevity", _safe(scan_data.get('domain_age', 'N/A'))),
        ("SSL Certificate", _safe(scan_data.get('ssl_certificate', 'N/A'))),
        ("Threat Intel (VT)", _safe(scan_data.get('virustotal', '0/94 Flags'))),
        ("Brand Analysis", _safe(scan_data.get('brand_check', 'Legitimate')))
    ]
    
    for label, value in metadata:
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(50, 8, f" {label}:", 1, 0, 'L', True)
        pdf.set_font('Arial', '', 10)
        pdf.cell(140, 8, f" {value}", 1, 1, 'L')
        
    pdf.ln(10)
    
    # 3. AI Cognitive Analysis Section
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '2. AI GUARDIAN COGNITIVE ANALYSIS', 0, 1, 'L')
    
    ai_data = scan_data.get('ai_report', {}) or {}
    if not isinstance(ai_data, dict):
        ai_data = {}
    
    # Box for AI Verdict
    pdf.set_draw_color(59, 130, 246)
    pdf.set_line_width(0.5)
    pdf.set_fill_color(239, 246, 255)
    
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(0, 10, _safe(f" AI Verdict: {ai_data.get('verdict', 'NEUTRAL')}"), 1, 1, 'L', True)
    
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(50, 50, 50)
    pdf.multi_cell(0, 6, _safe(f" Reasoning: {ai_data.get('reason', 'N/A')}"), 1)
    
    pdf.ln(5)
    
    # Operational Advice in colored box
    pdf.set_fill_color(255, 251, 235) # Light yellow
    pdf.set_font('Arial', 'B', 10)
    pdf.set_text_color(180, 83, 9) # Brown/Orange
    pdf.multi_cell(0, 8, _safe(f" PROACTIVE ADVICE: {ai_data.get('advice', 'N/A')}"), 1, 'L', True)
    
    pdf.ln(5)

    # 4. Automated Incident Response (SOAR)
    playbook = scan_data.get('soar_playbook', []) or []
    if isinstance(playbook, list) and playbook:
        pdf.set_text_color(30, 41, 59)
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, '3. AUTOMATED INCIDENT RESPONSE PLAYBOOK (SOAR)', 0, 1, 'L')
        pdf.set_font('Arial', '', 10)
        for i, step in enumerate(playbook):
            step_text = step if isinstance(step, str) else str(step)
            pdf.cell(10, 8, f"{i+1}.", 0, 0, 'L')
            pdf.cell(0, 8, _safe(step_text), 0, 1, 'L')

    # Security Awareness Disclaimer
    pdf.ln(10)
    pdf.set_font('Arial', 'I', 8)
    pdf.set_text_color(100, 100, 100)
    disclaimer = "This report was automatically generated following a proactive security scan. The user's decision to verify this payload demonstrates high security awareness and commitment to organizational data protection protocols."
    pdf.multi_cell(0, 4, disclaimer, 0, 'C')
    
    _reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "reports")
    os.makedirs(_reports_dir, exist_ok=True)
    filename = os.path.join(_reports_dir, f"SOC_Incident_{int(datetime.datetime.now().timestamp())}.pdf")
    pdf.output(filename)
    
    return filename
