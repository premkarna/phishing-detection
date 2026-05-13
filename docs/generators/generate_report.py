"""
PHISHING SENTINEL – Project Report Generator
Generates a Word document matching SRM University Department of CSE format.
Reference: DEPARTMENT CSE Live Project Format (May-2026)
Reference: Phishing_Sentinel_Project_Report_final (2).docx
"""

import os
from docx import Document
from docx.shared import Pt, Inches, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn, nsdecls
from docx.oxml import parse_xml
from docx.enum.section import WD_ORIENT
from lxml import etree

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _force_tnr(run):
    """Force Times New Roman at XML level to override Normal template."""
    rPr = run._r.get_or_add_rPr()
    rFonts = rPr.find(qn('w:rFonts'))
    if rFonts is None:
        rFonts = parse_xml(f'<w:rFonts {nsdecls("w")} w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman" w:eastAsia="Times New Roman"/>')
        rPr.insert(0, rFonts)
    else:
        for attr in ['w:ascii', 'w:hAnsi', 'w:cs', 'w:eastAsia']:
            rFonts.set(qn(attr), 'Times New Roman')

def _set_right_tab(para, tab_pos_inches=6.0):
    """Set a right-aligned tab stop with dot leader on a paragraph (for TOC entries)."""
    pPr = para._p.get_or_add_pPr()
    tabs_elem = pPr.find(qn('w:tabs'))
    if tabs_elem is None:
        tabs_elem = parse_xml(f'<w:tabs {nsdecls("w")}/>')
        pPr.append(tabs_elem)
    # tab_pos in twips (1 inch = 1440 twips)
    twips = int(tab_pos_inches * 1440)
    tab = parse_xml(f'<w:tab {nsdecls("w")} w:val="right" w:leader="dot" w:pos="{twips}"/>')
    tabs_elem.append(tab)

def _add_run(para, text, size=12, bold=False, italic=False, color=None):
    """Add a run with TNR enforcement."""
    r = para.add_run(text)
    r.font.name = 'Times New Roman'
    r.font.size = Pt(size)
    r.bold = bold
    r.italic = italic
    if color:
        r.font.color.rgb = RGBColor(*color)
    _force_tnr(r)
    return r

def chapter_heading(doc, text):
    """Chapter title: CENTER, 14pt, BOLD, page break before, bottom border line. Matches ref: color=1A5376."""
    p = doc.add_paragraph()
    p.paragraph_format.page_break_before = True
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    _add_run(p, text, size=14, bold=True, color=(0x1A, 0x53, 0x76))
    _add_bottom_border(p, color='1A5376', size='8')
    return p

def _add_bottom_border(para, color='2C3E50', size='6'):
    """Add a bottom border line under a paragraph."""
    pPr = para._p.get_or_add_pPr()
    pBdr = pPr.find(qn('w:pBdr'))
    if pBdr is None:
        pBdr = parse_xml(f'<w:pBdr {nsdecls("w")}/>')
        pPr.append(pBdr)
    bottom = parse_xml(f'<w:bottom {nsdecls("w")} w:val="single" w:sz="{size}" w:space="1" w:color="{color}"/>')
    pBdr.append(bottom)

def section_heading(doc, text):
    """Section heading (e.g., 1.1 Title): LEFT, BOLD. Matches ref: color=2C3E50, no explicit size."""
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.keep_with_next = True
    _add_run(p, text, size=12, bold=True, color=(0x2C, 0x3E, 0x50))
    return p

def subsection_heading(doc, text):
    """Subsection heading (e.g., 3.2.1 Title): LEFT, BOLD ITALIC, color=2C3E50."""
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(7)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    _add_run(p, text, size=12, bold=True, italic=True, color=(0x2C, 0x3E, 0x50))
    return p

def body(doc, text):
    """Body paragraph: JUSTIFY. Inherits Normal style (TNR 12pt, 1.5 spacing). Matches ref: sb=3pt sa=5pt."""
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(5)
    r = p.add_run(text)
    _force_tnr(r)
    return p

def bullet(doc, text):
    """Bullet point: LEFT, inherits Normal. Matches ref: sb=2pt sa=2pt, no indent."""
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    r = p.add_run(text)
    _force_tnr(r)
    return p

def _add_box_border(para, color='CCCCCC', size='4'):
    """Add a full box border (top, bottom, left, right) around a paragraph."""
    pPr = para._p.get_or_add_pPr()
    pBdr = pPr.find(qn('w:pBdr'))
    if pBdr is None:
        pBdr = parse_xml(f'<w:pBdr {nsdecls("w")}/>')
        pPr.append(pBdr)
    for side in ['top', 'bottom', 'left', 'right']:
        elem = parse_xml(f'<w:{side} {nsdecls("w")} w:val="single" w:sz="{size}" w:space="4" w:color="{color}"/>')
        pBdr.append(elem)

def _add_shading(para, fill='F2F2F2'):
    """Add light gray background shading to a paragraph."""
    pPr = para._p.get_or_add_pPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:val="clear" w:color="auto" w:fill="{fill}"/>')
    pPr.append(shd)

def code_block(doc, text):
    """Code snippet: LEFT, 9pt, single spacing, Courier New, with border box and shading."""
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.left_indent = Inches(0.3)
    p.paragraph_format.right_indent = Inches(0.3)
    from docx.enum.text import WD_LINE_SPACING
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.SINGLE
    r = p.add_run(text)
    r.font.name = 'Courier New'
    r.font.size = Pt(9)
    # Force Courier New
    rPr = r._r.get_or_add_rPr()
    rFonts = rPr.find(qn('w:rFonts'))
    if rFonts is None:
        rFonts = parse_xml(f'<w:rFonts {nsdecls("w")} w:ascii="Courier New" w:hAnsi="Courier New" w:cs="Courier New"/>')
        rPr.insert(0, rFonts)
    _add_box_border(p, color='BFBFBF', size='4')
    _add_shading(p, fill='F5F5F5')
    return p

def figure_caption(doc, number, caption_text):
    """Figure caption: CENTER, 12pt, bold number."""
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(12)
    _add_run(p, f"Figure {number}: ", size=12, bold=True)
    _add_run(p, caption_text, size=12)
    return p

def figure_placeholder(doc, number, caption_text, img_path=None):
    """Insert figure image (or placeholder) + centered caption."""
    if img_path and os.path.exists(img_path):
        p = doc.add_paragraph()
        p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(6)
        r = p.add_run()
        r.add_picture(img_path, width=Inches(5.0))
    else:
        p = doc.add_paragraph()
        p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(6)
        _add_run(p, f"[Figure {number} – Image: {caption_text}]", size=10, italic=True)
    figure_caption(doc, number, caption_text)

def table_caption(doc, number, caption_text):
    """Table caption: CENTER, 12pt, bold number — placed ABOVE table."""
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    _add_run(p, f"Table {number}: ", size=12, bold=True)
    _add_run(p, caption_text, size=12)
    return p

def add_table(doc, data):
    """Add table with header row shaded. data[0] is header."""
    t = doc.add_table(rows=len(data), cols=len(data[0]))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row_data in enumerate(data):
        for j, cell_text in enumerate(row_data):
            cell = t.rows[i].cells[j]
            cell.text = ''
            p = cell.paragraphs[0]
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            _add_run(p, str(cell_text), size=10, bold=(i == 0))
    # Shade header row
    for cell in t.rows[0].cells:
        shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="D9E2F3" w:val="clear"/>')
        cell._tc.get_or_add_tcPr().append(shading)
    # Set borders
    tbl = t._tbl
    tblPr = tbl.tblPr if tbl.tblPr is not None else parse_xml(f'<w:tblPr {nsdecls("w")}/>')
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        '<w:top w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
        '<w:left w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
        '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
        '<w:right w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
        '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
        '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
        '</w:tblBorders>'
    )
    tblPr.append(borders)
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    return t

def pb(doc):
    """Insert a page break."""
    from docx.enum.text import WD_BREAK
    p = doc.add_paragraph()
    r = p.add_run()
    r.add_break(WD_BREAK.PAGE)

def add_page_number_field(paragraph):
    """Add a PAGE field code to a paragraph."""
    run = paragraph.add_run()
    fldChar1 = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>')
    run._r.append(fldChar1)
    run2 = paragraph.add_run()
    instrText = parse_xml(f'<w:instrText {nsdecls("w")} xml:space="preserve"> PAGE </w:instrText>')
    run2._r.append(instrText)
    run3 = paragraph.add_run()
    fldChar2 = parse_xml(f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>')
    run3._r.append(fldChar2)

def setup_footer_page_numbers(section):
    """Add page number to section footer, bottom-center, 10pt TNR."""
    footer = section.footer
    footer.is_linked_to_previous = False
    p = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.clear()
    add_page_number_field(p)
    for r in p.runs:
        r.font.size = Pt(10)
        r.font.name = 'Times New Roman'
        _force_tnr(r)

def set_page_number_start(section, start=1, fmt='decimal'):
    """Set page number format and start value for a section."""
    sectPr = section._sectPr
    pgNumType = sectPr.find(qn('w:pgNumType'))
    if pgNumType is None:
        pgNumType = parse_xml(f'<w:pgNumType {nsdecls("w")}/>')
        sectPr.append(pgNumType)
    pgNumType.set(qn('w:start'), str(start))
    if fmt == 'roman':
        pgNumType.set(qn('w:fmt'), 'lowerRoman')
    else:
        pgNumType.set(qn('w:fmt'), 'decimal')

def add_section_break(doc):
    """Add a next-page section break."""
    p = doc.add_paragraph()
    pPr = p._p.get_or_add_pPr()
    sectPr = parse_xml(f'<w:sectPr {nsdecls("w")}><w:type {nsdecls("w")} w:val="nextPage"/></w:sectPr>')
    pPr.append(sectPr)

# ══════════════════════════════════════════════════════════════════════════════
# DOCUMENT SETUP
# ══════════════════════════════════════════════════════════════════════════════

def setup_doc():
    """Create document with A4, margins per SRM format. Normal style matches reference."""
    doc = Document()
    sec = doc.sections[0]
    sec.page_width = Cm(21.0)
    sec.page_height = Cm(29.7)
    sec.top_margin = Inches(1.0)
    sec.bottom_margin = Inches(1.0)
    sec.left_margin = Inches(1.25)
    sec.right_margin = Inches(1.0)
    # Set Normal style to match reference: TNR 12pt, 1.5 spacing
    style = doc.styles['Normal']
    font = style.font
    font.name = 'Times New Roman'
    font.size = Pt(12)
    # Force TNR at XML level on Normal style
    rPr = style.element.get_or_add_rPr()
    rFonts = rPr.find(qn('w:rFonts'))
    if rFonts is None:
        rFonts = parse_xml(f'<w:rFonts {nsdecls("w")} w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman" w:eastAsia="Times New Roman"/>')
        rPr.insert(0, rFonts)
    else:
        for attr in ['w:ascii', 'w:hAnsi', 'w:cs', 'w:eastAsia']:
            rFonts.set(qn(attr), 'Times New Roman')
    # Set 1.5 line spacing on Normal style
    from docx.enum.text import WD_LINE_SPACING
    style.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    return doc

# ══════════════════════════════════════════════════════════════════════════════
# FRONT MATTER
# ══════════════════════════════════════════════════════════════════════════════

def title_page(doc):
    """SRM format title page."""
    for _ in range(2):
        doc.add_paragraph()
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "LIVE PROJECT REPORT", size=18, bold=True)

    doc.add_paragraph()
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "PHISHING SENTINEL", size=20, italic=True)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "AI-Powered Multi-Vector Phishing Detection & SOC Platform", size=16, italic=True)

    for _ in range(2):
        doc.add_paragraph()
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "Submitted in partial fulfillment of the requirements", size=14, italic=True)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "for the award of the degree of", size=14, italic=True)

    for _ in range(2):
        doc.add_paragraph()
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "Bachelor of Technology", size=20)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "Computer Science and Engineering", size=20)

    for _ in range(2):
        doc.add_paragraph()
    # Supervisor and student info
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    _add_run(p, "Supervisor: ", size=12, bold=True)
    _add_run(p, "[Supervisor Name]", size=12)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    _add_run(p, "Designation: ", size=12, bold=True)
    _add_run(p, "[Designation]", size=12)

    doc.add_paragraph()
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _add_run(p, "Submitted by:", size=12, bold=True)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _add_run(p, "Prem Karna", size=12)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _add_run(p, "Roll No: [Your Roll No]", size=12)

    for _ in range(3):
        doc.add_paragraph()
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "SRM UNIVERSITY, DELHI-NCR, SONEPAT, HARYANA", size=12, bold=True)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "Plot No. 39, Rajiv Gandhi Education City, Sonepat, Haryana 131029", size=11)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "MAY 2026", size=12, bold=True)

def project_approval_page(doc):
    pb(doc)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "DEPARTMENT OF COMPUTER SCIENCE & ENGINEERING", size=12, bold=True)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "PROJECT APPROVAL PAGE", size=14, bold=True)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _add_run(p, "B.Tech CSE [Cloud Engg. & DevOps Automation] & [Blockchain & IOT]", size=12)

    doc.add_paragraph()
    body(doc, "GROUP No: ___          SESSION 2025 - 2026")
    doc.add_paragraph()
    body(doc, "To be filled in by the student:")
    body(doc, "Student Name(s): Prem Karna")
    body(doc, "Enrolment Number: [Your Roll No]")
    body(doc, "Project Title: PHISHING SENTINEL – AI-Powered Multi-Vector Phishing Detection & SOC Platform")
    body(doc, "Signature: ___________________")
    doc.add_paragraph()
    body(doc, "To be filled in by the supervisor:")
    body(doc, "This is to certify that the project submitted and presented by the above-mentioned student(s) is")
    body(doc, "COMPLETE          ACCEPTED")
    body(doc, "and the draft of the graduation project report has been corrected for all content flaws, typing errors, and language mistakes.")
    doc.add_paragraph()
    body(doc, "Supervisor name and Signature: ___________________          Date: ___________")
    body(doc, "Examiner's Name and Signature: ___________________          Date: ___________")
    body(doc, "HOD's Signature: ___________________          Date: ___________")

def declaration(doc):
    pb(doc)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(18)
    _add_run(p, "CANDIDATE'S DECLARATION", size=14, bold=True)

    body(doc, "I hereby certify that the work which is being presented in the project entitled \"PHISHING SENTINEL – AI-Powered Multi-Vector Phishing Detection & SOC Platform\" in partial fulfillment of the requirement for the award of the Degree of Bachelor of Technology in Computer Science and Engineering of SRM University, Delhi-NCR, Sonepat, Haryana, (India) is an authentic record of my own work carried out under the supervision of [Supervisor Name], as Live project in 6th Semester during the academic year 2025-26. The matter presented in this project has not been submitted for the award of any other degree of this or any other Institute/University.")
    for _ in range(4):
        doc.add_paragraph()
    p = doc.add_paragraph()
    _add_run(p, "Prem Karna", size=12)
    p = doc.add_paragraph()
    _add_run(p, "Registration No.: [Your Roll No]", size=12)

def certificate(doc):
    pb(doc)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(18)
    _add_run(p, "CERTIFICATE", size=14, bold=True)

    body(doc, "This is to certify that the \"PHISHING SENTINEL\" project is a Bonafide work completed as a Live Project (Course Code: 21CS4114) in partial fulfilment for the award of the degree of Bachelor of Technology in CSE under the guidance of [Supervisor Name]. This project is submitted by Prem Karna ([Your Roll No]), during the academic Semester VI of year 2025-2026 of SRM University, Delhi-NCR, Sonipat, Haryana.")
    for _ in range(5):
        doc.add_paragraph()
    p = doc.add_paragraph()
    _add_run(p, "[Supervisor Name]", size=12)
    p = doc.add_paragraph()
    _add_run(p, "[Designation]", size=12)

def acknowledgement(doc):
    pb(doc)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(18)
    _add_run(p, "ACKNOWLEDGEMENT", size=14, bold=True)

    body(doc, "Most importantly, I would like to express my immense gratitude to my supervisor [Supervisor Name], for his/her patient guidance, encouragement, training, and advice throughout the project. The knowledge I have gained throughout this time will stay with me for years to come. I have been extremely lucky to have such a supervisor who cared for my work and responded to my questions and queries so promptly.")
    body(doc, "I also sincerely thank the Project Coordinator, Dr. Mohd. Kaleem, for his valuable guidance, continuous support, and encouragement throughout the project.")
    body(doc, "I would like to extend my indebtedness to the Project Committee Members, Department of Computer Science and Engineering, SRM University Delhi-NCR, Sonepat as I have benefited so much from the constructive criticism and suggestions given during the project.")
    body(doc, "I also sincerely thank the Program Coordinator, Dr. Ruchi / Dr. Mohd Dilshad Ansari / Ms. Namrata Sukhija, for valuable guidance and support throughout the program.")
    body(doc, "I feel compelled to articulate my thankfulness to Prof. M. Mohan, HOD, Department of Computer Science and Engineering, SRM University for his encouragement which was a source of inspiration.")
    body(doc, "Lastly, I am indebted to all the teaching and non-teaching staff members of the university for helping me directly or indirectly throughout the course of study and project work.")

def abstract_page(doc):
    pb(doc)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(18)
    _add_run(p, "ABSTRACT", size=14, bold=True)

    body(doc, "Phishing attacks continue to be one of the most pervasive and damaging forms of cybercrime, accounting for billions of dollars in losses annually and serving as the initial access vector in over 90% of data breaches. Modern phishing has evolved far beyond simple email scams into a sophisticated multi-channel threat ecosystem exploiting URLs, emails, QR codes, SMS, voice calls, cloned websites, and social engineering manipulation simultaneously.")
    body(doc, "This project presents PHISHING SENTINEL, a comprehensive, enterprise-grade, multi-vector phishing detection and Security Operations Center (SOC) platform. The system integrates seven specialized detection engines — URLEngine (typosquatting and domain forensics), EMLEngine (spear-phishing with SPF/DKIM/DMARC validation), QREngine (quishing detection), SmishingEngine (SMS phishing analysis), VishingEngine (voice call social engineering detection), CloneEngine (website clone radar), and SocialEngineeringEngine (psychological manipulation pattern detection).")
    body(doc, "The platform features a real-time SOC dashboard with 3D threat visualization, automated SOAR playbook generation following NIST IR framework, OSINT intelligence scanning via VirusTotal and URLhaus APIs, and a multi-tier AI consensus architecture combining Google Gemini Pro AI analysis (35% weight), local Random Forest ML model (25% weight), and engine-specific heuristic scoring (40% weight).")
    body(doc, "Evaluation across 35+ test cases covering all 7 threat vectors demonstrates a detection accuracy of 94.3%, precision of 95.0%, recall of 95.0%, and F1 score of 95.0% — with sub-3-second response times on consumer hardware. The platform addresses four critical gaps identified in the literature: multi-vector unification, real-time OSINT integration, automated SOAR response, and comprehensive SOC visualization.")
    doc.add_paragraph()
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
    _add_run(p, "Keywords: ", size=12, bold=True)
    _add_run(p, "Phishing Detection, Multi-Vector Analysis, SOC Platform, Gemini AI, URL Forensics, EML Analysis, Quishing, Vishing, SOAR, Random Forest, Threat Intelligence", size=12)

def table_of_contents(doc):
    pb(doc)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(18)
    _add_run(p, "TABLE OF CONTENTS", size=14, bold=True)

    toc_items = [
        ("TITLE PAGE", "i"),
        ("PROJECT APPROVAL PAGE", "ii"),
        ("CANDIDATE'S DECLARATION", "iii"),
        ("CERTIFICATE", "iv"),
        ("ACKNOWLEDGEMENT", "v"),
        ("ABSTRACT", "vi"),
        ("TABLE OF CONTENTS", "vii"),
        ("LIST OF FIGURES", "viii"),
        ("LIST OF TABLES", "ix"),
        ("", ""),
        ("CHAPTER 1: INTRODUCTION", "1"),
        ("  1.1 Background and Context", "1"),
        ("  1.2 Problem Statement", "3"),
        ("  1.3 Objectives", "4"),
        ("  1.4 Project Scope", "5"),
        ("  1.5 Research Methodology Overview", "6"),
        ("  1.6 Report Organization", "7"),
        ("", ""),
        ("CHAPTER 2: LITERATURE REVIEW", "8"),
        ("  2.1 Evolution and Taxonomy of Phishing Attacks", "8"),
        ("  2.2 URL and Domain-Based Phishing Detection", "9"),
        ("  2.3 Email Forensics and Spear-Phishing Detection", "10"),
        ("  2.4 QR Code Quishing Research", "11"),
        ("  2.5 SMS Smishing and Voice Vishing Detection", "11"),
        ("  2.6 Clone Site Detection and Social Engineering", "12"),
        ("  2.7 AI and Large Language Models in Threat Detection", "13"),
        ("  2.8 Research Gaps Addressed by This Project", "14"),
        ("", ""),
        ("CHAPTER 3: METHODOLOGY", "16"),
        ("  3.1 Development Methodology and Project Phases", "16"),
        ("  3.2 Technology Stack and Selection Rationale", "17"),
        ("  3.3 System Architecture (Five-Layer Design)", "19"),
        ("  3.4 Multi-Tier AI Consensus Architecture", "20"),
        ("  3.5 Database and Caching Design", "21"),
        ("", ""),
        ("CHAPTER 4: SYSTEM DESIGN", "23"),
        ("  4.1 High-Level Architecture Diagram", "23"),
        ("  4.2 Seven-Engine Detection Pipeline", "24"),
        ("  4.3 REST API Design (9 Endpoints)", "26"),
        ("  4.4 Data Flow Diagrams", "27"),
        ("  4.5 Utility Module Architecture", "28"),
        ("  4.6 Security Design and Ethical Considerations", "30"),
        ("  4.7 SOC Dashboard UI/UX Design", "31"),
        ("", ""),
        ("CHAPTER 5: IMPLEMENTATION", "32"),
        ("  5.1 URL/Typosquatting Engine", "32"),
        ("  5.2 EML Spear-Phishing Engine", "34"),
        ("  5.3 QR/Quishing Engine", "35"),
        ("  5.4 SMS/Smishing Engine", "36"),
        ("  5.5 Voice/Vishing Engine", "37"),
        ("  5.6 Clone Site Radar", "39"),
        ("  5.7 Social Engineering Engine", "40"),
        ("  5.8 AI Handler", "41"),
        ("  5.9 Local ML Fallback", "42"),
        ("  5.10 SOAR and OSINT Integration", "43"),
        ("  5.11 Supporting Utility Modules", "45"),
        ("  5.12 Flask Orchestration Layer", "46"),
        ("  5.13 File Upload System", "48"),
        ("  5.14 Advanced Features API Layer", "49"),
        ("  5.15 Frontend Implementation", "50"),
        ("  5.16 Accuracy Dashboard", "53"),
        ("", ""),
        ("CHAPTER 6: TESTING AND RESULTS", "54"),
        ("  6.1 Testing Methodology", "54"),
        ("  6.2 URL Engine Test Results", "55"),
        ("  6.3 EML Engine Test Results", "56"),
        ("  6.4 QR/Quishing and Smishing Results", "57"),
        ("  6.5 Vishing, Clone, and Social Engineering Results", "58"),
        ("  6.6 Overall Accuracy Metrics", "59"),
        ("  6.7 Performance Benchmarks", "60"),
        ("  6.8 Bug Fixes and Resolution", "61"),
        ("", ""),
        ("CHAPTER 7: CONCLUSION AND FUTURE WORK", "62"),
        ("  7.1 Summary of Achievements", "62"),
        ("  7.2 Complete Feature Summary", "63"),
        ("  7.3 Quantitative Results", "64"),
        ("  7.4 Limitations", "65"),
        ("  7.5 Future Work", "65"),
        ("  7.6 Final Remarks", "66"),
        ("", ""),
        ("REFERENCES", "67"),
    ]
    for item, page in toc_items:
        if not item:
            doc.add_paragraph()
            continue
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(1)
        p.paragraph_format.space_after = Pt(1)
        # Right-aligned tab stop with dot leader at 6.0" (right margin edge)
        _set_right_tab(p, tab_pos_inches=6.0)
        if item.startswith("  "):
            p.paragraph_format.left_indent = Inches(0.4)
            _add_run(p, item.strip(), size=12)
        else:
            _add_run(p, item, size=12, bold=True)
        # Tab + page number (will snap to right edge with dots)
        tab_run = p.add_run()
        tab_run.font.name = 'Times New Roman'
        tab_run.font.size = Pt(12)
        _force_tnr(tab_run)
        tab_run.add_tab()
        _add_run(p, page, size=12)

def list_of_figures(doc):
    pb(doc)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(18)
    _add_run(p, "LIST OF FIGURES", size=14, bold=True)

    figures = [
        ("3.1", "High-Level System Architecture"),
        ("3.2", "Multi-Tier AI Consensus Architecture"),
        ("4.1", "Seven-Engine Detection Pipeline"),
        ("4.2", "Data Flow Diagram"),
        ("4.3", "SOC Dashboard UI \u2013 Neon Glassmorphic Design"),
        ("5.1", "URL Engine 8-Layer Detection Pipeline"),
        ("5.2", "URL Engine Risk Score Distribution"),
        ("6.1", "Accuracy Metrics Visualization"),
    ]
    for num, cap in figures:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        _set_right_tab(p, tab_pos_inches=6.0)
        _add_run(p, f"Figure {num}: {cap}", size=12)
        tab_run = p.add_run()
        tab_run.font.name = 'Times New Roman'
        tab_run.font.size = Pt(12)
        _force_tnr(tab_run)
        tab_run.add_tab()
        # Approximate page numbers for figures
        pg_map = {'3.1':'19','3.2':'21','4.1':'24','4.2':'27','4.3':'31','5.1':'33','5.2':'55','6.1':'59'}
        _add_run(p, pg_map.get(num, ''), size=12)

def list_of_tables(doc):
    pb(doc)
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(18)
    _add_run(p, "LIST OF TABLES", size=14, bold=True)

    tables = [
        ("2.1", "Comparison with Existing Open-Source Phishing Detection Tools"),
        ("3.1", "Technology Stack and Selection Rationale"),
        ("4.1", "REST API Endpoint Specifications"),
        ("5.1", "12 Advanced Vishing Detection Features"),
        ("6.1", "URL Engine Test Results"),
        ("6.2", "EML Engine Test Results"),
        ("6.3", "QR Engine Test Results"),
        ("6.4", "Smishing Engine Test Results"),
        ("6.5", "Vishing Engine Test Results"),
        ("6.6", "Clone Site Detection Results"),
        ("6.7", "Social Engineering Results"),
        ("6.8", "Confusion Matrix \u2013 Overall System Performance"),
        ("6.9", "Average Response Time by Engine"),
        ("6.10", "Bug Discovery and Resolution Summary"),
        ("7.1", "Key Performance Metrics"),
    ]
    for num, cap in tables:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        _set_right_tab(p, tab_pos_inches=6.0)
        _add_run(p, f"Table {num}: {cap}", size=12)
        tab_run = p.add_run()
        tab_run.font.name = 'Times New Roman'
        tab_run.font.size = Pt(12)
        _force_tnr(tab_run)
        tab_run.add_tab()
        # Approximate page numbers for tables
        pg_map = {'2.1':'14','3.1':'17','4.1':'26','5.1':'38','6.1':'55','6.2':'56','6.3':'57','6.4':'57','6.5':'58','6.6':'58','6.7':'58','6.8':'59','6.9':'60','6.10':'61','7.1':'64'}
        _add_run(p, pg_map.get(num, ''), size=12)

# ══════════════════════════════════════════════════════════════════════════════
# CHAPTER CONTENT
# ══════════════════════════════════════════════════════════════════════════════

from generate_report_chapters import chapter1, chapter2, chapter3, chapter4, chapter5, chapter6, chapter7, references

# ══════════════════════════════════════════════════════════════════════════════
# GENERATE
# ══════════════════════════════════════════════════════════════════════════════

def generate():
    doc = setup_doc()

    # ── Front matter (Roman numeral pages) ──
    title_page(doc)
    project_approval_page(doc)
    declaration(doc)
    certificate(doc)
    acknowledgement(doc)
    abstract_page(doc)
    table_of_contents(doc)
    list_of_figures(doc)
    list_of_tables(doc)

    # ── Section break: switch to Arabic page numbers ──
    add_section_break(doc)

    # ── Body chapters ──
    chapter1(doc)
    chapter2(doc)
    chapter3(doc)
    chapter4(doc)
    chapter5(doc)
    chapter6(doc)
    chapter7(doc)
    references(doc)

    # ── Set margins on ALL sections ──
    for sec in doc.sections:
        sec.top_margin = Inches(1.0)
        sec.bottom_margin = Inches(1.0)
        sec.left_margin = Inches(1.25)
        sec.right_margin = Inches(1.0)
        sec.page_width = Cm(21.0)
        sec.page_height = Cm(29.7)

    # ── Page numbering ──
    # Section 0: front matter with Roman numerals starting at i
    sec0 = doc.sections[0]
    set_page_number_start(sec0, start=1, fmt='roman')
    setup_footer_page_numbers(sec0)

    # Section 1: body with Arabic numerals starting at 1
    sec1 = doc.sections[-1]
    set_page_number_start(sec1, start=1, fmt='decimal')
    setup_footer_page_numbers(sec1)

    # Save
    out = r'c:\Users\premv\Phishing-detection\Phishing_Sentinel_Project_Report.docx'
    doc.save(out)
    print(f"[+] Report saved: {out}")
    print(f"    Paragraphs: {len(doc.paragraphs)}")
    print(f"    Tables: {len(doc.tables)}")
    print(f"    Sections: {len(doc.sections)}")

if __name__ == '__main__':
    generate()
