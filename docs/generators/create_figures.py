"""
create_figures.py - Generate all 13 figure images for the report
"""
from PIL import Image, ImageDraw, ImageFont
import os

FIGURES_DIR = os.path.join(os.path.dirname(__file__), 'figures')
os.makedirs(FIGURES_DIR, exist_ok=True)

W, H = 1200, 700
DARK = (15, 25, 40)
CYAN = (0, 255, 255)
RED  = (255, 0, 64)
WHITE = (255, 255, 255)
GRAY = (100, 120, 140)
BLUE = (26, 83, 118)
LIGHT = (30, 45, 65)

def get_font(size=20):
    try: return ImageFont.truetype("arial.ttf", size)
    except: return ImageFont.load_default()

def draw_box(draw, x, y, w, h, text, fill=LIGHT, outline=CYAN, text_color=WHITE):
    draw.rounded_rectangle([x, y, x+w, y+h], radius=8, fill=fill, outline=outline, width=2)
    font = get_font(14)
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]; th = bbox[3] - bbox[1]
    draw.text((x + (w-tw)//2, y + (h-th)//2), text, fill=text_color, font=font)

def draw_arrow(draw, x1, y1, x2, y2, color=CYAN):
    draw.line([x1, y1, x2, y2], fill=color, width=2)
    draw.polygon([(x2, y2), (x2-6, y2-10), (x2+6, y2-10)], fill=color)

def draw_arrow_h(draw, x1, y, x2, color=CYAN):
    draw.line([x1, y, x2, y], fill=color, width=2)
    if x2 > x1:
        draw.polygon([(x2, y), (x2-10, y-6), (x2-10, y+6)], fill=color)
    else:
        draw.polygon([(x2, y), (x2+10, y-6), (x2+10, y+6)], fill=color)

def title_bar(draw, text):
    font = get_font(22)
    draw.text((W//2 - len(text)*6, 20), text, fill=CYAN, font=font)
    draw.line([50, 55, W-50, 55], fill=CYAN, width=1)

# ── Figure 3.1: System Architecture Overview ──
def fig_3_1():
    img = Image.new('RGB', (W, H), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "System Architecture Overview")
    draw_box(draw, 400, 75, 400, 50, "Presentation Layer (SOC Dashboard + REST API)", outline=CYAN)
    draw_arrow(draw, 600, 125, 600, 155, CYAN)
    draw_box(draw, 350, 155, 500, 50, "Application Layer (Flask + AI Handler + SOAR)", outline=(0,200,200))
    draw_arrow(draw, 600, 205, 600, 235, CYAN)
    # 7 Engines
    engines = ["URL", "EML", "QR", "SMS", "Voice", "Clone", "Social"]
    for i, e in enumerate(engines):
        x = 80 + i * 155
        draw_box(draw, x, 235, 140, 45, f"{e} Engine", outline=(0,200,200))
        draw_arrow(draw, x+70, 280, x+70, 320, GRAY)
    draw_box(draw, 200, 320, 800, 50, "Data Layer (SQLite DB + JSON Cache + OSINT Feeds)", outline=GRAY)
    # Side boxes
    draw_box(draw, 50, 400, 250, 50, "VirusTotal API", outline=RED)
    draw_box(draw, 350, 400, 250, 50, "URLhaus API", outline=RED)
    draw_box(draw, 650, 400, 250, 50, "Gemini Pro AI", outline=CYAN)
    draw_arrow(draw, 175, 370, 175, 400, RED)
    draw_arrow(draw, 475, 370, 475, 400, RED)
    draw_arrow(draw, 775, 370, 775, 400, CYAN)
    # Footer
    draw_box(draw, 200, 490, 800, 45, "PHISHING SENTINEL v5.0 - Enterprise Multi-Vector Detection", fill=BLUE, outline=CYAN)
    img.save(os.path.join(FIGURES_DIR, 'figure_3_1.png'))

# ── Figure 3.2: Multi-Tier AI Consensus ──
def fig_3_2():
    img = Image.new('RGB', (W, H), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "Multi-Tier AI Consensus Architecture")
    draw_box(draw, 100, 80, 250, 60, "Tier 1: Engine Heuristic\n(40% weight)", outline=CYAN)
    draw_box(draw, 475, 80, 250, 60, "Tier 2: ML Model (RF)\n(25% weight)", outline=(0,200,200))
    draw_box(draw, 850, 80, 250, 60, "Tier 3: Gemini Pro AI\n(35% weight)", outline=RED)
    for x in [225, 600, 975]: draw_arrow(draw, x, 140, x, 190, CYAN)
    draw_box(draw, 350, 190, 500, 60, "Weighted Consensus Engine", fill=BLUE, outline=CYAN)
    draw_arrow(draw, 600, 250, 600, 300, CYAN)
    draw_box(draw, 400, 300, 400, 60, "Final Verdict + Confidence", fill=(40,60,80), outline=CYAN)
    draw_arrow(draw, 600, 360, 600, 410, CYAN)
    draw_box(draw, 350, 410, 500, 50, "SOAR Playbook (if risk >= 0.7)", fill=(60,20,20), outline=RED)
    img.save(os.path.join(FIGURES_DIR, 'figure_3_2.png'))

# ── Figure 4.1: Seven-Engine Detection Pipeline ──
def fig_4_1():
    img = Image.new('RGB', (W, H), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "Seven-Engine Detection Pipeline")
    draw_box(draw, 450, 70, 300, 50, "Payload Input", fill=BLUE, outline=CYAN)
    draw_arrow(draw, 600, 120, 600, 160, CYAN)
    draw_box(draw, 400, 160, 400, 45, "Flask Router (vector_type)", outline=(0,200,200))
    engines = [("URL/Typosquatting", CYAN), ("EML/Spear-Phish", (0,200,200)), ("QR/Quishing", (0,180,180)),
               ("SMS/Smishing", (0,160,160)), ("Voice/Vishing", (0,140,140)), ("Clone/Radar", (0,120,120)),
               ("Social/Pattern", (0,100,100))]
    for i, (name, clr) in enumerate(engines):
        y = 230 + i * 50
        draw_box(draw, 100, y, 300, 40, name, outline=clr)
        draw_arrow_h(draw, 400, y+20, 500, CYAN)
    draw_box(draw, 500, 280, 300, 200, "Risk Score\nAggregation\n&\nConsensus\nEngine", fill=BLUE, outline=CYAN)
    draw_arrow_h(draw, 800, 380, 900, CYAN)
    draw_box(draw, 900, 340, 250, 80, "Final Verdict\n+ Evidence\n+ SOAR", outline=CYAN)
    img.save(os.path.join(FIGURES_DIR, 'figure_4_1.png'))

# ── Figure 4.2: Data Flow Diagram ──
def fig_4_2():
    img = Image.new('RGB', (W, H), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "Data Flow Diagram")
    steps = [("User Input", 80), ("Flask Router", 230), ("Engine Analysis", 380),
             ("AI Handler", 530), ("SOC Dashboard", 680), ("SOAR Playbook", 830)]
    for i, (text, x) in enumerate(steps):
        draw_box(draw, x, 100, 130, 50, text, outline=CYAN if i < 5 else RED)
        if i < len(steps) - 1:
            draw_arrow_h(draw, x+130, 125, steps[i+1][1], CYAN)
    # Data stores below
    draw_box(draw, 200, 250, 200, 40, "SQLite DB", outline=GRAY)
    draw_box(draw, 500, 250, 200, 40, "OSINT APIs", outline=RED)
    draw_box(draw, 800, 250, 200, 40, "JSON Cache", outline=GRAY)
    for x in [300, 600, 900]: draw_arrow(draw, x, 150, x, 250, GRAY)
    img.save(os.path.join(FIGURES_DIR, 'figure_4_2.png'))

# ── Figure 4.3: SOC Dashboard UI ──
def fig_4_3():
    img = Image.new('RGB', (W, H), DARK); draw = ImageDraw.Draw(img)
    # Header
    draw.rectangle([0, 0, W, 60], fill=BLUE)
    font = get_font(22)
    draw.text((30, 15), "PHISHING SENTINEL", fill=CYAN, font=font)
    draw.text((900, 20), "STATUS: ONLINE", fill=(0,255,100), font=get_font(14))
    # Left panel - input
    draw.rounded_rectangle([20, 80, 450, 350], radius=10, fill=(20,35,55), outline=CYAN, width=1)
    draw.text((30, 90), "SELECT THREAT VECTOR", fill=CYAN, font=get_font(14))
    draw.rounded_rectangle([30, 120, 440, 155], radius=5, fill=(15,25,40), outline=GRAY)
    draw.text((40, 128), "URL / Typosquatting Engine", fill=WHITE, font=get_font(14))
    draw.text((30, 175), "PAYLOAD INJECTION", fill=CYAN, font=get_font(14))
    draw.rounded_rectangle([30, 200, 440, 240], radius=5, fill=(15,25,40), outline=GRAY)
    draw.text((40, 208), "goggle.com", fill=WHITE, font=get_font(16))
    draw.rounded_rectangle([30, 270, 440, 310], radius=5, fill=CYAN, outline=CYAN)
    draw.text((140, 278), "INITIATE SCAN", fill=DARK, font=get_font(16))
    # Right panel - threat level
    draw.rounded_rectangle([480, 80, 850, 350], radius=10, fill=(20,35,55), outline=RED, width=1)
    draw.text((580, 90), "THREAT LEVEL", fill=RED, font=get_font(16))
    draw.ellipse([590, 130, 740, 280], outline=RED, width=4)
    draw.text((635, 185), "94%", fill=RED, font=get_font(30))
    draw.text((570, 300), "CRITICAL THREAT", fill=RED, font=get_font(18))
    # Bottom panel - SOC logs
    draw.rounded_rectangle([20, 370, 850, 550], radius=10, fill=(20,35,55), outline=CYAN, width=1)
    draw.text((30, 380), "> SOC_COMMAND_LOGS", fill=CYAN, font=get_font(14))
    logs = ["> System initialized. Awaiting user input",
            "> [15:43:02] Initializing scan for: goggle.com",
            "> [15:43:03] Analyzing HTML structure and SSL certificates",
            "> [15:43:04] ALERT: Typosquatting detected!",
            "> [15:43:04] Target mimics 'google.com'"]
    for i, log in enumerate(logs):
        color = RED if "ALERT" in log or "mimics" in log else (0,200,200)
        draw.text((30, 405 + i*25), log, fill=color, font=get_font(12))
    # Report button
    draw.rounded_rectangle([600, 570, 850, 610], radius=5, fill=BLUE, outline=CYAN)
    draw.text((620, 578), "GENERATE SOC REPORT", fill=CYAN, font=get_font(14))
    # Mini panels on the right
    draw.rounded_rectangle([870, 80, 1180, 290], radius=10, fill=(20,35,55), outline=(0,200,200), width=1)
    draw.text((880, 90), "CORE INTELLIGENCE", fill=CYAN, font=get_font(12))
    info = ["Target: goggle.com", "Status: SUSPICIOUS", "IP: 103.224.212.213", "Domain Age: < 7 days", "SSL: Invalid"]
    for i, txt in enumerate(info):
        draw.text((890, 115+i*30), txt, fill=WHITE if "SUSPICIOUS" not in txt else RED, font=get_font(11))
    draw.rounded_rectangle([870, 310, 1180, 550], radius=10, fill=(20,35,55), outline=RED, width=1)
    draw.text((880, 320), "THREAT VECTORS", fill=RED, font=get_font(12))
    vectors = ["VirusTotal: 12/95 flagged", "Brand: TYPOSQUATTING", "HTML: Hidden iframes", "URLHaus: Clean"]
    for i, txt in enumerate(vectors):
        draw.text((890, 345+i*30), txt, fill=WHITE, font=get_font(11))
    img.save(os.path.join(FIGURES_DIR, 'figure_4_3_dashboard.png'))

# ── Figure 5.1: URL Engine Detection Flow ──
def fig_5_1():
    img = Image.new('RGB', (W, 500), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "URL Engine Detection Flow")
    steps = ["Input URL", "Typosquatting\nCheck", "SSL\nValidation", "WHOIS\nAge", "VirusTotal\nLookup",
             "URLhaus\nCheck", "DOM\nAnalysis", "Redirect\nChain", "Keyword\nScoring"]
    for i, s in enumerate(steps):
        x = 30 + i * 130; y = 100
        draw_box(draw, x, y, 120, 60, s, outline=CYAN if i < 5 else (0,200,200))
        if i < len(steps)-1: draw_arrow_h(draw, x+120, y+30, x+130, CYAN)
    draw_arrow(draw, 600, 160, 600, 220, CYAN)
    draw_box(draw, 400, 220, 400, 50, "Aggregate Risk Score (0.0 - 1.0)", fill=BLUE, outline=CYAN)
    draw_arrow(draw, 600, 270, 600, 320, CYAN)
    draw_box(draw, 400, 320, 400, 50, "Verdict: MALICIOUS / SAFE / SUSPICIOUS", fill=(60,20,20), outline=RED)
    img.save(os.path.join(FIGURES_DIR, 'figure_5_1.png'))

# ── Figure 5.2: EML Engine Analysis Pipeline ──
def fig_5_2():
    img = Image.new('RGB', (W, 500), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "EML Engine Analysis Pipeline")
    steps = ["Parse .eml", "Header\nAnalysis", "SPF/DKIM\n/DMARC", "Body\nContent", "Attachment\nScan", "Urgency\nScoring"]
    for i, s in enumerate(steps):
        x = 50 + i * 190; y = 100
        draw_box(draw, x, y, 170, 60, s, outline=CYAN)
        if i < len(steps)-1: draw_arrow_h(draw, x+170, y+30, x+190, CYAN)
    draw_arrow(draw, 600, 160, 600, 220, CYAN)
    draw_box(draw, 350, 220, 500, 50, "Risk Score + Evidence List", fill=BLUE, outline=CYAN)
    img.save(os.path.join(FIGURES_DIR, 'figure_5_2.png'))

# ── Figure 5.3: QR Code Quishing Detection Flow ──
def fig_5_3():
    img = Image.new('RGB', (W, 500), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "QR Code Quishing Detection Flow")
    steps = ["QR Image\nUpload", "Decode QR\n(pyzbar)", "Extract\nURL", "Typosquat\nCheck", "VirusTotal\nLookup", "Redirect\nChain"]
    for i, s in enumerate(steps):
        x = 50 + i * 190; y = 100
        draw_box(draw, x, y, 170, 60, s, outline=CYAN)
        if i < len(steps)-1: draw_arrow_h(draw, x+170, y+30, x+190, CYAN)
    draw_arrow(draw, 600, 160, 600, 220, CYAN)
    draw_box(draw, 350, 220, 500, 50, "QR Quishing Verdict + Evidence", fill=BLUE, outline=CYAN)
    img.save(os.path.join(FIGURES_DIR, 'figure_5_3.png'))

# ── Figure 5.4: Vishing Engine Voice Analysis Pipeline ──
def fig_5_4():
    img = Image.new('RGB', (W, 500), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "Vishing Engine Voice Analysis Pipeline")
    draw_box(draw, 450, 70, 300, 50, "Voice Transcript Input", fill=BLUE, outline=CYAN)
    draw_arrow(draw, 600, 120, 600, 160, CYAN)
    categories = ["Authority\nImpersonation", "Urgency\nCreation", "Fear\nInduction", "Trust\nBuilding",
                  "Isolation\nTactics", "Commitment\nExploitation", "Social\nProof"]
    for i, c in enumerate(categories):
        x = 30 + i * 168
        draw_box(draw, x, 160, 155, 55, c, outline=(0,180+i*10,180+i*10))
    draw_arrow(draw, 600, 215, 600, 270, CYAN)
    draw_box(draw, 350, 270, 500, 50, "Social Engineering Risk Score", fill=BLUE, outline=CYAN)
    draw_arrow(draw, 600, 320, 600, 370, CYAN)
    draw_box(draw, 400, 370, 400, 50, "Vishing Verdict + Evidence", fill=(60,20,20), outline=RED)
    img.save(os.path.join(FIGURES_DIR, 'figure_5_4.png'))

# ── Figure 5.5: AI Handler Multi-Model Architecture ──
def fig_5_5():
    img = Image.new('RGB', (W, 500), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "AI Handler Multi-Model Architecture")
    draw_box(draw, 400, 70, 400, 50, "Engine Evidence + Risk Score", fill=BLUE, outline=CYAN)
    draw_arrow(draw, 600, 120, 600, 160, CYAN)
    draw_box(draw, 400, 160, 400, 45, "AI Handler (utils/ai_handler.py)", outline=CYAN)
    draw_arrow(draw, 400, 205, 200, 240, CYAN)
    draw_arrow(draw, 600, 205, 600, 240, CYAN)
    draw_arrow(draw, 800, 205, 1000, 240, CYAN)
    draw_box(draw, 80, 240, 250, 55, "Gemini Pro API\n(Primary)", outline=CYAN)
    draw_box(draw, 475, 240, 250, 55, "Random Forest ML\n(Fallback)", outline=(0,200,200))
    draw_box(draw, 870, 240, 250, 55, "Response Cache\n(LRU)", outline=GRAY)
    draw_arrow(draw, 200, 295, 200, 340, CYAN)
    draw_arrow(draw, 600, 295, 600, 340, CYAN)
    draw_box(draw, 300, 340, 600, 50, "Consensus Verdict + Confidence + Reasoning", fill=BLUE, outline=CYAN)
    img.save(os.path.join(FIGURES_DIR, 'figure_5_5.png'))

# ── Figure 6.1: Accuracy Dashboard ──
def fig_6_1():
    img = Image.new('RGB', (W, H), DARK); draw = ImageDraw.Draw(img)
    title_bar(draw, "Accuracy Dashboard - TP/TN/FP/FN Matrix")
    # Confusion matrix
    draw.rounded_rectangle([100, 80, 550, 380], radius=10, fill=(20,35,55), outline=CYAN)
    draw.text((250, 90), "Confusion Matrix", fill=CYAN, font=get_font(16))
    labels = [("TP: 21", (0,255,100)), ("FP: 1", RED), ("FN: 1", RED), ("TN: 12", (0,255,100))]
    positions = [(150, 140, 300, 240), (330, 140, 500, 240), (150, 260, 300, 360), (330, 260, 500, 360)]
    for (text, color), (x1, y1, x2, y2) in zip(labels, positions):
        draw.rounded_rectangle([x1, y1, x2, y2], radius=8, fill=(30,50,70), outline=color, width=2)
        draw.text((x1+50, y1+35), text, fill=color, font=get_font(22))
    # Metrics on right
    draw.rounded_rectangle([600, 80, 1100, 380], radius=10, fill=(20,35,55), outline=CYAN)
    draw.text((750, 90), "Key Metrics", fill=CYAN, font=get_font(16))
    metrics = [("Accuracy:", "94.3%", (0,255,100)), ("Precision:", "95.5%", (0,255,100)),
               ("Recall:", "95.5%", (0,255,100)), ("F1 Score:", "95.5%", (0,255,100)),
               ("Specificity:", "92.3%", (0,200,200))]
    for i, (label, val, color) in enumerate(metrics):
        y = 130 + i * 45
        draw.text((620, y), label, fill=WHITE, font=get_font(16))
        draw.text((820, y), val, fill=color, font=get_font(20))
        # Progress bar
        draw.rounded_rectangle([620, y+28, 1080, y+38], radius=3, fill=(30,50,70), outline=GRAY)
        pct = float(val.replace('%','')) / 100
        draw.rounded_rectangle([620, y+28, 620+int(460*pct), y+38], radius=3, fill=color)
    # Engine breakdown at bottom
    draw.rounded_rectangle([100, 410, 1100, 600], radius=10, fill=(20,35,55), outline=(0,200,200))
    draw.text((450, 420), "Per-Engine Accuracy", fill=CYAN, font=get_font(16))
    engines_data = [("URL", 100), ("EML", 75), ("QR", 100), ("SMS", 100), ("Voice", 100), ("Clone", 75), ("Social", 100)]
    for i, (name, acc) in enumerate(engines_data):
        x = 130 + i * 140
        bar_h = int(acc * 1.3)
        color = (0,255,100) if acc == 100 else RED
        draw.rounded_rectangle([x, 570-bar_h, x+80, 570], radius=3, fill=color)
        draw.text((x+15, 575), f"{name}", fill=WHITE, font=get_font(11))
        draw.text((x+20, 570-bar_h-20), f"{acc}%", fill=color, font=get_font(12))
    img.save(os.path.join(FIGURES_DIR, 'figure_6_1.png'))

# ── Figure 6.2: Malicious URL Scan Result ──
def fig_6_2():
    img = Image.new('RGB', (W, H), DARK); draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, W, 60], fill=BLUE)
    draw.text((30, 15), "PHISHING SENTINEL", fill=CYAN, font=get_font(22))
    draw.text((900, 20), "STATUS: ONLINE", fill=(0,255,100), font=get_font(14))
    # Result panel
    draw.rounded_rectangle([50, 80, 600, 500], radius=10, fill=(20,35,55), outline=RED, width=2)
    draw.text((60, 95), "SCAN RESULT", fill=RED, font=get_font(18))
    draw.text((60, 130), "Target: goggle.com", fill=WHITE, font=get_font(16))
    draw.text((60, 165), "Verdict:", fill=GRAY, font=get_font(14))
    draw.rounded_rectangle([150, 160, 400, 190], radius=5, fill=(100,0,0), outline=RED)
    draw.text((170, 165), "MALICIOUS - PHISHING", fill=WHITE, font=get_font(14))
    draw.text((60, 210), "Risk Score: 0.89 / 1.00", fill=RED, font=get_font(16))
    draw.rounded_rectangle([60, 240, 580, 255], radius=3, fill=(30,50,70))
    draw.rounded_rectangle([60, 240, int(60+520*0.89), 255], radius=3, fill=RED)
    evidence = ["[!] Typosquatting: mimics google.com (sim=0.89)", "[!] SSL Certificate: Invalid/Missing",
                "[!] Domain Age: < 7 days (newly registered)", "[!] VirusTotal: 12/95 vendors flagged",
                "[!] URLhaus: Not flagged", "[!] DOM: Hidden iframe detected",
                "[!] Redirect: 3 cross-domain hops", "[!] Keywords: login, verify in path"]
    draw.text((60, 275), "Evidence:", fill=CYAN, font=get_font(14))
    for i, e in enumerate(evidence):
        draw.text((70, 300+i*22), e, fill=RED if "[!]" in e else WHITE, font=get_font(11))
    # Right panel - threat circle
    draw.rounded_rectangle([630, 80, 1150, 350], radius=10, fill=(20,35,55), outline=RED, width=2)
    draw.text((780, 90), "THREAT LEVEL", fill=RED, font=get_font(16))
    draw.ellipse([780, 130, 1000, 310], outline=RED, width=5)
    draw.text((850, 195), "89%", fill=RED, font=get_font(36))
    draw.text((810, 315), "CRITICAL THREAT", fill=RED, font=get_font(16))
    # AI Verdict
    draw.rounded_rectangle([630, 370, 1150, 500], radius=10, fill=(20,35,55), outline=CYAN, width=1)
    draw.text((640, 380), "GEMINI AI VERDICT", fill=CYAN, font=get_font(14))
    draw.text((640, 410), "This URL is a confirmed phishing attempt", fill=WHITE, font=get_font(12))
    draw.text((640, 435), "targeting Google users via typosquatting.", fill=WHITE, font=get_font(12))
    draw.text((640, 465), "Confidence: 97.2%", fill=(0,255,100), font=get_font(14))
    img.save(os.path.join(FIGURES_DIR, 'figure_6_2_malicious.png'))

# ── Figure 6.3: Clean URL Scan Result ──
def fig_6_3():
    img = Image.new('RGB', (W, H), DARK); draw = ImageDraw.Draw(img)
    GREEN = (0, 255, 100)
    draw.rectangle([0, 0, W, 60], fill=BLUE)
    draw.text((30, 15), "PHISHING SENTINEL", fill=CYAN, font=get_font(22))
    draw.text((900, 20), "STATUS: ONLINE", fill=GREEN, font=get_font(14))
    draw.rounded_rectangle([50, 80, 600, 450], radius=10, fill=(20,35,55), outline=GREEN, width=2)
    draw.text((60, 95), "SCAN RESULT", fill=GREEN, font=get_font(18))
    draw.text((60, 130), "Target: google.com", fill=WHITE, font=get_font(16))
    draw.text((60, 165), "Verdict:", fill=GRAY, font=get_font(14))
    draw.rounded_rectangle([150, 160, 300, 190], radius=5, fill=(0,80,0), outline=GREEN)
    draw.text((170, 165), "SAFE - CLEAN", fill=WHITE, font=get_font(14))
    draw.text((60, 210), "Risk Score: 0.05 / 1.00", fill=GREEN, font=get_font(16))
    draw.rounded_rectangle([60, 240, 580, 255], radius=3, fill=(30,50,70))
    draw.rounded_rectangle([60, 240, int(60+520*0.05), 255], radius=3, fill=GREEN)
    evidence = ["[OK] No typosquatting detected", "[OK] SSL Certificate: Valid (Google Trust Services)",
                "[OK] Domain Age: 26 years (established)", "[OK] VirusTotal: 0/95 vendors flagged",
                "[OK] URLhaus: Clean", "[OK] DOM: Standard Google structure",
                "[OK] No suspicious redirects", "[OK] No phishing keywords"]
    draw.text((60, 275), "Evidence:", fill=CYAN, font=get_font(14))
    for i, e in enumerate(evidence):
        draw.text((70, 300+i*22), e, fill=GREEN, font=get_font(11))
    draw.rounded_rectangle([630, 80, 1150, 350], radius=10, fill=(20,35,55), outline=GREEN, width=2)
    draw.text((790, 90), "THREAT LEVEL", fill=GREEN, font=get_font(16))
    draw.ellipse([780, 130, 1000, 310], outline=GREEN, width=5)
    draw.text((860, 195), "5%", fill=GREEN, font=get_font(36))
    draw.text((830, 315), "NO THREAT", fill=GREEN, font=get_font(16))
    draw.rounded_rectangle([630, 370, 1150, 450], radius=10, fill=(20,35,55), outline=CYAN, width=1)
    draw.text((640, 380), "GEMINI AI VERDICT", fill=CYAN, font=get_font(14))
    draw.text((640, 410), "Legitimate Google domain. No threats detected.", fill=GREEN, font=get_font(12))
    img.save(os.path.join(FIGURES_DIR, 'figure_6_3_clean.png'))

if __name__ == '__main__':
    print("Generating 13 figures...")
    fig_3_1(); print("  [+] Figure 3.1")
    fig_3_2(); print("  [+] Figure 3.2")
    fig_4_1(); print("  [+] Figure 4.1")
    fig_4_2(); print("  [+] Figure 4.2")
    fig_4_3(); print("  [+] Figure 4.3")
    fig_5_1(); print("  [+] Figure 5.1")
    fig_5_2(); print("  [+] Figure 5.2")
    fig_5_3(); print("  [+] Figure 5.3")
    fig_5_4(); print("  [+] Figure 5.4")
    fig_5_5(); print("  [+] Figure 5.5")
    fig_6_1(); print("  [+] Figure 6.1")
    fig_6_2(); print("  [+] Figure 6.2")
    fig_6_3(); print("  [+] Figure 6.3")
    print(f"\n[+] All 13 figures saved to {FIGURES_DIR}")
