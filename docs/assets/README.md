# 📸 Demo Assets for README

This folder contains screenshots and GIFs used in the main README.md.

## Required Assets

Add these files here to make the README visually stunning:

### 🎬 GIFs (Animated demos)

| File | Description | How to Create |
|------|-------------|---------------|
| `demo_3d_graph.gif` | 3D Threat Graph spinning/interacting | Screen record the 3D graph at `/accuracy` page, convert to GIF |
| `demo_qr_scan.gif` | QR code analysis in action | Record uploading a QR code and getting results |

### 📷 Screenshots (PNG/JPG)

| File | Description | How to Capture |
|------|-------------|----------------|
| `demo_critical_alert.png` | Red "CRITICAL (ATO RISK)" alert | Scan a known phishing URL, screenshot the result card |
| `demo_dashboard.png` | SOC Dashboard with metrics | Screenshot the main dashboard at `http://localhost:5000` |

## 🛠️ Tools to Create GIFs

- **Windows**: ShareX (free, best for GIFs)
- **Mac**: Giphy Capture or LICEcap
- **Online**: ezgif.com (convert video to GIF)
- **VS Code**: `ctrl+shift+p` → "Record GIF" (with extension)

## 📝 Tips for Best Results

1. **Keep GIFs under 5MB** — GitHub has size limits
2. **Resolution**: 800x600 or 1280x720 is ideal
3. **Duration**: 5-10 seconds max for GIFs
4. **Focus on the "wow" factor** — Show the AI analysis, 3D graph, or critical alerts
5. **Compress** — Use `gifski` or online tools to optimize file size

## 🚀 Quick Workflow

```bash
# 1. Start the app
python main.py

# 2. Open browser at http://localhost:5000

# 3. Record your screen showing:
#    - 3D threat graph spinning
#    - A critical alert appearing
#    - QR code scan process
#    - Dashboard with metrics

# 4. Convert to GIF using ShareX or ezgif.com

# 5. Save files here with exact names:
#    - demo_3d_graph.gif
#    - demo_critical_alert.png
#    - demo_dashboard.png
#    - demo_qr_scan.gif

# 6. Git add and push
git add docs/assets/
git commit -m "Add demo screenshots and GIFs"
git push
```

## ✅ Checklist

- [ ] `demo_3d_graph.gif` — 3D threat visualization
- [ ] `demo_critical_alert.png` — Red critical alert screenshot
- [ ] `demo_dashboard.png` — SOC dashboard view
- [ ] `demo_qr_scan.gif` — QR analysis demo

Once these are added, your README will look like a professional enterprise tool! 🎉
