# GPU Setup Guide for RTX 3050 (Windows)

## ⚠️ Python Version Issue

Your system has **Python 3.14** which is too new. PyTorch CUDA doesn't have wheels for Python 3.14 yet.

## ✅ Option 1: Use CPU Mode (Quick - Already Installed)

PyTorch CPU version already installed. GPU modules will work but on CPU:

```bash
# Already done - ready to test
python gpu_benchmark.py
```

## 🚀 Option 2: Full GPU Support (Recommended)

Install Python 3.11 (LTS version with full GPU support):

### Step 1: Download Python 3.11
```
https://www.python.org/downloads/release/python-3119/
Download: Windows installer (64-bit)
```

### Step 2: Install Python 3.11
- Run installer
- ✅ Check "Add Python to PATH"
- ✅ Check "Install pip"
- Install

### Step 3: Install PyTorch with CUDA
```bash
py -3.11 -m pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118
py -3.11 -m pip install -r requirements.txt
```

### Step 4: Verify GPU
```bash
py -3.11 -c "import torch; print(torch.cuda.get_device_name(0))"
```

### Step 5: Run Project with Python 3.11
```bash
py -3.11 main.py
```

## 🧪 Quick Test (CPU Mode - Works Now)

```bash
python utils/gpu_ml_engine.py
```

## Performance Expectations with RTX 3050 4GB

| Mode | URLs/sec | Batch Size |
|------|----------|------------|
| CPU (Current) | ~50 | 1 |
| GPU (After setup) | ~500-1000 | 64-128 |

## Troubleshooting

### "No module named torch"
```bash
pip install torch
```

### "CUDA not available"
- Update NVIDIA drivers: https://www.nvidia.com/drivers
- Verify CUDA version: `nvidia-smi`

### "Out of memory"
Reduce batch size in `utils/gpu_ml_engine.py`:
```python
engine = GPUMLEngine(batch_size=32)  # Instead of 64
```
