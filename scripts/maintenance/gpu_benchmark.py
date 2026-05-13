"""
GPU Benchmark for Phishing Sentinel
===================================
Tests RTX 3050 performance vs CPU for phishing detection tasks.

Run: python gpu_benchmark.py
"""

import time
import logging
import numpy as np
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(message)s')


def benchmark_cpu_ml(test_urls):
    """Benchmark CPU-based ML (existing scikit-learn)"""
    from sklearn.ensemble import RandomForestClassifier
    import joblib
    
    logging.info("\n[CPU] Testing scikit-learn RandomForest...")
    
    # Try to load existing model
    try:
        model = joblib.load("utils/rf_phishing_model.pkl")
    except:
        # Create dummy model for benchmark (12 features to match saved model)
        model = RandomForestClassifier(n_estimators=200, n_jobs=-1)
        # Mock fit with 12 features
        X_dummy = np.random.random((100, 12))
        y_dummy = np.random.randint(0, 2, 100)
        model.fit(X_dummy, y_dummy)
    
    # Extract simple features (12 features to match model)
    def extract_features(url):
        return [
            len(url),
            url.count('.'),
            url.count('-'),
            1 if 'https' in url else 0,
            1 if '@' in url else 0,
            sum(c.isdigit() for c in url),
            url.count('/'),
            len(url.split('.')) - 1,
            hash(url) % 100 / 100,  # pseudo-random feature
            url.count('?'),
            url.count('='),
            url.count('&')
        ]
    
    X = [extract_features(url) for url in test_urls]
    
    start = time.time()
    predictions = model.predict_proba(X)
    cpu_time = time.time() - start
    
    return cpu_time, len(test_urls) / cpu_time


def benchmark_gpu_ml(test_urls):
    """Benchmark GPU-based ML (PyTorch CUDA)"""
    try:
        from app.ml.gpu_ml_engine import GPUMLEngine
        
        logging.info("\n[GPU] Testing PyTorch CUDA ML...")
        
        engine = GPUMLEngine(batch_size=64)
        
        # Warmup
        _ = engine.predict_single("https://example.com")
        
        # Benchmark batch
        start = time.time()
        predictions = engine.predict_batch(test_urls)
        
        # Sync CUDA
        import torch
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        
        gpu_time = time.time() - start
        
        return gpu_time, len(test_urls) / gpu_time
        
    except Exception as e:
        logging.error(f"GPU benchmark failed: {e}")
        return None, None


def benchmark_cpu_image():
    """Benchmark CPU image processing"""
    import cv2
    import numpy as np
    
    logging.info("\n[CPU] Testing OpenCV CPU...")
    
    # Create synthetic images
    images = [np.random.randint(0, 255, (224, 224, 3), dtype=np.uint8) for _ in range(100)]
    
    start = time.time()
    for img in images:
        # Simulate processing
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, 50, 150)
        resized = cv2.resize(img, (224, 224))
    cpu_time = time.time() - start
    
    return cpu_time, len(images) / cpu_time


def benchmark_gpu_image():
    """Benchmark GPU image processing"""
    try:
        from app.ml.gpu_image_analyzer import GPUImageAnalyzer
        
        logging.info("\n[GPU] Testing GPU Image Analysis...")
        
        analyzer = GPUImageAnalyzer()
        
        # Create synthetic image bytes
        from PIL import Image
        import io
        
        images = []
        for _ in range(100):
            img = Image.new('RGB', (224, 224), color=(np.random.randint(0, 255), 
                                                      np.random.randint(0, 255), 
                                                      np.random.randint(0, 255)))
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            images.append(buf.getvalue())
        
        start = time.time()
        for img in images:
            analyzer.detect_visual_phishing(img)
        
        import torch
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        
        gpu_time = time.time() - start
        
        return gpu_time, len(images) / gpu_time
        
    except Exception as e:
        logging.error(f"GPU image benchmark failed: {e}")
        return None, None


def print_results(task, cpu_time, cpu_throughput, gpu_time, gpu_throughput):
    """Print benchmark comparison"""
    print("\n" + "=" * 60)
    print(f"📊 {task} Benchmark Results")
    print("=" * 60)
    
    if cpu_time:
        print(f"  CPU: {cpu_time:.3f}s | {cpu_throughput:.0f} items/sec")
    else:
        print(f"  CPU: N/A")
    
    if gpu_time:
        speedup = cpu_time / gpu_time if cpu_time else 0
        print(f"  GPU: {gpu_time:.3f}s | {gpu_throughput:.0f} items/sec")
        print(f"  🚀 Speedup: {speedup:.1f}x faster on RTX 3050!")
    else:
        print(f"  GPU: Not available (check CUDA installation)")


def main():
    print("=" * 60)
    print("🎮 Phishing Sentinel - GPU Benchmark")
    print("Testing your RTX 3050 4GB performance")
    print("=" * 60)
    
    # Check GPU
    try:
        import torch
        if torch.cuda.is_available():
            print(f"\n✅ GPU Detected: {torch.cuda.get_device_name(0)}")
            print(f"   VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
            print(f"   CUDA Cores: {torch.cuda.get_device_properties(0).multi_processor_count * 128}")
        else:
            print("\n❌ CUDA not available - GPU benchmarks will be skipped")
    except ImportError:
        print("\n❌ PyTorch not installed - Run: pip install torch torchvision")
        return
    
    # Generate test data
    test_urls = [f"https://example{i}.com/login?token={np.random.randint(10000)}" 
                 for i in range(1000)]
    
    # ML Benchmark
    cpu_ml_time, cpu_ml_tput = benchmark_cpu_ml(test_urls[:200])  # CPU is slower, use fewer samples
    gpu_ml_time, gpu_ml_tput = benchmark_gpu_ml(test_urls)
    
    print_results("Machine Learning (URL Analysis)", 
                  cpu_ml_time, cpu_ml_tput, 
                  gpu_ml_time, gpu_ml_tput)
    
    # Image Benchmark
    cpu_img_time, cpu_img_tput = benchmark_cpu_image()
    gpu_img_time, gpu_img_tput = benchmark_gpu_image()
    
    print_results("Image Analysis (Visual Phishing)", 
                  cpu_img_time, cpu_img_tput, 
                  gpu_img_time, gpu_img_tput)
    
    # Summary
    print("\n" + "=" * 60)
    print("📝 Summary")
    print("=" * 60)
    
    if gpu_ml_time and gpu_img_time:
        avg_speedup = ((cpu_ml_time/gpu_ml_time) + (cpu_img_time/gpu_img_time)) / 2
        print(f"   RTX 3050 provides ~{avg_speedup:.0f}x average speedup!")
        print(f"   Your laptop can now process:")
        print(f"   • {gpu_ml_tput:.0f} URLs/second with deep learning")
        print(f"   • {gpu_img_tput:.0f} images/second for visual analysis")
    
    print("\n💡 Next Steps:")
    print("   1. Install GPU dependencies: pip install -r requirements.txt")
    print("   2. Test integration: python utils/gpu_integration.py")
    print("   3. Use GPU engines in main.py for real-time analysis")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
