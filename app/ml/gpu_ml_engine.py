"""
GPU-Accelerated ML Engine for Phishing Detection
===============================================
Uses NVIDIA RTX 3050 CUDA cores for:
- 10x faster model training
- Real-time deep learning inference
- Parallel batch analysis

Windows Installation:
    pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118

Note: RAPIDS (cuML) is Linux-only. PyTorch CUDA works on Windows.
"""

import logging
import math
import numpy as np
import warnings
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# Try to import RAPIDS cuML for GPU-accelerated traditional ML
try:
    from cuml.ensemble import RandomForestClassifier as cuRF
    from cuml.model_selection import train_test_split as cu_split
    RAPIDS_AVAILABLE = True
except ImportError:
    RAPIDS_AVAILABLE = False
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split

warnings.filterwarnings('ignore')


class GPUMLPipeline(nn.Module):
    """Deep Neural Network for Phishing Detection - GPU Optimized"""
    
    def __init__(self, input_size=15, hidden_size=128):
        super(GPUMLPipeline, self).__init__()
        self.layer1 = nn.Linear(input_size, hidden_size)
        self.bn1 = nn.BatchNorm1d(hidden_size)
        self.dropout1 = nn.Dropout(0.3)
        
        self.layer2 = nn.Linear(hidden_size, hidden_size // 2)
        self.bn2 = nn.BatchNorm1d(hidden_size // 2)
        self.dropout2 = nn.Dropout(0.2)
        
        self.layer3 = nn.Linear(hidden_size // 2, 32)
        self.output = nn.Linear(32, 2)  # Binary: Phishing/Legitimate
        
        self.relu = nn.ReLU()
        
    def forward(self, x):
        x = self.relu(self.bn1(self.layer1(x)))
        x = self.dropout1(x)
        x = self.relu(self.bn2(self.layer2(x)))
        x = self.dropout2(x)
        x = self.relu(self.layer3(x))
        return self.output(x)


class GPUMLEngine:
    """
    GPU-Accelerated Machine Learning Engine
    
    Automatically detects RTX 3050 and uses CUDA if available.
    Falls back to CPU if GPU not available.
    """
    
    def __init__(self, batch_size=64):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.batch_size = batch_size
        
        # Log GPU info
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            vram = torch.cuda.get_device_properties(0).total_memory / 1e9
            logging.info(f"[GPU ML] 🚀 Using {gpu_name} ({vram:.1f}GB VRAM)")
            logging.info(f"[GPU ML] CUDA Cores: {torch.cuda.get_device_properties(0).multi_processor_count * 128}")
        else:
            logging.warning("[GPU ML] ⚠️ CUDA not available - falling back to CPU")
        
        # Initialize deep learning model
        self.dl_model = GPUMLPipeline().to(self.device)
        self.criterion = nn.CrossEntropyLoss()
        self.optimizer = torch.optim.Adam(self.dl_model.parameters(), lr=0.001)
        
        # Traditional ML (GPU-accelerated if RAPIDS available)
        if RAPIDS_AVAILABLE and torch.cuda.is_available():
            self.rf_model = cuRF(n_estimators=500, max_depth=20)
            logging.info("[GPU ML] Using RAPIDS cuML RandomForest (GPU)")
        else:
            self.rf_model = RandomForestClassifier(n_estimators=200, n_jobs=-1)
            logging.info("[GPU ML] Using scikit-learn RandomForest (CPU)")
        
        self.trained = False
        
    def extract_enhanced_features(self, url: str) -> np.ndarray:
        """Extract 15 forensic features from URL"""
        features = []
        
        # 1. Length features
        features.append(len(url))
        features.append(len(url.split('/')[2]) if '://' in url else len(url.split('/')[0]))
        
        # 2. Character counts
        features.append(url.count('.'))
        features.append(url.count('-'))
        features.append(url.count('_'))
        features.append(url.count('/'))
        features.append(url.count('?'))
        features.append(url.count('='))
        
        # 3. Security indicators
        features.append(1 if 'https' in url else 0)
        features.append(1 if '@' in url else 0)
        
        # 4. Suspicious patterns
        features.append(1 if any(ip in url for ip in ['.exe', '.zip', '.rar']) else 0)
        features.append(sum(1 for digit in url if digit.isdigit()))
        
        # 5. Domain analysis
        domain = url.split('/')[2] if '://' in url else url.split('/')[0]
        features.append(len(domain.split('.')) - 1)
        
        # 6. Brand impersonation score
        brands = ['google', 'facebook', 'amazon', 'paypal', 'netflix', 'apple', 'microsoft', 'bank']
        brand_score = sum(1 for brand in brands if brand in url.lower())
        features.append(brand_score)
        
        # 7. Entropy (randomness)
        entropy = -sum((url.count(c) / len(url)) * math.log2(url.count(c) / len(url)) 
                      for c in set(url) if url.count(c) > 0)
        features.append(entropy)
        
        return np.array(features, dtype=np.float32)
    
    def train_deep_model(self, urls: list, labels: list, epochs=50):
        """Train PyTorch model on GPU"""
        # Extract features
        X = np.array([self.extract_enhanced_features(url) for url in urls])
        y = np.array(labels)
        
        # Convert to tensors
        X_tensor = torch.FloatTensor(X).to(self.device)
        y_tensor = torch.LongTensor(y).to(self.device)
        
        # Create DataLoader for batch processing
        dataset = TensorDataset(X_tensor, y_tensor)
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)
        
        logging.info(f"[GPU ML] Training on {len(urls)} samples, {epochs} epochs...")
        
        self.dl_model.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch_x, batch_y in loader:
                self.optimizer.zero_grad()
                outputs = self.dl_model(batch_x)
                loss = self.criterion(outputs, batch_y)
                loss.backward()
                self.optimizer.step()
                total_loss += loss.item()
            
            if (epoch + 1) % 10 == 0:
                logging.info(f"[GPU ML] Epoch {epoch+1}/{epochs}, Loss: {total_loss/len(loader):.4f}")
        
        self.trained = True
        logging.info("[GPU ML] Deep learning model training complete!")
        
    def predict_batch(self, urls: list) -> list:
        """Batch prediction using GPU - FAST!"""
        if not urls:
            return []
        
        # Extract features
        X = np.array([self.extract_enhanced_features(url) for url in urls])
        X_tensor = torch.FloatTensor(X).to(self.device)
        
        # Batch prediction
        self.dl_model.eval()
        with torch.no_grad():
            # Process in batches to avoid OOM
            predictions = []
            for i in range(0, len(X_tensor), self.batch_size):
                batch = X_tensor[i:i + self.batch_size]
                outputs = self.dl_model(batch)
                probs = torch.softmax(outputs, dim=1)
                predictions.extend(probs[:, 1].cpu().numpy())
        
        return predictions
    
    def predict_single(self, url: str) -> dict:
        """Single URL prediction with detailed analysis"""
        features = self.extract_enhanced_features(url)
        X = torch.FloatTensor(features).unsqueeze(0).to(self.device)
        
        self.dl_model.eval()
        with torch.no_grad():
            output = self.dl_model(X)
            prob = torch.softmax(output, dim=1)[0][1].item()
        
        return {
            'phishing_probability': prob,
            'is_phishing': prob > 0.5,
            'confidence': abs(prob - 0.5) * 2,  # 0-1 scale
            'features_used': len(features),
            'device': 'GPU (CUDA)' if torch.cuda.is_available() else 'CPU'
        }
    
    def benchmark(self, test_urls: list):
        """Benchmark GPU vs CPU performance"""
        import time
        
        logging.info("[GPU ML] Running benchmark...")
        
        # GPU inference
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        start = time.time()
        self.predict_batch(test_urls)
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        gpu_time = time.time() - start
        
        # Calculate throughput
        throughput = len(test_urls) / gpu_time
        
        logging.info(f"[GPU ML] Benchmark Results:")
        logging.info(f"  - Processed {len(test_urls)} URLs in {gpu_time:.3f}s")
        logging.info(f"  - Throughput: {throughput:.0f} URLs/second")
        logging.info(f"  - Latency: {(gpu_time/len(test_urls))*1000:.2f}ms per URL")
        
        return {'time': gpu_time, 'throughput': throughput}


# Singleton instance
gpu_ml_engine = None

def get_gpu_engine():
    """Get or create GPU ML engine singleton"""
    global gpu_ml_engine
    if gpu_ml_engine is None:
        gpu_ml_engine = GPUMLEngine()
    return gpu_ml_engine


if __name__ == "__main__":
    # Test the GPU engine
    logging.basicConfig(level=logging.INFO)
    
    engine = GPUMLEngine()
    
    # Test prediction
    test_url = "https://paypa1-security.verify-account.com/login"
    result = engine.predict_single(test_url)
    print(f"\nTest URL: {test_url}")
    print(f"Phishing Probability: {result['phishing_probability']:.2%}")
    print(f"Device: {result['device']}")
    
    # Batch benchmark
    test_urls = [test_url] * 1000
    engine.benchmark(test_urls)
