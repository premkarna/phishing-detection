import os
import sys
import time

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ml.local_ml import LocalMLEngine

def test_local_ml_fallback():
    print("Starting Local ML Fallback Test Suite (Random Forest)...")
    engine = LocalMLEngine()
    
    test_scenarios = [
        # 1. URL Spoofing / Typosquatting
        {"name": "Typosquatting URL", "payload": "goggle-login.com", "vector": "url", "expected": "MALICIOUS"},
        {"name": "Legitimate URL", "payload": "facebook.com", "vector": "url", "expected": "CLEAN"},
        
        # 2. Punycode / Homograph
        {"name": "Punycode Attack", "payload": "xn--googl-pma.com", "vector": "social", "expected": "MALICIOUS"},
        {"name": "Homograph Attack", "payload": "аррӏе.com", "vector": "social", "expected": "MALICIOUS"},
        
        # 3. Risky TLDs
        {"name": "Risky TLD (.xyz)", "payload": "bank-verify.xyz", "vector": "url", "expected": "MALICIOUS"},
        {"name": "Risky TLD (.zip)", "payload": "update-software.zip", "vector": "url", "expected": "MALICIOUS"},
        
        # 4. Malicious Attachments (EML/Smishing)
        {"name": "Malicious Attachment", "payload": "urgent_invoice.exe", "vector": "eml", "expected": "MALICIOUS"},
        {"name": "Safe Attachment", "payload": "presentation.pptx", "vector": "eml", "expected": "CLEAN"},
        
        # 5. Specific Vectors (Vishing/QR)
        {"name": "Malicious Vishing Transcript", "payload": "urgent blocked provide password login", "vector": "vishing", "expected": "MALICIOUS"},
        {"name": "Malicious QR Payload", "payload": "http://malicious-site.top/scan", "vector": "qr", "expected": "MALICIOUS"}
    ]
    
    passed = 0
    total_latency = 0
    
    print("\n" + "="*80)
    print(f"{'SCENARIO':<30} | {'VERDICT':<10} | {'CONFIDENCE':<12} | {'LATENCY':<8}")
    print("-" * 80)
    
    for scenario in test_scenarios:
        start_time = time.time()
        res = engine.predict_offline(scenario)
        latency = time.time() - start_time
        total_latency += latency
        
        verdict = res['verdict']
        confidence = res.get('confidence', 'N/A')
        
        print(f"{scenario['name']:<30} | {verdict:<10} | {confidence:<12} | {latency:.4f}s")
        
        if verdict == scenario['expected']:
            passed += 1
            
    avg_latency = total_latency / len(test_scenarios)
    print("="*80)
    print(f"TEST SUMMARY: {passed}/{len(test_scenarios)} Passed")
    print(f"Average Prediction Latency: {avg_latency:.4f}s")
    print("="*80)
    
    if avg_latency < 0.1:
        print("\nPerformance Target Met: Prediction under 0.1s!")
    else:
        print("\nPerformance Warning: Prediction exceeded 0.1s.")

    if passed == len(test_scenarios):
        print("Accuracy Target Met: All scenarios correctly predicted!")
    else:
        print(f"Accuracy Warning: {len(test_scenarios) - passed} scenarios failed.")

if __name__ == "__main__":
    test_local_ml_fallback()
