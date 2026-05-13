"""
Test Zero-Click QR Extraction Module
====================================
This script tests the forensic-safe QR extraction without triggering trackers.
"""

import logging
from utils.zero_click_extractor import ZeroClickExtractor, extract_qr
from core.quishing_engine import QREngine

# Enable logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def test_zero_click_extractor():
    """Test the standalone zero-click extractor."""
    print("\n" + "="*60)
    print("TEST 1: Zero-Click Extractor (Standalone)")
    print("="*60)
    
    extractor = ZeroClickExtractor()
    
    # Test with a sample file path (you need to provide an actual file)
    test_file = input("\nEnter path to QR image or PDF (or press Enter to skip): ").strip()
    
    if test_file:
        result = extractor.extract(test_file, case_id="TEST_001")
        
        print(f"\nExtraction Result:")
        print(f"  Success: {result['success']}")
        print(f"  File Hash (SHA256): {result.get('file_hash_sha256', 'N/A')}")
        print(f"  Payloads Found: {result['payloads_found']}")
        print(f"  Tracker Safe: {result['forensic_notes']['tracker_safe']}")
        
        if result['payloads']:
            print(f"\n  Extracted Payloads:")
            for i, payload in enumerate(result['payloads'], 1):
                print(f"    {i}. {payload['payload'][:80]}...")
                print(f"       Source: {payload['source']}")
        else:
            print("\n  No QR codes found in file.")
    else:
        print("Skipped - no file provided")

def test_qr_engine_with_zero_click():
    """Test the full QREngine with zero-click integration."""
    print("\n" + "="*60)
    print("TEST 2: QREngine with Zero-Click Integration")
    print("="*60)
    
    engine = QREngine()
    
    test_file = input("\nEnter path to QR image or PDF (or press Enter to skip): ").strip()
    
    if test_file:
        result = engine.analyze(test_file, case_id="SOC_001")
        
        print(f"\nFull Analysis Result:")
        print(f"  Status: {result['status']}")
        print(f"  Forensic Hash: {result.get('forensic_hash', 'N/A')}")
        print(f"  Payload: {result['extracted_payload'][:80]}...")
        print(f"  Risk Score: {result['calculated_risk']}/100")
        print(f"  Payload Type: {result['payload_type']}")
        
        if result.get('forensic_extraction'):
            print(f"\n  Forensic Details:")
            print(f"    Method: {result['forensic_extraction']['method']}")
            print(f"    Tracker Safe: {result['forensic_extraction']['tracker_safe']}")
            print(f"    Extraction Time: {result['forensic_extraction']['extraction_time']}")
    else:
        print("Skipped - no file provided")

def show_capabilities():
    """Display what the zero-click module can do."""
    print("\n" + "="*60)
    print("ZERO-CLICK EXTRACTION CAPABILITIES")
    print("="*60)
    
    capabilities = """
    ✓ PNG/JPG/JPEG/BMP/TIFF/WEBP/GIF support
    ✓ PDF multi-page QR extraction
    ✓ Forensic-safe (NO tracker pixel triggering)
    ✓ SHA256 hash calculation for integrity
    ✓ Multiple decoding techniques:
      - Direct decode
      - Grayscale conversion
      - Adaptive thresholding
      - OTSU thresholding
      - Scale enhancement
    ✓ Batch processing support
    ✓ Case ID tracking for forensics
    ✓ JSON export for evidence
    """
    print(capabilities)

if __name__ == "__main__":
    show_capabilities()
    test_zero_click_extractor()
    test_qr_engine_with_zero_click()
    
    print("\n" + "="*60)
    print("Tests Complete!")
    print("="*60)
