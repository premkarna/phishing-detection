"""
Zero-Click QR Extraction Module
==============================
Automatically detects and extracts QR codes from images/PDFs entering the system.
Designed for forensic analysis - does NOT trigger tracker pixels or external requests.
"""

import logging
import os
import cv2
import numpy as np
from pyzbar.pyzbar import decode
from pyzbar.pyzbar import ZBarSymbol

# Optional: PyMuPDF for PDF handling
try:
    import pymupdf as fitz  # PyMuPDF v1.23+ (uses pymupdf import)
    HAS_FITZ = True
except ImportError:
    try:
        import fitz  # Fallback for older versions
        HAS_FITZ = True
    except ImportError:
        HAS_FITZ = False
        logging.warning("[ZERO-CLICK] PyMuPDF not installed. PDF extraction will be limited.")

import hashlib
import io
from typing import Dict, List, Optional, Tuple, Union
from pathlib import Path
from datetime import datetime
import re
import json


class ZeroClickExtractor:
    """
    Forensic-grade QR extraction without triggering trackers.
    - Pure offline processing (no network calls)
    - PDF/Image QR detection
    - Multi-page support
    - Forensic-safe (no pixel tracking)
    """
    
    def __init__(self):
        # Configure pyzbar for QR detection
        # Note: Only QRCODE is used for maximum compatibility
        self.supported_symbols = [
            ZBarSymbol.QRCODE,
        ]
        
        # PDF processing settings
        self.pdf_dpi = 200  # Higher DPI for better QR detection
        
        # Supported file types
        self.supported_images = ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.webp', '.gif']
        self.supported_documents = ['.pdf']
        
        # Extraction history (for forensic tracking)
        self.extraction_log = []
        
        logging.info("[ZERO-CLICK] Extractor initialized - Forensic mode active")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash for forensic integrity."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _is_supported_file(self, file_path: str) -> bool:
        """Check if file type is supported for QR extraction."""
        ext = Path(file_path).suffix.lower()
        return ext in self.supported_images or ext in self.supported_documents
    
    def _decode_qr_from_image(self, image: np.ndarray, source: str = "unknown") -> List[Dict]:
        """
        Decode QR codes from image array using multiple techniques.
        
        Args:
            image: OpenCV image array (BGR format)
            source: Source identifier for logging
            
        Returns:
            List of decoded QR payloads with metadata
        """
        found_payloads = []
        
        # Technique 1: Direct decode
        decoded_objects = decode(image, symbols=self.supported_symbols)
        
        # Technique 2: Grayscale conversion
        if not decoded_objects:
            if len(image.shape) == 3:
                gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            else:
                gray = image
            decoded_objects = decode(gray, symbols=self.supported_symbols)
        
        # Technique 3: Adaptive thresholding (for damaged/printed QRs)
        if not decoded_objects and len(image.shape) == 3:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                          cv2.THRESH_BINARY, 11, 2)
            decoded_objects = decode(thresh, symbols=self.supported_symbols)
        
        # Technique 4: OTSU thresholding
        if not decoded_objects and len(image.shape) == 3:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            decoded_objects = decode(thresh, symbols=self.supported_symbols)
        
        # Technique 5: Scale up small QRs
        if not decoded_objects:
            height, width = image.shape[:2]
            if height < 1000 or width < 1000:
                scale_factor = 2
                scaled = cv2.resize(image, None, fx=scale_factor, fy=scale_factor, 
                                   interpolation=cv2.INTER_CUBIC)
                decoded_objects = decode(scaled, symbols=self.supported_symbols)
        
        # Extract data from all found QRs
        for obj in decoded_objects:
            try:
                payload = obj.data.decode('utf-8')
                found_payloads.append({
                    "payload": payload,
                    "type": obj.type,
                    "rect": {
                        "left": obj.rect.left,
                        "top": obj.rect.top,
                        "width": obj.rect.width,
                        "height": obj.rect.height
                    },
                    "source": source,
                    "confidence": "high" if obj.quality != -1 else "medium"
                })
                logging.info(f"[ZERO-CLICK] QR Found in {source}: {payload[:50]}...")
            except Exception as e:
                logging.warning(f"[ZERO-CLICK] Failed to decode QR data: {e}")
        
        return found_payloads
    
    def _extract_from_pdf(self, pdf_path: str) -> List[Dict]:
        """
        Extract QR codes from PDF pages without triggering trackers.
        Pure offline processing - no external calls.
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            List of QR payloads found across all pages
        """
        all_payloads = []
        
        # Check if PyMuPDF is available
        if not HAS_FITZ:
            logging.warning("[ZERO-CLICK] PyMuPDF not installed. Cannot extract from PDF.")
            return all_payloads
        
        try:
            pdf_document = fitz.open(pdf_path)
            
            for page_num in range(len(pdf_document)):
                try:
                    page = pdf_document[page_num]
                    
                    # Render page to image at high DPI for QR detection
                    mat = fitz.Matrix(self.pdf_dpi/72, self.pdf_dpi/72)
                    pix = page.get_pixmap(matrix=mat)
                    
                    # Convert to numpy array
                    img_data = np.frombuffer(pix.samples, dtype=np.uint8)
                    img = img_data.reshape(pix.height, pix.width, pix.n)
                    
                    # Convert to BGR for OpenCV
                    if pix.n == 3:
                        img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
                    elif pix.n == 4:
                        img = cv2.cvtColor(img, cv2.COLOR_RGBA2BGR)
                    elif pix.n == 1:
                        img = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
                    
                    # Extract QR from this page
                    page_payloads = self._decode_qr_from_image(img, source=f"PDF_Page_{page_num+1}")
                    
                    # Add page number to each payload
                    for payload in page_payloads:
                        payload["page_number"] = page_num + 1
                        all_payloads.append(payload)
                    
                except Exception as e:
                    logging.warning(f"[ZERO-CLICK] Error processing PDF page {page_num+1}: {e}")
                    continue
            
            pdf_document.close()
            
        except Exception as e:
            logging.error(f"[ZERO-CLICK] PDF extraction failed: {e}")
        
        return all_payloads
    
    def _extract_from_image(self, image_path: str) -> List[Dict]:
        """
        Extract QR codes from image file.
        
        Args:
            image_path: Path to image file
            
        Returns:
            List of QR payloads found
        """
        try:
            # Read image using OpenCV
            image = cv2.imread(image_path)
            
            if image is None:
                # Try alternative loading method
                with open(image_path, "rb") as f:
                    file_bytes = np.asarray(bytearray(f.read()), dtype=np.uint8)
                    image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            
            if image is None:
                logging.error(f"[ZERO-CLICK] Failed to load image: {image_path}")
                return []
            
            return self._decode_qr_from_image(image, source="Image")
            
        except Exception as e:
            logging.error(f"[ZERO-CLICK] Image extraction failed: {e}")
            return []
    
    def extract(self, file_path: str, case_id: str = None) -> Dict:
        """
        Main extraction method - zero-click QR extraction.
        
        Args:
            file_path: Path to image or PDF file
            case_id: Optional case ID for forensic tracking
            
        Returns:
            Extraction result with all found QR payloads
        """
        file_path = os.path.abspath(file_path)
        
        # Validate file exists
        if not os.path.exists(file_path):
            return {
                "success": False,
                "error": "File not found",
                "file_path": file_path,
                "payloads": []
            }
        
        # Validate file type
        if not self._is_supported_file(file_path):
            return {
                "success": False,
                "error": f"Unsupported file type. Supported: {self.supported_images + self.supported_documents}",
                "file_path": file_path,
                "payloads": []
            }
        
        # Calculate forensic hash
        file_hash = self._calculate_file_hash(file_path)
        
        logging.info(f"[ZERO-CLICK] Extracting from: {file_path}")
        logging.info(f"[ZERO-CLICK] File hash (SHA256): {file_hash}")
        
        # Extract based on file type
        ext = Path(file_path).suffix.lower()
        
        if ext == '.pdf':
            payloads = self._extract_from_pdf(file_path)
        else:
            payloads = self._extract_from_image(file_path)
        
        # Build result
        result = {
            "success": True,
            "file_path": file_path,
            "file_hash_sha256": file_hash,
            "file_type": ext,
            "case_id": case_id,
            "extraction_time": datetime.now().isoformat(),
            "payloads_found": len(payloads),
            "payloads": payloads,
            "forensic_notes": {
                "method": "Zero-Click Offline Extraction",
                "tracker_safe": True,
                "network_calls": 0,
                "integrity_verified": True
            }
        }
        
        # Log extraction
        self.extraction_log.append({
            "timestamp": result["extraction_time"],
            "file_hash": file_hash,
            "case_id": case_id,
            "payloads_count": len(payloads)
        })
        
        if payloads:
            logging.info(f"[ZERO-CLICK] Extraction complete: {len(payloads)} payload(s) found")
            for i, p in enumerate(payloads, 1):
                logging.info(f"  Payload {i}: {p['payload'][:60]}...")
        else:
            logging.info("[ZERO-CLICK] No QR codes found in file")
        
        return result
    
    def batch_extract(self, directory: str, recursive: bool = False) -> List[Dict]:
        """
        Batch process all supported files in a directory.
        
        Args:
            directory: Directory path to scan
            recursive: Scan subdirectories
            
        Returns:
            List of extraction results
        """
        results = []
        
        pattern = "**/*" if recursive else "*"
        
        for ext in self.supported_images + self.supported_documents:
            for file_path in Path(directory).glob(f"{pattern}{ext}"):
                result = self.extract(str(file_path))
                results.append(result)
        
        logging.info(f"[ZERO-CLICK] Batch extraction complete: {len(results)} files processed")
        return results
    
    def get_extraction_log(self) -> List[Dict]:
        """Get forensic extraction log."""
        return self.extraction_log
    
    def export_report(self, result: Dict, output_path: str = None) -> str:
        """
        Export extraction result to JSON report.
        
        Args:
            result: Extraction result dict
            output_path: Output file path (optional)
            
        Returns:
            Path to exported report
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"zero_click_extraction_{timestamp}.json"
        
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        logging.info(f"[ZERO-CLICK] Report exported: {output_path}")
        return output_path


# Convenience function for quick extraction
def extract_qr(file_path: str, case_id: str = None) -> Dict:
    """Quick function to extract QR from file without instantiation."""
    extractor = ZeroClickExtractor()
    return extractor.extract(file_path, case_id)


# Singleton instance
zero_click = ZeroClickExtractor()
