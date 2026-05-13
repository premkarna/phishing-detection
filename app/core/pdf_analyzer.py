"""
Advanced PDF Analysis Module
============================
Detects embedded JavaScript, malicious actions, and suspicious content in PDFs.
Extracts and analyzes embedded files, form actions, and JavaScript.
"""

import logging
import os
import re
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from pathlib import Path


class PDFAnalyzer:
    """
    Advanced PDF security analysis engine.
    
    Detects:
    - Embedded JavaScript and actions
    - Automatic URL open actions
    - Form submission handlers
    - Embedded files and attachments
    - Suspicious keywords and patterns
    - Known malicious PDF structures
    """
    
    def __init__(self):
        # Suspicious JavaScript patterns in PDFs
        self.suspicious_js_patterns = [
            r'app\.launchURL',           # Open URL automatically
            r'this\.submitForm',          # Submit form to external
            r'URL\s*=',                   # URL assignment
            r'window\.open',              # Open window
            r'location\.href',           # Redirect
            r'document\.write',           # Write to document
            r'eval\s*\(',                 # Eval (dangerous)
            r'Function\s*\(',             # Function constructor
            r'setInterval\s*\(',          # Timed execution
            r'setTimeout\s*\(',          # Delayed execution
            r'XMLHttpRequest',            # HTTP requests
            r'fetch\s*\(',                # Fetch API
            r'navigator\.sendBeacon',     # Beacon API for exfil
            r'atob\s*\(|btoa\s*\(',      # Base64 encoding/decoding (obfuscation)
            r'unescape\s*\(|escape\s*\(', # URL encoding
            r'String\.fromCharCode',      # Char code obfuscation
        ]
        
        # Suspicious PDF action types
        self.suspicious_actions = [
            '/Launch',           # Launch external application
            '/URI',              # Open URL
            '/SubmitForm',       # Submit form data
            '/ImportData',       # Import external data
            '/GoToR',            # Go to remote destination
            '/Thread',           # Launch thread
            '/Sound',            # Play sound (covert channel)
            '/Movie',            # Play movie (exploit vector)
        ]
        
        # Suspicious PDF keywords
        self.suspicious_keywords = [
            b'/JavaScript',
            b'/JS',
            b'/OpenAction',
            b'/AA',              # Additional Actions
            b'/AcroForm',
            b'/Launch',
            b'/EmbeddedFile',
            b'/Filespec',
            b'/URI',
            b'/Action',
            b'/SubmitForm',
            b'/ImportData',
            b'/XFA',             # XML Forms Architecture (often exploited)
        ]
        
        # Known malicious PDF signatures
        self.malicious_signatures = [
            b'/CVE-',            # CVE references (exploit mentions)
            b'shellcode',
            b'heap spray',
            b'ROP chain',
            b'buffer overflow',
        ]
        
        logging.info("[PDF ANALYZER] Advanced PDF analysis engine initialized")
    
    def analyze(self, pdf_path: str, case_id: str = None) -> Dict:
        """
        Perform comprehensive security analysis of a PDF file.
        
        Args:
            pdf_path: Path to PDF file
            case_id: Optional case identifier
            
        Returns:
            Complete analysis report
        """
        if not os.path.exists(pdf_path):
            return {'error': 'File not found', 'file_path': pdf_path}
        
        logging.info(f"[PDF ANALYZER] Analyzing: {pdf_path}")
        
        results = {
            'file_path': pdf_path,
            'case_id': case_id,
            'analysis_time': datetime.now().isoformat(),
            'file_hash': self._calculate_hash(pdf_path),
            'file_size': os.path.getsize(pdf_path),
            'has_javascript': False,
            'has_embedded_files': False,
            'has_auto_open_url': False,
            'has_form_submit': False,
            'javascript_analysis': [],
            'embedded_files': [],
            'urls_found': [],
            'suspicious_actions': [],
            'risk_score': 0,
            'risk_level': 'LOW',
            'indicators': []
        }
        
        try:
            # Read PDF content
            with open(pdf_path, 'rb') as f:
                content = f.read()
            
            # Basic structure analysis
            results['is_valid_pdf'] = content.startswith(b'%PDF')
            results['pdf_version'] = self._extract_pdf_version(content)
            
            # Check for JavaScript
            js_analysis = self._analyze_javascript(content)
            results['has_javascript'] = js_analysis['has_js']
            results['javascript_analysis'] = js_analysis['details']
            
            # Check for embedded files
            embedded = self._detect_embedded_files(content)
            results['has_embedded_files'] = len(embedded) > 0
            results['embedded_files'] = embedded
            
            # Extract and analyze URLs
            urls = self._extract_urls(content)
            results['urls_found'] = urls
            
            # Check for automatic actions
            actions = self._analyze_actions(content)
            results['has_auto_open_url'] = actions['has_auto_open']
            results['has_form_submit'] = actions['has_form_submit']
            results['suspicious_actions'] = actions['details']
            
            # Calculate risk score
            results['risk_score'] = self._calculate_risk(results)
            results['risk_level'] = self._get_risk_level(results['risk_score'])
            
            # Generate indicators
            results['indicators'] = self._generate_indicators(results)
            
            logging.info(f"[PDF ANALYZER] Analysis complete: Risk={results['risk_level']} ({results['risk_score']}/100)")
            
        except Exception as e:
            logging.error(f"[PDF ANALYZER] Analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _extract_pdf_version(self, content: bytes) -> str:
        """Extract PDF version from header."""
        match = re.search(rb'%PDF-(\d\.\d)', content[:100])
        return match.group(1).decode() if match else 'unknown'
    
    def _analyze_javascript(self, content: bytes) -> Dict:
        """Analyze PDF for embedded JavaScript."""
        result = {'has_js': False, 'details': []}
        
        # Check for JavaScript markers
        js_markers = [b'/JavaScript', b'/JS', b'function(', b'var ', b'eval(']
        for marker in js_markers:
            if marker in content:
                result['has_js'] = True
                break
        
        # Extract and analyze JS content
        if result['has_js']:
            # Find JavaScript streams (simplified extraction)
            js_streams = self._extract_js_streams(content)
            
            for i, stream in enumerate(js_streams[:5]):  # Analyze first 5
                analysis = {
                    'stream_index': i,
                    'size': len(stream),
                    'suspicious_patterns': [],
                    'decoded_content': None
                }
                
                # Check for suspicious patterns
                for pattern in self.suspicious_js_patterns:
                    if re.search(pattern.encode(), stream, re.IGNORECASE):
                        analysis['suspicious_patterns'].append(pattern)
                
                # Check for obfuscation indicators
                if len(re.findall(b'%[0-9A-Fa-f]{2}', stream)) > 20:
                    analysis['suspicious_patterns'].append('URL encoding (possible obfuscation)')
                
                if b'eval' in stream.lower() or b'Function' in stream:
                    analysis['suspicious_patterns'].append('Dynamic code execution')
                
                result['details'].append(analysis)
        
        return result
    
    def _extract_js_streams(self, content: bytes) -> List[bytes]:
        """Extract JavaScript stream content from PDF."""
        streams = []
        
        # Look for /JavaScript followed by stream
        pattern = b'/JavaScript.*?stream\r?\n(.*?)endstream'
        matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
        
        for match in matches[:10]:  # Limit to 10 streams
            # De-flate if compressed (simplified - real implementation needs zlib)
            streams.append(match)
        
        return streams
    
    def _detect_embedded_files(self, content: bytes) -> List[Dict]:
        """Detect embedded files in PDF."""
        embedded = []
        
        # Look for /EmbeddedFile
        if b'/EmbeddedFile' in content:
            # Extract file specifications
            file_specs = re.findall(rb'/Filespec.*?/F \(([^)]+)\)', content, re.DOTALL)
            
            for spec in file_specs[:10]:
                try:
                    filename = spec.decode('utf-8', errors='ignore')
                    embedded.append({
                        'filename': filename,
                        'extension': Path(filename).suffix.lower(),
                        'type': self._classify_file_type(filename)
                    })
                except (UnicodeDecodeError, AttributeError):
                    # Decode error or missing attributes - skip this file
                    continue
        
        return embedded
    
    def _classify_file_type(self, filename: str) -> str:
        """Classify embedded file type by extension."""
        ext = Path(filename).suffix.lower()
        
        dangerous = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.msi']
        documents = ['.pdf', '.doc', '.docx', '.xls', '.xlsx']
        archives = ['.zip', '.rar', '.7z', '.tar', '.gz']
        
        if ext in dangerous:
            return 'DANGEROUS_EXECUTABLE'
        elif ext in documents:
            return 'DOCUMENT'
        elif ext in archives:
            return 'ARCHIVE'
        else:
            return 'OTHER'
    
    def _extract_urls(self, content: bytes) -> List[str]:
        """Extract URLs from PDF content."""
        urls = []
        
        # Pattern for /URI
        uri_pattern = rb'/URI\s*\(\s*([^)]+)\)'
        matches = re.findall(uri_pattern, content)
        
        for match in matches:
            try:
                url = match.decode('utf-8', errors='ignore')
                if url.startswith(('http://', 'https://', 'ftp://')):
                    urls.append(url)
            except (UnicodeDecodeError, AttributeError):
                # Decode error or missing attributes - skip this URL
                continue
        
        # Also look for plain URLs in text streams
        text_urls = re.findall(rb'https?://[^\s\x00-\x1F\x7F-">)]+', content)
        for url in text_urls:
            try:
                decoded = url.decode('utf-8', errors='ignore')
                if decoded not in urls:
                    urls.append(decoded)
            except (UnicodeDecodeError, AttributeError):
                # Decode error or missing attributes - skip this URL
                continue
        
        return urls[:20]  # Limit to 20 URLs
    
    def _analyze_actions(self, content: bytes) -> Dict:
        """Analyze PDF actions (OpenAction, Launch, etc.)."""
        result = {
            'has_auto_open': False,
            'has_form_submit': False,
            'details': []
        }
        
        # Check for /OpenAction (runs when PDF opens)
        if b'/OpenAction' in content:
            result['has_auto_open'] = True
            result['details'].append({
                'action': 'OpenAction',
                'risk': 'Runs automatically when PDF opened',
                'severity': 'HIGH'
            })
        
        # Check for /Launch (launch external app)
        if b'/Launch' in content:
            result['details'].append({
                'action': 'Launch',
                'risk': 'Attempts to launch external application',
                'severity': 'CRITICAL'
            })
        
        # Check for /SubmitForm
        if b'/SubmitForm' in content or b'/submitForm' in content:
            result['has_form_submit'] = True
            # Extract submission URL if possible
            submit_urls = re.findall(rb'/SubmitForm.*?(https?://[^\s)]+)', content, re.DOTALL)
            result['details'].append({
                'action': 'SubmitForm',
                'risk': 'Submits form data to external URL',
                'severity': 'HIGH',
                'urls': [u.decode('utf-8', errors='ignore') for u in submit_urls[:3]]
            })
        
        # Check for /URI actions
        uri_actions = len(re.findall(rb'/URI\s*\(', content))
        if uri_actions > 0:
            result['details'].append({
                'action': 'URI',
                'risk': f'{uri_actions} URL opening actions found',
                'severity': 'MEDIUM',
                'count': uri_actions
            })
        
        return result
    
    def _calculate_risk(self, results: Dict) -> int:
        """Calculate overall risk score."""
        score = 0
        
        # JavaScript risk
        if results['has_javascript']:
            score += 25
            # Add more for suspicious JS patterns
            for detail in results['javascript_analysis']:
                score += len(detail.get('suspicious_patterns', [])) * 5
        
        # Embedded files risk
        if results['has_embedded_files']:
            score += 20
            for file in results['embedded_files']:
                if file['type'] == 'DANGEROUS_EXECUTABLE':
                    score += 30  # CRITICAL!
                elif file['type'] == 'ARCHIVE':
                    score += 10
        
        # Auto-open risk
        if results['has_auto_open_url']:
            score += 25
        
        # Form submit risk
        if results['has_form_submit']:
            score += 30
        
        # Actions risk
        for action in results['suspicious_actions']:
            if action.get('severity') == 'CRITICAL':
                score += 25
            elif action.get('severity') == 'HIGH':
                score += 15
            elif action.get('severity') == 'MEDIUM':
                score += 10
        
        # URL risk (if many URLs, suspicious)
        if len(results['urls_found']) > 10:
            score += 10
        
        return min(score, 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level."""
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_indicators(self, results: Dict) -> List[str]:
        """Generate human-readable indicators."""
        indicators = []
        
        if results['has_javascript']:
            js_count = len(results['javascript_analysis'])
            indicators.append(f'⚠️ Embedded JavaScript detected ({js_count} streams)')
            
            # List suspicious JS patterns found
            for detail in results['javascript_analysis']:
                patterns = detail.get('suspicious_patterns', [])
                for pattern in patterns[:3]:
                    indicators.append(f'  → Suspicious JS: {pattern}')
        
        if results['has_embedded_files']:
            for file in results['embedded_files']:
                if file['type'] == 'DANGEROUS_EXECUTABLE':
                    indicators.append(f'🚨 DANGEROUS: Embedded executable "{file["filename"]}"')
                else:
                    indicators.append(f'📎 Embedded file: {file["filename"]}')
        
        if results['has_auto_open_url']:
            indicators.append('🚨 Auto-open URL: PDF opens website automatically!')
        
        if results['has_form_submit']:
            indicators.append('🚨 Form submission: Sends data to external server!')
        
        for url in results['urls_found'][:5]:
            indicators.append(f'🔗 URL: {url[:60]}...')
        
        return indicators


# Convenience function
def analyze_pdf(pdf_path: str, case_id: str = None) -> Dict:
    """Quick PDF analysis function."""
    analyzer = PDFAnalyzer()
    return analyzer.analyze(pdf_path, case_id)


# Singleton
pdf_analyzer = PDFAnalyzer()
