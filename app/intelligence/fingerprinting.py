"""
QR Fingerprinting & Campaign Tracking Module
============================================
Creates unique fingerprints for QR codes to track across campaigns.
Links related QR attacks to identify threat actor infrastructure.
"""

import logging
import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import os


@dataclass
class QRFingerprint:
    """Unique fingerprint of a QR code attack."""
    fingerprint_id: str
    qr_hash: str  # Visual hash of QR code
    payload_hash: str  # Hash of decoded content
    url_pattern: str  # Normalized URL pattern
    domain: str
    campaign_id: Optional[str]
    first_seen: str
    last_seen: str
    occurrence_count: int
    related_fingerprints: List[str]
    metadata: Dict


class QRFingerprintingEngine:
    """
    Tracks QR code attacks across time and campaigns.
    
    Features:
    - Visual QR code fingerprinting
    - Payload pattern matching
    - Campaign attribution
    - Infrastructure linking
    - Threat actor profiling
    """
    
    def __init__(self, storage_path: str = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "cache", "qr_fingerprints.json")):
        self.storage_path = storage_path
        self.fingerprints: Dict[str, QRFingerprint] = {}
        self.campaigns: Dict[str, List[str]] = defaultdict(list)  # campaign_id -> fingerprints
        self.domain_index: Dict[str, List[str]] = defaultdict(list)  # domain -> fingerprints
        
        # Load existing data
        self._load_data()
        
        logging.info(f"[QR FINGERPRINT] Engine initialized with {len(self.fingerprints)} fingerprints")
    
    def create_fingerprint(self, qr_payload: str, image_hash: str = None,
                          campaign_id: str = None, metadata: Dict = None) -> QRFingerprint:
        """
        Create a new fingerprint for a QR code.
        
        Args:
            qr_payload: Decoded QR content
            image_hash: Hash of QR image (visual fingerprint)
            campaign_id: Optional campaign identifier
            metadata: Additional context
            
        Returns:
            QRFingerprint object
        """
        # Create payload hash
        payload_hash = hashlib.sha256(qr_payload.encode()).hexdigest()[:16]
        
        # Extract and normalize URL pattern
        url_pattern = self._extract_url_pattern(qr_payload)
        domain = self._extract_domain(qr_payload)
        
        # Create visual fingerprint (if image hash not provided, use payload)
        visual_hash = image_hash or payload_hash
        
        # Generate fingerprint ID
        fingerprint_id = hashlib.sha256(
            f"{visual_hash}:{url_pattern}".encode()
        ).hexdigest()[:16]
        
        # Check if this fingerprint already exists
        if fingerprint_id in self.fingerprints:
            # Update existing
            fp = self.fingerprints[fingerprint_id]
            fp.last_seen = datetime.now().isoformat()
            fp.occurrence_count += 1
            
            if campaign_id and campaign_id not in self.campaigns:
                self.campaigns[campaign_id].append(fingerprint_id)
        
        else:
            # Create new fingerprint
            fp = QRFingerprint(
                fingerprint_id=fingerprint_id,
                qr_hash=visual_hash,
                payload_hash=payload_hash,
                url_pattern=url_pattern,
                domain=domain or 'unknown',
                campaign_id=campaign_id,
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                occurrence_count=1,
                related_fingerprints=[],
                metadata=metadata or {}
            )
            
            self.fingerprints[fingerprint_id] = fp
            
            # Index by campaign
            if campaign_id:
                self.campaigns[campaign_id].append(fingerprint_id)
            
            # Index by domain
            if domain:
                self.domain_index[domain].append(fingerprint_id)
            
            # Find related fingerprints
            self._link_related_fingerprints(fp)
            
            logging.info(f"[QR FINGERPRINT] New fingerprint created: {fingerprint_id}")
        
        self._save_data()
        return fp
    
    def _extract_url_pattern(self, payload: str) -> str:
        """Extract and normalize URL pattern from payload."""
        # Find URLs
        urls = re.findall(r'https?://[^\s\x00-\x1F\x7F"<>]+', payload)
        
        if not urls:
            return 'non_url_payload'
        
        url = urls[0]
        
        # Normalize:
        # 1. Remove random-looking path components (campaign IDs, tracking)
        # 2. Keep structure like /login/, /auth/, etc.
        
        # Remove query parameters
        url = url.split('?')[0]
        
        # Replace random-looking components with [RANDOM]
        # Match patterns like: /a1b2c3/, /xyz789/, etc.
        url = re.sub(r'/[a-z0-9]{6,12}/', '/[RANDOM]/', url)
        url = re.sub(r'/[a-z0-9]{8,16}$', '/[RANDOM]', url)
        
        return url
    
    def _extract_domain(self, payload: str) -> Optional[str]:
        """Extract domain from payload."""
        try:
            from urllib.parse import urlparse
            urls = re.findall(r'https?://[^\s\x00-\x1F\x7F"<>]+', payload)
            if urls:
                parsed = urlparse(urls[0])
                return parsed.netloc.lower() if parsed.netloc else None
        except (ValueError, AttributeError):
            # URL parsing error - return None
            pass
        return None
    
    def _link_related_fingerprints(self, new_fp: QRFingerprint):
        """Find and link related fingerprints (same campaign, similar patterns)."""
        related = []
        
        for fp_id, fp in self.fingerprints.items():
            if fp_id == new_fp.fingerprint_id:
                continue
            
            # Same campaign
            if fp.campaign_id and fp.campaign_id == new_fp.campaign_id:
                related.append(fp_id)
                continue
            
            # Same domain
            if fp.domain == new_fp.domain:
                related.append(fp_id)
                continue
            
            # Similar URL pattern (same structure, different random components)
            if self._patterns_similar(fp.url_pattern, new_fp.url_pattern):
                related.append(fp_id)
                continue
        
        new_fp.related_fingerprints = related[:10]  # Keep top 10
    
    def _patterns_similar(self, pattern1: str, pattern2: str) -> bool:
        """Check if two URL patterns are similar (same structure)."""
        # Remove random markers for comparison
        p1 = pattern1.replace('[RANDOM]', 'XXX')
        p2 = pattern2.replace('[RANDOM]', 'XXX')
        
        # Check if base paths match
        parts1 = p1.split('/')
        parts2 = p2.split('/')
        
        if len(parts1) != len(parts2):
            return False
        
        # Allow one component to differ (the random one)
        differences = sum(1 for a, b in zip(parts1, parts2) if a != b)
        return differences <= 1
    
    def find_matches(self, qr_payload: str) -> List[QRFingerprint]:
        """
        Find existing fingerprints matching this QR payload.
        
        Returns:
            List of matching fingerprints
        """
        matches = []
        
        payload_hash = hashlib.sha256(qr_payload.encode()).hexdigest()[:16]
        url_pattern = self._extract_url_pattern(qr_payload)
        domain = self._extract_domain(qr_payload)
        
        for fp in self.fingerprints.values():
            # Exact payload match
            if fp.payload_hash == payload_hash:
                matches.append(fp)
                continue
            
            # Same URL pattern
            if fp.url_pattern == url_pattern:
                matches.append(fp)
                continue
            
            # Same domain with similar pattern
            if domain and fp.domain == domain:
                if self._patterns_similar(fp.url_pattern, url_pattern):
                    matches.append(fp)
        
        return matches
    
    def get_campaign_analysis(self, campaign_id: str) -> Dict:
        """
        Analyze a campaign's QR attack patterns.
        
        Returns:
            Campaign analysis report
        """
        fp_ids = self.campaigns.get(campaign_id, [])
        fingerprints = [self.fingerprints[fp_id] for fp_id in fp_ids]
        
        if not fingerprints:
            return {'error': 'Campaign not found'}
        
        # Analyze patterns
        domains = defaultdict(int)
        url_patterns = defaultdict(int)
        
        for fp in fingerprints:
            domains[fp.domain] += fp.occurrence_count
            url_patterns[fp.url_pattern] += fp.occurrence_count
        
        # Timeline analysis
        first_seen = min(fp.first_seen for fp in fingerprints)
        last_seen = max(fp.last_seen for fp in fingerprints)
        
        # Infrastructure reuse
        related_campaigns = set()
        for fp in fingerprints:
            for related_id in fp.related_fingerprints:
                related_fp = self.fingerprints.get(related_id)
                if related_fp and related_fp.campaign_id:
                    related_campaigns.add(related_fp.campaign_id)
        
        return {
            'campaign_id': campaign_id,
            'total_qr_codes': len(fingerprints),
            'total_occurrences': sum(fp.occurrence_count for fp in fingerprints),
            'unique_domains': len(domains),
            'domains': dict(domains),
            'url_patterns': dict(url_patterns),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'duration_days': (datetime.fromisoformat(last_seen) - 
                            datetime.fromisoformat(first_seen)).days,
            'related_campaigns': list(related_campaigns)
        }
    
    def get_threat_actor_profile(self, fingerprint_ids: List[str]) -> Dict:
        """
        Build a threat actor profile from multiple fingerprints.
        
        Returns:
            Threat actor TTPs and infrastructure
        """
        fps = [self.fingerprints.get(fp_id) for fp_id in fingerprint_ids]
        fps = [fp for fp in fps if fp]
        
        if not fps:
            return {'error': 'No fingerprints found'}
        
        # Infrastructure
        domains = list(set(fp.domain for fp in fps))
        
        # Patterns
        url_structures = list(set(fp.url_pattern for fp in fps))
        
        # Timeline
        activity_periods = [(fp.first_seen, fp.last_seen) for fp in fps]
        
        # Campaigns
        campaigns = list(set(fp.campaign_id for fp in fps if fp.campaign_id))
        
        return {
            'fingerprints_analyzed': len(fps),
            'infrastructure': {
                'domains': domains,
                'domain_count': len(domains)
            },
            'tactics': {
                'url_structures': url_structures,
                'pattern_count': len(url_structures)
            },
            'campaigns': campaigns,
            'activity_summary': {
                'periods': activity_periods,
                'total_occurrences': sum(fp.occurrence_count for fp in fps)
            }
        }
    
    def generate_iocs(self, hours: int = 24) -> Dict:
        """Generate IOCs from recent fingerprints."""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        iocs = {
            'domains': set(),
            'urls': set(),
            'patterns': set()
        }
        
        for fp in self.fingerprints.values():
            last_seen = datetime.fromisoformat(fp.last_seen)
            if last_seen > cutoff:
                if fp.domain:
                    iocs['domains'].add(fp.domain)
                iocs['urls'].add(fp.url_pattern)
        
        return {
            'generated_at': datetime.now().isoformat(),
            'lookback_hours': hours,
            'domains': list(iocs['domains']),
            'url_patterns': list(iocs['urls'])
        }
    
    def _save_data(self):
        """Save fingerprints to storage."""
        try:
            data = {
                'fingerprints': {fid: asdict(fp) for fid, fp in self.fingerprints.items()},
                'campaigns': dict(self.campaigns),
                'last_saved': datetime.now().isoformat()
            }
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"[QR FINGERPRINT] Save failed: {e}")
    
    def _load_data(self):
        """Load fingerprints from storage."""
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                
                for fid, fp_data in data.get('fingerprints', {}).items():
                    self.fingerprints[fid] = QRFingerprint(**fp_data)
                
                for cid, fp_ids in data.get('campaigns', {}).items():
                    self.campaigns[cid] = fp_ids
                
                # Rebuild domain index
                for fp in self.fingerprints.values():
                    if fp.domain:
                        self.domain_index[fp.domain].append(fp.fingerprint_id)
                
                logging.info(f"[QR FINGERPRINT] Loaded {len(self.fingerprints)} fingerprints")
        except Exception as e:
            logging.error(f"[QR FINGERPRINT] Load failed: {e}")


# Singleton
qr_fingerprint_engine = QRFingerprintingEngine()


# Convenience functions
def fingerprint_qr(qr_payload: str, campaign_id: str = None) -> QRFingerprint:
    """Quick fingerprint creation."""
    return qr_fingerprint_engine.create_fingerprint(qr_payload, campaign_id=campaign_id)

def check_qr_history(qr_payload: str) -> List[QRFingerprint]:
    """Check if QR has been seen before."""
    return qr_fingerprint_engine.find_matches(qr_payload)
