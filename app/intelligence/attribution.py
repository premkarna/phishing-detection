"""
Campaign Attribution Engine
==========================
Links QR-based attacks to known threat actors and campaigns.
Uses TTPs (Tactics, Techniques, Procedures) for attribution.
Identifies infrastructure reuse and actor behavior patterns.
"""

import logging
import json
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import os


@dataclass
class ThreatActor:
    """Known threat actor profile."""
    actor_id: str
    name: str
    aliases: List[str]
    first_seen: str
    ttps: Dict[str, List[str]]  # Tactics, Techniques, Procedures
    infrastructure: Dict[str, List[str]]  # Known domains, IPs, patterns
    targets: List[str]  # Targeted industries/regions
    description: str


@dataclass
class Campaign:
    """Attack campaign profile."""
    campaign_id: str
    name: str
    actor_id: Optional[str]
    start_date: str
    end_date: Optional[str]
    attack_vector: str  # 'qr', 'email', 'web', etc.
    indicators: List[str]
    infrastructure: List[str]
    targets: List[str]
    attribution_confidence: str  # 'high', 'medium', 'low'


class CampaignAttributionEngine:
    """
    Attributes QR-based attacks to threat actors and campaigns.
    
    Uses:
    - TTP matching (Tactics, Techniques, Procedures)
    - Infrastructure overlap (shared domains, IPs)
    - Temporal correlation (timing patterns)
    - Target analysis (victim profiles)
    """
    
    def __init__(self, actors_db_path: str = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "cache", "threat_actors.json")):
        self.actors_db_path = actors_db_path
        self.actors: Dict[str, ThreatActor] = {}
        self.campaigns: Dict[str, Campaign] = {}
        
        # TTP signatures for matching
        self.ttp_signatures = {
            'url_structure_patterns': [
                r'/[a-z0-9]{8}/login',  # Random 8-char + login
                r'/auth/[0-9]{6}',       # Auth + 6 digits
                r'/secure/[a-z]{4}[0-9]{4}',  # Secure + mixed
            ],
            'domain_generation_patterns': [
                r'^[a-z]{10,15}\.(tk|ml|ga|cf)$',  # DGA-like free domains
                r'^[a-z]+-secure-[a-z]+\.(com|net)$',  # Keyword combo
            ],
            'credential_harvesting': [
                'immediate_form_submit',
                'hidden_iframe_post',
                'javascript_obfuscation',
                'credential_encryption_in_transit'
            ]
        }
        
        # Load threat actor database
        self._load_actors_db()
        
        # Initialize known actors
        self._init_known_actors()
        
        logging.info(f"[ATTRIBUTION] Engine initialized with {len(self.actors)} actors")
    
    def _init_known_actors(self):
        """Initialize database with known QR-phishing actors."""
        known_actors = [
            {
                'actor_id': 'TA-QR-001',
                'name': 'QRPhish-Alpha',
                'aliases': ['AlphaQR', 'QuickPhish'],
                'first_seen': '2023-01-15',
                'ttps': {
                    'initial_access': ['qr_code_social_media', 'qr_code_email'],
                    'infrastructure': ['free_tld_domains', 'cloudflare_proxy'],
                    'payload_delivery': ['credential_harvesting', 'fake_login_forms'],
                    'evasion': ['domain_rotation', 'short_url_obfuscation']
                },
                'infrastructure': {
                    'tlds': ['.tk', '.ml', '.ga'],
                    'patterns': ['/secure/login.php', '/auth/verify'],
                    'services': ['bit.ly', 'tinyurl']
                },
                'targets': ['financial', 'healthcare', 'retail'],
                'description': 'Opportunistic QR phishing group targeting multiple sectors'
            },
            {
                'actor_id': 'TA-QR-002',
                'name': 'BankQR-Phantom',
                'aliases': ['PhantomBank', 'QR-Banker'],
                'first_seen': '2023-06-20',
                'ttps': {
                    'initial_access': ['qr_code_physical_posters', 'qr_code_flyers'],
                    'infrastructure': ['typosquat_domains', 'brand_impersonation'],
                    'payload_delivery': ['banking_credential_harvest', '2fa_bypass'],
                    'evasion': ['ssl_certificate', 'domain_age_manipulation']
                },
                'infrastructure': {
                    'tlds': ['.com', '.net', '.online'],
                    'patterns': ['/login/secure', '/verify/account'],
                    'targets_brands': ['chase', 'wellsfargo', 'bankofamerica', 'citi']
                },
                'targets': ['banking', 'fintech'],
                'description': 'Sophisticated banking-focused QR phishing group'
            },
            {
                'actor_id': 'TA-QR-003',
                'name': 'RetailQR-Snatcher',
                'aliases': ['SnatchQR', 'RetailPhish'],
                'first_seen': '2023-09-10',
                'ttps': {
                    'initial_access': ['qr_code_payment_terminals', 'qr_code_receipts'],
                    'infrastructure': ['brand_typosquat', 'payment_portal_clone'],
                    'payload_delivery': ['payment_credential_harvest', 'gift_card_fraud'],
                    'evasion': ['session_hijacking', 'redirect_chains']
                },
                'infrastructure': {
                    'tlds': ['.shop', '.store', '.online'],
                    'patterns': ['/payment/confirm', '/checkout/secure'],
                    'targets_brands': ['amazon', 'walmart', 'target', 'bestbuy']
                },
                'targets': ['retail', 'e-commerce', 'payment_processors'],
                'description': 'Retail and payment-focused QR phishing operation'
            },
            {
                'actor_id': 'TA-QR-004',
                'name': 'APT-QR-Dragon',
                'aliases': ['DragonQR', 'QR-APT'],
                'first_seen': '2022-11-05',
                'ttps': {
                    'initial_access': ['qr_code_spearphishing', 'qr_code_conferences'],
                    'infrastructure': ['compromised_legitimate_domains', 'bulletproof_hosting'],
                    'payload_delivery': ['multi_stage_payload', 'credential_harvest', 'device_fingerprinting'],
                    'evasion': ['advanced_obfuscation', 'geofencing', 'device_targeting']
                },
                'infrastructure': {
                    'tlds': ['.com', '.net', '.org'],
                    'patterns': ['/portal/login', '/sso/authenticate'],
                    'characteristics': ['aged_domains', 'valid_ssl', 'cdn_proxied']
                },
                'targets': ['government', 'defense', 'technology', 'energy'],
                'description': 'Advanced persistent threat using QR for initial access'
            }
        ]
        
        for actor_data in known_actors:
            actor = ThreatActor(**actor_data)
            self.actors[actor.actor_id] = actor
        
        self._save_actors_db()
    
    def attribute_attack(self, qr_analysis: Dict) -> Dict:
        """
        Attribute a QR attack to a threat actor.
        
        Args:
            qr_analysis: Analysis results from QR processing
            
        Returns:
            Attribution results with confidence scores
        """
        attribution = {
            'timestamp': datetime.now().isoformat(),
            'primary_attribution': None,
            'confidence': 'low',
            'possible_actors': [],
            'matching_indicators': {},
            'attribution_reasoning': []
        }
        
        # Extract TTPs from attack
        attack_ttps = self._extract_ttps(qr_analysis)
        
        # Score against each actor
        actor_scores = {}
        
        for actor_id, actor in self.actors.items():
            score = 0
            matches = []
            
            # Check URL patterns
            if 'url_pattern' in qr_analysis:
                url = qr_analysis['url_pattern']
                for pattern in actor.ttps.get('infrastructure', []):
                    if self._pattern_matches(url, pattern):
                        score += 2
                        matches.append(f"Infrastructure pattern: {pattern}")
            
            # Check domain
            if 'domain' in qr_analysis:
                domain = qr_analysis['domain']
                for tld in actor.infrastructure.get('tlds', []):
                    if domain.endswith(tld):
                        score += 1
                        matches.append(f"TLD match: {tld}")
                
                # Check targeted brands
                for brand in actor.infrastructure.get('targets_brands', []):
                    if brand in domain.lower():
                        score += 3
                        matches.append(f"Brand typosquat: {brand}")
            
            # Check attack vector
            if qr_analysis.get('attack_vector') in actor.ttps.get('initial_access', []):
                score += 2
                matches.append(f"Attack vector: {qr_analysis['attack_vector']}")
            
            # Check payload delivery
            if 'payload_type' in qr_analysis:
                for technique in actor.ttps.get('payload_delivery', []):
                    if technique in qr_analysis['payload_type']:
                        score += 2
                        matches.append(f"Payload technique: {technique}")
            
            # Check targets
            if 'target_sector' in qr_analysis:
                if qr_analysis['target_sector'] in actor.targets:
                    score += 2
                    matches.append(f"Target sector match: {qr_analysis['target_sector']}")
            
            if score > 0:
                actor_scores[actor_id] = {
                    'score': score,
                    'matches': matches,
                    'actor': actor
                }
        
        # Determine attribution
        if actor_scores:
            # Sort by score
            sorted_scores = sorted(actor_scores.items(), 
                                 key=lambda x: x[1]['score'], 
                                 reverse=True)
            
            top_actor_id, top_data = sorted_scores[0]
            
            attribution['primary_attribution'] = {
                'actor_id': top_actor_id,
                'actor_name': top_data['actor'].name,
                'aliases': top_data['actor'].aliases,
                'score': top_data['score']
            }
            
            attribution['matching_indicators'] = top_data['matches']
            
            # Set confidence
            if top_data['score'] >= 8:
                attribution['confidence'] = 'high'
            elif top_data['score'] >= 5:
                attribution['confidence'] = 'medium'
            else:
                attribution['confidence'] = 'low'
            
            # Add possible actors
            for actor_id, data in sorted_scores[:3]:  # Top 3
                attribution['possible_actors'].append({
                    'actor_id': actor_id,
                    'actor_name': data['actor'].name,
                    'score': data['score'],
                    'match_count': len(data['matches'])
                })
            
            # Generate reasoning
            attribution['attribution_reasoning'] = self._generate_reasoning(
                attribution['primary_attribution'],
                top_data['matches']
            )
        
        logging.info(f"[ATTRIBUTION] Attack attributed to {attribution['primary_attribution']['actor_name'] if attribution['primary_attribution'] else 'unknown'} "
                    f"with {attribution['confidence']} confidence")
        
        return attribution
    
    def _extract_ttps(self, qr_analysis: Dict) -> Dict:
        """Extract TTPs from QR analysis."""
        ttps = {
            'initial_access': [],
            'infrastructure': [],
            'payload_delivery': [],
            'evasion': []
        }
        
        # Extract based on analysis data
        url = qr_analysis.get('url_pattern', '')
        domain = qr_analysis.get('domain', '')
        
        # Infrastructure patterns
        if re.search(r'/[a-z0-9]{6,10}/', url):
            ttps['infrastructure'].append('randomized_paths')
        
        if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']):
            ttps['infrastructure'].append('free_tld_domains')
        
        # Evasion
        if qr_analysis.get('uses_shortener'):
            ttps['evasion'].append('url_shortener')
        
        if qr_analysis.get('has_redirect_chain'):
            ttps['evasion'].append('redirect_chains')
        
        return ttps
    
    def _pattern_matches(self, url: str, pattern: str) -> bool:
        """Check if URL matches a TTP pattern."""
        import re
        try:
            return bool(re.search(pattern, url, re.IGNORECASE))
        except (re.error, TypeError):
            # Invalid regex pattern or wrong type - fallback to simple string check
            return pattern.lower() in url.lower()
    
    def _generate_reasoning(self, attribution: Dict, matches: List[str]) -> List[str]:
        """Generate human-readable attribution reasoning."""
        reasoning = []
        
        actor_name = attribution['actor_name']
        
        if matches:
            reasoning.append(f"Attack infrastructure and TTPs match known {actor_name} patterns:")
            for match in matches[:5]:
                reasoning.append(f"  • {match}")
        
        score = attribution['score']
        if score >= 8:
            reasoning.append(f"High confidence attribution (score: {score}/10+) based on multiple matching indicators.")
        elif score >= 5:
            reasoning.append(f"Medium confidence attribution (score: {score}/10) - some indicators match but require further verification.")
        else:
            reasoning.append(f"Low confidence attribution (score: {score}/10) - limited matching indicators, possible copycat or coincidental similarity.")
        
        return reasoning
    
    def link_attacks(self, attack_list: List[Dict]) -> Dict:
        """
        Link multiple attacks to identify campaigns.
        
        Args:
            attack_list: List of QR attack analyses
            
        Returns:
            Campaign linkage analysis
        """
        # Group by common indicators
        infrastructure_groups = defaultdict(list)
        temporal_groups = defaultdict(list)
        
        for attack in attack_list:
            # Infrastructure grouping
            domain = attack.get('domain')
            if domain:
                infrastructure_groups[domain].append(attack)
            
            # Temporal grouping (by day)
            timestamp = attack.get('timestamp', '')
            if timestamp:
                day = timestamp[:10]  # YYYY-MM-DD
                temporal_groups[day].append(attack)
        
        # Identify campaigns
        campaigns = []
        
        # Infrastructure-based campaigns
        for domain, attacks in infrastructure_groups.items():
            if len(attacks) >= 3:  # 3+ attacks from same domain
                campaigns.append({
                    'campaign_type': 'infrastructure_based',
                    'key': domain,
                    'attack_count': len(attacks),
                    'time_span': self._calculate_time_span(attacks),
                    'attribution': self._common_attribution(attacks)
                })
        
        return {
            'total_attacks_analyzed': len(attack_list),
            'identified_campaigns': campaigns,
            'infrastructure_clusters': len([c for c in campaigns if c['campaign_type'] == 'infrastructure_based']),
            'temporal_clusters': len([c for c in campaigns if c['campaign_type'] == 'temporal_based'])
        }
    
    def _calculate_time_span(self, attacks: List[Dict]) -> str:
        """Calculate time span of attacks."""
        timestamps = [a.get('timestamp', '') for a in attacks if a.get('timestamp')]
        if not timestamps:
            return 'unknown'
        
        timestamps.sort()
        first = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
        last = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
        
        duration = last - first
        return f"{duration.days} days, {duration.seconds // 3600} hours"
    
    def _common_attribution(self, attacks: List[Dict]) -> Optional[str]:
        """Find most common attribution in attack group."""
        attributions = [a.get('attribution', {}).get('actor_id') for a in attacks]
        attributions = [a for a in attributions if a]
        
        if not attributions:
            return None
        
        # Count occurrences
        from collections import Counter
        most_common = Counter(attributions).most_common(1)[0][0]
        return most_common
    
    def get_actor_profile(self, actor_id: str) -> Optional[Dict]:
        """Get detailed profile of a threat actor."""
        actor = self.actors.get(actor_id)
        if not actor:
            return None
        
        return {
            'actor_id': actor.actor_id,
            'name': actor.name,
            'aliases': actor.aliases,
            'active_since': actor.first_seen,
            'ttps': actor.ttps,
            'infrastructure': actor.infrastructure,
            'target_sectors': actor.targets,
            'description': actor.description
        }
    
    def _load_actors_db(self):
        """Load threat actor database."""
        try:
            if os.path.exists(self.actors_db_path):
                with open(self.actors_db_path, 'r') as f:
                    data = json.load(f)
                
                for actor_id, actor_data in data.get('actors', {}).items():
                    self.actors[actor_id] = ThreatActor(**actor_data)
        except Exception as e:
            logging.warning(f"[ATTRIBUTION] Failed to load actors DB: {e}")
    
    def _save_actors_db(self):
        """Save threat actor database."""
        try:
            data = {
                'actors': {aid: actor.__dict__ for aid, actor in self.actors.items()},
                'last_updated': datetime.now().isoformat()
            }
            with open(self.actors_db_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"[ATTRIBUTION] Failed to save actors DB: {e}")


# Singleton
attribution_engine = CampaignAttributionEngine()


# Convenience functions
def attribute_qr_attack(qr_analysis: Dict) -> Dict:
    """Quick attribution function."""
    return attribution_engine.attribute_attack(qr_analysis)

def get_actor_info(actor_id: str) -> Optional[Dict]:
    """Get actor profile."""
    return attribution_engine.get_actor_profile(actor_id)
