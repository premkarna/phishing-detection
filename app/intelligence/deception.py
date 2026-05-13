"""
Honeytoken Integration Module
============================
Embeds trackable fake credentials in QR payloads to catch attackers.
Monitors if stolen credentials are actually used.
Provides geolocation and attacker behavior tracking.
"""

import logging
import hashlib
import json
import uuid
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import os


@dataclass
class Honeytoken:
    """Represents a trackable honeytoken credential."""
    token_id: str
    email: str
    password: str
    qr_hash: str  # Links to specific QR code
    campaign_id: str
    created_at: str
    expires_at: str
    status: str  # 'active', 'triggered', 'expired'
    trigger_data: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


class HoneytokenManager:
    """
    Manages honeytoken creation, embedding, and monitoring.
    
    Features:
    - Generate unique trackable credentials
    - Embed in QR payloads (email/password fields)
    - Monitor for usage across the internet
    - Alert when credentials are triggered
    - Track attacker geolocation and behavior
    """
    
    def __init__(self, storage_path: str = ""):
        if not storage_path:
            _root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            storage_path = os.path.join(_root, "data", "cache", "honeytoken_db.json")
        self.storage_path = storage_path
        self.tokens: Dict[str, Honeytoken] = {}
        self.email_domains = [
            'honey-check.com',
            'trap-email.net', 
            'bait-account.org',
            'canary-login.com'
        ]
        self.common_names = [
            'john.smith', 'jane.doe', 'admin', 'user', 'support',
            'billing', 'noreply', 'info', 'contact', 'service'
        ]
        
        # Load existing tokens
        self._load_tokens()
        
        logging.info(f"[HONEYTOKEN] Manager initialized with {len(self.tokens)} existing tokens")
    
    def _generate_unique_email(self) -> str:
        """Generate a unique, trackable email address."""
        name = self.common_names[hash(str(uuid.uuid4())) % len(self.common_names)]
        random_suffix = uuid.uuid4().hex[:8]
        domain = self.email_domains[hash(name) % len(self.email_domains)]
        return f"{name}.{random_suffix}@{domain}"
    
    def _generate_unique_password(self) -> str:
        """Generate a unique, realistic-looking password."""
        patterns = [
            "Welcome2024!",
            "Password123!",
            "Admin@2024",
            "Login#Secure1",
            "User@Pass123",
            "Access2024!",
            "Secure#Login1",
            "P@ssw0rd2024"
        ]
        # Add uniqueness
        base = patterns[hash(str(uuid.uuid4())) % len(patterns)]
        unique_suffix = uuid.uuid4().hex[:4]
        return f"{base}{unique_suffix}"
    
    def create_token(self, qr_payload: str, campaign_id: str = None) -> Honeytoken:
        """
        Create a new honeytoken linked to a specific QR code.
        
        Args:
            qr_payload: The QR code content (for linking)
            campaign_id: Optional campaign identifier
            
        Returns:
            New Honeytoken object
        """
        # Generate QR hash for linking
        qr_hash = hashlib.sha256(qr_payload.encode()).hexdigest()[:16]
        
        # Create token
        token = Honeytoken(
            token_id=str(uuid.uuid4()),
            email=self._generate_unique_email(),
            password=self._generate_unique_password(),
            qr_hash=qr_hash,
            campaign_id=campaign_id or f"CAMP_{datetime.now().strftime('%Y%m%d')}",
            created_at=datetime.now().isoformat(),
            expires_at=(datetime.now() + timedelta(days=30)).isoformat(),
            status='active',
            trigger_data=None
        )
        
        # Store token
        self.tokens[token.token_id] = token
        self._save_tokens()
        
        logging.info(f"[HONEYTOKEN] Created token {token.token_id[:8]}... for QR {qr_hash}")
        logging.info(f"[HONEYTOKEN] Email: {token.email}")
        
        return token
    
    def embed_in_payload(self, original_payload: str, campaign_id: str = None) -> Tuple[str, Honeytoken]:
        """
        Embed honeytoken into a QR payload by modifying URL parameters.
        
        Args:
            original_payload: Original URL from QR
            campaign_id: Optional campaign ID
            
        Returns:
            Tuple of (modified_payload_with_honeytoken, honeytoken_object)
        """
        token = self.create_token(original_payload, campaign_id)
        
        # For URLs with query parameters, add honeytoken as tracking parameter
        if '?' in original_payload:
            # Add as innocuous-looking parameter
            modified = f"{original_payload}&utm_source={token.email.split('@')[0]}&track_id={token.token_id[:8]}"
        else:
            modified = f"{original_payload}?utm_source={token.email.split('@')[0]}&track_id={token.token_id[:8]}"
        
        logging.info(f"[HONEYTOKEN] Embedded in payload: {modified[:80]}...")
        
        return modified, token
    
    def check_credential_usage(self, email: str, password: str, 
                              source_ip: str = None, 
                              user_agent: str = None,
                              timestamp: str = None) -> Optional[Dict]:
        """
        Check if submitted credentials match any honeytoken.
        Call this when monitoring login attempts.
        
        Args:
            email: Email attempting to login
            password: Password attempting to login
            source_ip: Attacker's IP (optional)
            user_agent: Attacker's browser (optional)
            timestamp: When attempt occurred (optional)
            
        Returns:
            Alert data if honeytoken triggered, None otherwise
        """
        for token_id, token in self.tokens.items():
            if token.status != 'active':
                continue
            
            # Check exact match
            if email.lower() == token.email.lower() and password == token.password:
                # HONEYTOKEN TRIGGERED! 🚨
                token.status = 'triggered'
                token.trigger_data = {
                    'timestamp': timestamp or datetime.now().isoformat(),
                    'source_ip': source_ip,
                    'user_agent': user_agent,
                    'attempted_email': email,
                    'attempted_password': password  # Yes, we capture what they tried
                }
                
                self._save_tokens()
                
                alert = {
                    'alert_type': 'HONEYTOKEN_TRIGGERED',
                    'severity': 'CRITICAL',
                    'token_id': token_id,
                    'campaign_id': token.campaign_id,
                    'qr_hash': token.qr_hash,
                    'trigger_data': token.trigger_data,
                    'message': f'🚨 HONEYTOKEN ALERT: Stolen credentials from QR {token.qr_hash} are being used!'
                }
                
                logging.critical(f"🚨🚨🚨 [HONEYTOKEN] TRIGGERED! Token: {token_id[:8]}...")
                logging.critical(f"🚨🚨🚨 Source IP: {source_ip}, Campaign: {token.campaign_id}")
                
                return alert
        
        return None
    
    def monitor_email_inbox(self, email: str) -> List[Dict]:
        """
        Check if honeytoken email address received any emails.
        Attackers sometimes test credentials or trigger password resets.
        
        Returns:
            List of received emails (would integrate with email API)
        """
        # This would integrate with email catching service
        # For now, return placeholder
        return []
    
    def get_active_tokens(self) -> List[Honeytoken]:
        """Get all currently active honeytokens."""
        return [t for t in self.tokens.values() if t.status == 'active']
    
    def get_triggered_tokens(self) -> List[Honeytoken]:
        """Get all triggered honeytokens (attacked!)."""
        return [t for t in self.tokens.values() if t.status == 'triggered']
    
    def get_campaign_report(self, campaign_id: str) -> Dict:
        """
        Generate report for a specific campaign.
        
        Returns:
            Campaign statistics
        """
        campaign_tokens = [t for t in self.tokens.values() if t.campaign_id == campaign_id]
        
        triggered = len([t for t in campaign_tokens if t.status == 'triggered'])
        active = len([t for t in campaign_tokens if t.status == 'active'])
        expired = len([t for t in campaign_tokens if t.status == 'expired'])
        
        return {
            'campaign_id': campaign_id,
            'total_tokens': len(campaign_tokens),
            'triggered': triggered,
            'active': active,
            'expired': expired,
            'compromise_rate': (triggered / len(campaign_tokens) * 100) if campaign_tokens else 0,
            'triggered_tokens': [t.to_dict() for t in campaign_tokens if t.status == 'triggered']
        }
    
    def _load_tokens(self):
        """Load tokens from storage."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for token_id, token_data in data.items():
                        self.tokens[token_id] = Honeytoken(**token_data)
            except Exception as e:
                logging.error(f"[HONEYTOKEN] Failed to load tokens: {e}")
    
    def _save_tokens(self):
        """Save tokens to storage."""
        try:
            data = {tid: t.to_dict() for tid, t in self.tokens.items()}
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"[HONEYTOKEN] Failed to save tokens: {e}")
    
    def cleanup_expired(self):
        """Mark expired tokens and archive them."""
        now = datetime.now()
        cleaned = 0
        
        for token in self.tokens.values():
            if token.status == 'active':
                expires = datetime.fromisoformat(token.expires_at)
                if now > expires:
                    token.status = 'expired'
                    cleaned += 1
        
        if cleaned > 0:
            self._save_tokens()
            logging.info(f"[HONEYTOKEN] Cleaned up {cleaned} expired tokens")


# Convenience function
def create_honeytoken(qr_payload: str, campaign_id: str = None) -> Tuple[str, Honeytoken]:
    """Quick function to create and embed honeytoken."""
    manager = HoneytokenManager()
    return manager.embed_in_payload(qr_payload, campaign_id)


# Singleton
honeytoken_manager = HoneytokenManager()
