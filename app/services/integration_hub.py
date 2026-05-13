"""
Integration Hub for SIEM/SOAR Platforms
========================================
Provides connectors for major security platforms:
- Splunk
- IBM QRadar
- Palo Alto XSOAR (Demisto)
- ServiceNow
- Jira
- Slack/Teams alerting
"""

import logging
import requests
import json
from datetime import datetime
from typing import Dict, List, Optional
import os


class IntegrationHub:
    """
    Central hub for integrating with security platforms.
    
    Supports:
    - SIEM platforms (Splunk, QRadar)
    - SOAR platforms (XSOAR, Phantom)
    - Ticketing systems (ServiceNow, Jira)
    - Communication (Slack, Teams, Email)
    - Threat intel sharing (MISP, TAXII)
    """
    
    def __init__(self):
        # Platform configurations
        self.splunk_config = {
            'host': os.getenv('SPLUNK_HOST', ''),
            'token': os.getenv('SPLUNK_HEC_TOKEN', ''),
            'port': int(os.getenv('SPLUNK_PORT', '8088')),
            'ssl': os.getenv('SPLUNK_SSL', 'true').lower() == 'true'
        }
        
        self.qradar_config = {
            'host': os.getenv('QRADAR_HOST', ''),
            'token': os.getenv('QRADAR_TOKEN', ''),
            'port': int(os.getenv('QRADAR_PORT', '443')),
            'ssl': os.getenv('QRADAR_SSL', 'true').lower() == 'true'
        }
        
        self.xsoar_config = {
            'host': os.getenv('XSOAR_HOST', ''),
            'api_key': os.getenv('XSOAR_API_KEY', ''),
            'port': int(os.getenv('XSOAR_PORT', '443')),
        }
        
        self.servicenow_config = {
            'instance': os.getenv('SERVICENOW_INSTANCE', ''),
            'username': os.getenv('SERVICENOW_USER', ''),
            'password': os.getenv('SERVICENOW_PASS', ''),
        }
        
        self.jira_config = {
            'server': os.getenv('JIRA_SERVER', ''),
            'username': os.getenv('JIRA_USER', ''),
            'token': os.getenv('JIRA_TOKEN', ''),
        }
        
        self.slack_config = {
            'webhook_url': os.getenv('SLACK_WEBHOOK', ''),
            'channel': os.getenv('SLACK_CHANNEL', '#security-alerts'),
        }
        
        self.teams_config = {
            'webhook_url': os.getenv('TEAMS_WEBHOOK', ''),
        }
        
        logging.info("[INTEGRATION] Hub initialized")
    
    def send_to_splunk(self, alert_data: Dict, index: str = "security") -> bool:
        """
        Send alert to Splunk HTTP Event Collector (HEC).
        
        Args:
            alert_data: Alert information
            index: Splunk index name
            
        Returns:
            True if successful
        """
        if not all([self.splunk_config['host'], self.splunk_config['token']]):
            logging.warning("[INTEGRATION] Splunk not configured")
            return False
        
        try:
            url = f"{'https' if self.splunk_config['ssl'] else 'http'}://" \
                  f"{self.splunk_config['host']}:{self.splunk_config['port']}/services/collector/event"
            
            headers = {
                'Authorization': f"Splunk {self.splunk_config['token']}",
                'Content-Type': 'application/json'
            }
            
            event = {
                'time': datetime.now().timestamp(),
                'index': index,
                'sourcetype': 'quishing:detection',
                'event': alert_data
            }
            
            response = requests.post(url, headers=headers, json=event, timeout=30)
            
            if response.status_code == 200:
                logging.info("[INTEGRATION] Alert sent to Splunk")
                return True
            else:
                logging.error(f"[INTEGRATION] Splunk error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logging.error(f"[INTEGRATION] Failed to send to Splunk: {e}")
            return False
    
    def send_to_qradar(self, alert_data: Dict) -> bool:
        """
        Send offense to IBM QRadar.
        
        Args:
            alert_data: Alert information
            
        Returns:
            True if successful
        """
        if not all([self.qradar_config['host'], self.qradar_config['token']]):
            logging.warning("[INTEGRATION] QRadar not configured")
            return False
        
        try:
            url = f"{'https' if self.qradar_config['ssl'] else 'http'}://" \
                  f"{self.qradar_config['host']}:{self.qradar_config['port']}/api/siem/offenses"
            
            headers = {
                'SEC': self.qradar_config['token'],
                'Content-Type': 'application/json',
                'Version': '9.1'
            }
            
            # Map to QRadar offense format
            offense = {
                'description': alert_data.get('description', 'QR Phishing Detected'),
                'offense_type': 0,  # Custom type
                'magnitude': self._calculate_magnitude(alert_data.get('risk_score', 50)),
                'source_ip': alert_data.get('source_ip'),
                'destination_ip': alert_data.get('destination_ip'),
                'severity': self._map_to_severity(alert_data.get('risk_level', 'MEDIUM'))
            }
            
            response = requests.post(url, headers=headers, json=offense, timeout=30)
            
            if response.status_code in [200, 201]:
                logging.info("[INTEGRATION] Offense created in QRadar")
                return True
            else:
                logging.error(f"[INTEGRATION] QRadar error: {response.status_code}")
                return False
                
        except Exception as e:
            logging.error(f"[INTEGRATION] Failed to send to QRadar: {e}")
            return False
    
    def create_xsoar_incident(self, alert_data: Dict) -> Optional[str]:
        """
        Create incident in Palo Alto XSOAR (Demisto).
        
        Args:
            alert_data: Alert information
            
        Returns:
            Incident ID if successful
        """
        if not all([self.xsoar_config['host'], self.xsoar_config['api_key']]):
            logging.warning("[INTEGRATION] XSOAR not configured")
            return None
        
        try:
            url = f"https://{self.xsoar_config['host']}:{self.xsoar_config['port']}/incident"
            
            headers = {
                'Authorization': self.xsoar_config['api_key'],
                'Content-Type': 'application/json'
            }
            
            incident = {
                'type': 'Quishing Detection',
                'name': f"QR Phishing: {alert_data.get('extracted_payload', 'Unknown')[:50]}",
                'severity': self._map_to_xsoar_severity(alert_data.get('risk_level', 'MEDIUM')),
                'details': json.dumps(alert_data),
                'labels': [
                    {'type': 'ThreatType', 'value': 'Phishing'},
                    {'type': 'Vector', 'value': 'QR Code'},
                    {'type': 'RiskLevel', 'value': alert_data.get('risk_level', 'UNKNOWN')}
                ]
            }
            
            response = requests.post(url, headers=headers, json=incident, timeout=30)
            
            if response.status_code == 200:
                incident_id = response.json().get('id')
                logging.info(f"[INTEGRATION] XSOAR incident created: {incident_id}")
                return incident_id
            else:
                logging.error(f"[INTEGRATION] XSOAR error: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"[INTEGRATION] Failed to create XSOAR incident: {e}")
            return None
    
    def create_servicenow_ticket(self, alert_data: Dict) -> Optional[str]:
        """
        Create security incident in ServiceNow.
        
        Args:
            alert_data: Alert information
            
        Returns:
            Ticket number if successful
        """
        if not all([self.servicenow_config['instance'], 
                    self.servicenow_config['username'],
                    self.servicenow_config['password']]):
            logging.warning("[INTEGRATION] ServiceNow not configured")
            return None
        
        try:
            url = f"https://{self.servicenow_config['instance']}.service-now.com/api/now/table/incident"
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            ticket = {
                'short_description': f"QR Phishing Detection: {alert_data.get('extracted_payload', 'Unknown')[:80]}",
                'description': json.dumps(alert_data, indent=2),
                'urgency': self._map_to_servicenow_priority(alert_data.get('risk_level', 'MEDIUM')),
                'impact': self._map_to_servicenow_priority(alert_data.get('risk_level', 'MEDIUM')),
                'category': 'Security',
                'subcategory': 'Phishing'
            }
            
            response = requests.post(
                url, 
                headers=headers, 
                json=ticket, 
                auth=(self.servicenow_config['username'], self.servicenow_config['password']),
                timeout=30
            )
            
            if response.status_code == 201:
                ticket_num = response.json().get('result', {}).get('number')
                logging.info(f"[INTEGRATION] ServiceNow ticket created: {ticket_num}")
                return ticket_num
            else:
                logging.error(f"[INTEGRATION] ServiceNow error: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"[INTEGRATION] Failed to create ServiceNow ticket: {e}")
            return None
    
    def create_jira_ticket(self, alert_data: Dict, project_key: str = "SEC") -> Optional[str]:
        """
        Create Jira security issue.
        
        Args:
            alert_data: Alert information
            project_key: Jira project key
            
        Returns:
            Issue key if successful
        """
        if not all([self.jira_config['server'], 
                    self.jira_config['username'],
                    self.jira_config['token']]):
            logging.warning("[INTEGRATION] Jira not configured")
            return None
        
        try:
            url = f"{self.jira_config['server']}/rest/api/2/issue"
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            issue = {
                'fields': {
                    'project': {'key': project_key},
                    'summary': f"QR Phishing: {alert_data.get('extracted_payload', 'Unknown')[:60]}",
                    'description': self._format_jira_description(alert_data),
                    'issuetype': {'name': 'Security Incident'},
                    'priority': {'name': self._map_to_jira_priority(alert_data.get('risk_level', 'Medium'))},
                    'labels': ['phishing', 'qr-code', 'quishing']
                }
            }
            
            response = requests.post(
                url,
                headers=headers,
                json=issue,
                auth=(self.jira_config['username'], self.jira_config['token']),
                timeout=30
            )
            
            if response.status_code == 201:
                issue_key = response.json().get('key')
                logging.info(f"[INTEGRATION] Jira issue created: {issue_key}")
                return issue_key
            else:
                logging.error(f"[INTEGRATION] Jira error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logging.error(f"[INTEGRATION] Failed to create Jira issue: {e}")
            return None
    
    def send_slack_alert(self, alert_data: Dict) -> bool:
        """
        Send alert to Slack channel.
        
        Args:
            alert_data: Alert information
            
        Returns:
            True if successful
        """
        if not self.slack_config['webhook_url']:
            logging.warning("[INTEGRATION] Slack not configured")
            return False
        
        try:
            # Format alert for Slack
            risk_level = alert_data.get('risk_level', 'UNKNOWN')
            color = {
                'CRITICAL': '#FF0000',
                'HIGH': '#FF8800',
                'MEDIUM': '#FFCC00',
                'LOW': '#00CC00'
            }.get(risk_level, '#999999')
            
            payload = {
                'channel': self.slack_config['channel'],
                'username': 'Quishing-Detector',
                'icon_emoji': ':warning:',
                'attachments': [
                    {
                        'color': color,
                        'title': f'🚨 QR Phishing Alert - {risk_level}',
                        'fields': [
                            {
                                'title': 'Extracted URL',
                                'value': alert_data.get('extracted_payload', 'Unknown')[:80],
                                'short': False
                            },
                            {
                                'title': 'Risk Score',
                                'value': str(alert_data.get('calculated_risk', 'N/A')),
                                'short': True
                            },
                            {
                                'title': 'Final Destination',
                                'value': alert_data.get('final_url', 'N/A')[:60],
                                'short': False
                            }
                        ],
                        'footer': 'Sentinel Guardian',
                        'ts': int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.slack_config['webhook_url'],
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                logging.info("[INTEGRATION] Slack alert sent")
                return True
            else:
                logging.error(f"[INTEGRATION] Slack error: {response.status_code}")
                return False
                
        except Exception as e:
            logging.error(f"[INTEGRATION] Failed to send Slack alert: {e}")
            return False
    
    def send_teams_alert(self, alert_data: Dict) -> bool:
        """Send alert to Microsoft Teams."""
        if not self.teams_config['webhook_url']:
            logging.warning("[INTEGRATION] Teams not configured")
            return False
        
        try:
            card = {
                '@type': 'MessageCard',
                '@context': 'https://schema.org/extensions',
                'themeColor': 'FF0000',
                'summary': 'QR Phishing Alert',
                'sections': [
                    {
                        'activityTitle': '🚨 QR Phishing Detected',
                        'activitySubtitle': f"Risk Level: {alert_data.get('risk_level', 'UNKNOWN')}",
                        'facts': [
                            {'name': 'Extracted URL:', 'value': alert_data.get('extracted_payload', 'Unknown')[:80]},
                            {'name': 'Risk Score:', 'value': str(alert_data.get('calculated_risk', 'N/A'))},
                            {'name': 'Final Destination:', 'value': alert_data.get('final_url', 'N/A')[:60]},
                            {'name': 'Detected Brand:', 'value': alert_data.get('detected_brand', 'N/A')}
                        ]
                    }
                ]
            }
            
            response = requests.post(
                self.teams_config['webhook_url'],
                json=card,
                timeout=30
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logging.error(f"[INTEGRATION] Failed to send Teams alert: {e}")
            return False
    
    def send_all_alerts(self, alert_data: Dict) -> Dict:
        """
        Send alert to all configured platforms.
        
        Returns:
            Status of each integration
        """
        results = {
            'splunk': self.send_to_splunk(alert_data),
            'qradar': self.send_to_qradar(alert_data),
            'xsoar': self.create_xsoar_incident(alert_data) is not None,
            'servicenow': self.create_servicenow_ticket(alert_data) is not None,
            'jira': self.create_jira_ticket(alert_data) is not None,
            'slack': self.send_slack_alert(alert_data),
            'teams': self.send_teams_alert(alert_data)
        }
        
        # Count successful integrations
        successful = sum(1 for v in results.values() if v)
        logging.info(f"[INTEGRATION] Alerts sent to {successful}/{len(results)} platforms")
        
        return results
    
    def _map_to_severity(self, risk_level: str) -> int:
        """Map risk level to numeric severity."""
        mapping = {
            'CRITICAL': 10,
            'HIGH': 8,
            'MEDIUM': 5,
            'LOW': 3
        }
        return mapping.get(risk_level, 5)
    
    def _map_to_xsoar_severity(self, risk_level: str) -> int:
        """Map to XSOAR severity (0-4)."""
        mapping = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }
        return mapping.get(risk_level, 2)
    
    def _map_to_servicenow_priority(self, risk_level: str) -> int:
        """Map to ServiceNow priority (1-4, 1=critical)."""
        mapping = {
            'CRITICAL': 1,
            'HIGH': 2,
            'MEDIUM': 3,
            'LOW': 4
        }
        return mapping.get(risk_level, 3)
    
    def _map_to_jira_priority(self, risk_level: str) -> str:
        """Map to Jira priority."""
        mapping = {
            'CRITICAL': 'Highest',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low'
        }
        return mapping.get(risk_level, 'Medium')
    
    def _calculate_magnitude(self, risk_score: int) -> int:
        """Calculate QRadar magnitude from risk score."""
        return min(10, max(1, risk_score // 10))
    
    def _format_jira_description(self, alert_data: Dict) -> str:
        """Format alert data as Jira description."""
        lines = [
            "h2. QR Phishing Detection Details",
            "",
            f"*Extracted Payload:* {alert_data.get('extracted_payload', 'N/A')}",
            f"*Final URL:* {alert_data.get('final_url', 'N/A')}",
            f"*Risk Score:* {alert_data.get('calculated_risk', 'N/A')}/100",
            f"*Risk Level:* {alert_data.get('risk_level', 'UNKNOWN')}",
            f"*Detected Brand:* {alert_data.get('detected_brand', 'N/A')}",
            "",
            "h3. Analysis Results",
            "{code:json}",
            json.dumps(alert_data, indent=2),
            "{code}"
        ]
        return '\n'.join(lines)


# Singleton
integration_hub = IntegrationHub()


# Convenience function
def send_alert_all_platforms(alert_data: Dict) -> Dict:
    """Send alert to all configured platforms."""
    return integration_hub.send_all_alerts(alert_data)
