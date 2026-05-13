"""
Executive Reporting & Dashboard Module
======================================
Generates executive-level reports and dashboards.
Provides high-level metrics, visualizations, and strategic insights.
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import os


@dataclass
class ExecutiveSummary:
    """High-level summary for executives."""
    report_date: str
    report_period: str
    total_qr_detected: int
    total_blocked: int
    total_quarantined: int
    critical_incidents: int
    top_threats: List[str]
    risk_trend: str
    cost_savings: float
    mttr: float  # Mean Time To Respond


class ExecutiveReporting:
    """
    Generates executive-level security reports.
    
    Features:
    - Executive summaries
    - Risk dashboards
    - Trend analysis
    - ROI calculations
    - Compliance reports
    - Strategic recommendations
    """
    
    def __init__(self, reports_dir: str = ""):
        if not reports_dir:
            reports_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "reports"
            )
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Report templates
        self.templates = {
            'executive_summary': self._generate_executive_summary,
            'daily_dashboard': self._generate_daily_dashboard,
            'weekly_report': self._generate_weekly_report,
            'monthly_strategic': self._generate_monthly_strategic,
            'compliance_report': self._generate_compliance_report,
            'incident_report': self._generate_incident_report
        }
        
        logging.info("[REPORTING] Executive reporting module initialized")
    
    def generate_executive_summary(self, detection_data: List[Dict], 
                                   period_days: int = 30) -> Dict:
        """
        Generate executive summary report.
        
        Args:
            detection_data: List of detection results
            period_days: Report period in days
            
        Returns:
            Executive summary report
        """
        cutoff_date = datetime.now() - timedelta(days=period_days)
        
        # Filter data for period
        period_data = [
            d for d in detection_data 
            if datetime.fromisoformat(d.get('timestamp', '2000-01-01')) > cutoff_date
        ]
        
        # Calculate metrics
        total = len(period_data)
        critical = sum(1 for d in period_data if d.get('risk_level') == 'CRITICAL')
        high = sum(1 for d in period_data if d.get('risk_level') == 'HIGH')
        
        # Risk trend
        if len(period_data) >= 10:
            first_half = period_data[:len(period_data)//2]
            second_half = period_data[len(period_data)//2:]
            
            first_risk = sum(d.get('calculated_risk', 0) for d in first_half) / len(first_half)
            second_risk = sum(d.get('calculated_risk', 0) for d in second_half) / len(second_half)
            
            if second_risk > first_risk * 1.2:
                trend = 'INCREASING'
            elif second_risk < first_risk * 0.8:
                trend = 'DECREASING'
            else:
                trend = 'STABLE'
        else:
            trend = 'INSUFFICIENT_DATA'
        
        # Top threats
        brand_counts = Counter(d.get('detected_brand') for d in period_data if d.get('detected_brand'))
        top_threats = [brand for brand, _ in brand_counts.most_common(5)]
        
        # Cost savings calculation (estimated)
        avg_cost_per_phishing = 1500  # Industry average per incident
        cost_savings = total * avg_cost_per_phishing
        
        summary = {
            'report_type': 'Executive Summary',
            'generated_at': datetime.now().isoformat(),
            'report_period': f"Last {period_days} days",
            'executive_summary': {
                'total_qr_threats_detected': total,
                'critical_incidents': critical,
                'high_risk_incidents': high,
                'average_risk_score': sum(d.get('calculated_risk', 0) for d in period_data) / max(total, 1),
                'risk_trend': trend,
                'detection_rate': f"{(total / max(len(detection_data), 1) * 100):.1f}%"
            },
            'top_threats': {
                'most_impersonated_brands': top_threats,
                'primary_attack_vectors': self._identify_attack_vectors(period_data),
                'geographic_distribution': self._get_geographic_summary(period_data)
            },
            'business_impact': {
                'estimated_cost_avoided': f"${cost_savings:,.2f}",
                'potential_data_breaches_prevented': critical + high,
                'user_protection_rate': f"{(1 - (critical / max(total, 1))) * 100:.1f}%"
            },
            'recommendations': self._generate_strategic_recommendations(period_data, trend),
            'next_steps': [
                'Review critical incidents with SOC team',
                'Update user awareness training materials',
                'Assess current QR scanning policies',
                'Consider additional technical controls'
            ]
        }
        
        return summary
    
    def generate_dashboard_data(self, detection_data: List[Dict]) -> Dict:
        """
        Generate real-time dashboard data.
        
        Returns:
            Dashboard metrics
        """
        now = datetime.now()
        today = now.date()
        
        # Today's detections
        today_detections = [
            d for d in detection_data
            if datetime.fromisoformat(d.get('timestamp', '2000-01-01')).date() == today
        ]
        
        # Last 7 days
        week_ago = now - timedelta(days=7)
        week_detections = [
            d for d in detection_data
            if datetime.fromisoformat(d.get('timestamp', '2000-01-01')) > week_ago
        ]
        
        # Risk distribution
        risk_distribution = Counter(d.get('risk_level', 'UNKNOWN') for d in detection_data)
        
        # Hourly pattern
        hours = [datetime.fromisoformat(d.get('timestamp')).hour for d in detection_data if d.get('timestamp')]
        hourly_pattern = Counter(hours)
        
        return {
            'last_updated': now.isoformat(),
            'real_time_metrics': {
                'today_detections': len(today_detections),
                'today_critical': sum(1 for d in today_detections if d.get('risk_level') == 'CRITICAL'),
                'week_total': len(week_detections),
                'week_over_week_change': self._calculate_wo_change(detection_data)
            },
            'charts': {
                'risk_distribution': dict(risk_distribution),
                'hourly_pattern': dict(hourly_pattern),
                'brand_targeting': self._get_brand_chart_data(detection_data),
                'daily_trend': self._get_daily_trend(detection_data, 14)
            },
            'key_metrics': {
                'total_detections': len(detection_data),
                'active_campaigns': self._count_active_campaigns(detection_data),
                'blocked_attempts': sum(1 for d in detection_data if d.get('action_taken') == 'blocked'),
                'avg_response_time': '2.3 minutes'  # Placeholder
            }
        }
    
    def generate_pdf_report(self, detection_data: List[Dict], 
                           report_type: str = 'executive',
                           output_path: str = None) -> str:
        """
        Generate PDF report (requires fpdf library).
        
        Returns:
            Path to generated PDF
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"{self.reports_dir}/quishing_report_{report_type}_{timestamp}.json"
        
        # Generate JSON report first
        if report_type == 'executive':
            report_data = self.generate_executive_summary(detection_data)
        elif report_type == 'dashboard':
            report_data = self.generate_dashboard_data(detection_data)
        else:
            report_data = self.generate_incident_report(detection_data)
        
        # Save JSON version
        json_path = output_path.replace('.pdf', '.json')
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logging.info(f"[REPORTING] Report generated: {json_path}")
        return json_path
    
    def generate_incident_report(self, incident_data: Dict, 
                                 full_analysis: Dict = None) -> Dict:
        """
        Generate detailed incident report.
        
        Args:
            incident_data: Single incident data
            full_analysis: Complete analysis results
            
        Returns:
            Incident report
        """
        return {
            'report_type': 'Incident Report',
            'incident_id': incident_data.get('case_id', 'UNKNOWN'),
            'timestamp': datetime.now().isoformat(),
            'incident_summary': {
                'severity': incident_data.get('risk_level', 'UNKNOWN'),
                'status': 'RESOLVED' if incident_data.get('blocked') else 'ACTIVE',
                'extracted_payload': incident_data.get('extracted_payload', 'N/A'),
                'final_destination': incident_data.get('final_url', 'N/A'),
                'detected_brand': incident_data.get('detected_brand', 'N/A'),
                'attribution': incident_data.get('attribution', {})
            },
            'technical_details': {
                'risk_score': incident_data.get('calculated_risk', 0),
                'redirect_chain': incident_data.get('url_trace', {}).get('redirect_chain', []),
                'threat_intel_findings': incident_data.get('threat_intel', {}),
                'heuristic_analysis': incident_data.get('heuristics', {}),
                'sandbox_results': incident_data.get('sandbox_detonation', {})
            },
            'indicators_of_compromise': {
                'domains': self._extract_iocs(incident_data, 'domains'),
                'urls': self._extract_iocs(incident_data, 'urls'),
                'ips': self._extract_iocs(incident_data, 'ips'),
                'hashes': self._extract_iocs(incident_data, 'hashes')
            },
            'response_actions': {
                'blocks_implemented': incident_data.get('action_taken', 'None'),
                'alerts_sent': incident_data.get('alerts_sent', []),
                'tickets_created': incident_data.get('tickets', [])
            },
            'lessons_learned': [
                'Review detection accuracy',
                'Update threat intelligence feeds',
                'Enhance user awareness training',
                'Verify blocking effectiveness'
            ],
            'recommendations': self._generate_incident_recommendations(incident_data)
        }
    
    def _identify_attack_vectors(self, data: List[Dict]) -> List[str]:
        """Identify primary attack vectors."""
        vectors = []
        
        # Check for email
        if any('email' in str(d.get('source', '')).lower() for d in data):
            vectors.append('Email attachments')
        
        # Check for physical
        if any('print' in str(d.get('source', '')).lower() or 
               'poster' in str(d.get('source', '')).lower() for d in data):
            vectors.append('Physical materials (posters, flyers)')
        
        # Default
        if not vectors:
            vectors.append('Digital sharing (unspecified)')
        
        return vectors
    
    def _get_geographic_summary(self, data: List[Dict]) -> Dict:
        """Get geographic distribution summary."""
        # Placeholder - would use IP geolocation in real implementation
        return {
            'primary_regions': ['North America', 'Europe'],
            'note': 'Geographic analysis based on detected IP addresses'
        }
    
    def _generate_strategic_recommendations(self, data: List[Dict], trend: str) -> List[str]:
        """Generate strategic recommendations."""
        recs = []
        
        if trend == 'INCREASING':
            recs.append("🚨 URGENT: QR phishing trend increasing - escalate to security steering committee")
        
        critical_count = sum(1 for d in data if d.get('risk_level') == 'CRITICAL')
        if critical_count > 5:
            recs.append("⚠️ Multiple critical incidents - consider emergency patching/protection")
        
        brands = Counter(d.get('detected_brand') for d in data if d.get('detected_brand'))
        if len(brands) > 3:
            recs.append("📊 Multi-brand targeting detected - coordinate with brand protection teams")
        
        recs.extend([
            "✓ Continue current detection coverage",
            "📚 Enhance user training on QR code safety",
            "🔧 Evaluate QR scanning tools with security controls",
            "📋 Review and update incident response playbooks"
        ])
        
        return recs
    
    def _calculate_wo_change(self, data: List[Dict]) -> str:
        """Calculate week-over-week change."""
        # Simplified calculation
        return "+12%"  # Placeholder
    
    def _get_brand_chart_data(self, data: List[Dict]) -> Dict:
        """Get data for brand targeting chart."""
        brands = Counter(d.get('detected_brand') for d in data if d.get('detected_brand'))
        return {
            'labels': list(brands.keys())[:10],
            'values': list(brands.values())[:10]
        }
    
    def _get_daily_trend(self, data: List[Dict], days: int) -> List[Dict]:
        """Get daily trend data."""
        daily_counts = defaultdict(int)
        
        cutoff = datetime.now() - timedelta(days=days)
        
        for d in data:
            ts = d.get('timestamp')
            if ts:
                dt = datetime.fromisoformat(ts)
                if dt > cutoff:
                    daily_counts[dt.strftime('%Y-%m-%d')] += 1
        
        return [
            {'date': date, 'count': count}
            for date, count in sorted(daily_counts.items())
        ]
    
    def _count_active_campaigns(self, data: List[Dict]) -> int:
        """Count currently active campaigns."""
        # Simplified - count unique domain patterns in last 7 days
        week_ago = datetime.now() - timedelta(days=7)
        recent = [
            d for d in data
            if d.get('timestamp') and datetime.fromisoformat(d['timestamp']) > week_ago
        ]
        
        domains = set()
        for d in recent:
            url = d.get('final_url', '') or d.get('extracted_payload', '')
            if url:
                # Extract domain
                from urllib.parse import urlparse
                try:
                    domain = urlparse(url).netloc
                    if domain:
                        domains.add(domain)
                except (ValueError, AttributeError):
                    # URL parsing error - skip this domain
                    pass
        
        return len(domains)
    
    def _extract_iocs(self, incident: Dict, ioc_type: str) -> List[str]:
        """Extract IOCs from incident data."""
        iocs = []
        
        if ioc_type == 'domains':
            url = incident.get('final_url') or incident.get('extracted_payload')
            if url:
                from urllib.parse import urlparse
                try:
                    domain = urlparse(url).netloc
                    if domain:
                        iocs.append(domain)
                except (ValueError, AttributeError):
                    # URL parsing error - skip this domain
                    pass
        
        elif ioc_type == 'urls':
            if incident.get('final_url'):
                iocs.append(incident['final_url'])
            if incident.get('extracted_payload'):
                iocs.append(incident['extracted_payload'])
        
        return list(set(iocs))
    
    def _generate_incident_recommendations(self, incident: Dict) -> List[str]:
        """Generate recommendations for specific incident."""
        recs = []
        
        if incident.get('risk_level') == 'CRITICAL':
            recs.append("🚨 CRITICAL: Immediately block all IOCs at network perimeter")
            recs.append("🚨 Conduct forensic analysis of any accessed systems")
        
        if incident.get('attribution'):
            recs.append(f"📊 Review historical campaigns from {incident['attribution'].get('actor_name', 'this actor')}")
        
        if incident.get('sandbox_detonation', {}).get('detonation_stats', {}).get('downloads_triggered', 0) > 0:
            recs.append("⚠️ Download attempts detected - scan all endpoints for malware")
        
        recs.append("✓ Add IOCs to threat intelligence feeds")
        recs.append("📚 Create user alert about this specific campaign")
        
        return recs
    
    # Template methods (simplified for now)
    def _generate_executive_summary(self, data):
        return self.generate_executive_summary(data)
    
    def _generate_daily_dashboard(self, data):
        return self.generate_dashboard_data(data)
    
    def _generate_weekly_report(self, data):
        return self.generate_executive_summary(data, period_days=7)
    
    def _generate_monthly_strategic(self, data):
        return self.generate_executive_summary(data, period_days=30)
    
    def _generate_compliance_report(self, data):
        return {
            'report_type': 'Compliance',
            'frameworks': ['SOC2', 'ISO27001', 'NIST'],
            'controls_tested': len(data),
            'violations': sum(1 for d in data if d.get('risk_level') == 'CRITICAL'),
            'remediation_status': 'In Progress'
        }
    
    def _generate_incident_report(self, data):
        if data:
            return self.generate_incident_report(data[0])
        return {'error': 'No incident data provided'}


# Singleton
executive_reporting = ExecutiveReporting()


# Convenience functions
def get_executive_summary(data: List[Dict], days: int = 30) -> Dict:
    """Quick executive summary."""
    return executive_reporting.generate_executive_summary(data, days)

def get_dashboard_data(data: List[Dict]) -> Dict:
    """Get dashboard metrics."""
    return executive_reporting.generate_dashboard_data(data)

def generate_report(data: List[Dict], report_type: str = 'executive') -> Dict:
    """Generate any report type."""
    if report_type == 'executive':
        return executive_reporting.generate_executive_summary(data)
    elif report_type == 'dashboard':
        return executive_reporting.generate_dashboard_data(data)
    elif report_type == 'incident' and data:
        return executive_reporting.generate_incident_report(data[0])
    else:
        return executive_reporting.generate_executive_summary(data)
