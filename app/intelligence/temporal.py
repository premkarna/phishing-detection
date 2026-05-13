"""
Temporal Analysis Engine
=======================
Analyzes time-based patterns in QR phishing attacks.
Identifies campaign timing, peak attack hours, and lifecycle patterns.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, Counter
import statistics


class TemporalAnalysisEngine:
    """
    Analyzes temporal patterns in phishing attacks.
    
    Detects:
    - Peak attack hours/days
    - Campaign duration and lifecycle
    - Time-based correlation between attacks
    - Seasonal patterns
    - Attack velocity and acceleration
    """
    
    def __init__(self):
        self.time_patterns = defaultdict(list)
        logging.info("[TEMPORAL] Analysis engine initialized")
    
    def analyze_attack_timeline(self, attacks: List[Dict]) -> Dict:
        """
        Analyze timeline of attacks.
        
        Args:
            attacks: List of attack records with timestamps
            
        Returns:
            Temporal analysis report
        """
        if not attacks:
            return {'error': 'No attacks provided'}
        
        # Extract timestamps
        timestamps = []
        for attack in attacks:
            ts = attack.get('timestamp') or attack.get('detection_time')
            if ts:
                try:
                    # Handle various timestamp formats
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    elif isinstance(ts, datetime):
                        dt = ts
                    else:
                        continue
                    timestamps.append(dt)
                except (ValueError, TypeError, AttributeError):
                    # Invalid timestamp format or type - skip this entry
                    continue
        
        if not timestamps:
            return {'error': 'No valid timestamps found'}
        
        timestamps.sort()
        
        return {
            'timeline_summary': self._analyze_timeline_summary(timestamps),
            'hourly_distribution': self._analyze_hourly_patterns(timestamps),
            'daily_distribution': self._analyze_daily_patterns(timestamps),
            'campaign_duration': self._calculate_campaign_duration(timestamps),
            'attack_velocity': self._calculate_attack_velocity(timestamps),
            'peak_times': self._identify_peak_times(timestamps),
            'time_clusters': self._identify_time_clusters(timestamps),
            'seasonal_patterns': self._analyze_seasonal_patterns(timestamps)
        }
    
    def _analyze_timeline_summary(self, timestamps: List[datetime]) -> Dict:
        """Generate timeline summary statistics."""
        return {
            'first_attack': timestamps[0].isoformat(),
            'last_attack': timestamps[-1].isoformat(),
            'total_attacks': len(timestamps),
            'time_span_days': (timestamps[-1] - timestamps[0]).days,
            'time_span_hours': (timestamps[-1] - timestamps[0]).total_seconds() / 3600
        }
    
    def _analyze_hourly_patterns(self, timestamps: List[datetime]) -> Dict:
        """Analyze which hours attacks occur."""
        hours = [ts.hour for ts in timestamps]
        hour_counts = Counter(hours)
        
        # Find peak hours
        most_common = hour_counts.most_common()
        
        return {
            'distribution': dict(hour_counts),
            'peak_hours': [h for h, c in most_common[:3]],
            'quiet_hours': [h for h, c in most_common[-3:]],
            'business_hours_attacks': sum(count for hour, count in hour_counts.items() 
                                        if 9 <= hour <= 17),
            'after_hours_attacks': sum(count for hour, count in hour_counts.items() 
                                      if hour < 9 or hour > 17),
            'analysis': self._interpret_hourly_pattern(hour_counts)
        }
    
    def _interpret_hourly_pattern(self, hour_counts: Counter) -> str:
        """Interpret what hourly patterns mean."""
        most_active = hour_counts.most_common(1)[0][0]
        
        if 9 <= most_active <= 17:
            return "Attacks peak during business hours - suggests targeted social engineering"
        elif 0 <= most_active <= 5:
            return "Attacks peak late night - suggests automated campaigns or non-targeted spray"
        elif 18 <= most_active <= 23:
            return "Attacks peak evening - suggests consumer targeting after work hours"
        else:
            return "Distributed attack pattern - no clear time preference"
    
    def _analyze_daily_patterns(self, timestamps: List[datetime]) -> Dict:
        """Analyze day-of-week patterns."""
        weekdays = [ts.weekday() for ts in timestamps]  # 0=Monday, 6=Sunday
        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 
                     'Friday', 'Saturday', 'Sunday']
        
        day_counts = Counter(weekdays)
        
        weekday_attacks = sum(day_counts[i] for i in range(5))
        weekend_attacks = sum(day_counts[i] for i in [5, 6])
        
        return {
            'distribution': {day_names[day]: count for day, count in day_counts.items()},
            'weekday_attacks': weekday_attacks,
            'weekend_attacks': weekend_attacks,
            'peak_day': day_names[day_counts.most_common(1)[0][0]],
            'weekend_ratio': weekend_attacks / max(weekday_attacks, 1),
            'analysis': self._interpret_daily_pattern(day_counts)
        }
    
    def _interpret_daily_pattern(self, day_counts: Counter) -> str:
        """Interpret day-of-week patterns."""
        weekend = sum(day_counts[i] for i in [5, 6])  # Sat, Sun
        weekday = sum(day_counts[i] for i in range(5))  # Mon-Fri
        
        if weekend > weekday:
            return "More attacks on weekends - targets personal time usage"
        elif day_counts[0] > day_counts[4]:  # Monday > Friday
            return "More attacks early week - targets fresh work week starts"
        elif day_counts[4] > day_counts[0]:  # Friday > Monday
            return "More attacks on Fridays - targets end-of-week fatigue"
        else:
            return "Even distribution across weekdays - consistent operation"
    
    def _calculate_campaign_duration(self, timestamps: List[datetime]) -> Dict:
        """Calculate campaign duration characteristics."""
        if len(timestamps) < 2:
            return {'duration_type': 'single_attack'}
        
        # Calculate gaps between attacks
        gaps = []
        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600  # hours
            gaps.append(gap)
        
        avg_gap = statistics.mean(gaps) if gaps else 0
        max_gap = max(gaps) if gaps else 0
        
        # Determine campaign type
        total_duration = (timestamps[-1] - timestamps[0]).days
        
        if total_duration <= 1:
            campaign_type = "burst_attack"
            description = "All attacks within 24 hours - coordinated burst campaign"
        elif total_duration <= 7:
            campaign_type = "short_campaign"
            description = "Week-long campaign - sustained but limited operation"
        elif total_duration <= 30:
            campaign_type = "medium_campaign"
            description = "Month-long campaign - persistent threat actor"
        else:
            campaign_type = "long_campaign"
            description = "Extended campaign - highly persistent or APT-level"
        
        return {
            'total_duration_days': total_duration,
            'attack_count': len(timestamps),
            'average_gap_hours': round(avg_gap, 2),
            'max_gap_hours': round(max_gap, 2),
            'campaign_type': campaign_type,
            'description': description,
            'attack_frequency': len(timestamps) / max(total_duration, 1)
        }
    
    def _calculate_attack_velocity(self, timestamps: List[datetime]) -> Dict:
        """Calculate attack velocity and trends."""
        if len(timestamps) < 3:
            return {'analysis': 'Insufficient data for velocity analysis'}
        
        # Divide into time windows
        total_duration = (timestamps[-1] - timestamps[0]).total_seconds() / 3600
        
        if total_duration < 1:
            return {'analysis': 'Attacks too concentrated for velocity analysis'}
        
        # Calculate attacks per hour
        attacks_per_hour = len(timestamps) / total_duration
        
        # Check for acceleration (increasing rate)
        first_half = timestamps[:len(timestamps)//2]
        second_half = timestamps[len(timestamps)//2:]
        
        first_duration = (first_half[-1] - first_half[0]).total_seconds() / 3600
        second_duration = (second_half[-1] - second_half[0]).total_seconds() / 3600
        
        first_rate = len(first_half) / max(first_duration, 1)
        second_rate = len(second_half) / max(second_duration, 1)
        
        acceleration = second_rate - first_rate
        
        return {
            'average_attacks_per_hour': round(attacks_per_hour, 2),
            'first_half_rate': round(first_rate, 2),
            'second_half_rate': round(second_rate, 2),
            'acceleration': round(acceleration, 2),
            'trend': 'accelerating' if acceleration > 0.5 else 
                    'decelerating' if acceleration < -0.5 else 'steady',
            'analysis': self._interpret_velocity(acceleration, attacks_per_hour)
        }
    
    def _interpret_velocity(self, acceleration: float, rate: float) -> str:
        """Interpret attack velocity patterns."""
        if acceleration > 1 and rate > 5:
            return "🚨 Rapidly accelerating high-volume attack - likely coordinated campaign"
        elif acceleration > 0.5:
            return "Increasing attack rate - campaign gaining momentum or expanding"
        elif acceleration < -0.5:
            return "Decreasing attack rate - campaign winding down or being blocked"
        elif rate > 10:
            return "High sustained velocity - automated spray campaign"
        elif rate < 1:
            return "Low velocity - highly targeted or manual operation"
        else:
            return "Moderate steady pace - typical operational tempo"
    
    def _identify_peak_times(self, timestamps: List[datetime]) -> Dict:
        """Identify peak attack times and patterns."""
        if len(timestamps) < 5:
            return {'analysis': 'Insufficient data for peak time analysis'}
        
        # Find consecutive attack windows
        windows = []
        current_window = [timestamps[0]]
        
        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - timestamps[i-1]).total_seconds() / 60  # minutes
            
            if gap < 30:  # Within 30 minutes = same window
                current_window.append(timestamps[i])
            else:
                windows.append(current_window)
                current_window = [timestamps[i]]
        
        if current_window:
            windows.append(current_window)
        
        # Find busiest window
        busiest = max(windows, key=len)
        
        return {
            'total_windows': len(windows),
            'busiest_window_attacks': len(busiest),
            'busiest_window_start': busiest[0].isoformat(),
            'busiest_window_end': busiest[-1].isoformat(),
            'average_window_size': statistics.mean(len(w) for w in windows),
            'concentrated_periods': len([w for w in windows if len(w) >= 5])
        }
    
    def _identify_time_clusters(self, timestamps: List[datetime]) -> List[Dict]:
        """Identify clusters of attacks in time."""
        if len(timestamps) < 5:
            return []
        
        clusters = []
        current_cluster = [timestamps[0]]
        
        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600  # hours
            
            if gap <= 2:  # Within 2 hours = same cluster
                current_cluster.append(timestamps[i])
            else:
                if len(current_cluster) >= 3:
                    clusters.append({
                        'start': current_cluster[0].isoformat(),
                        'end': current_cluster[-1].isoformat(),
                        'attacks': len(current_cluster),
                        'type': 'coordinated_burst' if len(current_cluster) > 10 else 'standard_cluster'
                    })
                current_cluster = [timestamps[i]]
        
        # Don't forget the last cluster
        if len(current_cluster) >= 3:
            clusters.append({
                'start': current_cluster[0].isoformat(),
                'end': current_cluster[-1].isoformat(),
                'attacks': len(current_cluster),
                'type': 'coordinated_burst' if len(current_cluster) > 10 else 'standard_cluster'
            })
        
        return clusters
    
    def _analyze_seasonal_patterns(self, timestamps: List[datetime]) -> Dict:
        """Analyze seasonal patterns in attacks."""
        months = [ts.month for ts in timestamps]
        month_counts = Counter(months)
        
        # Identify quarters
        quarters = {
            'Q1': sum(month_counts[m] for m in [1, 2, 3]),
            'Q2': sum(month_counts[m] for m in [4, 5, 6]),
            'Q3': sum(month_counts[m] for m in [7, 8, 9]),
            'Q4': sum(month_counts[m] for m in [10, 11, 12])
        }
        
        peak_quarter = max(quarters, key=quarters.get)
        
        # Check for holiday patterns
        holiday_months = [11, 12]  # Black Friday, Christmas
        holiday_attacks = sum(month_counts[m] for m in holiday_months)
        
        return {
            'monthly_distribution': dict(month_counts),
            'quarterly_distribution': quarters,
            'peak_quarter': peak_quarter,
            'holiday_season_attacks': holiday_attacks,
            'holiday_ratio': holiday_attacks / len(timestamps) if timestamps else 0,
            'analysis': f"Peak activity in {peak_quarter}, {holiday_attacks} attacks during holiday season"
        }
    
    def correlate_with_external_events(self, timestamps: List[datetime], 
                                     event_dates: List[Tuple[str, str]]) -> Dict:
        """
        Correlate attacks with external events (holidays, news, etc.).
        
        Args:
            timestamps: Attack timestamps
            event_dates: List of (event_name, date_string) tuples
            
        Returns:
            Correlation analysis
        """
        correlations = []
        
        for event_name, event_date_str in event_dates:
            try:
                event_date = datetime.fromisoformat(event_date_str)
                
                # Check for attacks within 7 days before and after
                window_start = event_date - timedelta(days=7)
                window_end = event_date + timedelta(days=7)
                
                related_attacks = [ts for ts in timestamps if window_start <= ts <= window_end]
                
                if related_attacks:
                    correlations.append({
                        'event': event_name,
                        'event_date': event_date_str,
                        'related_attacks': len(related_attacks),
                        'attack_dates': [ts.isoformat() for ts in related_attacks[:5]],
                        'correlation_strength': 'strong' if len(related_attacks) > 5 else 'moderate' if len(related_attacks) > 2 else 'weak'
                    })
            except (KeyError, TypeError, AttributeError):
                # Missing data or wrong type - skip this entry
                continue
        
        return {
            'correlated_events': correlations,
            'event_driven_attacks': sum(c['related_attacks'] for c in correlations),
            'analysis': f"Found {len(correlations)} potential event correlations"
        }


# Singleton
temporal_engine = TemporalAnalysisEngine()


# Convenience function
def analyze_attack_timing(attacks: List[Dict]) -> Dict:
    """Quick temporal analysis."""
    return temporal_engine.analyze_attack_timeline(attacks)
