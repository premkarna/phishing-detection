"""
Auto Sync Scheduler - Hourly Global Threat Feed Updates
ప్రతి గంటకోసారి PhishTank, OpenPhish నుండి కొత్త థ్రెట్స్ సేకరించు
"""

import logging
import threading
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from app.services.threat_sync import ThreatIntelDB

class ThreatSyncScheduler:
    """Manages automatic hourly synchronization of global threat feeds."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.scheduler = None
        self.threat_db = ThreatIntelDB()
        self.sync_count = 0
        self.last_sync = None
        self.running = False
    
    def start(self):
        """Start the hourly sync scheduler."""
        if self.running:
            logging.info("[AUTO-SYNC] Scheduler already running")
            return
        
        self.scheduler = BackgroundScheduler()
        self.scheduler.add_job(
            self._sync_job,
            'interval',
            hours=1,
            id='threat_sync_hourly',
            replace_existing=True,
            misfire_grace_time=300
        )
        
        # Add daily CSV update job
        self.scheduler.add_job(
            self._csv_update_job,
            'cron',
            hour=2,  # 2 AM daily
            minute=0,
            id='csv_update_daily',
            replace_existing=True,
            misfire_grace_time=600
        )
        self.scheduler.start()
        self.running = True
        
        logging.info("[AUTO-SYNC] Hourly threat sync enabled (PhishTank + OpenPhish + EmergingThreats)")
        
        # Delay initial sync by 5s so Flask finishes binding first
        threading.Thread(target=self._delayed_initial_sync, daemon=True, name="ThreatSync-Init").start()
    
    def _delayed_initial_sync(self):
        """Run first sync after a short startup delay."""
        import time
        time.sleep(5)
        self._sync_job()

    def _sync_job(self):
        """Execute the sync job — each feed is isolated so one failure won't block others."""
        try:
            logging.info(f"[AUTO-SYNC] Starting sync at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            new_threats = self.threat_db.sync_global_feeds()
            self.sync_count += 1
            self.last_sync = datetime.now()
            stats = self.threat_db.get_sync_stats()
            total_threats = stats.get('total_threats', 0)
            logging.info(f"[AUTO-SYNC] Sync #{self.sync_count} complete — {new_threats} new threats | {total_threats} total in DB")
        except Exception as e:
            logging.warning(f"[AUTO-SYNC] Sync job failed: {type(e).__name__}: {e}")
    
    def _csv_update_job(self):
        """Execute daily CSV update job."""
        try:
            logging.info(f"[CSV-UPDATE] Starting daily CSV update at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            new_records = self.threat_db.update_dataset_csv()
            
            logging.info(f"[CSV-UPDATE] ╔════════════════════════════════════╗")
            logging.info(f"[CSV-UPDATE] ║  CSV UPDATE COMPLETE                ║")
            logging.info(f"[CSV-UPDATE] ║  New Records: {new_records:4d}                     ║")
            logging.info(f"[CSV-UPDATE] ╚════════════════════════════════════╝")
            
        except Exception as e:
            logging.error(f"[CSV-UPDATE] CSV update failed: {e}")
    
    def stop(self):
        """Stop the scheduler."""
        if self.scheduler:
            self.scheduler.shutdown()
            self.running = False
            logging.info("[AUTO-SYNC] Scheduler stopped")
    
    def get_status(self):
        """Get current sync status."""
        next_sync = None
        next_csv = None
        try:
            if self.running and self.scheduler:
                job = self.scheduler.get_job('threat_sync_hourly')
                if job and job.next_run_time:
                    next_sync = job.next_run_time.isoformat()
                csv_job = self.scheduler.get_job('csv_update_daily')
                if csv_job and csv_job.next_run_time:
                    next_csv = csv_job.next_run_time.isoformat()
        except Exception:
            pass
        return {
            "running": self.running,
            "sync_count": self.sync_count,
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
            "next_sync": next_sync,
            "next_csv_update": next_csv,
        }

# Global instance
auto_sync = ThreatSyncScheduler()

def start_auto_sync():
    """Start auto sync - call this in main.py"""
    auto_sync.start()

def get_sync_status():
    """Get current sync status for API/dashboard"""
    return auto_sync.get_status()

if __name__ == "__main__":
    # Test mode
    start_auto_sync()
    import time
    time.sleep(5)  # Let first sync complete
    print(get_sync_status())
