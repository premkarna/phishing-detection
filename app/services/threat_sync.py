import sqlite3
import logging
import os
import re
import datetime
import json
import time
import csv
import shutil
from urllib.parse import urlparse
from typing import Tuple, List, Dict, Optional

# Secure HTTP requests
from app.integrations.secure_requests import secure_get

def retry_on_failure(max_retries=2, delay=1, exceptions=(Exception,)):
    """Decorator for retrying failed operations with exponential backoff."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)
                        logging.warning(f"[RETRY] {func.__name__} attempt {attempt + 1}/{max_retries} failed: {type(e).__name__}. Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        logging.warning(f"[RETRY] {func.__name__} gave up after {max_retries} attempts: {type(e).__name__}")
            return (0, 0)  # Safe default — never crash caller
        return wrapper
    return decorator

class ThreatIntelDB:
    def __init__(self):
        # Project root: app/services/threat_sync.py -> app/services -> app -> root
        from pathlib import Path
        _cache_dir = Path(__file__).parent.parent.parent / "data" / "cache"
        _cache_dir.mkdir(parents=True, exist_ok=True)
        self.project_root = str(_cache_dir.parent.parent)
        self.db_path = str(_cache_dir / "global_threats.db")
        self._init_db()
        # Free threat feeds — no API key required
        # Updated: Replaced broken feeds (URLhaus 401, PhishStats 404)
        # Added: PhishTank (JSON), EmergingThreats (Suricata rules)
        self.feeds = {
            "OpenPhish": "https://openphish.com/feed.txt",
            "PhishTank": "https://data.phishtank.com/data/online-valid.csv",
            "EmergingThreats": "https://rules.emergingthreats.net/open/suricata/rules/emerging-phishing.rules",
        }
        # Per-feed failure counter — skip feed after 3 consecutive failures
        self._feed_failures: Dict[str, int] = {k: 0 for k in self.feeds}
        self._feed_skip_threshold = 3

    def _init_db(self):
        """Initializes the SQLite database with optimized schema."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # Primary threat table
        c.execute('''CREATE TABLE IF NOT EXISTS phishing_urls
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      url TEXT UNIQUE, 
                      source TEXT, 
                      threat_type TEXT,
                      confidence INTEGER,
                      date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Sync logs table
        c.execute('''CREATE TABLE IF NOT EXISTS sync_history
                     (timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      feed_name TEXT,
                      new_records INTEGER,
                      status TEXT)''')
        
        conn.commit()
        conn.close()

    def sync_global_feeds(self):
        """Orchestrates the synchronization of multiple global threat feeds."""
        logging.info("[*] THREAT SYNC: Starting feed sync (OpenPhish + PhishTank + EmergingThreats)...")
        total_synced = 0
        results = {}

        for name, sync_fn in [
            ("OpenPhish", self._sync_openphish),
            ("PhishTank", self._sync_phishtank),
            ("EmergingThreats", self._sync_emergingthreats),
        ]:
            if self._feed_failures.get(name, 0) >= self._feed_skip_threshold:
                logging.warning(f"[SYNC] Skipping {name} — {self._feed_skip_threshold}+ consecutive failures (circuit open)")
                results[name] = 0
                continue
            try:
                _, new = sync_fn()
                total_synced += new
                results[name] = new
                self._feed_failures[name] = 0  # reset on success
            except Exception as e:
                self._feed_failures[name] = self._feed_failures.get(name, 0) + 1
                logging.warning(f"[SYNC] {name} failed ({self._feed_failures[name]} consecutive): {type(e).__name__}")
                results[name] = 0

        logging.info(f"[+] THREAT SYNC COMPLETE: {total_synced} new threats | {results}")
        return total_synced

    @retry_on_failure(max_retries=2, delay=1)
    def _sync_openphish(self) -> Tuple[int, int]:
        """Sync with OpenPhish feed."""
        res = secure_get(self.feeds["OpenPhish"], timeout=(5, 10), enable_ssl_fallback=True)
        if res.status_code != 200:
            logging.warning(f"[SYNC] OpenPhish returned HTTP {res.status_code}")
            self._log_sync("OpenPhish", 0, f"HTTP {res.status_code}")
            return 0, 0
        urls = [u.strip() for u in res.text.strip().split('\n') if u.strip() and u.startswith('http')]
        valid_urls = [u for u in urls if self._is_valid_url(u)][:5000]
        new_count = self._bulk_insert(valid_urls, "OpenPhish", "URL Phishing", 80)
        self._log_sync("OpenPhish", new_count, "Success")
        logging.info(f"[SYNC] OpenPhish: {new_count} new threats ({len(valid_urls)} valid)")
        return len(valid_urls), new_count

    @retry_on_failure(max_retries=2, delay=1)
    def _sync_phishtank(self) -> Tuple[int, int]:
        """PhishTank — CSV feed of verified phishing URLs."""
        res = secure_get(self.feeds["PhishTank"], timeout=(5, 15), enable_ssl_fallback=True)
        if res.status_code != 200:
            logging.warning(f"[SYNC] PhishTank returned HTTP {res.status_code}")
            self._log_sync("PhishTank", 0, f"HTTP {res.status_code}")
            return 0, 0
        urls = []
        for line in res.text.strip().split('\n'):
            # CSV format: url,phish_id,... — extract first column
            parts = line.split(',')
            url = parts[0].strip().strip('"')
            if url and url.startswith('http'):
                urls.append(url)
        valid_urls = list(set(u for u in urls if self._is_valid_url(u)))[:2000]
        new_count = self._bulk_insert(valid_urls, "PhishTank", "Verified Phishing", 95)
        self._log_sync("PhishTank", new_count, "Success")
        logging.info(f"[SYNC] PhishTank: {new_count} new threats ({len(valid_urls)} valid)")
        return len(valid_urls), new_count

    @retry_on_failure(max_retries=2, delay=1)
    def _sync_emergingthreats(self) -> Tuple[int, int]:
        """EmergingThreats — free Suricata rules feed with phishing indicators."""
        res = secure_get(self.feeds["EmergingThreats"], timeout=(5, 15), enable_ssl_fallback=True)
        if res.status_code != 200:
            logging.warning(f"[SYNC] EmergingThreats returned HTTP {res.status_code}")
            self._log_sync("EmergingThreats", 0, f"HTTP {res.status_code}")
            return 0, 0
        urls = []
        pattern = r'content:\s*"([^"]+)"'
        for match in re.findall(pattern, res.text):
            if '.' in match and not match.startswith('http'):
                url = f"http://{match}"
                if self._is_valid_url(url):
                    urls.append(url)
            elif match.startswith('http') and self._is_valid_url(match):
                urls.append(match)
        valid_urls = list(set(urls))[:1000]
        new_count = self._bulk_insert(valid_urls, "EmergingThreats", "IOC/Phishing", 80)
        self._log_sync("EmergingThreats", new_count, "Success")
        logging.info(f"[SYNC] EmergingThreats: {new_count} new threats ({len(valid_urls)} valid)")
        return len(valid_urls), new_count

    def _is_valid_url(self, url: str) -> bool:
        """Basic URL validation."""
        if not url or len(url) > 2048:
            return False
        if not url.startswith(('http://', 'https://')):
            return False
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return bool(url_pattern.match(url))

    def _bulk_insert(self, urls: List[str], source: str, threat_type: str, confidence: int) -> int:
        """Bulk insert URLs with error handling."""
        if not urls:
            return 0
            
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        new_count = 0
        errors = 0
        
        for url in urls:
            try:
                c.execute("INSERT OR IGNORE INTO phishing_urls (url, source, threat_type, confidence) VALUES (?, ?, ?, ?)", 
                          (url, source, threat_type, confidence))
                if c.rowcount > 0:
                    new_count += 1
            except Exception as e:
                errors += 1
                if errors <= 5:  # Log first 5 errors only
                    logging.debug(f"[BULK_INSERT] Error inserting URL: {e}")
                continue
        
        try:
            conn.commit()
        except Exception as e:
            logging.error(f"[BULK_INSERT] Commit failed: {e}")
        finally:
            conn.close()
        
        if errors > 5:
            logging.debug(f"[BULK_INSERT] Suppressed {errors - 5} additional errors")
        
        return new_count

    def _log_sync(self, feed, count, status):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT INTO sync_history (feed_name, new_records, status) VALUES (?, ?, ?)", 
                  (feed, count, status))
        conn.commit()
        conn.close()

    def is_known_threat(self, url):
        """Checks if a URL exists in our local database with intelligence metadata."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # 1. Exact URL match
        c.execute("SELECT source, threat_type, confidence FROM phishing_urls WHERE url = ?", (url,))
        result = c.fetchone()

        # 2. Domain-level match (e.g. http://evil.com/page → matches http://evil.com/other)
        if not result:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc or parsed.path.split('/')[0]
                if domain:
                    c.execute(
                        "SELECT source, threat_type, confidence FROM phishing_urls WHERE url LIKE ? LIMIT 1",
                        (f"%{domain}%",)
                    )
                    result = c.fetchone()
            except Exception:
                pass

        conn.close()

        if result:
            return {
                "source": result[0],
                "type": result[1],
                "confidence": result[2]
            }
        return None

    def get_sync_stats(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM phishing_urls")
        total = c.fetchone()[0]
        c.execute("SELECT feed_name, MAX(timestamp), new_records FROM sync_history GROUP BY feed_name")
        history = c.fetchall()
        conn.close()
        return {"total_threats": total, "history": history}

    def _backup_csv(self):
        """Create backup of dataset.csv before updating."""
        _data_dir = os.path.join(self.project_root, "data", "datasets")
        csv_path = os.path.join(_data_dir, "dataset.csv")
        if not os.path.exists(csv_path):
            return False
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(_data_dir, f"dataset_backup_{timestamp}.csv")
        
        try:
            shutil.copy2(csv_path, backup_path)
            logging.info(f"[CSV_BACKUP] Created backup: {backup_path}")
            return True
        except Exception as e:
            logging.error(f"[CSV_BACKUP] Failed to backup: {e}")
            return False

    def update_dataset_csv(self):
        """Update dataset.csv with new threat data from global feeds."""
        _data_dir = os.path.join(self.project_root, "data", "datasets")
        os.makedirs(_data_dir, exist_ok=True)
        csv_path = os.path.join(_data_dir, "dataset.csv")
        
        # Create backup first
        self._backup_csv()
        
        # Get new threats from database (last 24 hours)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # First, get existing URLs from CSV
        existing_urls = set()
        if os.path.exists(csv_path):
            try:
                with open(csv_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    next(reader)  # Skip header
                    for row in reader:
                        if row and len(row) >= 1:
                            existing_urls.add(row[0].strip())
            except Exception as e:
                logging.error(f"[CSV_UPDATE] Error reading existing CSV: {e}")
        
        # Create temporary table for existing URLs
        c.execute("CREATE TEMP TABLE IF NOT EXISTS temp_existing_urls (url TEXT)")
        for url in existing_urls:
            c.execute("INSERT INTO temp_existing_urls (url) VALUES (?)", (url,))
        
        # Get new threats (last 24 hours, not in CSV)
        c.execute("""
            SELECT DISTINCT url FROM phishing_urls 
            WHERE date_added >= datetime('now', '-1 day')
            AND url NOT IN (SELECT url FROM temp_existing_urls)
        """)
        
        new_threats = [row[0] for row in c.fetchall()]
        c.execute("DROP TABLE temp_existing_urls")
        conn.close()
        
        if not new_threats:
            logging.info("[CSV_UPDATE] No new threats to add to CSV")
            return 0
        
        # Append new threats to CSV
        try:
            with open(csv_path, 'a', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                for url in new_threats:
                    if self._is_valid_url(url):
                        writer.writerow([url, 'bad'])
            
            logging.info(f"[CSV_UPDATE] Added {len(new_threats)} new threats to dataset.csv")
            self._log_sync("CSV_Update", len(new_threats), "Success")
            
            # Retrain ML model with new data
            if len(new_threats) > 0:
                try:
                    from app.ml.local_ml import LocalMLEngine
                    ml_engine = LocalMLEngine()
                    ml_engine._train_advanced_model()
                    logging.info("[CSV_UPDATE] ML model retrained with new data")
                except Exception as e:
                    logging.error(f"[CSV_UPDATE] Failed to retrain ML: {e}")
            
            return len(new_threats)
            
        except Exception as e:
            logging.error(f"[CSV_UPDATE] Failed to update CSV: {e}")
            self._log_sync("CSV_Update", 0, f"Failed: {e}")
            return 0

if __name__ == "__main__":
    # Manual trigger
    db = ThreatIntelDB()
    new_ones = db.sync_global_feeds()
    print(f"Sync complete. Found {new_ones} new threats.")
    print(db.get_sync_stats())
