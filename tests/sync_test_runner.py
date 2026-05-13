import os
import sys
import sqlite3
from unittest.mock import patch, MagicMock

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.threat_sync import ThreatIntelDB

def test_global_threat_sync():
    print("Starting Global Threat Sync Test Suite...")
    # Use a temporary test database
    test_db = "test_threats.db"
    if os.path.exists(test_db):
        os.remove(test_db)
        
    with patch('utils.threat_sync.ThreatIntelDB.__init__', lambda self: None):
        db = ThreatIntelDB()
        db.db_path = test_db
        db.feeds = {
            "OpenPhish": "http://mock-openphish.com",
            "PhishTank": "http://mock-phishtank.com"
        }
        db._init_db()
        
        # 1. Test OpenPhish Sync Logic
        print("\n[TEST] Verifying OpenPhish Data Ingestion...")
        mock_text = "http://malicious-site-1.com\nhttp://malicious-site-2.com"
        with patch('requests.get') as mock_get:
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.text = mock_text
            mock_get.return_value = mock_res
            
            total, new = db._sync_openphish()
            print(f"OpenPhish Result: Total={total}, New={new}")
            assert total == 2
            assert new == 2
            
        # 2. Test PhishTank Sync Logic (JSON)
        print("\n[TEST] Verifying PhishTank JSON Ingestion...")
        mock_json = [
            {"url": "http://phish-tank-1.com", "phish_id": "123"},
            {"url": "http://phish-tank-2.com", "phish_id": "456"}
        ]
        with patch('requests.get') as mock_get:
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = mock_json
            mock_get.return_value = mock_res
            
            total, new = db._sync_phishtank()
            print(f"PhishTank Result: Total={total}, New={new}")
            assert total == 2
            assert new == 2

        # 3. Test Database Persistence & Lookup
        print("\n[TEST] Verifying Threat Lookup Logic...")
        threat = db.is_known_threat("http://malicious-site-1.com")
        print(f"Lookup Result: {threat}")
        assert threat is not None
        assert threat['source'] == "OpenPhish"
        
        # 4. Test Sync Stats
        print("\n[TEST] Verifying Sync Statistics...")
        stats = db.get_sync_stats()
        print(f"Stats: {stats}")
        assert stats['total_threats'] == 4
        assert len(stats['history']) == 2 # One for each feed

    # Cleanup
    if os.path.exists(test_db):
        os.remove(test_db)
        
    print("\n" + "="*50)
    print("GLOBAL THREAT SYNC: All test cases passed!")
    print("="*50)

if __name__ == "__main__":
    test_global_threat_sync()
