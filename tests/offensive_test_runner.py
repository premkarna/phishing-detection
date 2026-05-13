import os
import sys
import time
from unittest.mock import patch, MagicMock

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.intelligence.countermeasures import OffensiveDefense

def test_offensive_pollution():
    print("Starting Offensive Defense (Pollution Attack) Test Suite...")
    attacker = OffensiveDefense()
    
    # Test Scenario: 1,000 entries (scaled down for testing speed, but logic is same for 10,000)
    target_url = "http://hacker-login-trap.xyz/login.php"
    target_count = 1000
    
    print(f"\n[TEST] Verifying Fake Credential Generation...")
    email, password = attacker._generate_fake_creds()
    print(f"Sample Entry: {email} | {password}")
    assert "@" in email
    assert len(password) >= 10
    
    print(f"\n[TEST] Simulating Pollution Attack on {target_url}...")
    
    # Mocking requests.post to avoid actual network traffic during test
    with patch('requests.post') as mock_post:
        # Simulate successful responses from the hacker's server
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        start_time = time.time()
        # Using a smaller count for the unit test to keep it fast
        actual_injected = attacker.flood_hacker_database(target_url, count=target_count, max_workers=50)
        end_time = time.time()
        
        duration = end_time - start_time
        print(f"\nAttack Results:")
        print(f"Target Count: {target_count}")
        print(f"Actual Injected: {actual_injected}")
        print(f"Total Time: {duration:.2f}s")
        print(f"Throughput: {actual_injected/duration:.2f} requests/sec")
        
        assert actual_injected == target_count
        assert mock_post.call_count == target_count
        
        # Verify that payloads contain expected fields
        args, kwargs = mock_post.call_args
        sent_payload = kwargs['data']
        assert 'username' in sent_payload
        assert 'password' in sent_payload
        assert 'ua' in sent_payload # Stealth user agent
        
    print("\n" + "="*50)
    print("OFFENSIVE DEFENSE: All test cases passed!")
    print("="*50)

if __name__ == "__main__":
    test_offensive_pollution()
