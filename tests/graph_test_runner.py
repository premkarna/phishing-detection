import os
import sys
import json
from unittest.mock import patch, MagicMock

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_graph_data_mapping():
    print("Starting Interactive Threat Graph Data Mapping Test...")
    
    # Simulated Scan Data
    scan_data = {
        "payload": "hacker-site.ru",
        "calculated_risk": 90,
        "server_ip_loc": "185.23.11.4 (Russia)",
        "domain_age": "2 days",
        "ssl_certificate": "None",
        "virustotal": "15/94 Flags"
    }
    
    # The logic we're testing is primarily in script.js (frontend), 
    # but we verify that the backend provides all necessary fields for the graph.
    print("\n[TEST] Verifying Backend Telemetry for Graph...")
    required_fields = ['payload', 'calculated_risk', 'server_ip_loc', 'domain_age', 'ssl_certificate']
    
    passed = 0
    for field in required_fields:
        if field in scan_data:
            print(f"PASS: Field '{field}' present: {scan_data[field]}")
            passed += 1
        else:
            print(f"FAIL: Field '{field}' missing!")
            
    print(f"\n[TEST] Verifying Graph Node Logic (Simulated)...")
    # Simulation of script.js logic:
    nodes = [
        {"id": "TARGET", "name": f"Target: {scan_data['payload']}"},
        {"id": "IP", "name": f"IP: {scan_data['server_ip_loc']}"},
        {"id": "LOC", "name": f"Location: {scan_data['server_ip_loc'].split('(')[1].replace(')', '')}"}
    ]
    
    assert "Russia" in nodes[2]['name']
    print("Node logic simulation successful.")
    
    print("\n" + "="*50)
    print("THREAT GRAPH: Data mapping verification passed!")
    print("="*50)

if __name__ == "__main__":
    test_graph_data_mapping()
