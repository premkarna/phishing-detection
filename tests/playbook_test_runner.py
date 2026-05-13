import os
import sys
import json
from unittest.mock import patch, MagicMock

# Add root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.soar_playbook import SOARPlaybook

def test_auto_soc_playbook():
    print("Starting Auto-SOC Playbook Test Suite...")
    soar = SOARPlaybook()
    
    # Scenario 1: AI-Generated Dynamic Playbook
    print("\n[TEST] Verifying AI Dynamic Playbook Integration...")
    ai_steps = [
        "Isolate: Disconnect user machine from VLAN 10.",
        "Analyze: Memory dump for suspicious 'meesho-login' strings.",
        "Block: DNS sinkhole meesho-gift.xyz immediately.",
        "Educate: Schedule 1:1 security debrief with the user."
    ]
    
    playbook_ai = soar.generate_playbook(90, "url", {}, ai_playbook=ai_steps)
    print(f"Severity: {playbook_ai['severity']}")
    print(f"Total Steps: {len(playbook_ai['steps'])}")
    
    assert playbook_ai['severity'] == "CRITICAL"
    assert len(playbook_ai['steps']) == 4
    assert "AI Directed" in playbook_ai['steps'][0]['action']
    assert "VLAN 10" in playbook_ai['steps'][0]['desc']
    print("PASS: AI Playbook logic verified.")

    # Scenario 2: Static Fallback Playbook (EML)
    print("\n[TEST] Verifying Static Fallback (EML) Logic...")
    playbook_fallback = soar.generate_playbook(45, "eml", {}, ai_playbook=None)
    print(f"Severity: {playbook_fallback['severity']}")
    
    assert playbook_fallback['severity'] == "MEDIUM"
    assert any("Mailbox Remediation" in s['action'] for s in playbook_fallback['steps'])
    print("PASS: Static Fallback logic verified.")

    # Scenario 3: Static Fallback Playbook (QR)
    print("\n[TEST] Verifying Static Fallback (QR) Logic...")
    playbook_qr = soar.generate_playbook(75, "qr", {}, ai_playbook=None)
    
    assert playbook_qr['severity'] == "HIGH"
    assert any("Physical Access Control" in s['action'] for s in playbook_qr['steps'])
    print("PASS: QR Specific fallback verified.")

    print("\n" + "="*50)
    print("AUTO-SOC PLAYBOOK: All test cases passed!")
    print("="*50)

if __name__ == "__main__":
    test_auto_soc_playbook()
