import logging
import json

class SOARPlaybook:
    def __init__(self):
        self.severity_levels = {
            "CRITICAL": 3,
            "HIGH": 2,
            "MEDIUM": 1,
            "LOW": 0
        }

    def generate_playbook(self, risk_score, vector_type, engine_result, ai_playbook=None):
        """
        Generates a professional Incident Response Playbook.
        Prioritizes Gemini AI generated steps if available, otherwise falls back to static SOC templates.
        """
        severity = "LOW"
        if risk_score >= 80: severity = "CRITICAL"
        elif risk_score >= 60: severity = "HIGH"
        elif risk_score >= 30: severity = "MEDIUM"

        playbook = {
            "incident_id": f"SG-{vector_type.upper()}-{int(risk_score)}",
            "severity": severity,
            "steps": []
        }

        # Use AI-generated steps if provided by Gemini
        if ai_playbook and isinstance(ai_playbook, list) and len(ai_playbook) > 0:
            logging.info("[+] SOAR: Integrating Gemini AI Dynamic Playbook steps.")
            phases = ["CONTAINMENT", "INVESTIGATION", "REMEDIATION", "POST-INCIDENT"]
            for i, step_text in enumerate(ai_playbook):
                phase = phases[i] if i < len(phases) else "ADDITIONAL ACTION"
                playbook["steps"].append({
                    "phase": phase,
                    "action": f"AI Directed: {step_text.split(':')[0] if ':' in step_text else 'Forensic Action'}",
                    "desc": step_text
                })
        else:
            # Fallback to Static Professional Templates (Boss's Standard Operating Procedures)
            logging.info("[*] SOAR: AI playbook missing. Using Standard SOC Fallback templates.")
            
            # 1. Containment Phase
            if severity in ["CRITICAL", "HIGH"]:
                playbook["steps"].append({
                    "phase": "CONTAINMENT",
                    "action": "Endpoint Isolation",
                    "desc": f"Immediately isolate host system from corporate network to prevent lateral movement of {vector_type} threat."
                })
            else:
                playbook["steps"].append({
                    "phase": "CONTAINMENT",
                    "action": "Traffic Monitoring",
                    "desc": "Enable enhanced logging for the target endpoint and monitor for suspicious outbound requests."
                })
            
            # 2. Investigation Phase
            playbook["steps"].append({
                "phase": "INVESTIGATION",
                "action": "Artifact Analysis",
                "desc": f"Perform deep forensic scan on {vector_type} payload. Extracting headers, DOM artifacts, and binary signatures."
            })

            # 3. Remediation Phase
            if "url" in vector_type or "social" in vector_type:
                playbook["steps"].append({
                    "phase": "REMEDIATION",
                    "action": "DNS Sinkholing",
                    "desc": "Update enterprise DNS to sinkhole the malicious domain and trigger automated takedown notices."
                })
            elif "eml" in vector_type:
                playbook["steps"].append({
                    "phase": "REMEDIATION",
                    "action": "Mailbox Remediation",
                    "desc": "Executing O365/G-Suite search-and-destroy to purge similar malicious emails across the organization."
                })
            elif "qr" in vector_type:
                playbook["steps"].append({
                    "phase": "REMEDIATION",
                    "action": "Physical Access Control",
                    "desc": "Notify physical security to inspect and remove fraudulent QR stickers from premises."
                })

            # 4. Post-Incident
            playbook["steps"].append({
                "phase": "POST-INCIDENT",
                "action": "Security Awareness",
                "desc": "Flag user for mandatory advanced phishing simulation and SOC security debrief."
            })

        return playbook
