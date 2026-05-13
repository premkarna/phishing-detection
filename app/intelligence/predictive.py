import random

class PredictiveIntel:
    def __init__(self):
        self.brand_affinities = {
            "google": ["microsoft", "apple", "adobe"],
            "paypal": ["bankofamerica", "chase", "stripe"],
            "instagram": ["facebook", "tiktok", "whatsapp"],
            "microsoft": ["azure", "outlook", "sharepoint"]
        }

    def predict_next_target(self, current_result):
        """Predicts the next likely brand or infrastructure target."""
        brand = current_result.get('mimicked_brand', 'None').lower()
        
        if brand != 'none' and brand in self.brand_affinities:
            predicted = random.choice(self.brand_affinities[brand])
            confidence = random.randint(75, 98)
            reason = f"Based on {brand} attack patterns, adversaries often pivot to {predicted} infrastructure."
        else:
            predicted = "Generic Enterprise Portal"
            confidence = random.randint(40, 60)
            reason = "No specific brand affinity detected. Monitoring for generic credential harvesting."

        return {
            "predicted_target": predicted,
            "confidence_score": f"{confidence}%",
            "threat_actor_motivation": "Financial Gain / Credential Harvesting",
            "prediction_reasoning": reason
        }
