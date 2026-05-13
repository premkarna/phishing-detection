import json
import os
import datetime
from pathlib import Path

# Project root: app/services/accuracy_engine.py -> app/services -> app -> root
_PROJECT_ROOT = Path(__file__).parent.parent.parent
_CACHE_DIR = _PROJECT_ROOT / "data" / "cache"
_CACHE_DIR.mkdir(parents=True, exist_ok=True)
METRICS_FILE = str(_CACHE_DIR / "soc_metrics.json")

class AccuracyEngine:
    def __init__(self):
        self.metrics = self.load_metrics()

    def load_metrics(self):
        if os.path.exists(METRICS_FILE):
            try:
                with open(METRICS_FILE, 'r') as f:
                    data = json.load(f)
                    return {key: data.get(key, 0) for key in ("TP", "TN", "FP", "FN", "accuracy", "precision", "recall", "f1_score")}
            except:
                pass
        return {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0}

    def update_metrics(self, tp, tn, fp, fn):
        self.metrics["TP"] = tp
        self.metrics["TN"] = tn
        self.metrics["FP"] = fp
        self.metrics["FN"] = fn
        
        # Calculate derived metrics
        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        self.metrics["accuracy"] = round(accuracy * 100, 2)
        self.metrics["precision"] = round(precision * 100, 2)
        self.metrics["recall"] = round(recall * 100, 2)
        self.metrics["f1_score"] = round(f1 * 100, 2)

        self.save_metrics()

    def save_metrics(self):
        try:
            with open(METRICS_FILE, 'w') as f:
                json.dump(self.metrics, f, indent=4)
        except OSError as e:
            import logging
            logging.error(f"[AccuracyEngine] Failed to save metrics: {e}")

    def get_metrics(self):
        return self.metrics
