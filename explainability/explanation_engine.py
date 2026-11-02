"""
ThreatShield Explainability Module
----------------------------------
Provides human-readable explanations for Deep Learning predictions.

This module DOES NOT modify the prediction.
It only explains why the prediction was made.
"""

import re


class ExplanationEngine:
    """Generate human-readable explanations for ThreatShield predictions."""

    def __init__(self):
        pass

    def explain(self, payload: str, prediction: str, confidence: float):
        """
        Generate explanation for a prediction.

        Parameters
        ----------
        payload : str
            Incoming HTTP request or URL.

        prediction : str
            Predicted attack class.

        confidence : float
            Model confidence.

        Returns
        -------
        dict
            Explanation dictionary.
        """

        payload = payload.lower().strip()

        reasons = []
        explanation_text = ""
        risk_level = "LOW"

        # ---------------- SQL Injection ----------------
        if prediction == "SQL Injection":

            risk_level = "HIGH"

            if "union" in payload:
                reasons.append("UNION keyword detected")

            if "select" in payload:
                reasons.append("SELECT keyword detected")

            if "or 1=1" in payload:
                reasons.append("Authentication bypass pattern detected")

            if "drop table" in payload:
                reasons.append("Dangerous SQL command detected")

            explanation_text = (
                "The Bi-Directional LSTM model classified this request as "
                "SQL Injection because it detected SQL query manipulation "
                "patterns commonly used to access or modify databases."
            )

        # ---------------- Cross Site Scripting ----------------
        elif prediction == "Cross Site Scripting":

            risk_level = "HIGH"

            if "<script>" in payload:
                reasons.append("Executable JavaScript detected")

            if "alert(" in payload:
                reasons.append("Suspicious JavaScript function found")

            explanation_text = (
                "The Bi-Directional LSTM model detected executable "
                "JavaScript code that may be used to perform a "
                "Cross-Site Scripting (XSS) attack."
            )

        # ---------------- Path Traversal ----------------
        elif prediction == "Path Traversal":

            risk_level = "HIGH"

            if "../" in payload:
                reasons.append("Directory traversal pattern detected")

            explanation_text = (
                "The request contains directory traversal sequences "
                "that may allow unauthorized access to sensitive files."
            )

        # ---------------- Phishing ----------------
        elif prediction == "Phishing URL":

            risk_level = "HIGH" if any(k in payload for k in ("bank", "account", "verify", "login", "credential", "secure")) else "MEDIUM"

            if any(k in payload for k in ("bank", "account", "verification", "verify", "login", "signin", "credential")):
                reasons.append("Credential or financial harvesting keyword identified")

            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', payload):
                reasons.append("Raw IP address used as URL host (domain evasion indicator)")

            if not reasons:
                reasons.append("Suspicious URL characteristics detected")

            explanation_text = (
                "The Deep Learning model identified characteristics "
                "commonly associated with phishing websites, such as "
                "deceptive URLs and suspicious structures."
            )

        # ---------------- Normal ----------------
        else:

            risk_level = "LOW"

            reasons.append("No malicious attack patterns detected")

            explanation_text = (
                "The Bi-Directional LSTM model did not detect any "
                "known malicious patterns. The request appears to be legitimate."
            )

        # Confidence interpretation
        if confidence >= 0.95:
            confidence_level = "Very High"
        elif confidence >= 0.85:
            confidence_level = "High"
        elif confidence >= 0.70:
            confidence_level = "Medium"
        else:
            confidence_level = "Low"

        # Recommended action
        if risk_level == "HIGH":
            recommended_action = (
                "Immediately block the request, log the event, "
                "and notify the administrator."
            )

        elif risk_level == "MEDIUM":
            recommended_action = (
                "Monitor the request and perform additional verification."
            )

        else:
            recommended_action = (
                "Allow the request and continue normal monitoring."
            )

        return {

            "prediction": prediction,

            "confidence": round(confidence * 100, 2),

            "confidence_level": confidence_level,

            "risk_level": risk_level,

            "summary": explanation_text,

            "explanation": reasons,

            "recommended_action": recommended_action

        }


def generate_saliency_heatmap(payload, predict_function, target_class=None):
    """
    Generate character-level saliency scores using an Occlusion/Perturbation-based approach.

    Parameters
    ----------
    payload : str
        Incoming HTTP request, URL, or payload to analyze.
    predict_function : callable
        Prediction callable returning model predictions or probability distributions.
    target_class : str, optional
        Target attack class to measure confidence drops against.

    Returns
    -------
    list of tuple
        A list of (character/chunk, importance_score) tuples with scores normalized between 0.0 and 1.0.
        Returns an empty list [] on any tensor, array, or runtime mismatch.
    """
    try:
        if not payload or not isinstance(payload, str) or not callable(predict_function):
            return []

        def _extract_target_probability(output, target):
            """Safely extracts target class probability from diverse model output formats."""
            if output is None:
                return 0.0
            if isinstance(output, (float, int)):
                return float(output)

            # Dictionary format (e.g. {"SQL Injection": 0.98, "Normal": 0.02})
            if isinstance(output, dict):
                if target and target in output:
                    return float(output[target])
                if target:
                    target_lower = str(target).strip().lower()
                    for k, v in output.items():
                        if str(k).strip().lower() == target_lower:
                            return float(v)
                if output:
                    return float(max(output.values()))
                return 0.0

            # Tuple/List format (e.g. (attack_type, confidence, probabilities_dict))
            if isinstance(output, (tuple, list)):
                for item in output:
                    if isinstance(item, dict):
                        return _extract_target_probability(item, target)
                if len(output) >= 2 and isinstance(output[1], (float, int)):
                    label, conf = output[0], output[1]
                    if target is None or str(label).strip().lower() == str(target).strip().lower():
                        return float(conf)
                    return 0.0
                if len(output) >= 1 and isinstance(output[0], (float, int)):
                    return float(output[0])

            return 0.0

        # Baseline model prediction
        base_output = predict_function(payload)

        # Infer target class if not explicitly provided
        if target_class is None:
            if isinstance(base_output, (tuple, list)) and len(base_output) > 0 and isinstance(base_output[0], str):
                target_class = base_output[0]
            elif isinstance(base_output, dict) and base_output:
                target_class = max(base_output.items(), key=lambda x: x[1])[0]

        base_confidence = _extract_target_probability(base_output, target_class)

        raw_drops = []
        for i in range(len(payload)):
            # Occlusion: mask out character i
            masked_payload = payload[:i] + payload[i + 1:]
            perturbed_output = predict_function(masked_payload)
            perturbed_confidence = _extract_target_probability(perturbed_output, target_class)

            # Measure drop in confidence for the target class
            confidence_drop = max(0.0, base_confidence - perturbed_confidence)
            raw_drops.append((payload[i], confidence_drop))

        # Normalize confidence drops to [0.0, 1.0] range
        max_drop = max([drop for _, drop in raw_drops], default=0.0)

        if max_drop > 0.0:
            saliency_scores = [(char, round(drop / max_drop, 4)) for char, drop in raw_drops]
        else:
            saliency_scores = [(char, 0.0) for char, _ in raw_drops]

        return saliency_scores

    except Exception:
        # Guarantee non-destructive behavior: never crash caller
        return []