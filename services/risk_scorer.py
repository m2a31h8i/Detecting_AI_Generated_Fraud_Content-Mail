TIER_THRESHOLDS = {"CRITICAL": 85, "HIGH": 65, "MEDIUM": 40, "LOW": 20}
TIER_COLOURS    = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22",
                   "MEDIUM": "#f1c40f", "LOW": "#2ecc71", "SAFE": "#27ae60"}

def assign_tier(score_0_to_100: float) -> dict:
    for tier, threshold in TIER_THRESHOLDS.items():
        if score_0_to_100 >= threshold:
            return {"tier": tier, "colour": TIER_COLOURS[tier]}
    return {"tier": "SAFE", "colour": TIER_COLOURS["SAFE"]}

def simple_explanation(tier: str, evidence: list) -> dict:
    messages = {
        "CRITICAL": "This email shows strong indicators of AI-generated phishing.",
        "HIGH":     "This email has multiple high-confidence phishing signals.",
        "MEDIUM":   "This email has some suspicious characteristics.",
        "LOW":      "This email has minor suspicious indicators.",
        "SAFE":     "This email appears legitimate.",
    }
    actions = {
        "CRITICAL": ["Do not click any links.", "Report to IT security immediately.", "Delete this email."],
        "HIGH":     ["Verify sender through another channel.", "Do not provide credentials.", "Mark as phishing."],
        "MEDIUM":   ["Treat with caution.", "Verify the sender identity.", "Do not share personal info."],
        "LOW":      ["Review before responding.", "Check sender domain carefully."],
        "SAFE":     ["No action required."],
    }
    return {
        "summary": messages.get(tier, "Analysis complete."),
        "actions": actions.get(tier, []),
        "evidence": evidence,
    }

def score_email(module_score_0_to_1: float, evidence: list) -> dict:
    score_100 = round(module_score_0_to_1 * 100, 1)
    tier_info = assign_tier(score_100)
    explanation = simple_explanation(tier_info["tier"], evidence)
    return {
        "composite_score": score_100,
        "tier": tier_info["tier"],
        "colour": tier_info["colour"],
        "explanation": explanation,
    }