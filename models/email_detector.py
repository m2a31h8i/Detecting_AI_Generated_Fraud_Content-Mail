"""
Module 1 — Phishing Email Detector
Four-layer analysis: zero-shot classification, AI-text detection,
perplexity scoring, and pattern matching.
"""

import time
import math
import re
import yaml
from pathlib import Path
from typing import Dict, List

import torch
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification, GPT2LMHeadModel, GPT2TokenizerFast


PATTERNS_PATH = Path(__file__).parent.parent / "data" / "phishing_patterns.yaml"

WEIGHTS = {
    "zero_shot": 0.30,
    "ai_detector": 0.30,
    "perplexity": 0.20,
    "pattern": 0.20,
}


class EmailPhishingDetector:
    def __init__(self):
        print("[EmailDetector] Loading models...")
        # Zero-shot classifier
        self.zero_shot = pipeline(
            "zero-shot-classification",
            model="facebook/bart-large-mnli",
            device=-1,  # CPU
        )

        # AI-text detector (RoBERTa)
        self.roberta_tokenizer = AutoTokenizer.from_pretrained(
            "Hello-SimpleAI/chatgpt-detector-roberta"
        )
        self.roberta_model = AutoModelForSequenceClassification.from_pretrained(
            "Hello-SimpleAI/chatgpt-detector-roberta"
        )
        self.roberta_model.eval()

        # GPT-2 for perplexity
        self.gpt2_tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
        self.gpt2_model = GPT2LMHeadModel.from_pretrained("gpt2")
        self.gpt2_model.eval()

        # Pattern library
        self._patterns = self._load_patterns()
        print("[EmailDetector] All models loaded.")

    def _load_patterns(self) -> List[Dict]:
        with open(PATTERNS_PATH) as f:
            data = yaml.safe_load(f)
        compiled = []
        for p in data.get("patterns", []):
            compiled.append({
                "name": p["name"],
                "regex": re.compile(p["regex"], re.IGNORECASE),
                "weight": p.get("weight", 1.0),
            })
        return compiled

    def _zero_shot_score(self, text: str) -> float:
        result = self.zero_shot(
            text[:1024],  # cap length
            candidate_labels=["phishing email", "legitimate email", "spam"],
        )
        label_scores = dict(zip(result["labels"], result["scores"]))
        return round(label_scores.get("phishing email", 0.0), 4)

    def _ai_detector_score(self, text: str) -> float:
        inputs = self.roberta_tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512
        )
        with torch.no_grad():
            logits = self.roberta_model(**inputs).logits
        probs = torch.softmax(logits, dim=-1).squeeze()
        # Label 1 = AI-generated (model-specific; check label mapping)
        label_map = self.roberta_model.config.id2label
        ai_label_id = next(
            (k for k, v in label_map.items() if "fake" in v.lower() or "ai" in v.lower() or "chatgpt" in v.lower()),
            1,
        )
        return round(probs[ai_label_id].item(), 4)

    def _perplexity_score(self, text: str) -> float:
        inputs = self.gpt2_tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512
        )
        input_ids = inputs["input_ids"]
        with torch.no_grad():
            outputs = self.gpt2_model(input_ids, labels=input_ids)
            loss = outputs.loss
        perplexity = math.exp(loss.item())
        # Normalise: lower perplexity = higher suspicion (AI text is fluent)
        score = 1.0 - min(perplexity / 200.0, 1.0)
        return round(score, 4)

    def _pattern_score(self, text: str) -> tuple:
        total_weight = sum(p["weight"] for p in self._patterns)
        matched_weight = 0.0
        matched_names = []
        for p in self._patterns:
            if p["regex"].search(text):
                matched_weight += p["weight"]
                matched_names.append(p["name"])
        score = matched_weight / total_weight if total_weight > 0 else 0.0
        return round(score, 4), matched_names

    def analyze(self, subject: str, body: str) -> Dict:
        start = time.time()
        combined = f"Subject: {subject}\n\n{body}"

        zs = self._zero_shot_score(combined)
        ai = self._ai_detector_score(combined)
        pp = self._perplexity_score(combined)
        pat, matched_patterns = self._pattern_score(combined)

        module_score = (
            zs * WEIGHTS["zero_shot"]
            + ai * WEIGHTS["ai_detector"]
            + pp * WEIGHTS["perplexity"]
            + pat * WEIGHTS["pattern"]
        )

        evidence = []
        if zs > 0.5:
            evidence.append(f"Zero-shot phishing probability: {zs:.2f}")
        if ai > 0.5:
            evidence.append(f"AI-generation probability: {ai:.2f}")
        if pp > 0.5:
            evidence.append(f"Low perplexity (fluent AI text) score: {pp:.2f}")
        for name in matched_patterns:
            evidence.append(f"Pattern: {name.replace('_', ' ')}")

        return {
            "module_name": "phishing_email",
            "module_score": round(module_score, 4),
            "sub_scores": {
                "zero_shot_classifier": zs,
                "ai_text_detector": ai,
                "perplexity": pp,
                "pattern_matcher": pat,
            },
            "evidence_items": evidence,
            "matched_patterns": matched_patterns,
            "processing_ms": int((time.time() - start) * 1000),
        }