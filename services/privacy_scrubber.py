"""
Privacy Gateway — must be called before any other processing.
Scrubs PII from input text using spaCy NER + regex patterns.
"""

import re
import hashlib
from typing import Tuple
import spacy


class PrivacyScrubber:
    _nlp = None  # Class-level singleton

    ENTITY_REPLACEMENTS = {
        "PERSON": "[PERSON]",
        "ORG": "[ORGANISATION]",
        "GPE": "[LOCATION]",
        "LOC": "[LOCATION]",
        "FAC": "[LOCATION]",
        "PHONE": "[PHONE]",
        "MONEY": "[AMOUNT]",
        "CARDINAL": "[NUMBER]",
        "DATE": "[DATE]",
        "TIME": "[TIME]",
    }

    REGEX_PATTERNS = [
        (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_ADDRESS]"),
        (re.compile(r"\b(?:\d[ \-]?){13,16}\b"), "[CREDIT_CARD]"),
        (re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"), "[SSN]"),
        (re.compile(r"\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"), "[PHONE]"),
        (re.compile(r"\b[A-Z]{2}\d{6}[A-Z]?\b"), "[ID_NUMBER]"),
    ]

    def __init__(self):
        if PrivacyScrubber._nlp is None:
            PrivacyScrubber._nlp = spacy.load("en_core_web_sm")
        self.nlp = PrivacyScrubber._nlp

    def scrub(self, text: str) -> Tuple[str, str]:
        """
        Scrubs PII from text.
        Returns (scrubbed_text, sha256_hash_of_original).
        The original is never returned.
        """
        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        # Step 1: NER replacement (process in reverse to preserve offsets)
        doc = self.nlp(text)
        entities = sorted(doc.ents, key=lambda e: e.start_char, reverse=True)
        scrubbed = text
        for ent in entities:
            token = self.ENTITY_REPLACEMENTS.get(ent.label_, f"[{ent.label_}]")
            scrubbed = scrubbed[: ent.start_char] + token + scrubbed[ent.end_char :]

        # Step 2: Regex patterns
        for pattern, replacement in self.REGEX_PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)

        # Return scrubbed text and hash only — never the original
        return scrubbed, content_hash