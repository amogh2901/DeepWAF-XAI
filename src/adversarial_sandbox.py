"""
ThreatShield DeepWAF-XAI Adversarial Evasion Sandbox
---------------------------------------------------
Generates mutated payloads using common WAF evasion and perturbation techniques
to evaluate the adversarial robustness and resilience of the neural network model.

Techniques Implemented:
1. Case Randomization (e.g., sElEct * FrOm)
2. Inline Comment Insertion (e.g., SELECT/**/*/**/FROM)
3. Whitespace to Tab/Newline conversion (\t, \n)
4. Null-Byte Injection (e.g., SELECT%00)
5. URL Hex Encoding (e.g., %27, %3c, %20)
"""

import random
import re


class AdversarialSandbox:
    """Generates mutated adversarial payloads for WAF robustness evaluation."""

    @staticmethod
    def case_randomization(payload: str) -> str:
        """Alternates character casing across letters in the payload."""
        if not payload:
            return ""
        result = []
        upper_flag = True
        for char in payload:
            if char.isalpha():
                result.append(char.upper() if upper_flag else char.lower())
                upper_flag = not upper_flag
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def inline_comment_insertion(payload: str) -> str:
        """Replaces whitespace and delimiters with inline SQL/HTML comment structures."""
        if not payload:
            return ""
        if " " in payload:
            return payload.replace(" ", "/**/")
        # If no spaces, insert comment after punctuation or keywords
        if "<" in payload or ">" in payload:
            return payload.replace(">", "><!-- -->")
        if "/" in payload:
            return payload.replace("/", "/**//")
        return payload + "/**/"

    @staticmethod
    def whitespace_to_tab_newline(payload: str) -> str:
        """Converts standard spaces to tabs (\t) and newlines (\n)."""
        if not payload:
            return ""
        if " " in payload:
            parts = payload.split(" ")
            # Alternate between tabs and newlines
            joined = []
            for i, part in enumerate(parts):
                joined.append(part)
                if i < len(parts) - 1:
                    joined.append("\t" if i % 2 == 0 else "\n")
            return "".join(joined)
        return "\t" + payload + "\n"

    @staticmethod
    def null_byte_injection(payload: str) -> str:
        """Injects string-terminator null-bytes (%00) into delimiters or token boundaries."""
        if not payload:
            return ""
        if " " in payload:
            return payload.replace(" ", "%00 ")
        if "/" in payload:
            return payload.replace("/", "%00/")
        if "." in payload:
            return payload.replace(".", "%00.")
        return payload + "%00"

    @staticmethod
    def url_hex_encoding(payload: str) -> str:
        """Encodes key delimiters and special characters into hexadecimal URL entities."""
        if not payload:
            return ""
        replacements = {
            "'": "%27",
            '"': "%22",
            "<": "%3C",
            ">": "%3E",
            " ": "%20",
            "/": "%2F",
            "=": "%3D"
        }
        encoded = payload
        for char, hex_code in replacements.items():
            if char in encoded:
                encoded = encoded.replace(char, hex_code)
        return encoded


def generate_adversarial_mutations(payload: str) -> list:
    """
    Generate a comprehensive list of mutated payloads across diverse evasion techniques.

    Parameters
    ----------
    payload : str
        The raw input payload to perturb.

    Returns
    -------
    list of dict
        List of dictionaries containing technique name, mutated payload, and description.
    """
    try:
        if not payload or not isinstance(payload, str):
            return []

        payload = payload.strip()
        if not payload:
            return []

        sandbox = AdversarialSandbox()

        mutations = [
            {
                "technique": "Case Randomization",
                "payload": sandbox.case_randomization(payload),
                "description": "Alternates uppercase and lowercase characters to test case normalization."
            },
            {
                "technique": "Inline Comment Insertion",
                "payload": sandbox.inline_comment_insertion(payload),
                "description": "Substitutes delimiters with inline comment tokens (/**/) to fragment keywords."
            },
            {
                "technique": "Whitespace Tab/Newline",
                "payload": sandbox.whitespace_to_tab_newline(payload),
                "description": "Converts space characters into tab and newline whitespace sequences."
            },
            {
                "technique": "Null-Byte Injection",
                "payload": sandbox.null_byte_injection(payload),
                "description": "Injects string terminator null-byte sequences (%00) at token boundaries."
            },
            {
                "technique": "URL Hex Encoding",
                "payload": sandbox.url_hex_encoding(payload),
                "description": "Transforms delimiters and operators into percent-encoded hexadecimal values."
            }
        ]

        # Filter out mutations that produced no change from original payload
        return mutations

    except Exception:
        return []
