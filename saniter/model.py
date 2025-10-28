import joblib
import os
from saniter.context import decode_unicode_text

try:
    model = joblib.load(os.path.join(os.path.dirname(__file__), 'models', 'model_alpha.joblib'))
    vectorizer = joblib.load(os.path.join(os.path.dirname(__file__), 'models', 'vectorizer_alpha.joblib'))
except Exception as e:
    # Provide a clearer error for users running the module interactively
    raise RuntimeError(f"Failed to load model or vectorizer: {e}")

def check(input: str):
    """Decode input and predict label (0 safe / 1 malicious).

    Returns an int (0 or 1). Raises a RuntimeError if the model isn't loaded.
    """
    if model is None or vectorizer is None:
        raise RuntimeError("Model or vectorizer not loaded")

    decoded_input = decode_unicode_text(input)

    # Fast rule-based pre-check for high-confidence XSS tokens.
    # This handles obvious payloads (tags, event handlers, javascript: URIs)
    s = decoded_input.lower()
    import re
    rule_patterns = [
        r"<script\b",
        r"<svg\b",
        r"<img\b",
        r"<iframe\b",
        r"on\w+\s*=",
        r"javascript:\/\/",
        r"javascript:",
        r"alert\s*\(",
        r"prompt\s*\(",
        r"confirm\s*\(",
        r"%3c",  # encoded '<'
        r"%3e",  # encoded '>'
    ]
    # Also detect literal escape sequences (e.g. "\u0061"), hex escapes, and HTML entities
    escape_patterns = [
        r"\\u[0-9a-f]{4}",
        r"\\x[0-9a-f]{2}",
        r"&#\d+;",
    ]
    # Check raw input for escape sequences before decoding (use original string)
    raw_s = str(input)
    for pat in escape_patterns:
        if re.search(pat, raw_s, flags=re.IGNORECASE):
            return 1
    for pat in rule_patterns:
        if re.search(pat, s):
            return 1

    x_test = vectorizer.transform([decoded_input])
    predict = model.predict(x_test)
    return int(predict[0])


if __name__ == "__main__":
    # Quick interactive check when running this file directly
    test_cases = [
        "text-with-dashes",
        r"user@ex\u0061mple.com",
        r"<\u0073vg onload=alert(1)>",
    ]
    for t in test_cases:
        try:
            print(f"{t} -> {check(t)}")
        except Exception as e:
            print(f"Error checking '{t}': {e}")