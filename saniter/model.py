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
    # Basic HTML tags and attributes
    r"<script\b",
    r"<svg\b",
    r"<img\b",
    r"<iframe\b",
    r"<embed\b",
    r"<object\b",
    r"<frame\b",
    r"<frameset\b",
    r"<meta\b",
    r"<link\b",
    r"<base\b",
    r"<form\b",
    r"<input\b",
    r"<button\b",
    r"<select\b",
    r"<textarea\b",
    r"<style\b",
    r"<marquee\b",
    
    # Event handlers
    r"on\w+\s*=",
    r"onload\s*=",
    r"onerror\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"onfocus\s*=",
    r"onblur\s*=",
    r"onsubmit\s*=",
    r"onchange\s*=",
    r"onkeypress\s*=",
    r"onkeydown\s*=",
    r"onkeyup\s*=",
    
    # JavaScript protocols and functions
    r"javascript:\/\/",
    r"javascript:",
    r"vbscript:",
    r"data:text\/html",
    r"data:text\/javascript",
    r"alert\s*\(",
    r"prompt\s*\(",
    r"confirm\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"Function\s*\(",
    r"execScript\s*\(",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"insertAdjacentHTML\s*\(",
    
    # Dangerous attributes
    r"src\s*=",
    r"href\s*=",
    r"action\s*=",
    r"formaction\s*=",
    r"poster\s*=",
    r"background\s*=",
    r"lowsrc\s*=",
    r"dynsrc\s*=",
    r"xlink:href\s*=",
    
    # Encoded characters
    r"%3c",  # encoded '<'
    r"%3e",  # encoded '>'
    r"%22",  # encoded '"'
    r"%27",  # encoded "'"
    r"%28",  # encoded '('
    r"%29",  # encoded ')'
    r"%2f",  # encoded '/'
    r"%5c",  # encoded '\'
    
    # CSS-based attacks
    r"expression\s*\(",
    r"url\s*\(",
    r"@import",
    r"javascript:",
    r"behavior:",
    
    # Advanced evasion techniques
    r"<\!\-\-",
    r"-\-\>",
    r"<\?",
    r"\?>",
    r"<%",
    r"%>",
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


def is_xss(input: str)  -> bool:
    """Decode input and predict label (False: safe / True: malicious).

    Returns an boolean (True or False). Raises a RuntimeError if the model isn't loaded.
    """
    result = check(input)
    if check == 0: return False
    else: return True
def is_safe(input: str) -> bool:
    """Decode input and predict label (True: safe / False: malicious).

    Returns an boolean (True or False). Raises a RuntimeError if the model isn't loaded.
    """
    result = check(input)
    if check == 1: return False
    else: return True
def check_type(input: str)  -> str:
    """Decode input and predict label (SAFE: safe / XSS: malicious).

    Returns an string (SAFE or XSS). Raises a RuntimeError if the model isn't loaded.
    """
    result = check(input)
    if check == 0: return "SAFE"
    else: return "XSS"
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