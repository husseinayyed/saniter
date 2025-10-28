import pandas as pd
import numpy as np
import re
import html
import urllib.parse

def inner_text(text: str):
    cleaned_text = text.strip()
    if cleaned_text.startswith('"') and cleaned_text.endswith('"'):
        return cleaned_text[1:-1]
    else:
        return cleaned_text

def unicode10(word_list):
    import random
    obfuscated_list = []
    styles = ['decimal', 'hex', 'mixed', 'url', 'unicode', 'js', 'css']
    
    for word in word_list:
        style = random.choice(styles)
        result = []
        
        for char in word:
            code = ord(char)
            
            if style == 'decimal':
                result.append(f'&#{code};')
            elif style == 'hex':
                hex_str = f'{code:x}'
                result.append(f'&#x{hex_str};')
            elif style == 'mixed':
                if random.random() > 0.5:
                    result.append(f'&#{code};')
                else:
                    hex_str = f'{code:x}'
                    result.append(f'&#x{hex_str};')
            elif style == 'url':
                hex_str = f'{code:02x}'
                result.append(f'%{hex_str}')
            elif style == 'unicode':
                if code <= 0xFFFF:
                    result.append(f'\\u{code:04x}')
                else:
                    result.append(f'\\U{code:08x}')
            elif style == 'js':
                result.append(f'\\u{code:04x}')
            elif style == 'css':
                result.append(f'\\{code:04x}')
        
        obfuscated_list.append(''.join(result))
    
    return obfuscated_list

def decode_unicode_text(text):
    """
    Decode Unicode escapes to match what browser actually executes
    """
    if not isinstance(text, str):
        text = str(text)
    
    def decode_unicode(match):
        try:
            return chr(int(match.group(1), 16))
        except:
            return match.group(0)
    
    text = re.sub(r'\\u([0-9a-fA-F]{4})', decode_unicode, text)
    text = html.unescape(text)
    text = urllib.parse.unquote(text)
    
    return text

def fix_mislabeled_safe(text):
    """Identify safe text that was mislabeled as XSS"""
    text_str = str(text)
    safe_patterns = [
        # Names with dashes (Carpenter-Weaver, Johnson-Peters)
        r'^[A-Z][a-z]+-[A-Z][a-z]+$',
        # Dates (2002-03-07)
        r'^\d{4}-\d{2}-\d{2}$',
        # Normal English text with dashes
        r'^[A-Za-z]+-[a-z]+\s+[a-z]+\s+[a-z]+',
        # Multiple words with normal structure
        r'^[A-Za-z\s\-]+$',
    ]
    
    for pattern in safe_patterns:
        if re.match(pattern, text_str):
            return True
    
    # Additional safe keywords
    safe_keywords = ['oriented', 'explicit', 'matrix', 'emulation', 'carpenter', 
                    'weaver', 'johnson', 'peters', 'vision', 'cross-group']
    if any(keyword in text_str.lower() for keyword in safe_keywords):
        return True
        
    return False