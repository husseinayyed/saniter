import pytest
import numpy as np
from saniter.model import check  # Your XSS detection function

class TestFormInputXSS:
    
    # SAFE NORMAL INPUTS (should return 0)
    def test_safe_emails(self):
        """Test normal email addresses"""
        safe_emails = [
            "user@example.com",
            "test.email+tag@domain.co.uk", 
            "first.last@company.org",
            "email@subdomain.example.com",
            "1234567890@example.com",
            "email@example-one.com",
            "_______@example.com",
            "email@example.name",
            "email@example.museum",
            "email@example.co.jp"
        ]
        for email in safe_emails:
            assert check(email) == 0, f"False positive on safe email: {email}"
    
    def test_safe_passwords(self):
        """Test normal password inputs"""
        safe_passwords = [
            "mypassword123",
            "SecurePass!2024",
            "normal_password",
            "P@ssw0rd",
            "correct horse battery staple",
            "Tr0ub4dor&3",
            "normal_text_123",
            "Summer2024!",
            "MyP@ssw0rd123",
            "simple_password"
        ]
        for pwd in safe_passwords:
            assert check(pwd) == 0, f"False positive on safe password: {pwd}"
    
    def test_safe_names_and_text(self):
        """Test normal names and text inputs"""
        safe_inputs = [
            "John Doe",
            "Maria Garcia",
            "Zhang Wei",
            "Hello world",
            "123 Main Street",
            "+1-555-0123",
            "Paris, France",
            "Software Engineer",
            "Product Manager",
            "California, USA"
        ]
        for text in safe_inputs:
            assert check(text) == 0, f"False positive on safe text: {text}"
    
    def test_safe_special_chars(self):
        """Test special characters that are safe in inputs"""
        safe_special = [
            "user.name@domain.com",
            "test+filter@domain.com",
            "first-last@company.com",
            "email@domain.co.uk",
            "name_with_underscores",
            "text-with-dashes",
            "numbers123",
            "mixed_Case123",
            "normal.text.here",
            "address+tag@email.com"
        ]
        for text in safe_special:
            assert check(text) == 0, f"False positive on safe special chars: {text}"
    
    def test_empty_and_whitespace(self):
        """Test empty and whitespace inputs"""
        assert check("") == 0
        assert check("   ") == 0
        assert check("\t") == 0
        assert check("\n") == 0
    
    # MALICIOUS INPUTS (should return 1)
    def test_xss_in_emails(self):
        """Test emails containing XSS payloads"""
        malicious_emails = [
            "user<script>alert(1)</script>@example.com",
            "test@<svg onload=alert(1)>.com",
            "x@x.com<img src=x onerror=alert(1)>",
            "test@example.com' onmouseover='alert(1)",
            "user@<iframe src=javascript:alert(1)>.com",
            "test@example.com\"><script>alert(1)</script>",
            "x@x.com\"><img src=x onerror=alert(1)>",
            "test@example.com';alert(1)//",
            "user@<math><brute href=javascript:alert(1)>.com",
            "test@example.com`-alert(1)-`"
        ]
        for email in malicious_emails:
            assert check(email) == 1, f"False negative on malicious email: {email}"
    
    def test_xss_in_passwords(self):
        """Test passwords containing XSS payloads"""
        malicious_passwords = [
            "password<script>alert(1)</script>",
            "pass<svg onload=alert(1)>",
            "pwd<img src=x onerror=alert(1)>",
            "pass' onfocus='alert(1)'",
            "pwd\"><script>alert(1)</script>",
            "password<iframe src=javascript:alert(1)>",
            "pass<math><brute href=javascript:alert(1)>",
            "pwd';alert(1)//",
            "password`-alert(1)-`",
            "pass<object data=javascript:alert(1)>"
        ]
        for pwd in malicious_passwords:
            assert check(pwd) == 1, f"False negative on malicious password: {pwd}"
    
    def test_xss_in_names(self):
        """Test names containing XSS payloads"""
        malicious_names = [
            "John<script>alert(1)</script>Doe",
            "Maria<svg onload=alert(1)>Garcia",
            "Zhang<img src=x onerror=alert(1)>Wei",
            "Name' onmouseover='alert(1)'",
            "User\"><script>alert(1)</script>",
            "Test<iframe src=javascript:alert(1)>Name",
            "X<math><brute href=javascript:alert(1)>Y",
            "Name';alert(1)//",
            "User`-alert(1)-`",
            "Test<embed src=javascript:alert(1)>Name"
        ]
        for name in malicious_names:
            assert check(name) == 1, f"False negative on malicious name: {name}"
    
    def test_obfuscated_xss(self):
        """Test obfuscated XSS payloads"""
        obfuscated_payloads = [
            "user@ex\\u0061mple.com",  # Unicode escape (escaped backslash so runtime sees \u...)
            "test@<sv\\u0067 onload=alert(1)>.com",
            "x@x.com<im\\u0067 src=x onerror=alert(1)>",
            "password<scri\\u0070t>alert(1)</script>",
            "name<\\u0073vg onload=alert(1)>",
            "test@example.com%22%3E%3Cscript%3Ealert(1)%3C/script%3E",  # URL encoded
            "user@<IFRAME SRC=javascript:alert(1)>.com",  # Mixed case
            "test@example.com';a=alert,a(1)//",  # Function obfuscation
            "x@x.com`-prompt(1)-`",
            "password'-eval(\"window['pro'%2B'mpt'](1)\")-'"
        ]
        for payload in obfuscated_payloads:
            assert check(payload) == 1, f"False negative on obfuscated payload: {payload}"
    
    def test_event_handlers_in_inputs(self):
        """Test various event handlers in form inputs"""
        event_handler_payloads = [
            "test@example.com' onclick='alert(1)",
            "password' onfocus='alert(1)'",
            "name' onmouseover='alert(1)'",
            "input' onload='alert(1)'",
            "text' onerror='alert(1)'",
            "email' onsubmit='alert(1)'",
            "user' onchange='alert(1)'",
            "pass' onkeypress='alert(1)'",
            "field' onblur='alert(1)'",
            "data' ondblclick='alert(1)'"
        ]
        for payload in event_handler_payloads:
            assert check(payload) == 1, f"False negative on event handler: {payload}"
    
    def test_edge_cases_form_inputs(self):
        """Test edge cases specific to form inputs"""
        edge_cases = [
            # Very long but safe
            "a" * 1000,
            "user@example.com" + "a" * 500,
            
            # SQL injection attempts (should not trigger XSS detection)
            "user@example.com' OR '1'='1",
            "test@domain.com'; DROP TABLE users;--",
            "admin'--",
            "x' UNION SELECT * FROM passwords--",
            
            # Mixed safe and malicious
            "normal@email.com<script>alert(1)</script>",
            "safe_password' onfocus='alert(1)'rest",
            "John<script>alert(1)</script>Doe@company.com"
        ]
        
        for i, case in enumerate(edge_cases):
            if i < 2:  # First two are safe
                assert check(case) == 0, f"False positive on long safe input: {case}"
            elif i >= 2 and i < 6:  # SQL injection - depends on your model scope
                # These might be 0 or 1 based on your training
                pass  
            else:  # Mixed cases should be detected
                assert check(case) == 1, f"False negative on mixed input: {case}"

class TestFormInputPerformance:
    """Performance tests for form input detection"""
    
    def test_detection_speed(self):
        """Test that detection is fast enough for form validation"""
        import time
        
        test_inputs = [
            "normal@email.com",
            "password123",
            "John Doe",
            "user<script>alert(1)</script>@example.com",
            "pass<svg onload=alert(1)>"
        ]
        
        max_time = 0.1  # 100ms max per prediction
        for inp in test_inputs:
            start_time = time.time()
            result = check(inp)
            end_time = time.time()
            duration = end_time - start_time
            assert duration < max_time, f"Detection too slow: {duration}s for input: {inp}"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])