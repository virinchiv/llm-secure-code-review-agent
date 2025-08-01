import ast
import sys
import os

# Add the project root to Python path so we can import from backend
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from backend.utils.security_rules import detect_sql_injection, detect_hardcoded_secrets, detect_dangerous_calls, detect_xss, detect_insecure_randomness, detect_insecure_deserialization

def test_sql_injection_detection():
    """Test that SQL injection detection works correctly"""
    code = '''
user_input = input("Enter ID:")
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)
'''
    tree = ast.parse(code)
    # Check if SQL injection is detected
    detected = False
    for node in ast.walk(tree):
        if detect_sql_injection(node):
            detected = True
            break
    
    assert detected, "SQL injection should be detected in this code"

def test_hardcoded_secrets_detection():
    """Test that hardcoded secrets detection works correctly"""
    code = '''
password = "123456"
api_key = "sk-1234567890abcdef"
secret = "AKIAIOSFODNN7EXAMPLE"
'''
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if detect_hardcoded_secrets(node):
            print("Hardcoded secret detected.")

def test_dangerous_calls_detection():
    """Test that dangerous calls detection works correctly"""
    code = '''
import os
cmd = input("Enter: ")
os.system("ls "+cmd)
'''
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if detect_dangerous_calls(node):
            print("Command injection risk found.")

def test_xss_detection():
    code = '''
from flask import request, render_template_string
@app.route("/")
def home():
    user_input = request.args.get("q")
    return render_template_string("<p>" + user_input + "</p>")
'''
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if detect_xss(node):
            print("Potential XSS vulnerability detected.")

def test_insecure_randomness_detection():
    code = '''
import random

def generate_otp():
    otp = str(random.randint(100000, 999999))
    return otp
'''
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if detect_insecure_randomness(node):
            print("Insecure randomness detected.")

def test_insecure_deserialization():
    code = '''
import pickle

def deserialize(data):
    return pickle.loads(data)  #
'''
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if detect_insecure_deserialization(node):
            print("Insecure deserialization detected.")


if __name__ == "__main__":
    test_sql_injection_detection()
    print("Test passed: SQL injection detection working correctly!")
    test_hardcoded_secrets_detection()
    test_dangerous_calls_detection()
    test_xss_detection()
    test_insecure_randomness_detection()
    test_insecure_deserialization()
    

