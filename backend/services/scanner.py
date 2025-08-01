import ast
from utils.security_rules import (
    detect_sql_injection,
    detect_xss,
    detect_hardcoded_secrets,
    detect_dangerous_calls,
    detect_insecure_randomness,
    detect_insecure_deserialization,
)

def scan_for_code_vulnerabilities(code):
    tree = ast.parse(code)
    vulnerabilities = []
    for node in ast.walk(tree):
        if detect_sql_injection(node):
            vulnerabilities.append({
                "type": "SQL Injection",
                "line": getattr(node, 'lineno', -1),
                "code": ast.unparse(node) if hasattr(ast, 'unparse') else "<code unavailable>"
            })
        if detect_xss(node):
            vulnerabilities.append({
                "type": "Cross-Site Scripting (XSS)",
                "line": getattr(node, 'lineno', -1),
                "code": ast.unparse(node)
            })
        if detect_hardcoded_secrets(node):
            vulnerabilities.append({
                "type": "Hardcoded Secret",
                "line": getattr(node, 'lineno', -1),
                "code": ast.unparse(node)
            })
        if detect_dangerous_calls(node):
            vulnerabilities.append({
                "type": "Command Injection",
                "line": getattr(node, 'lineno', -1),
                "code": ast.unparse(node)
            })
        if detect_insecure_randomness(node):
            vulnerabilities.append({
                "type": "Insecure Randomness",
                "line": getattr(node, 'lineno', -1),
                "code": ast.unparse(node)
            })
        if detect_insecure_deserialization(node):
            vulnerabilities.append({
                "type": "Insecure Deserialization",
                "line": getattr(node, 'lineno', -1),
                "code": ast.unparse(node)
            })
    return vulnerabilities
