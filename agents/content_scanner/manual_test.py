import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from agents.content_scanner.scanner import ContentScanner

def manual_test():
    scanner = ContentScanner()
    test_texts = [
        "Call me at +123456789",
        "No privacy data here",
        "Send email to user@example.com"
    ]
    for text in test_texts:
        result = scanner.analyze_content(text)
        print(f"Input: {text}\nOutput: {result}\n")

if __name__ == "__main__":
    manual_test()
