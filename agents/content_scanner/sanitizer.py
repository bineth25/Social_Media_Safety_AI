import re

def sanitize_text(text):
    """
    Remove or escape potentially dangerous characters.
    - Removes script tags and HTML tags
    - Escapes quotes and backslashes
    """
    # Remove script tags and content inside
    text = re.sub(r'<script.*?>.*?</script>', '', text, flags=re.I|re.S)
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Escape quotes and backslashes
    text = text.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
    # Optional: Strip leading/trailing whitespace
    return text.strip()
