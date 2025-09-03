pii_patterns = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(?:\+?(\d{1,3}))?[-.\s]?(\d{3})[-.\s]?(\d{3,4})[-.\s]?(\d{4})\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
}
