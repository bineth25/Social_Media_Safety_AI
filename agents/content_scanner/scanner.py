import re
from agents.content_scanner.pii_regex import pii_patterns
from agents.content_scanner.sanitizer import sanitize_text
import spacy
import openai
import requests
from agents.content_scanner.encryption import encrypt_message
import json

API_KEY = "your-secure-api-key"  # Define your API key here

class ContentScanner:
    def __init__(self, openai_api_key=None):
        self.patterns = pii_patterns
        self.nlp = spacy.load("en_core_web_sm")
        if openai_api_key:
            openai.api_key = openai_api_key

    def detect_pii(self, text):
        results = {}
        for key, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                results[key] = matches
        return results

    def detect_entities(self, text):
        doc = self.nlp(text)
        entities = []
        for ent in doc.ents:
            if ent.label_ in ("PERSON", "ORG", "GPE", "LOC", "DATE", "MONEY", "EMAIL"):
                entities.append({"text": ent.text, "label": ent.label_})
        return entities

    def llm_classify(self, text):
        if not openai.api_key:
            return False
        prompt = (f"Analyze the following text and determine if it contains harmful or sensitive content. "
                  f"Respond with YES or NO:\n\n{text}")
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=10,
                temperature=0
            )
            answer = response.choices[0].message['content'].strip().lower()
            return answer == "yes"
        except Exception as e:
            print(f"LLM classification error: {e}")
            return False

    def send_to_risk_detector(self, analysis_result):
        url = "http://localhost:8001/risk_detect"
        headers = {"Authorization": f"Bearer {API_KEY}"}
        try:
            json_payload = json.dumps(analysis_result)
            encrypted_payload = encrypt_message(json_payload)
            response = requests.post(url, data=encrypted_payload, headers=headers, timeout=5)
            response.raise_for_status()
            print("Sent encrypted data to Risk Detector:", response.json())
            return response.json()
        except requests.RequestException as e:
            print(f"Error sending encrypted data to Risk Detector: {e}")
            return None

    def analyze_content(self, text):
        clean_text = sanitize_text(text)
        pii_results = self.detect_pii(clean_text)
        entities = self.detect_entities(clean_text)
        llm_flag = self.llm_classify(clean_text)
        pii_keys = set(pii_results.keys())
        ner_labels = set(ent["label"].lower() for ent in entities)
        combined_detected = pii_keys.union(ner_labels)
        suspicious = bool(combined_detected) or llm_flag
        return {
            "pii_detected": list(combined_detected),
            "entities": entities,
            "llm_flagged": llm_flag,
            "is_suspicious": suspicious
        }

    def analyze_and_notify(self, text):
        result = self.analyze_content(text)
        if result["is_suspicious"]:
            self.send_to_risk_detector(result)
        return result


if __name__ == "__main__":
    scanner = ContentScanner()
    sample_text = "Contact me at example@example.com or +1 123 456 7890. John Doe works at OpenAI in San Francisco."
    analysis = scanner.analyze_and_notify(sample_text)
    print("Scan Results:", analysis)
