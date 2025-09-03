import requests

def send_to_risk_detector(analysis_result):
    url = "http://localhost:8001/risk_detect"  # Risk Detector API endpoint
    try:
        response = requests.post(url, json=analysis_result, timeout=5)
        response.raise_for_status()
        print("Successfully sent data to Risk Detector:", response.json())
        return response.json()
    except requests.RequestException as e:
        print("Failed to send data to Risk Detector:", e)
        return None
