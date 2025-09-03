from flask import Flask, request, jsonify, abort
from agents.content_scanner.encryption import decrypt_message
import json

app = Flask(__name__)

API_KEY = "your-secure-api-key"

@app.route('/risk_detect', methods=['POST'])
def risk_detect():
    auth_header = request.headers.get('Authorization')
    if auth_header != f"Bearer {API_KEY}":
        abort(401, "Unauthorized: Invalid API Key")

    try:
        encrypted_data = request.data
        decrypted_json_str = decrypt_message(encrypted_data)
        data = json.loads(decrypted_json_str)
    except Exception as e:
        print(f"Failed to decrypt or parse  {e}")
        abort(400, "Invalid encrypted payload")

    print("Risk Detector received decrypted ", data)
    risk_score = 0.8 if data.get("is_suspicious") else 0.1
    return jsonify({"risk_score": risk_score, "message": "Risk analyzed successfully"}), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8001)
