from flask import Flask, request, jsonify
import numpy as np
import joblib
from tensorflow.keras.models import load_model

# -----------------------------------
# Initialize Flask app
# -----------------------------------
app = Flask(__name__)

# -----------------------------------
# Load model and scaler ONCE
# -----------------------------------
model = load_model("vaultid_login_lstm.keras")
scaler = joblib.load("login_scaler.pkl")

SEQUENCE_LENGTH = 5
FEATURES = 4

# -----------------------------------
# Prediction API
# -----------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()

        # 1️⃣ Extract sequence from JSON
        sequence = data.get("sequence")

        if sequence is None:
            return jsonify({"error": "Sequence not provided"}), 400

        # 2️⃣ Convert to NumPy array
        sequence_np = np.array(sequence)

        # Expected shape: (5, 4)
        if sequence_np.shape != (SEQUENCE_LENGTH, FEATURES):
            return jsonify({
                "error": "Invalid sequence shape",
                "expected": [SEQUENCE_LENGTH, FEATURES],
                "received": list(sequence_np.shape)
            }), 400

        # 3️⃣ Scale using training scaler
        sequence_scaled = scaler.transform(sequence_np)

        # 4️⃣ Reshape for LSTM → (1, timesteps, features)
        sequence_scaled = sequence_scaled.reshape(1, SEQUENCE_LENGTH, FEATURES)

        # 5️⃣ Predict anomaly score
        prediction = model.predict(sequence_scaled)
        anomaly_score = float(prediction[0][0])

        # 6️⃣ Return result
        return jsonify({
            "anomaly_score": anomaly_score,
            "is_anomaly": anomaly_score > 0.5
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------------
# Start Flask server
# -----------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
