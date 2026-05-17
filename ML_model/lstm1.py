import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
import joblib

# ======================================
# 1. Generate synthetic login behavior
# ======================================

def generate_login_data(samples=3000):
    data = []
    labels = []

    for _ in range(samples):

        # 80% Normal behavior
        if np.random.rand() > 0.2:
            time_gap = np.random.randint(30, 600)
            ip_change = 0
            device_change = 0
            location_change = 0
            label = 0

        # 20% Anomalous behavior
        else:
            time_gap = np.random.randint(1, 20)
            ip_change = np.random.choice([0, 1])
            device_change = np.random.choice([0, 1])
            location_change = np.random.choice([0, 1])
            label = 1

        data.append([
            time_gap,
            ip_change,
            device_change,
            location_change
        ])

        labels.append(label)

    df = pd.DataFrame(data, columns=[
        "timeGap",
        "ipChange",
        "deviceChange",
        "locationChange"
    ])

    df["label"] = labels
    return df


df = generate_login_data()
print(df.head())

# ======================================
# 2. Preprocessing
# ======================================

X = df[["timeGap", "ipChange", "deviceChange", "locationChange"]].values
y = df["label"].values

scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# LSTM expects 3D input
# (samples, timesteps, features)
X_scaled = X_scaled.reshape(X_scaled.shape[0], 1, 4)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

# ======================================
# 3. Build LSTM Model
# ======================================

model = Sequential([
    LSTM(32, return_sequences=True, input_shape=(1, 4)),
    Dropout(0.2),
    LSTM(16),
    Dropout(0.2),
    Dense(1, activation="sigmoid")
])

model.compile(
    optimizer="adam",
    loss="binary_crossentropy",
    metrics=["accuracy"]
)

model.summary()

# ======================================
# 4. Train
# ======================================

early_stop = EarlyStopping(
    monitor="val_loss",
    patience=3,
    restore_best_weights=True
)

model.fit(
    X_train,
    y_train,
    epochs=20,
    batch_size=32,
    validation_split=0.2,
    callbacks=[early_stop]
)

# ======================================
# 5. Evaluate
# ======================================

loss, accuracy = model.evaluate(X_test, y_test)
print(f"Accuracy: {accuracy * 100:.2f}%")

# ======================================
# 6. Save model and scaler
# ======================================

model.save("vaultid_login_lstm.keras")
joblib.dump(scaler, "login_scaler.pkl")

print("Model and scaler saved successfully.")
