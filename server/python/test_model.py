import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from keras.models import Sequential
from keras.layers import Dense
import json
import joblib
import os

# Ensure model directory exists
os.makedirs("server/python/model", exist_ok=True)

# Load dataset
df = pd.read_csv("server/python/data/url_dataset.csv")

# Ensure 'label' column exists
if 'label' not in df.columns:
    raise ValueError("'label' column not found in the dataset.")

# Separate features and labels
X = df.drop("label", axis=1)
y = df["label"]

# Scale features
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Build the model
model = Sequential()
model.add(Dense(32, input_dim=X.shape[1], activation='relu'))
model.add(Dense(16, activation='relu'))
model.add(Dense(1, activation='sigmoid'))

# Compile and train
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
model.fit(X_train, y_train, epochs=20, batch_size=16, validation_data=(X_test, y_test))

# Save model
model.save("server/python/model/phishing_model.h5")

# Save feature list
features = list(X.columns)
with open("server/python/model/feature_list.json", "w") as f:
    json.dump(features, f)

# Save scaler
joblib.dump(scaler, "server/python/model/scaler.pkl")

print("✅ Model, scaler, and feature list saved successfully.")
