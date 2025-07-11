import os
import re
import json
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from keras.models import Sequential, load_model
from keras.layers import Dense, Dropout, BatchNormalization
from keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
from keras.regularizers import l2

# Set random seed for reproducibility
np.random.seed(42)

def load_dataset(filepath):
    """Load and preprocess the dataset"""
    print("📊 Loading dataset...")
    df = pd.read_csv(filepath)
    
    # Basic data validation
    if 'phishing' not in df.columns:
        raise ValueError("Dataset must contain 'phishing' column as target variable")
    
    print(f"✅ Loaded {len(df)} samples")
    print(f"📊 Class distribution:\n{df['phishing'].value_counts()}")
    
    return df

def extract_features_from_url(url):
    """
    This function is kept for backward compatibility but not used directly
    since we're using pre-extracted features.
    """
    raise NotImplementedError("This function is not used with pre-extracted features")

def prepare_data(df):
    """Prepare the dataset for training"""
    print("🔧 Preparing data...")
    
    # Separate features and target
    feature_columns = [col for col in df.columns if col != 'phishing']
    X = df[feature_columns]
    y = df['phishing']
    
    # Handle any missing values
    X = X.fillna(0)
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale the features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"✅ Training set: {X_train_scaled.shape[0]} samples")
    print(f"✅ Test set: {X_test_scaled.shape[0]} samples")
    print(f"✅ Number of features: {X_train.shape[1]}")
    
    return X_train_scaled, X_test_scaled, y_train, y_test, X.columns, scaler

def build_model(input_dim):
    """Build and compile the neural network model"""
    print("🧠 Building model...")
    
    model = Sequential([
        # Input layer
        Dense(128, input_dim=input_dim, activation='relu', kernel_regularizer=l2(0.01)),
        BatchNormalization(),
        Dropout(0.5),
        
        # Hidden layers
        Dense(64, activation='relu', kernel_regularizer=l2(0.01)),
        BatchNormalization(),
        Dropout(0.4),
        
        Dense(32, activation='relu', kernel_regularizer=l2(0.01)),
        Dropout(0.3),
        
        # Output layer
        Dense(1, activation='sigmoid')
    ])
    
    # Compile the model
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy', 'AUC', 'Precision', 'Recall']
    )
    
    return model

def train_model(X_train, y_train, X_test, y_test, epochs=30, batch_size=32):
    """Train the model with callbacks"""
    model = build_model(X_train.shape[1])
    
    # Define callbacks
    callbacks = [
        EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
        ReduceLROnPlateau(monitor='val_loss', factor=0.2, patience=3, min_lr=1e-6),
        ModelCheckpoint(
            'best_model.h5',
            monitor='val_accuracy',
            save_best_only=True,
            mode='max',
            verbose=1
        )
    ]
    
    # Train the model
    print("🚀 Training model...")
    history = model.fit(
        X_train, y_train,
        validation_data=(X_test, y_test),
        epochs=epochs,
        batch_size=batch_size,
        callbacks=callbacks,
        verbose=1
    )
    
    return model, history

def evaluate_model(model, X_test, y_test):
    """Evaluate the model and print metrics"""
    print("📊 Evaluating model...")
    
    # Make predictions
    y_pred = (model.predict(X_test) > 0.5).astype('int32')
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred)
    class_report = classification_report(y_test, y_pred)
    
    print(f"\n📈 Accuracy: {accuracy:.4f}")
    print("\n📊 Confusion Matrix:")
    print(conf_matrix)
    print("\n📋 Classification Report:")
    print(class_report)
    
    return accuracy, conf_matrix, class_report

def save_model_artifacts(model, scaler, features, model_dir='model'):
    """Save the trained model and artifacts"""
    print("💾 Saving model artifacts...")
    
    # Create directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)
    
    # Save the model
    model_path = os.path.join(model_dir, 'phishing_model.h5')
    model.save(model_path)
    
    # Save the scaler
    scaler_path = os.path.join(model_dir, 'scaler.pkl')
    joblib.dump(scaler, scaler_path)
    
    # Save the feature list
    features_path = os.path.join(model_dir, 'feature_list.json')
    with open(features_path, 'w') as f:
        json.dump(features.tolist(), f)
    
    print(f"✅ Model saved to {model_path}")
    print(f"✅ Scaler saved to {scaler_path}")
    print(f"✅ Features list saved to {features_path}")

def main():
    # Path to your dataset
    dataset_path = "E:/CyberPbl/server/python/data/url_dataset.csv"
    
    try:
        # Load and prepare data
        df = load_dataset(dataset_path)
        X_train, X_test, y_train, y_test, features, scaler = prepare_data(df)
        
        # Train the model
        model, history = train_model(X_train, y_train, X_test, y_test)
        
        # Evaluate the model
        evaluate_model(model, X_test, y_test)
        
        # Save the model and artifacts
        save_model_artifacts(model, scaler, features, model_dir='server/python/model')
        
        print("\n✨ Model training completed successfully!")
        
    except Exception as e:
        print(f"❌ An error occurred: {str(e)}")
        raise

if __name__ == "__main__":
    main()
