from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import json
import time
import os
import sys
from datetime import datetime
from prediction_service import (
    app as prediction_app,
    load_models,
    predict,
    extract_features_with_trust_status as extract_features,
    get_scaler,
    model,
    scaler,
    feature_list
)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Root endpoint
@app.route('/')
def index():
    return jsonify({
        'status': 'running',
        'endpoints': {
            'health': '/api/health (GET)',
            'scan': '/api/scan (POST)',
            'history': '/api/history (GET)'
        },
        'websocket': 'Use SocketIO client to connect'
    })

# Initialize SocketIO 
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True
)


scan_history = []


print("Initializing application...")

def initialize_models():
    """Initialize all ML models and return status"""
    global model, scaler, feature_list
    print("\n=== Initializing ML models ===")
    
    
    success = load_models()
    
    if success:
        from prediction_service import model as ml_model, get_scaler, feature_list as fl
        model = ml_model
        scaler = get_scaler()
        feature_list = fl
        print("=== Models initialized successfully ===")
    else:
        print("!!! Failed to initialize models !!!")
    
    return success

if not initialize_models():
    print("Failed to load models. Exiting...")
    sys.exit(1)

print("\n=== Application Initialization Complete ===")
print("Model loaded:", model is not None)
print("Scaler loaded:", scaler is not None)
print("Feature list loaded:", feature_list is not None and len(feature_list) > 0)


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

# Prediction endpoint
@app.route('/api/scan', methods=['POST'])
def scan_url():
    try:
        print("\n=== New Scan Request ===")
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL is required"}), 400
        
        url = data['url'].strip()
        print(f"Scanning URL: {url}")
        
        try:
            # Ensure models are loaded and get the scaler
            print("Loading models and scaler...")
            current_scaler = get_scaler()
            if current_scaler is None:
                raise ValueError("Failed to load scaler")
                    
            
            global model
            if model is None:
                print("Model is None, attempting to reinitialize models...")
                if not initialize_models():
                    raise ValueError("Failed to load model")
            
            if model is None:
                print("CRITICAL: Model is still None after reinitialization")
                raise ValueError("Failed to initialize ML model")
            
            # Extract features - returns (features_df, is_trusted)
            print("Extracting features...")
            features_result = extract_features(url)
            if not isinstance(features_result, tuple) or len(features_result) != 2:
                raise ValueError("Unexpected return type from extract_features")
                
            features_df, is_trusted = features_result
            print(f"Extracted features: {features_df}")
            
            # Scale features using the scaler
            print("Scaling features...")
            try:
                # Convert features to DataFrame if it's a numpy array
                if hasattr(features_df, 'to_dict'):
                    print(f"Features as dict: {features_df.to_dict()}")
                features_scaled = current_scaler.transform(features_df)
                print("Features scaled successfully")
            except Exception as e:
                error_msg = f"Error scaling features: {str(e)}"
                print(error_msg)
                return jsonify({"error": error_msg}), 500
            
            # Make prediction
            print("Making prediction...")
            prediction = model.predict(features_scaled)
            confidence = float(prediction[0][0])
            is_phishing = confidence > 0.5
            
            print(f"Prediction complete - Phishing: {is_phishing}, Confidence: {confidence:.2f}")
            
        except Exception as e:
            error_msg = f"Error during processing: {str(e)}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            return jsonify({"error": error_msg}), 500
        
        # Add to history
        scan_entry = {
            "url": url,
            "is_phishing": is_phishing,
            "timestamp": datetime.now().isoformat(),
            "confidence": confidence
        }
        scan_history.append(scan_entry)
        
        # Emit real-time update
        socketio.emit('scan_update', {
            'total_scans': len(scan_history),
            'phishing_count': len([s for s in scan_history if s['is_phishing']]),
            'recent_scans': scan_history[-5:][::-1]  # Last 5 scans, most recent first
        })
        
        return jsonify(scan_entry)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get scan history
@app.route('/api/history', methods=['GET'])
def get_history():
    return jsonify({
        'total_scans': len(scan_history),
        'phishing_count': len([s for s in scan_history if s['is_phishing']]),
        'safe_count': len([s for s in scan_history if not s['is_phishing']]),
        'scans': scan_history[::-1]  # Most recent first
    })

# WebSocket connection handler
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('scan_update', {
        'total_scans': len(scan_history),
        'phishing_count': len([s for s in scan_history if s['is_phishing']]),
        'recent_scans': scan_history[-5:][::-1]
    })

if __name__ == '__main__':
    
    if not load_models():
        print("Failed to load models. Exiting...")
        exit(1)
    
    print("\n=== Starting server ===")
    print(" * Web server running at http://localhost:5000")
    print(" * WebSocket available at ws://localhost:5000")
    print(" * API documentation available at http://localhost:5000")
    print(" * Press Ctrl+C to stop\n")
    
    # Start the server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
