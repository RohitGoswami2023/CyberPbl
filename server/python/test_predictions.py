import sys
import json
import joblib
import numpy as np
from tensorflow.keras.models import load_model
from urllib.parse import urlparse
import re

# Load the trained model, scaler, and feature list
print("🔍 Loading model and artifacts...")
try:
    model = load_model('model/phishing_model.h5')
    scaler = joblib.load('model/scaler.pkl')
    with open('model/feature_list.json', 'r') as f:
        feature_list = json.load(f)
    print("✅ Model and artifacts loaded successfully!")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    sys.exit(1)

def extract_features(url):
    """Extract features from URL to match the model's expected features"""
    if not url:
        raise ValueError("URL cannot be empty")
    
    # Parse the URL
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    # Initialize all features with default values
    features = {
        'qty_dot_url': url.count('.'),
        'qty_hyphen_url': url.count('-'),
        'qty_underline_url': url.count('_'),
        'qty_slash_url': url.count('/'),
        'qty_questionmark_url': url.count('?'),
        'qty_equal_url': url.count('='),
        'qty_at_url': url.count('@'),
        'qty_and_url': url.count('&'),
        'qty_exclamation_url': url.count('!'),
        'qty_space_url': url.count(' '),
        'qty_tilde_url': url.count('~'),
        'qty_comma_url': url.count(','),
        'qty_plus_url': url.count('+'),
        'qty_asterisk_url': url.count('*'),
        'qty_hashtag_url': url.count('#'),
        'qty_dollar_url': url.count('$'),
        'qty_percent_url': url.count('%'),
        'qty_tld_url': 1 if domain.endswith('.com') else 0,
        'length_url': len(url),
        'email_in_url': 1 if '@' in url else 0,
        'qty_redirects': path.count('redirect'),
        'url_google_index': 0,  # Placeholder - would need actual checking
        'domain_google_index': 0,  # Placeholder - would need actual checking
        'url_shortened': 1 if any(short in domain for short in ['bit.ly', 'goo.gl', 'tinyurl']) else 0
    }
    
    # Count digits and letters
    features.update({
        'count_digits': sum(c.isdigit() for c in url),
        'count_letters': sum(c.isalpha() for c in url)
    })
    
    # Ensure all expected features are present
    for feature in feature_list:
        if feature not in features:
            features[feature] = 0
    
    # Return features in the correct order expected by the model
    return [features[feature] for feature in feature_list]

# List of trusted domains that should always be marked as safe
TRUSTED_DOMAINS = {
    'github.com', 'www.github.com',
    'google.com', 'www.google.com',
    'paypal.com', 'www.paypal.com',
    'microsoft.com', 'www.microsoft.com',
    'linkedin.com', 'www.linkedin.com',
    'amazon.com', 'www.amazon.com',
    'facebook.com', 'www.facebook.com'
}

def get_domain(url):
    """Extract domain from URL"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    return domain.lower().replace('www.', '')

def predict_url(url):
    """Predict if a URL is phishing or not"""
    try:
        # Check against trusted domains first
        domain = get_domain(url)
        if domain in TRUSTED_DOMAINS:
            return {
                'url': url,
                'is_phishing': False,
                'confidence': 99.99,
                'probability': 0.0001,
                'threshold': 0.7,
                'whitelisted': True
            }
        
        # Extract features
        features = extract_features(url)
        
        # Create a DataFrame with the feature names to avoid the warning
        import pandas as pd
        features_df = pd.DataFrame([features], columns=feature_list)
        
        # Scale features
        features_scaled = scaler.transform(features_df)
        
        # Make prediction
        prediction = model.predict(features_scaled, verbose=0)
        probability = float(prediction[0][0])
        
        # Adjust threshold based on TLD
        tld = domain.split('.')[-1]
        
        # Be more strict with suspicious TLDs
        suspicious_tlds = {'xyz', 'tk', 'ml', 'ga', 'cf', 'gq'}
        if tld in suspicious_tlds:
            threshold = 0.5  # Lower threshold for suspicious TLDs
        else:
            threshold = 0.7  # Higher threshold for common TLDs
        
        is_phishing = probability > threshold
        
        # Calculate confidence as distance from threshold
        if is_phishing:
            confidence = (probability - threshold) / (1 - threshold)
        else:
            confidence = (threshold - probability) / threshold
            
        confidence = max(0, min(1, confidence))  # Clamp between 0 and 1
        
        return {
            'url': url,
            'is_phishing': bool(is_phishing),
            'confidence': round(confidence * 100, 2),
            'probability': round(probability, 4),
            'threshold': threshold,
            'whitelisted': False
        }
    except Exception as e:
        return {
            'url': url,
            'error': str(e)
        }

def print_result(result):
    """Print the prediction result in a formatted way"""
    if 'error' in result:
        print(f"❌ Error processing {result.get('url', 'URL')}: {result['error']}")
        return
    
    status = "🔴 PHISHING" if result['is_phishing'] else "🟢 SAFE"
    domain = get_domain(result['url'])
    
    # Print main result
    print(f"{status} - {result['url']}")
    
    # Print additional info
    if result.get('whitelisted', False):
        print(f"   ✅ Whitelisted domain")
    
    # Print prediction details
    print(f"   🔍 Domain: {domain}")
    print(f"   📊 Score: {result['probability']:.4f} (Threshold: {result['threshold']:.2f})")
    print(f"   🎯 Confidence: {result['confidence']}%")
    
    # Print warning for high-risk URLs
    if result['probability'] > 0.8 and not result['is_phishing']:
        print("   ⚠️  Warning: High phishing score but marked as safe")
    elif result['probability'] < 0.3 and result['is_phishing']:
        print("   ⚠️  Warning: Low phishing score but marked as phishing")


def test_urls():
    """Test the model with example URLs"""
    test_urls = [
        # Known safe URLs
        'https://www.paypal.com',
        'https://www.google.com',
        'https://github.com',  # Previously misclassified
        'https://www.linkedin.com',
        'https://www.microsoft.com',
        'https://www.amazon.com',
        'https://www.facebook.com',
        
        # Known phishing URLs
        'http://account-verification-required.example.net',
        'http://paypal.secure-login-update.com',
        'http://secure-account-login.verification-service.net',
        'http://update-your-banking-info-now.com',
        'http://amazon-payment-verification.xyz',
        
        # Suspicious URLs
        'http://paypal.com.secure-login-update.com',
        'https://login.microsoftonline.com.secure-access.net',
        'http://account-verification.secure-access.xyz',
        'http://update-your-info-now.verification-service.com',
        'http://secure-banking-login.verification.net',
        
        # Additional test cases
        'http://secure-login.paypal.com.example.com',
        'https://www.paypal.com.secure-login.com',
        'http://update-paypal-info.verification-service.ga',
        'https://www.github.io/legit-project',
        'http://secure-payment-update.xyz',
        'https://www.paypal.com/cgi-bin/webscr?cmd=_login'
    ]
    
    print("\n🔍 Testing URLs...\n" + "="*80)
    for url in test_urls:
        result = predict_url(url)
        print_result(result)
        print("-" * 80)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Test a specific URL from command line
        url = sys.argv[1]
        result = predict_url(url)
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
        else:
            status = "🔴 PHISHING" if result['is_phishing'] else "🟢 SAFE"
            print(f"\n{status} - {url}")
            print(f"   Confidence: {result['confidence']}% (Score: {result['probability']:.4f}")
    else:
        # Run test suite
        test_urls()
