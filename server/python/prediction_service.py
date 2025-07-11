import os
import sys
import json
import logging
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from keras.models import load_model
import joblib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('prediction_service.log')
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Global variables to store the loaded models
model = None
scaler = None
feature_list = None

# Model paths
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model')
MODEL_PATHS = {
    'model': os.path.join(MODEL_DIR, 'phishing_model.h5'),
    'scaler': os.path.join(MODEL_DIR, 'scaler.pkl'),
    'features': os.path.join(MODEL_DIR, 'feature_list.json')
}

# Ensure the model directory exists
os.makedirs(MODEL_DIR, exist_ok=True)

def load_models():
    """Load ML models and configurations."""
    global model, scaler, feature_list
    
    try:
        print("\n=== Starting model loading process ===")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Model directory: {MODEL_DIR}")
        print(f"Model paths: {MODEL_PATHS}")
        
        # Check if model files exist
        all_files_exist = True
        for name, path in MODEL_PATHS.items():
            exists = os.path.exists(path)
            print(f"Checking {name}: {path} - {'Exists' if exists else 'MISSING'}")
            if not exists:
                print(f"ERROR: Model file not found: {path}")
                all_files_exist = False
        
        if not all_files_exist:
            print("\nERROR: One or more model files are missing")
            return False
            
        print("\nAll required files found. Loading models...")
        
        # Load the model
        print("\n1. Loading Keras model...")
        try:
            model = load_model(MODEL_PATHS['model'])
            print(f"   Model loaded. Type: {type(model)}")
            print(f"   Model summary:")
            model.summary()
        except Exception as e:
            print(f"   ERROR loading model: {str(e)}")
            return False
        
        # Load the scaler
        print("\n2. Loading Scaler...")
        try:
            scaler = joblib.load(MODEL_PATHS['scaler'])
            print(f"   Scaler loaded. Type: {type(scaler)}")
            print(f"   Scaler params: {scaler.get_params()}")
        except Exception as e:
            print(f"   ERROR loading scaler: {str(e)}")
            return False
        
        # Load feature list
        print("\n3. Loading feature list...")
        try:
            with open(MODEL_PATHS['features'], "r") as f:
                feature_list = json.load(f)
            print(f"   Features loaded. Number of features: {len(feature_list)}")
            print(f"   Features: {feature_list}")
        except Exception as e:
            print(f"   ERROR loading feature list: {str(e)}")
            return False
        
        # Verify all required objects are loaded
        print("\n=== Model Loading Verification ===")
        model_loaded = model is not None
        scaler_loaded = scaler is not None
        features_loaded = feature_list is not None
        
        print(f"Model loaded: {'Yes' if model_loaded else 'No'}")
        print(f"Scaler loaded: {'Yes' if scaler_loaded else 'No'}")
        print(f"Feature list loaded: {'Yes' if features_loaded else 'No'}")
        
        if not all([model_loaded, scaler_loaded, features_loaded]):
            print("\nERROR: One or more components failed to load")
            return False
            
        print("\n=== All models loaded successfully ===\n")
        return True
        
    except Exception as e:
        print(f"\n!!! ERROR in load_models: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def get_scaler():
    """Get or load the scaler."""
    global scaler
    if scaler is None:
        print("Scaler is None, attempting to load...")
        if not load_models():
            raise ValueError("Failed to load models")
    return scaler

def validate_url(url: str) -> bool:
    """
    Validate the input URL.
    
    Args:
        url (str): The URL to validate
        
    Returns:
        bool: True if URL is valid
        
    Raises:
        ValueError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    
    # Basic URL validation
    if not (url.startswith('http://') or url.startswith('https://')):
        raise ValueError("URL must start with http:// or https://")
    
    # Check for suspicious patterns
    if '..' in url or '//' in url[7:]:
        raise ValueError("URL contains suspicious patterns")
    
    # Check URL length
    if len(url) > 2000:  # Reasonable URL length limit
        raise ValueError("URL is too long")
    
    return True

def extract_features_with_trust_status(url: str) -> tuple[pd.DataFrame, bool]:
    """
    Extract features from URL and return both features and trusted status.
    
    Args:
        url (str): The URL to extract features from
        
    Returns:
        tuple: (DataFrame with features, is_trusted_financial)
    """
    """
    Extract features from URL with enhanced detection.
    
    Args:
        url (str): The URL to extract features from
        
    Returns:
        pd.DataFrame: DataFrame containing the extracted features
        
    Raises:
        ValueError: If URL is invalid or features cannot be extracted
    """
    try:
        import re
        import tldextract
        from urllib.parse import urlparse, parse_qs
        
        # Validate URL first
        validate_url(url)
        
        # Parse URL components
        parsed = urlparse(url)
        domain_info = tldextract.extract(url)
        query_params = parse_qs(parsed.query)
        
        # Known legitimate domains (will be treated more leniently)
        trusted_financial_domains = [
            # Major search engines and tech companies
            'google.com', 'google.co.in', 'google.co.uk', 'google.com.au',
            'bing.com', 'yahoo.com', 'duckduckgo.com',
            'microsoft.com', 'microsoftonline.com', 'office.com', 'live.com', 'outlook.com',
            'apple.com', 'icloud.com', 'me.com',
            'mozilla.org', 'firefox.com', 'github.com', 'gitlab.com',
            
            # Social media
            'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
            'reddit.com', 'pinterest.com', 'tiktok.com', 'whatsapp.com',
            'telegram.org', 'signal.org', 'discord.com', 'slack.com',
            
            # Major tech and cloud providers
            'amazon.com', 'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
            'digitalocean.com', 'heroku.com', 'cloudflare.com', 'fastly.com',
            
            # Common services
            'dropbox.com', 'box.com', 'onedrive.com', 'icloud.com',
            'adobe.com', 'adobelogin.com', 'creativecloud.com',
            'spotify.com', 'netflix.com', 'youtube.com', 'vimeo.com',
            
            
            # Financial institutions
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com',
            'capitalone.com', 'usbank.com', 'pncbank.com', 'tdbank.com',
            'americanexpress.com', 'discover.com', 'synchronybank.com',
            'ally.com', 'usaa.com', 'navyfederal.org', 'schwab.com',
            'fidelity.com', 'vanguard.com', 'morganstanley.com', 'ml.com',
            'bofa.com'  # Bank of America's domain
        ]
        
        # Common phishing terms
        phishing_terms = [
            'login', 'signin', 'account', 'verify', 'banking', 'secure', 
            'update', 'confirm', 'billing', 'payment', 'ebayisapi', 'paypal',
            'webscr', 'login.jsp', 'logon.jsp', 'signin.jsp', 'secure-', 'security',
            'authenticate', 'authentication', 'password', 'credential', 'oauth',
            'verification', 'validate', 'validation', 'account-recovery', 'recover',
            'update-your', 'verify-your', 'confirm-your', 'security-alert', 'urgent',
            'immediate-action', 'suspicious-activity', 'unauthorized-attempt', 'account-locked'
        ]
        
        # Common TLDs that are often used in phishing
        suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.club', '.work', '.site']
        
        # Common URL shorteners
        url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
            'tiny.cc', 'bit.do', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.one'
        ]
        
        # Check if URL is from a trusted financial domain or its subdomains
        netloc = parsed.netloc.lower()
        is_trusted_financial = bool(any(
            netloc == domain or netloc.endswith('.' + domain)
            for domain in trusted_financial_domains
        ))
        
        # Check if URL contains any phishing terms
        url_lower = url.lower()
        has_phishing_terms = any(term in url_lower for term in phishing_terms)
        
        # If it's a trusted financial domain, be more lenient with phishing terms
        if is_trusted_financial:
            # Only flag if there are multiple suspicious terms
            suspicious_term_count = sum(1 for term in phishing_terms if term in url_lower)
            has_phishing_terms = suspicious_term_count > 2
        
        # Check if domain is an IP address
        is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_info.domain))
        
        # Check for @ symbol in URL (potential credential stuffing)
        has_at_symbol = '@' in url
        
        # Check if URL is shortened
        is_shortened = any(shortener in parsed.netloc for shortener in [
            'bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd', 
            'buff.ly', 'adf.ly', 'bitly.com', 'cutt.ly'
        ])
        
        # Check for suspicious TLDs
        suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'icu', 'cyou', 
                         'gdn', 'bid', 'win', 'loan', 'men', 'stream'}
        is_suspicious_tld = domain_info.suffix.lower() in suspicious_tlds
        
        # Count number of subdomains
        num_subdomains = len([x for x in domain_info.subdomain.split('.') if x])
        
        # Enhanced typosquatting detection with improved homoglyph handling
        def is_typosquatting(domain, known_domains):
            """Check if a domain is likely a typosquat of a known domain."""
            try:
                from Levenshtein import distance
                
                # Expanded homoglyphs and their legitimate counterparts
                homoglyphs = {
                    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
                    '6': 'g', '7': 't', '8': 'b', '9': 'g',
                    '!': 'i', '@': 'a', '$': 's',
                    '|': 'i', 'l': '1', '|': '1', '£': 'e',
                    'vv': 'w', 'rn': 'm', 'cj': 'g', 'vv': 'w',
                    'cl': 'd', 'vv': 'w', '\'': '', '`': '',
                }
                
                # Common TLDs to strip for comparison
                tlds = ['.com', '.net', '.org', '.co', '.io', '.ai', '.app', '.uk', '.us', '.ca', '.au']
                
                # Remove TLD and www. for comparison
                domain_base = domain.lower()
                for tld in tlds:
                    if domain_base.endswith(tld):
                        domain_base = domain_base[:-len(tld)]
                        break
                if domain_base.startswith('www.'):
                    domain_base = domain_base[4:]
                    
                for known in known_domains:
                    known_base = known.lower()
                    for tld in tlds:
                        if known_base.endswith(tld):
                            known_base = known_base[:-len(tld)]
                            break
                    if known_base.startswith('www.'):
                        known_base = known_base[4:]
                        
                    # Skip if domains are identical
                    if domain_base == known_base:
                        continue
                        
                    # Check for character substitutions
                    normalized = ''.join(homoglyphs.get(c, c) for c in domain_base)
                    
                    # Check for common typos and homoglyphs
                    if (distance(normalized, known_base) <= 2 and len(normalized) > 3) or \
                       known_base in normalized or \
                       (len(domain_base) > 3 and (known_base in domain_base or domain_base in known_base)):
                        return True
                        
                    # Check for character insertions/deletions (e.g., 'bank0famerica' vs 'bankofamerica')
                    if abs(len(domain_base) - len(known_base)) <= 2:
                        if known_base in domain_base or domain_base in known_base:
                            return True
                            
                    # Check for common typos (e.g., 'linkdin' -> 'linkedin')
                    common_typos = {
                        'linkdin': 'linkedin',
                        'bank0famerica': 'bankofamerica',
                        'micr0soft': 'microsoft',
                        'paypa1': 'paypal',
                        'g00gle': 'google',
                        'faceb00k': 'facebook',
                        'tw1tter': 'twitter',
                        '1nstagram': 'instagram',
                        'y0utube': 'youtube',
                        'amaz0n': 'amazon'
                    }
                    
                    if domain_base in common_typos and common_typos[domain_base] == known_base:
                        return True
                        
            except ImportError:
                # Fallback to simple check if Levenshtein is not available
                import difflib
                for known in known_domains:
                    if difflib.SequenceMatcher(None, domain.lower(), known.lower()).ratio() > 0.85:
                        return True
            
            return False
            
            # Normalize domain by removing TLD
            domain_base = domain.split('.')[-2] if '.' in domain else domain
            
            for known in known_domains:
                known_base = known.split('.')[-2] if '.' in known else known
                
                # Check for homoglyph substitution
                normalized = ''
                for c in domain_base:
                    normalized += homoglyphs.get(c, c)
                
                # Check for common typos
                if (distance(normalized, known_base) <= 2 and len(normalized) > 3) or \
                   known_base in domain_base and len(domain_base) - len(known_base) <= 2:
                    return True
                    
                # Check for character insertion/deletion
                if len(domain_base) > 3 and (known_base in domain_base or domain_base in known_base):
                    return True
                    
            return False
        
        # Check for suspicious patterns
        has_consecutive_chars = bool(re.search(r'(.)\1{3,}', url))
        is_typo = is_typosquatting(domain_info.domain + '.' + domain_info.suffix, trusted_financial_domains)
        
        # Initialize features with all required fields
        features = {
            # Basic character counts
            'qty_dot_url': min(url.count('.'), 10),  # Cap at 10 to prevent outliers
            'qty_hyphen_url': min(url.count('-'), 5),  # Cap at 5
            'qty_underline_url': min(url.count('_'), 5),  # Cap at 5
            'qty_slash_url': min(url.count('/'), 10),  # Cap at 10
            'qty_questionmark_url': min(url.count('?'), 5),  # Cap at 5
            'qty_equal_url': min(url.count('='), 5),  # Cap at 5
            'qty_at_url': min(url.count('@'), 2),  # More than 1 is suspicious
            'qty_and_url': min(url.count('&'), 5),  # Cap at 5
            'qty_exclamation_url': min(url.count('!'), 3),  # Cap at 3
            'qty_space_url': min(url.count(' '), 1),  # Any space is suspicious
            'qty_tilde_url': min(url.count('~'), 1),  # Any tilde is suspicious
            'qty_comma_url': min(url.count(','), 1),  # Any comma is suspicious
            'qty_plus_url': min(url.count('+'), 3),  # Cap at 3
            'qty_asterisk_url': min(url.count('*'), 1),  # Any asterisk is suspicious
            'qty_hashtag_url': min(url.count('#'), 2),  # Cap at 2
            'qty_dollar_url': min(url.count('$'), 2),  # Cap at 2
            'qty_percent_url': min(url.count('%'), 2),  # Cap at 2
            
            # URL structure features
            'qty_tld_url': min(len(domain_info.suffix) if domain_info.suffix else 0, 20),  # Cap at 20
            'length_url': min(len(url), 200),  # Cap at 200 chars
            'email_in_url': 1 if '@' in url else 0,
            'qty_redirects': min(url.count('//') - 1, 3),  # Cap at 3 redirects
            'count_digits': sum(c.isdigit() for c in url),
            'count_letters': sum(c.isalpha() for c in url),
            
            # Enhanced features
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'has_port': 1 if parsed.port is not None else 0,
            'path_length': len(parsed.path),
            'num_subdomains': num_subdomains,
            'is_ip': 1 if is_ip else 0,
            'has_at_symbol': 1 if has_at_symbol else 0,
            'is_shortened': 1 if is_shortened else 0,
            'has_phishing_terms': 1 if has_phishing_terms else 0,
            'domain_length': len(domain_info.domain),
            'is_suspicious_tld': 1 if is_suspicious_tld else 0,
            'has_consecutive_chars': 1 if has_consecutive_chars else 0,
            
            # Required features with improved defaults
            'domain_google_index': 1 if is_trusted_financial else (0 if is_suspicious_tld or is_shortened or is_ip else 1),
            'url_google_index': 1 if is_trusted_financial else (0 if is_suspicious_tld or is_shortened or is_ip else 1),
            'url_shortened': 1 if any(short in url for short in ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bitly.com', 'cutt.ly']) else 0
        }
        
        # Log extracted features for debugging
        logger.debug(f"Extracted features for URL: {url}")
        
        # Ensure all features are in the correct order and match the model's expected features
        if not feature_list:
            raise ValueError("Feature list is not loaded")
            
        # Create DataFrame with features in the correct order
        ordered_features = {k: features.get(k, 0) for k in feature_list}
        
        # Log any missing features
        missing_features = set(feature_list) - set(features.keys())
        if missing_features:
            logger.warning(f"Missing features, using default values: {missing_features}")
        
        return pd.DataFrame([ordered_features]), is_trusted_financial
        
    except Exception as e:
        logger.error(f"Error extracting features from URL {url}: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to extract features: {str(e)}") from e

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    if model is None or scaler is None or feature_list is None:
        return jsonify({"status": "error", "message": "Models not loaded"}), 500
    return jsonify({"status": "ok", "message": "Service is running"}), 200

@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict if a URL is phishing or safe.
    
    Expected JSON payload:
    {
        "url": "http://example.com"
    }
    
    Returns:
        JSON response with prediction results or error message
    """
    global model, scaler, feature_list
    
    # Log request
    logger.info("Received prediction request")
    
    # Check if models are loaded
    if model is None or scaler is None or feature_list is None:
        logger.warning("Models not loaded, attempting to load...")
        if not load_models():
            error_msg = "Failed to load prediction models"
            logger.error(error_msg)
            return jsonify({
                "status": "error",
                "message": error_msg,
                "error": "SERVICE_UNAVAILABLE"
            }), 503  # Service Unavailable
    
    # Get and validate request data
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            error_msg = "Missing required field: url"
            logger.warning(error_msg)
            return jsonify({
                "status": "error",
                "message": error_msg,
                "error": "BAD_REQUEST"
            }), 400
            
        url = data['url'].strip()
        logger.info(f"Processing URL: {url}")
        
        # Extract features and get trusted domain status
        features_df, is_trusted_financial = extract_features_with_trust_status(url)
        
        # Scale features
        scaler = get_scaler()
        features_scaled = scaler.transform(features_df)
        
        # Get domain for additional checks
        domain = url.split('://')[-1].split('/')[0]
        
        # Make prediction with enhanced domain verification
        prediction = model.predict(features_scaled, verbose=0)
        probability = float(prediction[0][0])
        
        # Define suspicious TLDs and their thresholds
        suspicious_tlds = {'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'gdn', 'bid', 'win'}
        
        # Get TLD and base domain
        domain_parts = domain.split('.')
        tld = domain_parts[-1] if domain_parts else ''
        
        # Check against trusted domains first
        trusted_domains = {
            'google.com', 'github.com', 'paypal.com', 'microsoft.com',
            'linkedin.com', 'amazon.com', 'facebook.com', 'youtube.com',
            'twitter.com', 'instagram.com', 'netflix.com', 'reddit.com',
            'amazon.in', 'google.co.in'  # Add country-specific TLDs as needed
        }
        
        # Function to check if a domain is trusted or a subdomain of a trusted domain
        def is_domain_trusted(domain_to_check):
            # Check exact match first
            if domain_to_check in trusted_domains:
                return True
                
            # Check subdomains (e.g., www.google.com should match google.com)
            domain_parts = domain_to_check.split('.')
            for i in range(len(domain_parts)):
                potential_domain = '.'.join(domain_parts[i:])
                if potential_domain in trusted_domains:
                    return True
            return False
        
        # Check if the domain or any of its parent domains are trusted
        is_trusted = is_domain_trusted(domain) or \
                   (len(domain_parts) > 1 and is_domain_trusted(f"{domain_parts[-2]}.{tld}"))
        
        if is_trusted:
            return jsonify({
                "status": "success",
                "data": {
                    "url": url,
                    "isPhishing": False,
                    "is_suspicious": False,
                    "prediction": "safe",
                    "confidence": 99.9,
                    "reason": "URL is from a trusted domain"
                }
            }), 200
        
        # Determine threshold based on TLD and domain characteristics
        if tld in suspicious_tlds:
            threshold = 0.4  # More sensitive for suspicious TLDs
            is_suspicious = True
        else:
            threshold = 0.65  # Standard threshold for common TLDs
            is_suspicious = False
            
            # Additional checks for suspicious patterns
            if len(domain_parts) > 2 and len(domain_parts[-2]) < 4:  # Short subdomains
                is_suspicious = True
                threshold = 0.5
                
            # Check for domain impersonation
            for trusted in trusted_domains:
                if trusted in domain and domain != trusted and not domain.endswith('.' + trusted):
                    is_suspicious = True
                    threshold = 0.45
                    break
        
        is_phishing = probability > threshold
        
        # Calculate confidence score
        if is_phishing:
            confidence = 50 + 50 * ((probability - threshold) / (1 - threshold))
        else:
            confidence = 50 + 50 * ((threshold - probability) / threshold)
            
        confidence = max(5, min(99, confidence))  # Keep confidence between 5-99%
        
        # Determine category and reason
        if is_phishing:
            category = 'phishing'
            reason = 'Phishing detected based on URL analysis'
        elif is_suspicious or (0.4 <= probability <= 0.65):
            category = 'suspicious'
            is_phishing = False
            reason = 'URL shows some suspicious characteristics'
        else:
            category = 'safe'
            reason = 'No significant risk indicators detected'
            
        response = {
            "status": "success",
            "data": {
                "url": url,
                "isPhishing": is_phishing,
                "is_suspicious": category == 'suspicious',
                "prediction": category,
                "confidence": round(confidence, 2),
                "reason": reason,
                "features": features_df.iloc[0].to_dict() if logger.level <= logging.DEBUG else None
            }
        }
        
        return jsonify(response), 200
        
    except ValueError as ve:
        error_msg = f"Invalid input: {str(ve)}"
        logger.error(error_msg, exc_info=True)
        return jsonify({
            "status": "error",
            "message": error_msg,
            "error": "INVALID_INPUT"
        }), 400
        
    except Exception as e:
        error_msg = f"Prediction failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return jsonify({
            "status": "error",
            "message": error_msg,
            "error": "PREDICTION_FAILED"
        }), 500

if __name__ == "__main__":
    # Load models when starting the service
    if not load_models():
        print("Failed to load models. Exiting...")
        sys.exit(1)
    
    # Start the Flask server
    port = int(os.environ.get('PORT', 5001))
    print(f"Starting prediction service on port {port}...")
    app.run(host='0.0.0.0', port=port, threaded=True)
