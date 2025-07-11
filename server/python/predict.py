import sys
import json
import re
import logging
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from keras.models import load_model
import joblib
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('phishing_detector.log')
    ]
)
logger = logging.getLogger(__name__)

# Initialize globals
model = None
scaler = None
feature_list = None

# List of trusted domains and TLDs
TRUSTED_DOMAINS = {
    # Major services
    'github.com', 'www.github.com', 'github.io',
    'google.com', 'www.google.com', 'accounts.google.com',
    'paypal.com', 'www.paypal.com', 'paypal.me',
    'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com',
    'linkedin.com', 'www.linkedin.com',
    'amazon.com', 'www.amazon.com', 'aws.amazon.com',
    'facebook.com', 'www.facebook.com',
    'twitter.com', 'www.twitter.com',
    'apple.com', 'www.apple.com', 'appleid.apple.com',
    'netflix.com', 'www.netflix.com',
    'dropbox.com', 'www.dropbox.com',
    'adobe.com', 'www.adobe.com',
    'mozilla.org', 'www.mozilla.org',
    'wordpress.com', 'www.wordpress.com',
    'wikipedia.org', 'www.wikipedia.org',
    
    # Common TLDs
    'gov', 'edu', 'mil', 'int', 'com', 'org', 'net', 'io', 'ai',
    
    # Country TLDs
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
    'ca', 'com.au', 'co.nz', 'in', 'de', 'fr', 'jp', 'uk', 'us'
}

# Suspicious TLDs that should have a lower threshold
SUSPICIOUS_TLDS = {
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'club', 'gdn', 'work',
    'bid', 'win', 'loan', 'date', 'party', 'review', 'stream', 'gq', 'cf', 'ga', 'ml', 'tk'
}

# Known URL shorteners
URL_SHORTENERS = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly', 'is.gd', 't2m.io',
    'bit.do', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rebrand.ly', 'soo.gd', 's2r.co',
    'shorte.st', 'adcrun.ch', 'bc.vc', 'clk.sh', 'cutt.us', 'db.tt', 'git.io', 'ity.im',
    'j.mp', 'kutt.it', 'l.instagram.com', 'mcaf.ee', 'ow.ly', 's.id', 'short.cm',
    'tiny.one', 'tiny.uc', 'x.co', 'zpr.io', '1url.com', '2big.at', '2tu.us',
    '4url.cc', '7.ly', 'a.gg', 'a.nf', 'adf.ly', 'adflav.com', 'adfoc.us', 'alturl.com',
    'bc.vc', 'binged.it', 'bitly.com', 'bl.ink', 'budurl.com', 'buff.ly', 'buk.me',
    'chilp.it', 'clicky.me', 'clk.ink', 'cutt.eu', 'dft.ba', 'dld.bz', 'dopice.sk',
    'ex9.co', 'ff.im', 'fly2.ws', 'fon.gs', 'fwd4.me', 'g.co', 'gg.gg', 'gizmo.do',
    'gl.am', 'go.aws', 'goo.gl', 'grabify.link', 'hadej.co', 'hex.io', 'hmm.li',
    'hubs.ly', 'hugeurl.com', 'hurl.me', 'hurl.ws', 'hyperurl.co', 'i.ajk.li',
    'i2r.at', 'ican.li', 'idek.net', 'iii.pw', 'ilix.in', 'is.gd', 'iscool.net',
    'ity.im', 'ix.sk', 'j.gs', 'j.mp', 'jdem.cz', 'kask.us', 'korta.nu', 'kr3w.de',
    'krat.si', 'krod.jp', 'kuc.cz', 'kutt.it', 'l-k.be', 'l9k.net', 'lat.ms', 'liip.to',
    'liltext.com', 'link.tl', 'linkbun.ch', 'linkbucks.com', 'linkto.im', 'lnkd.in',
    'loopt.us', 'lru.jp', 'lt.tl', 'lurl.no', 'macte.ch', 'migre.me', 'minilien.com',
    'minilink.com', 'minu.me', 'moourl.com', 'multiurl.com', 'myurl.in', 'n.pr',
    'nbc.co', 'nig.gr', 'njx.me', 'notlong.com', 'nsfw.in', 'nutshellurl.com',
    'nxy.in', 'o-x.fr', 'oc1.us', 'om.ly', 'omf.gd', 'ow.ly', 'p.ost.im', 'p.tl',
    'pd.am', 'pic.gd', 'ping.fm', 'plu.sh', 'pnt.me', 'politi.co', 'poprl.com',
    'post.ly', 'pp.gg', 'profile.to', 'q.gs', 'qkme.me', 'qlnk.net', 'qoo.by',
    'qte.me', 'quip-art.com', 'r.af', 'r.im', 'rb6.me', 'rb6.yy.vc', 'rdz.vg',
    'redir.ec', 'redir.fr', 'redirects.ca', 'redirx.com', 'retwt.me', 'ri.ms',
    'rickroll.it', 'riz.gd', 'rt.nu', 'ru.ly', 'rubyurl.com', 'rurl.org', 's4c.in',
    's7y.us', 'safe.mn', 'scrnch.me', 'sh.st', 'shar.as', 'sharetabs.com', 'shorl.com',
    'short.ie', 'short.to', 'shorten.ws', 'shorturl.com', 'shorturl.org', 'shout.to',
    'show.my', 'shrinkify.com', 'shrinkster.com', 'shrt.in', 'shrt.st', 'shrtco.de',
    'shrten.com', 'shrtfly.com', 'shw.me', 'simurl.com', 'slink.to', 'smsh.me',
    'smshaz.com', 'sn.im', 'snipr.com', 'snipurl.com', 'snurl.com', 'sp2.ro',
    'sp2.ro', 'spedr.com', 'sq6.ru', 'sqrl.it', 'ssl.gs', 'starturl.com', 'su.pr',
    'surl.co.uk', 'surl.me', 't.co', 't.gg', 't.lh.com', 'ta.gd', 'tbd.ly', 'tcrn.ch',
    'tdjt.cz', 'thinfi.com', 'thrdl.es', 'tighturl.com', 'tini.cc', 'tiny.cc',
    'tiny.lt', 'tiny.pl', 'tiny123.com', 'tinyarro.ws', 'tinyarrows.com', 'tinylink.in',
    'tinypic.com', 'tinyurl.com', 'tinyurl.hu', 'tinyvid.io', 'tixsu.com', 'tl.gd',
    'tldrify.com', 'tldrify.com', 'tmblr.co', 'tnij.org', 'tny.com', 'tny.cz',
    'togoto.us', 'tpmr.com', 'tr.im', 'tr.my', 'tr5.in', 'trib.al', 'trunc.it',
    'turo.us', 'tweetburner.com', 'twirl.at', 'twit.ac', 'twitclicks.com',
    'twitterpan.com', 'twitthis.com', 'twiturl.de', 'twurl.cc', 'twurl.nl', 'u.mavrev.com',
    'u.nu', 'u.to', 'u6e.de', 'ub0.cc', 'ulu.lu', 'updating.me', 'upzat.com',
    'ur1.ca', 'url.co.uk', 'url.ie', 'url2.fr', 'url4.eu', 'url5.org', 'urlcash.com',
    'urlcover.com', 'urlcut.com', 'urlcuy.com', 'urlenco.de', 'urlhawk.com',
    'urlkiss.com', 'urlpass.com', 'urlx.ie', 'urub.us', 'usat.ly', 'usehover.com',
    'v.ht', 'v5.gd', 'vaza.me', 'vbly.us', 'vd55.com', 'vgn.am', 'virl.com',
    'vl.am', 'vov.li', 'vsll.eu', 'vt802.us', 'vur.me', 'vurl.com', 'vzturl.com',
    'w1p.fr', 'w3t.org', 'waa.ai', 'wapurl.co.uk', 'warp.ly', 'web99.ovh', 'wed.li',
    'wipi.li', 'wp.me', 'wtc.la', 'wu.cz', 'ww7.fr', 'wwy.li', 'x.co', 'x.vu',
    'xaddr.com', 'xav.cc', 'xgd.in', 'xib.me', 'xoe.cz', 'xr.com', 'xrl.in',
    'xrl.us', 'xsear.ch', 'xua.me', 'xub.me', 'xurl.es', 'xurl.jp', 'xzb.cc',
    'y2u.be', 'yep.it', 'yfrog.com', 'yogh.me', 'ysear.ch', 'yu2.it', 'yweb.com',
    'yyv.co', 'z9.fr', 'zSMS.net', 'zapit.nu', 'zeek.ir', 'zi.ma', 'zip.net',
    'zipmyurl.com', 'zpr.io', 'zud.me', 'zurl.ws', 'zz.gd', 'zzb.bz'
]

# Known phishing patterns
PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'update', 'confirm', 'secure', 'banking',
    'security', 'alert', 'ebayisapi', 'webscr', 'password', 'credit', 'debit', 'card',
    'paypal', 'bank', 'account', 'verification', 'service', 'suspended', 'limited',
    'action', 'required', 'immediately', 'urgent', 'verify', 'confirm', 'billing',
    'invoice', 'payment', 'unusual', 'activity', 'suspicious', 'unauthorized',
    'blocked', 'restricted', 'validate', 'identity', 'personal', 'information',
    'ssn', 'social', 'security', 'tax', 'irs', 'refund', 'verify', 'credentials',
    'expire', 'expired', 'expiration', 'suspended', 'suspension', 'locked', 'lock',
    'unlock', 'restore', 'reactivate', 'authorize', 'authorization', 'verification'
]

def load_models():
    """Load ML models and configurations."""
    global model, scaler, feature_list
    
    try:
        # Get the directory of the current script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        model_dir = os.path.join(script_dir, 'model')
        
        # Create model directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
        
        # Define model paths
        model_path = os.path.join(model_dir, 'phishing_model.h5')
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        features_path = os.path.join(model_dir, 'feature_list.json')
        
        # Check if model files exist
        if not os.path.exists(model_path):
            logger.error(f"Model file not found: {model_path}")
            raise FileNotFoundError(f"Model file not found: {model_path}")
            
        if not os.path.exists(scaler_path):
            logger.error(f"Scaler file not found: {scaler_path}")
            raise FileNotFoundError(f"Scaler file not found: {scaler_path}")
            
        if not os.path.exists(features_path):
            logger.error(f"Features file not found: {features_path}")
            raise FileNotFoundError(f"Features file not found: {features_path}")
        
        # Load model and artifacts
        logger.info("Loading model and artifacts...")
        model = load_model(model_path)
        scaler = joblib.load(scaler_path)
        
        with open(features_path, 'r') as f:
            feature_list = json.load(f)
            
        logger.info("Model and artifacts loaded successfully")
        
    except Exception as e:
        logger.error(f"Error loading models: {e}")
        raise

def normalize_url(url: str) -> str:
    """Normalize URL by fixing common issues."""
    if not url:
        return ""
    
    # Fix double http(s)://
    url = re.sub(r'(https?://)(https?://)', r'\1', url, flags=re.IGNORECASE)
    
    # Remove any whitespace
    url = url.strip()
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    return url

def get_domain(url: str) -> str:
    """Extract domain from URL with validation."""
    try:
        # Normalize the URL first
        normalized_url = normalize_url(url)
        
        # Parse the URL
        parsed = urlparse(normalized_url)
        
        # If still no netloc, try to extract from path
        if not parsed.netloc and parsed.path:
            # Try to extract domain from path (case where user entered domain without http)
            parts = parsed.path.split('/')
            if parts and parts[0]:
                domain = parts[0].lower()
            else:
                domain = url.lower()
        else:
            domain = parsed.netloc.lower()
            
        # Remove port number if present
        domain = domain.split(':')[0]
        
        # Remove www. if present
        domain = domain.replace('www.', '')
        
        # Validate domain format
        if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain):
            logger.warning(f"Invalid domain format: {domain} from URL: {url}")
            return url.lower()
            
        return domain
    except Exception as e:
        logger.warning(f"Error parsing domain from {url}: {e}")
        return url.lower()

def is_whitelisted(url: str) -> bool:
    """Check if a URL is whitelisted."""
    try:
        domain = get_domain(url).lower()
        
        # Check for exact domain matches
        if domain in TRUSTED_DOMAINS:
            return True
            
        # Check for subdomains of trusted domains
        parts = domain.split('.')
        while len(parts) > 2:  # At least domain.tld remains
            parts = parts[1:]  # Remove the leftmost part
            parent_domain = '.'.join(parts)
            if parent_domain in TRUSTED_DOMAINS:
                return True
                
        return False
    except Exception as e:
        logger.warning(f"Error checking whitelist for {url}: {e}")
        return False

def is_suspicious_tld(domain: str) -> bool:
    """Check if a domain has a suspicious TLD."""
    try:
        tld = domain.split('.')[-1].lower()
        return tld in SUSPICIOUS_TLDS
    except Exception as e:
        logger.warning(f"Error checking TLD for {domain}: {e}")
        return False

def extract_features_from_url(url: str) -> dict:
    """Extract features from URL to match the model's expected features."""
    try:
        if not url:
            return {}
            
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url)
        domain = get_domain(url)
        path = parsed.path
        query = parsed.query
        
        # Initialize features with default values
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'path_length': len(path),
            'query_length': len(query),
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'has_http': 1 if parsed.scheme == 'http' else 0,
            'has_port': 1 if ':' in parsed.netloc else 0,
            'has_at': 1 if '@' in url else 0,
            'has_dash': 1 if '-' in domain else 0,
            'has_underscore': 1 if '_' in url else 0,
            'has_dot': 1 if '.' in domain else 0,
            'has_question': 1 if '?' in url else 0,
            'has_equals': 1 if '=' in url else 0,
            'has_ampersand': 1 if '&' in url else 0,
            'has_tilde': 1 if '~' in url else 0,
            'has_percent': 1 if '%' in url else 0,
            'has_dollar': 1 if '$' in url else 0,
            'has_exclamation': 1 if '!' in url else 0,
            'has_hash': 1 if '#' in url else 0,
            'has_asterisk': 1 if '*' in url else 0,
            'has_parenthesis': 1 if '(' in url or ')' in url else 0,
            'has_bracket': 1 if '[' in url or ']' in url else 0,
            'has_brace': 1 if '{' in url or '}' in url else 0,
            'has_redirect': 1 if any(kw in query.lower() for kw in ['redirect', 'return', 'next']) else 0,
            'has_login': 1 if any(kw in path.lower() for kw in ['login', 'signin', 'auth']) else 0,
            'has_account': 1 if any(kw in path.lower() for kw in ['account', 'profile', 'user']) else 0,
            'has_secure': 1 if any(kw in path.lower() for kw in ['secure', 'security', 'verify']) else 0,
            'has_update': 1 if any(kw in path.lower() for kw in ['update', 'change', 'modify']) else 0,
            'has_confirm': 1 if any(kw in path.lower() for kw in ['confirm', 'verif', 'validate']) else 0,
            'has_support': 1 if any(kw in path.lower() for kw in ['support', 'help', 'contact']) else 0,
            'has_php': 1 if '.php' in path.lower() else 0,
            'has_asp': 1 if '.asp' in path.lower() else 0,
            'has_js': 1 if '.js' in path.lower() else 0,
            'has_cgi': 1 if '.cgi' in path.lower() else 0,
            'has_html': 1 if '.html' in path.lower() or '.htm' in path.lower() else 0,
            'suspicious_tld': 1 if is_suspicious_tld(domain) else 0,
            'suspicious_keywords': sum(1 for kw in PHISHING_KEYWORDS if kw in url.lower()),
            'domain_in_path': 1 if any(d in path.lower() for d in TRUSTED_DOMAINS if len(d) > 3) else 0,
            'is_ip': 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) else 0,
            'is_short': 1 if len(domain) < 10 else 0,
            'is_long': 1 if len(domain) > 30 else 0,
            'has_digit': 1 if any(c.isdigit() for c in domain) else 0,
            'has_https_in_path': 1 if 'https' in path.lower() else 0,
            'has_http_in_path': 1 if 'http' in path.lower() else 0,
            'has_www': 1 if url.lower().startswith('www.') or '.www.' in url.lower() else 0,
            'has_port_in_url': 1 if ':' in url and '://' in url and ':' in url.split('://')[1] else 0,
            'has_unicode': 1 if any(ord(c) > 127 for c in url) else 0,
            'has_hex_encoded': 1 if any('%' in c for c in url) else 0,
            'has_multiple_subdomains': 1 if domain.count('.') > 2 else 0,
            'has_suspicious_keywords': 1 if any(kw in url.lower() for kw in PHISHING_KEYWORDS) else 0
        }
        
        # Count digits and letters
        features.update({
            'count_digits': sum(c.isdigit() for c in url),
            'count_letters': sum(c.isalpha() for c in url),
            'count_other': len(url) - sum(c.isalnum() or c in '.-_~:/?#[]@!$&\'()*+,;=' for c in url)
        })
        
        return features
        
    except Exception as e:
        logger.error(f"Error extracting features from URL {url}: {str(e)}")
        # Return empty features on error
        return {f: 0 for f in feature_list} if feature_list else {}

def check_obfuscation(url: str) -> list:
    """Check for common URL obfuscation techniques.
    
    Args:
        url (str): The URL to check for obfuscation
        
    Returns:
        list: List of detected obfuscation techniques
    """
    obfuscations = []
    try:
        # Check for IP address in URL
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            obfuscations.append("ip_address")
            
        # Check for hex encoding
        if '%' in url and len(re.findall(r'%[0-9a-fA-F]{2}', url)) > 2:
            obfuscations.append("hex_encoding")
            
        # Check for URL shorteners
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly', 'is.gd',
                     'buff.ly', 'adf.ly', 'bitly.com', 'tiny.cc', 'cutt.ly']
        if any(short in url.lower() for short in shorteners):
            obfuscations.append("url_shortener")
            
        # Check for @ symbol in URL (possible credential embedding)
        if '@' in url:
            obfuscations.append("credential_embedding")
            
        # Check for multiple subdomains (potential domain spoofing)
        domain = get_domain(url)
        if domain.count('.') > 3:  # More than 3 dots in domain
            obfuscations.append("multiple_subdomains")
            
        # Check for suspicious patterns in the domain
        suspicious_patterns = [
            (r'\d+[a-zA-Z]', "digits_before_letters"),  # Numbers followed by letters
            (r'[a-zA-Z]\d+', "letters_before_digits"),  # Letters followed by numbers
            (r'[^a-zA-Z0-9.-]', "suspicious_characters"),  # Non-alphanumeric characters
            (r'\.(tk|ml|ga|cf|gq|xyz|top|club|gdn|work|bid|win|loan|date|party|review|stream|surf|webcam|click|cricket|download|faith|link|lol|mom|ninja|pics|pw|racing|rocks|science|space|tech|uno|wtf)$', "suspicious_tld"),
            (r'[0-9]{4,}', "long_number_sequence"),  # Long sequences of numbers
            (r'[a-z]{15,}', "long_letter_sequence"),  # Long sequences of letters
            (r'[0-9a-fA-F]{8,}', "hex_like_string"),  # Hex-like strings
            (r'[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}', "uuid_like_pattern")  # UUID-like patterns
        ]
        
        for pattern, name in suspicious_patterns:
            if re.search(pattern, domain):
                obfuscations.append(name)
        
        # Check for suspicious keywords in the URL
        url_lower = url.lower()
        found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
        if found_keywords:
            obfuscations.append(f"suspicious_keywords: {', '.join(found_keywords[:3])}" + 
                              ("..." if len(found_keywords) > 3 else ""))
        
        return obfuscations
        
    except Exception as e:
        logger.warning(f"Error checking URL obfuscation for {url}: {e}")
        return ["error_checking_obfuscation"]

def get_phishing_reasons(url, features, probability):
    """Generate detailed reasons why a URL is classified as phishing or suspicious.
    
    Args:
        url (str): The URL being analyzed
        features (dict): Extracted features from the URL
        probability (float): The phishing probability (0-1)
        
    Returns:
        dict: Dictionary containing classification reasons and suspicious factors
    """
    reasons = []
    suspicious_factors = []
    
    # Parse the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    path = parsed_url.path.lower()
    query = parsed_url.query.lower()
    
    # Check for suspicious TLDs
    if is_suspicious_tld(domain):
        tld = domain.split('.')[-1]
        reasons.append(f"Suspicious top-level domain: .{tld}")
        suspicious_factors.append(f"suspicious_tld_{tld}")
    
    # Check for URL shorteners
    if any(shortener in domain for shortener in URL_SHORTENERS):
        reasons.append("URL shortening service detected")
        suspicious_factors.append("url_shortener")
    
    # Check for @ symbol in URL (credential phishing)
    if '@' in url:
        reasons.append("URL contains '@' symbol (possible credential phishing)")
        suspicious_factors.append("at_symbol_in_url")
    
    # Check for IP address in URL
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, domain):
        reasons.append("IP address used instead of domain name")
        suspicious_factors.append("ip_in_domain")
    
    # Check for subdomains count
    if domain.count('.') > 2:  # More than one subdomain
        reasons.append(f"Multiple subdomains detected ({domain.count('.')} levels)")
        suspicious_factors.append("multiple_subdomains")
    
    # Check for suspicious keywords in domain/path
    for keyword in PHISHING_KEYWORDS:
        if keyword in domain or keyword in path or keyword in query:
            reasons.append(f"Suspicious keyword in URL: '{keyword}'")
            suspicious_factors.append(f"suspicious_keyword_{keyword}")
    
    # Check URL length
    if len(url) > 100:
        reasons.append(f"Long URL ({len(url)} characters)")
        suspicious_factors.append("long_url")
    
    # Check for HTTPS
    if not url.lower().startswith('https'):
        reasons.append("Connection is not secure (no HTTPS)")
        suspicious_factors.append("no_https")
    
    # Check for obfuscation techniques
    obfuscation_checks = check_obfuscation(url)
    if obfuscation_checks:
        reasons.append("URL contains obfuscation techniques")
        suspicious_factors.extend([f"obfuscation_{tech}" for tech in obfuscation_checks])
    
    # Determine the main reason based on probability
    main_reason = ""
    if probability > 0.9:
        main_reason = "Very high likelihood of being a phishing attempt"
    elif probability > 0.7:
        main_reason = "High likelihood of being a phishing attempt"
    elif probability > 0.5:
        main_reason = "Suspicious characteristics detected"
    else:
        main_reason = "No significant risk indicators detected"
    
    return {
        'main_reason': main_reason,
        'detailed_reasons': reasons,
        'suspicious_factors': suspicious_factors,
        'confidence': probability * 100
    }


def predict_url(url, threshold=0.6):
    """Predict if a URL is phishing or not.
    
    Args:
        url (str): The URL to analyze
        threshold (float, optional): Base threshold for classification. Defaults to 0.6.
        
    Returns:
        dict: Dictionary containing prediction results
    """
    global model, scaler, feature_list
    
    # Initialize default values
    domain = ''
    tld = ''
    suspicious_factors = []
    
    try:
        # Check if models are loaded
        if model is None or scaler is None or feature_list is None:
            load_models()
            
        # Check against whitelist first
        if is_whitelisted(url):
            return {
                'url': url,
                'is_phishing': False,
                'confidence': 99.99,
                'probability': 0.0001,
                'threshold': threshold,
                'whitelisted': True,
                'message': 'URL is in the whitelist',
                'suspicious_factors': []
            }
            
        # Extract domain and TLD for additional checks
        domain = get_domain(url)
        tld = domain.split('.')[-1].lower() if '.' in domain else ''
        
        # Initialize suspicious score and factors
        suspicious_score = 0
        suspicious_factors = []
        
        # Check for URL shorteners first (very high risk)
        url_lower = url.lower()
        is_shortened = any(shortener in url_lower for shortener in URL_SHORTENERS)
        if is_shortened:
            suspicious_score += 0.5  # Very high score for URL shorteners
            suspicious_factors.append("URL shortener detected (high risk)")
        
        # Check for suspicious TLDs
        if tld in SUSPICIOUS_TLDS:
            suspicious_score += 0.3  # Increased weight for suspicious TLDs
            suspicious_factors.append(f"Suspicious TLD: {tld}")
        
        # Check for suspicious keywords in URL, but be more lenient with the main domain
        path_and_query = url_lower.split(domain)[1] if domain in url_lower else url_lower
        found_keywords = []
        
        # Only check path and query for keywords, not the main domain
        for kw in PHISHING_KEYWORDS:
            if kw in path_and_query:  # Check in path/query
                found_keywords.append(kw)
            # Only check main domain for specific high-risk keywords
            elif kw in ['login', 'signin', 'verify', 'account', 'secure', 'banking', 'paypal'] and kw in domain:
                found_keywords.append(kw)
                
        if found_keywords:
            # More keywords = higher score, but with diminishing returns
            keyword_score = min(0.3, 0.1 + (len(found_keywords) * 0.04))  # Reduced base score and increment
            suspicious_score += keyword_score
            suspicious_factors.append(f"Suspicious keywords in path/query: {', '.join(found_keywords[:3])}")
        
        # Check for long domain (potential obfuscation)
        domain_length = len(domain)
        if domain_length > 30:
            domain_score = min(0.3, 0.1 + (domain_length - 30) * 0.005)
            suspicious_score += domain_score
            suspicious_factors.append(f"Long domain name ({domain_length} characters)")
        
        # Check for hyphens in domain (potential spoofing)
        hyphen_count = domain.count('-')
        if hyphen_count > 0:
            hyphen_score = min(0.2, 0.05 + (hyphen_count * 0.05))
            suspicious_score += hyphen_score
            suspicious_factors.append(f"Hyphen in domain (x{hyphen_count})")
        
        # Check for multiple subdomains (potential obfuscation)
        subdomain_count = domain.count('.')
        if subdomain_count > 2:
            subdomain_score = min(0.3, 0.1 + (subdomain_count - 2) * 0.05)
            suspicious_score += subdomain_score
            suspicious_factors.append(f"Multiple subdomains ({subdomain_count} levels)")
            
        # Check for IP address in URL (suspicious)
        import re
        if re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
            suspicious_score += 0.3
            suspicious_factors.append("IP address in URL")
            
        # Get features for the URL
        features = extract_features_from_url(url)
        
        # Generate reasons for the classification
        reasons = get_phishing_reasons(url, features, 0)  # Will be updated with actual probability
        
        # Ensure all expected features are present and in correct order
        features_ordered = [features.get(feature, 0) for feature in feature_list]
        
        # Create a DataFrame with the feature names to avoid warnings
        features_df = pd.DataFrame([features_ordered], columns=feature_list)
        
        # Scale features
        features_scaled = scaler.transform(features_df)
        
        # Make prediction
        prediction = model.predict(features_scaled, verbose=0)
        
        # Get the probability from the model
        probability = float(prediction[0][0])
        
        # Update reasons with actual probability
        reasons = get_phishing_reasons(url, features, probability)
        
        # Adjust probability based on suspicious factors
        adjusted_probability = min(0.99, probability + suspicious_score)
        
        # Define thresholds for different risk levels (70-90% for suspicious range)
        suspicious_min = 0.7  # 70% for suspicious range start
        suspicious_max = 0.9  # 90% for suspicious range end
        
        # Calculate suspicious range based on threshold
        suspicious_range_min = threshold * suspicious_min
        suspicious_range_max = threshold * suspicious_max
        
        # Check if the URL is in the suspicious range (70-90% of threshold)
        is_suspicious = (adjusted_probability > suspicious_range_min and 
                       adjusted_probability <= suspicious_range_max)
        
        # Adjust threshold based on TLD and suspicious factors
        if tld in SUSPICIOUS_TLDS:
            threshold = 0.5  # Lower threshold for suspicious TLDs
            suspicious_range_min = threshold * suspicious_min
            suspicious_range_max = threshold * suspicious_max
            
        # If we have multiple suspicious factors, be more aggressive
        if len(suspicious_factors) >= 2:
            threshold = max(0.4, threshold - 0.1)
            suspicious_range_min = threshold * suspicious_min
            suspicious_range_max = threshold * suspicious_max
        
        is_phishing = adjusted_probability > suspicious_range_max  # Above 90% is phishing
        
        # Calculate confidence and determine message
        if is_phishing:
            # Scale confidence for phishing to be between 90-100%
            confidence = 90 + ((adjusted_probability - suspicious_max) / (1 - suspicious_max) * 10)  # 90-100%
            message = 'URL appears to be phishing'
            category = 'phishing'
            # Use the main reason from the reasons dictionary
            reason = reasons['main_reason']
        elif is_suspicious:
            # Scale confidence for suspicious URLs to be between 70-90%
            confidence = 70 + ((adjusted_probability - suspicious_min) / 
                            (suspicious_max - suspicious_min) * 20)  # 70-90%
            message = 'URL appears suspicious'
            category = 'suspicious'
            # Use the main reason from the reasons dictionary
            reason = reasons['main_reason']
        else:
            # Scale confidence for safe URLs to be between 0-70%
            confidence = (suspicious_min - adjusted_probability) / suspicious_min * 70  # 0-70%
            confidence = max(0, min(79.9, confidence))  # Cap at 79.9% for safe URLs
            message = 'URL appears to be safe'
            category = 'safe'
            reason = 'No significant risk indicators detected'
            
        # Add suspicious factors to message if any
        if suspicious_factors:
            message += f"\nSuspicious factors: {'; '.join(suspicious_factors)}"
        
        return {
            'url': url,
            'is_phishing': bool(is_phishing),
            'is_suspicious': category == 'suspicious',
            'category': category,
            'confidence': round(confidence, 2),
            'probability': round(adjusted_probability, 4),
            'threshold': threshold,
            'whitelisted': False,
            'message': message,
            'reason': reason,  # Added detailed reason
            'domain': domain,
            'tld': tld,
            'suspicious_factors': suspicious_factors,
            'features': {
                'length': len(url),
                'has_https': features.get('has_https', 0),
                'has_subdomain': features.get('has_subdomain', 0),
                'suspicious_keywords': len(found_keywords) if 'found_keywords' in locals() else 0,
                'is_shortened': features.get('url_shortened', 0)
            },
            'reasons': reasons['detailed_reasons'],
            'main_reason': reasons['main_reason']
        }
        
    except Exception as e:
        logger.error(f"Error predicting URL {url}: {str(e)}", exc_info=True)
        return {
            'url': url,
            'error': str(e),
            'is_phishing': None,
            'confidence': 0.0,
            'probability': 0.0,
            'threshold': threshold,
            'message': f'Error processing URL: {str(e)}',
            'suspicious_factors': []
        }

# Function implementations moved to the top of the file to avoid duplicates

# Suspicious TLDs that should have a lower threshold
SUSPICIOUS_TLDS = {
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'club', 'gdn', 'work',
    'bid', 'win', 'loan', 'date', 'party', 'review', 'stream', 'gq', 'cf', 'ga', 'ml', 'tk',
    'zip', 'cricket', 'gq', 'science', 'party', 'rest', 'bar', 'biz', 'info', 'online',
    'pro', 'shop', 'site', 'store', 'tech', 'webcam', 'win', 'work', 'xyz'
}

# Known phishing patterns
PHISHING_KEYWORDS = {
    'account', 'verify', 'login', 'signin', 'secure', 'update', 'banking',
    'verification', 'confirm', 'security', 'alert', 'suspended', 'limited',
    'action', 'required', 'immediately', 'unauthorized', 'suspicious',
    'billing', 'invoice', 'payment', 'card', 'expire', 'expired', 'expiration',
    'urgent', 'important', 'notice', 'attention', 'verify', 'validation',
    'reactivate', 'restore', 'locked', 'blocked', 'hacked', 'compromised',
    'suspended', 'limit', 'exceeded', 'unauthorized', 'unusual', 'activity',
    'verify', 'identity', 'password', 'credentials', 'account', 'update',
    'confirm', 'information', 'details', 'personal', 'sensitive', 'data',
    'social', 'security', 'number', 'ssn', 'credit', 'card', 'debit', 'bank',
    'routing', 'account', 'number', 'expiration', 'date', 'cvv', 'cvc', 'pin',
    'verification', 'code', 'otp', '2fa', 'two-factor', 'authentication',
    'login', 'signin', 'sign-in', 'log-in', 'account', 'profile', 'settings',
    'preferences', 'billing', 'payment', 'subscription', 'renewal', 'invoice',
    'receipt', 'statement', 'transaction', 'purchase', 'order', 'shipping',
    'tracking', 'delivery', 'confirmation', 'verification', 'validate', 'confirm',
    'update', 'change', 'modify', 'edit', 'remove', 'delete', 'cancel', 'stop',
    'suspend', 'reactivate', 'restore', 'unlock', 'unblock', 'verify', 'check',
    'validate', 'confirm', 'secure', 'security', 'protect', 'safety', 'privacy',
    'fraud', 'scam', 'phishing', 'hack', 'compromise', 'breach', 'leak', 'theft',
    'identity', 'personal', 'sensitive', 'private', 'confidential', 'restricted',
    'exclusive', 'limited', 'urgent', 'important', 'immediate', 'action',
    'required', 'necessary', 'critical', 'alert', 'warning', 'notice', 'attention'
}

def main():
    """Main entry point for the phishing URL detector."""
    import argparse
    
    try:
        # Set up argument parser
        parser = argparse.ArgumentParser(description='Phishing URL Detector')
        parser.add_argument('url', nargs='?', help='URL to check')
        parser.add_argument('--threshold', type=float, default=0.7, 
                          help='Classification threshold (0-1), default: 0.7')
        parser.add_argument('--verbose', action='store_true', 
                          help='Enable verbose output')
        
        args = parser.parse_args()
        
        # Set log level
        if args.verbose:
            logger.setLevel(logging.DEBUG)
        
        logger.info("Starting phishing URL detector...")
        
        # Load models
        load_models()
        
        if args.url:
            # Check single URL (used by Node.js backend)
            try:
                result = predict_url(args.url, args.threshold)
                # Include all relevant fields in the output for Node.js backend
                output = {
                    'is_phishing': bool(result.get('is_phishing', False)),
                    'is_suspicious': bool(result.get('is_suspicious', False)),
                    'category': str(result.get('category', 'safe')),
                    'confidence': float(result.get('confidence', 0)),
                    'probability': float(result.get('probability', 0)),
                    'threshold': float(result.get('threshold', 0.7)),
                    'url': str(result.get('url', '')),
                    'domain': str(result.get('domain', '')),
                    'tld': str(result.get('tld', '')),
                    'whitelisted': bool(result.get('whitelisted', False)),
                    'suspicious_factors': list(result.get('suspicious_factors', [])),
                    'message': str(result.get('message', '')),
                    'reason': str(result.get('reason', '')),
                    'main_reason': str(result.get('main_reason', result.get('reason', ''))),
                    'reasons': list(result.get('reasons', [])),
                    'features': dict(result.get('features', {}))
                }
                print(json.dumps(output))
            except Exception as e:
                logger.error(f"Error processing URL: {e}")
                print(json.dumps({
                    'error': 'Failed to process URL',
                    'details': str(e)
                }))
                sys.exit(1)
        else:
            # Interactive mode (for testing)
            print("Phishing URL Detector (Ctrl+C to exit)")
            print("Enter URLs to check, one per line:")
            
            while True:
                try:
                    url = input("> ").strip()
                    if not url:
                        continue
                        
                    result = predict_url(url, args.threshold)
                    
                    # Format output for human readability
                    status = "PHISHING" if result.get('is_phishing', False) else "SAFE"
                    print(f"\n[ {status} ] {result.get('url', '')}")
                    print("-" * 80)
                    
                    if result.get('whitelisted', False):
                        print("• Whitelisted domain")
                    
                    print(f"• Domain: {result.get('domain', 'N/A')}")
                    print(f"• Score: {result.get('probability', 0):.4f} (Threshold: {result.get('threshold', 0.7):.2f})")
                    print(f"• Confidence: {result.get('confidence', 0):.2f}%")
                    
                    if result.get('suspicious_factors'):
                        print("\nSuspicious factors:")
                        for factor in result['suspicious_factors']:
                            print(f"  • {factor}")
                    
                    print("\n" + "=" * 80 + "\n")
                    
                except KeyboardInterrupt:
                    print("\nExiting...")
                    break
                except Exception as e:
                    logger.error(f"Error processing URL: {e}")
                    print(f"Error: {e}\n")
                    
    except Exception as e:
        error_msg = f"Fatal error: {e}"
        logger.error(error_msg, exc_info=True)
        print(json.dumps({
            'error': 'Internal server error',
            'details': error_msg
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()
