import sys
import os
import json
from predict import predict_url, get_phishing_reasons

def test_url(url):
    """Test a single URL and print detailed results."""
    print(f"\n{'='*80}")
    print(f"Testing URL: {url}")
    print("="*80)
    
    try:
        # Get prediction with detailed reasons
        result = predict_url(url)
        
        # Print basic results
        print(f"\n🔍 Analysis Results:")
        print(f"   - URL: {result['url']}")
        print(f"   - Is Phishing: {result['is_phishing']}")
        print(f"   - Category: {result.get('category', 'N/A')}")
        print(f"   - Confidence: {result.get('confidence', 0):.2f}%")
        
        # Print main reason
        print(f"\n🔑 Main Reason:")
        print(f"   {result.get('main_reason', 'No specific reason provided')}")
        
        # Print detailed reasons if available
        if 'reasons' in result and result['reasons']:
            print("\n📋 Detailed Reasons:")
            for i, reason in enumerate(result['reasons'], 1):
                print(f"   {i}. {reason}")
        
        # Print suspicious factors if available
        if 'suspicious_factors' in result and result['suspicious_factors']:
            print("\n⚠️  Suspicious Factors:")
            for i, factor in enumerate(result['suspicious_factors'], 1):
                print(f"   {i}. {factor}")
        
        # Print technical details
        print("\n🔧 Technical Details:")
        print(f"   - URL Length: {len(url)} characters")
        print(f"   - Has HTTPS: {'https' in url.lower()}")
        print(f"   - Has Subdomains: {'.' in url.replace('www.', '')}")
        
    except Exception as e:
        print(f"\n❌ Error processing URL: {str(e)}")
    
    print("\n" + "="*80 + "\n")

def main():
    """Main function to test multiple URLs."""
    # Example URLs to test
    test_urls = [
        # Legitimate URLs
        "https://www.paypal.com/signin",
        "https://github.com/login",
        "https://www.google.com",
        
        # Suspicious URLs
        "http://paypal-confirm-account.xyz/login.php",
        "https://secure-account-update.xyz/verify",
        "https://www.apple.com.secure-login.xyz/account",
        
        # Phishing URLs (examples - these are not real phishing sites)
        "http://faceb00k-login.xyz/password/reset",
        "https://netflix-update-billing.xyz/account",
        "http://amazon-payment-verification.xyz/update"
    ]
    
    # Test each URL
    for url in test_urls:
        test_url(url)

if __name__ == "__main__":
    # Add the current directory to the path
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    main()
