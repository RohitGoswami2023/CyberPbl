// Simulate phishing model prediction
function predictPhishing(url) {
  // Simulated logic (replace this with your actual ML model later)
  if (url.includes('phish')) {
    return { isPhishing: true, confidence: 90 }; // Phishing URL
  } else {
    return { isPhishing: false, confidence: 5 }; // Safe URL
  }
}

module.exports = { predictPhishing };
