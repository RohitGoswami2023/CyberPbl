// routes/urlRoutes.js
const express = require('express');
const router = express.Router();
const { PythonShell } = require('python-shell');
const path = require('path');
const Report = require('../models/Report');
const UrlScan = require('../models/UrlScan');

// Helper function to log scan results
async function logScanResult(url, isPhishing, confidence, error = null) {
  try {
    const scan = new UrlScan({
      url,
      isPhishing,
      confidence,
      timestamp: new Date(),
      error: error ? error.message : null,
      rawResult: error ? error.stack : null
    });
    await scan.save();
  } catch (logError) {
    console.error('Error logging scan result:', logError);
  }
}

// POST /api/scan - Scans a URL using the Python ML model
router.post('/scan', async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ 
      error: 'Invalid input',
      message: 'URL is required and must be a string' 
    });
  }

  // Basic URL validation
  try {
    new URL(url);
  } catch (e) {
    return res.status(400).json({ 
      error: 'Invalid URL',
      message: 'Please provide a valid URL including protocol (http:// or https://)'
    });
  }

  try {
    console.log(`Starting scan for URL: ${url}`);
    
    PythonShell.run(
      path.join(__dirname, '../python/predict.py'), 
      { 
        args: [url],
        pythonPath: 'python3',
        pythonOptions: ['-u'] // Unbuffered output
      }, 
      async (err, result) => {
        try {
          if (err) {
            console.error('Python script execution error:', err);
            await logScanResult(url, false, 0, err);
            return res.status(500).json({ 
              error: 'Scan failed',
              message: 'Error processing the URL',
              details: err.message 
            });
          }

          if (!result || result.length === 0) {
            const error = new Error('No prediction returned from scanner');
            await logScanResult(url, false, 0, error);
            return res.status(500).json({ 
              error: 'Scan failed',
              message: 'Could not determine if the site is safe',
              details: 'The scanner did not return any results'
            });
          }

          // Parse the JSON response from the Python script
          let predictionResult = {};
          try {
            // The first line should be the JSON string from the Python script
            predictionResult = JSON.parse(result[0]);
          } catch (parseError) {
            console.error('Error parsing prediction result:', parseError);
            // Fallback to basic parsing if JSON parsing fails
            const prediction = result[0].trim().toLowerCase();
            const isPhishing = prediction === 'phishing';
            const confidence = 80; // Default confidence for fallback
            
            await logScanResult(url, isPhishing, confidence);
            
            return res.json({
              isPhishing,
              is_suspicious: false,
              confidence,
              message: isPhishing 
                ? 'Warning: This site appears to be a phishing site.' 
                : 'This site appears to be safe.',
              reason: isPhishing ? 'Suspicious characteristics detected' : 'No significant risk indicators detected'
            });
          }
          
          const { 
            is_phishing, 
            is_suspicious, 
            confidence = 0, 
            message = '', 
            reason = '', 
            main_reason = reason,
            reasons = [],
            suspicious_factors = []
          } = predictionResult;

          // Save detailed scan result
          const report = new Report({
            url,
            isPhishing: is_phishing,
            isSuspicious: is_suspicious,
            confidence,
            timestamp: new Date(),
            details: {
              prediction: is_phishing ? 'phishing' : is_suspicious ? 'suspicious' : 'safe',
              main_reason,
              reasons,
              suspicious_factors,
              features: predictionResult.features || {}
            }
          });

          await report.save();
          await logScanResult(url, is_phishing, confidence);

          console.log(`Scan completed for ${url}: ${is_phishing ? 'Phishing' : is_suspicious ? 'Suspicious' : 'Safe'} (${confidence}% confidence)`);
          
          // Send the enriched response to the frontend
          res.json({
            isPhishing: is_phishing,
            is_suspicious: is_suspicious,
            confidence,
            message: message || (is_phishing 
              ? 'Warning: This site appears to be a phishing site.' 
              : is_suspicious
                ? 'This site appears suspicious.'
                : 'This site appears to be safe.'),
            reason: reason || main_reason || (is_phishing ? 'Suspicious characteristics detected' : 'No significant risk indicators detected'),
            main_reason: main_reason || reason || (is_phishing ? 'Suspicious characteristics detected' : 'No significant risk indicators detected'),
            reasons: reasons || [],
            suspicious_factors: suspicious_factors || [],
            features: predictionResult.features || {}
          });

        } catch (processError) {
          console.error('Error processing scan result:', processError);
          await logScanResult(url, false, 0, processError);
          res.status(500).json({ 
            error: 'Processing error',
            message: 'Error processing scan results',
            details: processError.message 
          });
        }
      }
    );
  } catch (error) {
    console.error('Unexpected server error during scan:', error);
    logScanResult(url, false, 0, error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: 'An unexpected error occurred',
      details: error.message 
    });
  }
});

module.exports = router;
