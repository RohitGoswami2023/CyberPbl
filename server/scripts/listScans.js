const mongoose = require('mongoose');
const UrlScan = require('../models/UrlScan');

// Connect to MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/phishing-detector';

async function listScans() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('Connected to MongoDB');
    
    // Get the most recent 20 scans
    const recentScans = await UrlScan.find({})
      .sort({ timestamp: -1 })
      .limit(20);
    
    console.log('\n=== RECENT SCANS ===');
    recentScans.forEach((scan, index) => {
      console.log(`\nScan ${index + 1}:`);
      console.log(`  URL: ${scan.url}`);
      console.log(`  Domain: ${scan.domain || 'N/A'}`);
      console.log(`  isPhishing: ${scan.isPhishing}`);
      console.log(`  is_suspicious: ${scan.is_suspicious || 'N/A'}`);
      console.log(`  Confidence: ${scan.confidence}%`);
      console.log(`  Timestamp: ${scan.timestamp}`);
    });
    
    // Check specifically for netflix.com in URLs or domains
    const netflixScans = await UrlScan.find({
      $or: [
        { url: { $regex: 'netflix', $options: 'i' } },
        { domain: { $regex: 'netflix', $options: 'i' } }
      ]
    });
    
    console.log('\n=== NETFLIX-RELATED SCANS ===');
    if (netflixScans.length === 0) {
      console.log('No Netflix-related scans found in the database.');
    } else {
      netflixScans.forEach((scan, index) => {
        console.log(`\nNetflix Scan ${index + 1}:`);
        console.log(`  URL: ${scan.url}`);
        console.log(`  Domain: ${scan.domain || 'N/A'}`);
        console.log(`  isPhishing: ${scan.isPhishing}`);
        console.log(`  is_suspicious: ${scan.is_suspicious || 'N/A'}`);
        console.log(`  Confidence: ${scan.confidence}%`);
        console.log(`  Timestamp: ${scan.timestamp}`);
      });
    }
    
  } catch (error) {
    console.error('Error listing scans:', error);
  } finally {
    await mongoose.disconnect();
    console.log('\nDisconnected from MongoDB');
  }
}

// Run the script
listScans();
