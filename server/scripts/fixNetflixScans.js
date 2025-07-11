const mongoose = require('mongoose');
const UrlScan = require('../models/UrlScan');

// Connect to MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/phishing-detector';

async function fixNetflixScans() {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('Connected to MongoDB');
    
    // Find all scans related to netflix.com
    const netflixScans = await UrlScan.find({
      $or: [
        { url: { $regex: 'netflix\.com', $options: 'i' } },
        { domain: { $regex: 'netflix\.com$', $options: 'i' } }
      ]
    });
    
    console.log(`Found ${netflixScans.length} Netflix-related scans`);
    
    let updatedCount = 0;
    
    // Update each scan to ensure it's marked as safe
    for (const scan of netflixScans) {
      // Only update if it's currently marked as phishing
      if (scan.isPhishing === true || scan.confidence >= 80) {
        console.log(`Updating scan for ${scan.url} (was phishing: ${scan.isPhishing}, confidence: ${scan.confidence}%)`);
        
        // Update to mark as safe
        await UrlScan.updateOne(
          { _id: scan._id },
          {
            $set: {
              isPhishing: false,
              is_suspicious: false,
              confidence: 0
            }
          }
        );
        
        updatedCount++;
      }
    }
    
    console.log(`\nUpdated ${updatedCount} Netflix scans to be marked as safe`);
    
  } catch (error) {
    console.error('Error fixing Netflix scans:', error);
  } finally {
    await mongoose.disconnect();
    console.log('Disconnected from MongoDB');
  }
}

// Run the script
fixNetflixScans();
