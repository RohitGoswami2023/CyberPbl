const mongoose = require('mongoose');

const urlScanSchema = new mongoose.Schema({
    url: {
        type: String,
        required: true,
        trim: true
    },
    isPhishing: {
        type: Boolean,
        required: true
    },
    confidence: {
        type: Number,
        required: true
    },
    domain: String,
    path: String,
    ipAddress: String,
    userAgent: String,
    referrer: String,
    timestamp: {
        type: Date,
        default: Date.now
    }
});

// Create the model
const UrlScan = mongoose.model('UrlScan', urlScanSchema);

// Export the model
module.exports = UrlScan;
