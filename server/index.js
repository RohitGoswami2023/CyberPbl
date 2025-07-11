require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const { createServer } = require('http');
const { Server } = require('socket.io');
const connectDB = require('./config/db');
const UrlScan = require('./models/UrlScan');

const app = express();
const httpServer = createServer(app);


const allowedOrigins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173"
];

const io = new Server(httpServer, {
    cors: {
        origin: function(origin, callback) {
            
            if (!origin) return callback(null, true);
            
            
            const isAllowed = allowedOrigins.some(allowedOrigin => {
                return origin === allowedOrigin || 
                       origin.startsWith('http://localhost:') ||
                       origin.startsWith('https://localhost:') ||
                       origin.includes('127.0.0.1');
            });
            
            if (isAllowed) {
                callback(null, true);
            } else {
                console.warn('CORS blocked origin:', origin);
                callback(new Error('Not allowed by CORS'));
            }
        },
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization", "socket-id", "X-Client-Type"],
        credentials: true
    },
    // Allow both WebSocket and HTTP long-polling
    transports: ['websocket', 'polling'],
    // Configure timeouts
    pingTimeout: 60000,  
    pingInterval: 25000,  
    
    perMessageDeflate: {
        threshold: 1024, 
        zlibDeflateOptions: {
            level: 3
        },
        zlibInflateOptions: {
            chunkSize: 10 * 1024
        },
        // Disable compression for small messages
        threshold: 1024
    },
    // Allow binary data
    maxHttpBufferSize: 1e6, 
    
    handlePreflightRequest: (req, res) => {
        const headers = {
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, socket-id, X-Client-Type',
            'Access-Control-Allow-Origin': req.headers.origin || '*',
            'Access-Control-Allow-Credentials': true,
            'Access-Control-Max-Age': '86400' // 24 hours
        };
        res.writeHead(200, headers);
        res.end();
    },
    // Disable cookie-based session ID
    cookie: false,
    // Don't serve the client
    serveClient: false,
    // Enable compatibility with older Socket.IO clients
    allowEIO3: true,
    // HTTP compression is enabled by default
    httpCompression: true,
    // Don't destroy upgrade requests
    destroyUpgrade: false,
    // Don't destroy upgrade delay
    destroyUpgradeDelay: 1000
});

// Handle socket connections
io.on('connection', (socket) => {
    const clientIp = socket.handshake.address;
    console.log(`🔌 New client connected: ${socket.id} from ${clientIp}`);
    
    // Log connection details
    console.log('🔍 Connection details:', {
        id: socket.id,
        handshake: {
            headers: socket.handshake.headers,
            query: socket.handshake.query,
            auth: socket.handshake.auth
        },
        rooms: [...socket.rooms],
        connected: socket.connected,
        disconnected: socket.disconnected
    });
    
    // Handle test connection from client
    socket.on('testConnection', (data) => {
        console.log(`✅ Test connection received from ${socket.id}:`, data);
        socket.emit('testResponse', { 
            status: 'success', 
            message: 'Server is connected and responding',
            timestamp: new Date().toISOString()
        });
    });
    
    // Handle scan updates
    socket.on('scanUpdate', (data) => {
        console.log(`📡 Received scan update from ${socket.id}:`, data);
    
        socket.broadcast.emit('scanUpdate', data);
    });
    
    // Handle disconnection
    socket.on('disconnect', (reason) => {
        console.log(`❌ Client disconnected: ${socket.id} (${reason})`);
        console.log('Remaining connections:', io.engine.clientsCount);
    });
    
    // Handle errors
    socket.on('error', (error) => {
        console.error(`❌ Socket error (${socket.id}):`, error);
    });
    
    // Send initial connection confirmation
    socket.emit('connection', { 
        status: 'connected', 
        socketId: socket.id,
        timestamp: new Date().toISOString()
    });
});

// Log server status
console.log('🚀 WebSocket server started');
console.log('Allowed origins:', allowedOrigins);
console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode`);

// Handle server errors
io.engine.on('connection_error', (err) => {
    console.error('❌ Server connection error:', err);
    console.error('Error details:', {
        message: err.message,
        code: err.code,
        context: err.context
    });
});

// Connect to MongoDB
connectDB().catch(err => {
    console.error('❌ Failed to connect to MongoDB:', err);
    process.exit(1);
});

// Middleware
app.use(cors({
    origin: allowedOrigins,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true
}));
app.use(express.json());

// Serve static files from the React app
const clientPath = path.join(__dirname, '../../client/dist');
if (fs.existsSync(clientPath)) {
    app.use(express.static(clientPath));
    
    // Handle React routing, return all requests to React app
    app.get('*', (req, res) => {
        res.sendFile(path.join(clientPath, 'index.html'));
    });
} else {
    // Fallback if frontend isn't built
    app.get('/', (req, res) => {
        res.send('Phishing Detection API is running. Frontend not built.');
    });
}


app.get('/api/scans', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const scans = await UrlScan.find()
            .sort('-timestamp')
            .skip(skip)
            .limit(limit);

        const total = await UrlScan.countDocuments();
        
        res.json({
            scans,
            total,
            page,
            totalPages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error('Error fetching scans:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Search scans by URL
app.get('/api/scans/search', async (req, res) => {
    try {
        const query = req.query.q;
        if (!query) {
            return res.status(400).json({ error: 'Search query is required' });
        }

        const scans = await UrlScan.find({
            url: { $regex: query, $options: 'i' }
        }).sort('-timestamp').limit(20);

        res.json(scans);
    } catch (err) {
        console.error('Search error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// URL Scan Endpoint
app.post('/api/scan', async (req, res) => {
    const { url, ipAddress, userAgent, referrer } = req.body;
    const socketId = req.headers['socket-id'] || 'unknown';

    if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: 'Invalid or missing URL' });
    }

    // Extract domain and path
    let domain, urlPath;
    try {
        const urlObj = new URL(url);
        domain = urlObj.hostname;
        urlPath = urlObj.pathname;
    } catch (e) {
        domain = url.split('/')[0];
        urlPath = '/';
    }

    // Call Python ML model
    const { exec } = require('child_process');
    
    // Get the absolute path to the Python script using the existing path import
    const pythonScriptPath = path.join(__dirname, 'python', 'predict.py');
    
    // Escape quotes in the URL for the command line
    const escapedUrl = url.replace(/"/g, '\\"');
    
    // Build the command based on the platform
    let command;
    if (process.platform === 'win32') {
        // Windows
        command = `python "${pythonScriptPath}" "${escapedUrl}"`;
    } else {
        // Unix/Linux/Mac
        command = `python3 "${pythonScriptPath}" "${escapedUrl}"`;
    }
    
    console.log('Executing command:', command);
    
    // Execute the Python script
    exec(command, 
    { maxBuffer: 1024 * 5000 }, // Increase buffer size for large outputs
    async (error, stdout, stderr) => {
        if (error) {
            console.error('Python script error:', error);
            return res.status(500).json({ 
                error: 'Failed to process URL',
                details: error.message 
            });
        }

        if (stderr) {
            console.error('Python script stderr:', stderr);
        }

        try {
            // Parse the Python script output
            const result = JSON.parse(stdout);
            
            // Calculate confidence (ensure it's a number between 0-100)
            const confidence = Math.min(100, Math.max(0, parseFloat(result.confidence) || 0));
            
           
            const hasSuspiciousFactors = Array.isArray(result.suspicious_factors) && 
                                      result.suspicious_factors.length > 0;
            
            const isSuspicious = (
                result.is_suspicious || 
                result.category === 'suspicious' ||
                (confidence >= 55 && confidence < 80) ||
                (hasSuspiciousFactors && !result.is_phishing)
            ) && !result.is_phishing; // Don't mark as suspicious if it's already phishing
            
            console.log('Scan result:', {
                url,
                is_phishing: result.is_phishing,
                is_suspicious: isSuspicious,
                confidence,
                category: result.category,
                hasSuspiciousFactors,
                suspicious_factors: result.suspicious_factors || []
            });
            
            const newScan = new UrlScan({
                url,
                isPhishing: result.is_phishing,
                is_suspicious: isSuspicious,
                confidence: confidence,
                domain,
                path: urlPath,
                ipAddress: ipAddress || req.ip,
                userAgent: userAgent || req.get('user-agent'),
                referrer: referrer || req.get('referer'),
                details: {
                    probability: result.probability,
                    threshold: result.threshold,
                    suspicious_factors: result.suspicious_factors || [],
                    category: result.category,
                    is_suspicious: isSuspicious
                },
                category: result.is_phishing ? 'phishing' : (isSuspicious ? 'suspicious' : 'safe')
            });
            
            await newScan.save();
            
            // Emit the complete scan result via WebSocket with all details
            const scanUpdate = {
                _id: newScan._id,
                url: newScan.url,
                isPhishing: result.is_phishing,
                is_suspicious: isSuspicious && !result.is_phishing, // Don't mark as suspicious if it's already phishing
                confidence: result.confidence,
                domain: newScan.domain,
                timestamp: newScan.timestamp,
                reason: result.reason || (isSuspicious ? 'Suspicious characteristics detected' : 'No significant risk indicators'),
                main_reason: result.main_reason || result.reason || 
                    (result.is_phishing ? 'Phishing detected' : 
                    (isSuspicious ? 'Suspicious characteristics detected' : 'No significant risk indicators')),
                reasons: result.reasons || [],
                // Add origin socket ID to prevent unnecessary updates
                originSocketId: socketId,
                suspicious_factors: result.suspicious_factors || [],
                message: result.message || 
                    (result.is_phishing ? 'Warning: This site appears to be a phishing site.' : 
                    (isSuspicious ? 'This site appears suspicious.' : 'This site appears to be safe.')),
                category: result.is_phishing ? 'phishing' : (isSuspicious ? 'suspicious' : 'safe')
            };
            
            // Emit to all connected clients
            io.emit('scanUpdate', scanUpdate);
            
            console.log('Emitted scan update:', scanUpdate);
            
            // Return the enriched result to the client
            // Build the response data with consistent status between initial scan and history
            const responseData = {
                url,
                isPhishing: result.is_phishing,
                is_suspicious: isSuspicious, // Use the same calculated value as when saving to DB
                confidence: confidence, // Use the calculated confidence value
                reason: result.reason || (result.is_phishing 
                    ? 'Phishing detected based on URL analysis'
                    : isSuspicious
                        ? 'Suspicious indicators found but not confirmed as phishing'
                        : 'No significant risk indicators detected'),
                main_reason: result.main_reason || (result.is_phishing 
                    ? 'Suspicious characteristics detected' 
                    : 'No significant risk indicators'),
                category: result.category,
                suspicious_factors: result.suspicious_factors || [],
                reasons: result.reasons || [],
                message: result.message || (result.is_phishing 
                    ? 'Warning: This site appears to be a phishing site.' 
                    : result.category === 'suspicious'
                        ? 'This site appears suspicious.'
                        : 'This site appears to be safe.'),
                timestamp: new Date()
            };
            
            // Send the consistent response data back to the client
            res.json(responseData);
        } catch (parseError) {
            console.error('Failed to parse Python script output:', parseError);
            res.status(500).json({ 
                error: 'Invalid response from scanner',
                details: parseError.message 
            });
        }
    });
});

// Get all scans without pagination
app.get('/api/scans/all', async (req, res) => {
    try {
        const scans = await UrlScan.find({})
            .sort({ timestamp: -1 });
        
        res.json({ scans });
    } catch (error) {
        console.error('Error fetching all scans:', error);
        res.status(500).json({ 
            error: 'Failed to fetch scan history',
            details: error.message 
        });
    }
});

// Get scan statistics
app.get('/api/statistics', async (req, res) => {
    try {
        console.log('Fetching all scans for statistics...');
        // First, get all scans to ensure we have consistent counts
        const allScans = await UrlScan.find({}).lean();
        console.log(`Found ${allScans.length} total scans`);
        
        // Helper function to determine the category of a scan
        // This must match the logic used when saving the scan in the database
        const getScanCategory = (scan) => {
            try {
                // Ensure confidence is a valid number between 0-100
                let confidence = parseFloat(scan.confidence);
                if (isNaN(confidence) || confidence < 0 || confidence > 100) {
                    console.warn(`Invalid confidence value (${scan.confidence}) for scan ${scan._id}, defaulting to 0`);
                    confidence = 0;
                }
                
                // Debug log for all scans
                console.log(`Scan ID: ${scan._id}, URL: ${scan.url}, ` +
                           `Confidence: ${confidence}%, ` +
                           `isPhishing: ${scan.isPhishing}, ` +
                           `is_suspicious: ${scan.is_suspicious}`);
                
                // Check whitelisted domains first
                const domain = scan.domain || '';
                const isWhitelisted = domain.endsWith('netflix.com') || 
                                     domain.endsWith('google.com') || 
                                     domain.endsWith('github.com');
                
                if (isWhitelisted) {
                    console.log(`  Categorized as SAFE - Whitelisted domain: ${domain}`);
                    return 'safe';
                }
                
                // Use the same logic as when saving the scan
                if (scan.isPhishing === true || confidence >= 80) {
                    console.log(`  Categorized as PHISHING - Confidence: ${confidence}%`);
                    return 'phishing';
                }
                
                // Check suspicious based on saved flag or confidence range
                if (scan.is_suspicious === true || (confidence >= 50 && confidence < 80)) {
                    console.log(`  Categorized as SUSPICIOUS - Confidence: ${confidence}%`);
                    return 'suspicious';
                }
                
                // Default to safe
                console.log(`  Categorized as SAFE - Confidence: ${confidence}%`);
                return 'safe';
                
            } catch (error) {
                console.error('Error categorizing scan:', error, 'Scan data:', scan);
                return 'safe'; // Default to safe if there's an error
            }
        };
        
        // Count each category and analyze confidence distribution
        let phishingScans = 0;
        let suspiciousScans = 0;
        let safeScans = 0;
        
        // Track confidence score distribution and category details
        const confidenceRanges = {
            '0-10': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } },
            '11-20': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } },
            '21-30': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } },
            '31-40': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } },
            '41-50': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } },
            '51-60': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } },
            '61-70': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } },
            '71-80': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } },
            '81-90': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } },
            '91-100': { count: 0, categories: { phishing: 0, suspicious: 0, safe: 0 } }
        };
        
        // Track some example scans for debugging
        const exampleScans = [];
        
        allScans.forEach((scan, index) => {
            try {
                const confidence = scan.confidence || 0;
                const range = Math.floor(confidence / 10) * 10;
                const rangeKey = range === 100 ? '91-100' : 
                                range === 0 ? '0-10' : 
                                `${range + 1}-${range + 10}`;
                
                const category = getScanCategory(scan);
                
                // Update counters
                if (category === 'phishing') phishingScans++;
                else if (category === 'suspicious') suspiciousScans++;
                else safeScans++;
                
                // Update confidence distribution
                confidenceRanges[rangeKey].count++;
                confidenceRanges[rangeKey].categories[category]++;
                
                // Save some example scans for debugging
                if (exampleScans.length < 5 && (index % 20 === 0 || confidence >= 50)) {
                    exampleScans.push({
                        url: scan.url,
                        confidence,
                        isPhishing: scan.isPhishing,
                        is_suspicious: scan.is_suspicious,
                        category,
                        timestamp: scan.timestamp
                    });
                }
            } catch (error) {
                console.error('Error processing scan:', error, 'Scan data:', scan);
                safeScans++; // Default to safe if there's an error
            }
        });
        
        // For debugging - log detailed information
        console.log('=== SCAN STATISTICS ===');
        console.log('Total scans:', allScans.length);
        console.log('Phishing scans:', phishingScans);
        console.log('Suspicious scans:', suspiciousScans);
        console.log('Safe scans:', safeScans);
        console.log('\n=== CONFIDENCE DISTRIBUTION ===');
        Object.entries(confidenceRanges).forEach(([range, data]) => {
            if (data.count > 0) {
                console.log(`${range}% (${data.count} scans):`, {
                    phishing: data.categories.phishing || 0,
                    suspicious: data.categories.suspicious || 0,
                    safe: data.categories.safe || 0
                });
            }
        });
        console.log('\n=== EXAMPLE SCANS ===');
        exampleScans.forEach((scan, i) => {
            console.log(`Scan ${i + 1}:`, scan);
        });
        
        // Verify counts add up
        const calculatedTotal = phishingScans + suspiciousScans + safeScans;
        if (calculatedTotal !== allScans.length) {
            console.error(`\n!!! COUNT MISMATCH !!!\n` +
                        `Sum of categories (${calculatedTotal}) does not equal total scans (${allScans.length})\n` +
                        `Difference: ${Math.abs(calculatedTotal - allScans.length)}`);
        }
        
        // Get scans by date for the last 7 days with all three categories
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        
        // Use the calculated counts instead of querying the database again
        const totalScans = allScans.length;
        
        console.log('\n=== FETCHING SCANS BY DATE ===');
        const scansByDate = await UrlScan.aggregate([
            { $match: { timestamp: { $gte: sevenDaysAgo } } },
            { 
                $project: {
                    date: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
                    url: 1,
                    isPhishing: 1,
                    is_suspicious: 1,
                    confidence: { $ifNull: ["$confidence", 0] },
                    // Categorize each scan using the same logic as getScanCategory
                    category: {
                        $let: {
                            vars: {
                                // Ensure confidence is a valid number between 0-100
                                safeConfidence: {
                                    $cond: [
                                        { $and: [
                                            { $gte: ["$confidence", 0] },
                                            { $lte: ["$confidence", 100] }
                                        ]},
                                        "$confidence",
                                        0  // Default to 0 if invalid
                                    ]
                                }
                            },
                            in: {
                                $cond: [
                                    // Check for phishing first (highest priority)
                                    { $or: [
                                        { $eq: ["$isPhishing", true] },
                                        { $gte: ["$$safeConfidence", 80] }
                                    ]},
                                    "phishing",
                                    {
                                        $cond: [
                                            // Then check for suspicious
                                            { $or: [
                                                { $eq: ["$is_suspicious", true] },
                                                { $and: [
                                                    { $gte: ["$$safeConfidence", 55] },
                                                    { $lt: ["$$safeConfidence", 80] }
                                                ]}
                                            ]},
                                            "suspicious",
                                            // Default to safe
                                            "safe"
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                }
            },
            {
                $group: {
                    _id: "$date",
                    total: { $sum: 1 },
                    phishing: { $sum: { $cond: [{ $eq: ["$category", "phishing"] }, 1, 0] } },
                    suspicious: { $sum: { $cond: [{ $eq: ["$category", "suspicious"] }, 1, 0] } },
                    safe: { $sum: { $cond: [{ $eq: ["$category", "safe"] }, 1, 0] } }
                }
            },
            { $sort: { _id: 1 } }
        ]);
        
        console.log('Scans by date aggregation results:', JSON.stringify(scansByDate, null, 2));

        res.json({
            totalScans,
            phishingScans,
            suspiciousScans,
            safeScans,
            scansByDate
        });
    } catch (error) {
        console.error('Error getting statistics:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Health Check Endpoint
app.get('/api/health', async (req, res) => {
    try {
        await mongoose.connection.db.admin().ping();
        res.json({
            status: 'ok',
            database: 'connected',
            predictionService: 'local-script',
        });
    } catch (error) {
        console.error('❌ Health check failed:', error);
        res.status(500).json({
            status: 'error',
            database: 'disconnected',
            predictionService: 'unavailable',
            error: error.message,
        });
    }
});

// Socket.IO connection handler
io.on('connection', (socket) => {
    console.log('New client connected:', socket.id);
    
    // Handle test connection
    socket.on('test-connection', (data, callback) => {
        console.log('Test connection received:', data);
        if (callback) {
            callback({
                status: 'success',
                message: 'WebSocket connection is working!',
                serverTime: new Date().toISOString(),
                clientData: data
            });
        }
    });
    
    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// Test WebSocket endpoint
app.get('/api/ws-test', (req, res) => {
    res.json({
        status: 'success',
        message: 'WebSocket test endpoint is working',
        serverTime: new Date().toISOString()
    });
});

// Start server
const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log('📊 Dashboard available at http://localhost:5173');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('❌ Unhandled Rejection:', err);
    httpServer.close(() => process.exit(1));
});