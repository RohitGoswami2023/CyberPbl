// db.js - MongoDB Connection Setup
const mongoose = require('mongoose');
require('dotenv').config();

// Create the connection function
const connectDB = async () => {
    console.log('Attempting to connect to MongoDB...');
    try {
        mongoose.set('strictQuery', false);
        const conn = await mongoose.connect(
            process.env.MONGO_URI || 'mongodb://localhost:27017/cyberpbl'
        );
        console.log('✅ MongoDB Connected:', conn.connection.host);
        return conn;
    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error.message);
        process.exit(1);
    }
};

// Event handlers
mongoose.connection.on('connected', () => {
    console.log('✅ Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
    console.error('❌ Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('ℹ️  Mongoose disconnected from MongoDB');
});

// Graceful shutdown
process.on('SIGINT', async () => {
    try {
        await mongoose.connection.close();
        console.log('ℹ️  MongoDB connection closed');
        process.exit(0);
    } catch (err) {
        console.error('❌ Error closing MongoDB connection:', err);
        process.exit(1);
    }
});

// Export the function
module.exports = connectDB;
