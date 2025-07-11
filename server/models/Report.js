// models/Report.js
const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  url: { type: String, required: true },
  isPhishing: { type: Boolean, required: true },
  comments: { type: String },
  date: { type: Date, default: Date.now }
});

const Report = mongoose.model('Report', reportSchema);

module.exports = Report;
