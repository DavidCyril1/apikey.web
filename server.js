require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const app = express();

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/apiKeyDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

// Session Store
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/apiKeyDB',
  collectionName: 'sessions'
});

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 1 day
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  }
}));

// Models
const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

const ApiKeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  owner: { type: String, required: true },
  email: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: Date,
  lastUsed: Date,
  isActive: { type: Boolean, default: true },
  usageCount: { type: Number, default: 0 },
  rateLimit: { type: Number, default: 100 },
  tier: { type: String, enum: ['free', 'basic', 'pro', 'enterprise'], default: 'free' },
  paymentId: String,
  paymentMethod: String
});

const PaymentSchema = new mongoose.Schema({
  email: String,
  amount: Number,
  currency: String,
  paymentId: String,
  paymentMethod: String,
  status: { type: String, default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  apiKeyId: mongoose.Schema.Types.ObjectId
});

const Admin = mongoose.model('Admin', AdminSchema);
const ApiKey = mongoose.model('ApiKey', ApiKeySchema);
const Payment = mongoose.model('Payment', PaymentSchema);

// Initialize Admin Account
async function initializeAdminAccount() {
  const adminEmail = process.env.ADMIN_EMAIL || 'davidcyril209@gmail.com';
  const adminPassword = process.env.ADMIN_PASSWORD || '85200555';
  
  const existingAdmin = await Admin.findOne({ email: adminEmail });
  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash(adminPassword, 12);
    await Admin.create({
      email: adminEmail,
      password: hashedPassword
    });
    console.log('Default admin account created');
  }
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Authentication Middleware
const requireAuth = (req, res, next) => {
  if (!req.session.admin) {
    if (req.originalUrl.startsWith('/admin/api')) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    return res.redirect('/admin/login');
  }
  next();
};

// Routes

// Admin Login
app.get('/admin/login', (req, res) => {
  if (req.session.admin) {
    return res.redirect('/admin/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });
    
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Update last login
    admin.lastLogin = new Date();
    await admin.save();
    
    // Create session
    req.session.admin = {
      id: admin._id,
      email: admin.email
    };
    
    res.json({ success: true, redirect: '/admin/dashboard' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Could not log out');
    }
    res.redirect('/admin/login');
  });
});

// Admin Dashboard
app.get('/admin/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// Payment Page
app.get('/payment-page', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'payment-page.html'));
});

// API Routes
app.get('/admin/api/keys', requireAuth, async (req, res) => {
  try {
    const keys = await ApiKey.find({}).sort({ createdAt: -1 });
    res.json({ success: true, data: keys });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch API keys' });
  }
});

app.post('/admin/api/keys', requireAuth, async (req, res) => {
  try {
    const { owner, email, tier, rateLimit } = req.body;
    
    // Generate a secure random API key
    const key = crypto.randomBytes(32).toString('hex');
    
    const newKey = new ApiKey({
      key,
      owner,
      email,
      tier: tier || 'free',
      rateLimit: rateLimit || 100,
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year from now
    });
    
    await newKey.save();
    
    res.json({ success: true, data: newKey });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to create API key' });
  }
});

app.put('/admin/api/keys/:id', requireAuth, async (req, res) => {
  try {
    const { isActive, rateLimit, tier } = req.body;
    const key = await ApiKey.findByIdAndUpdate(
      req.params.id,
      { isActive, rateLimit, tier },
      { new: true }
    );
    
    if (!key) {
      return res.status(404).json({ success: false, message: 'API key not found' });
    }
    
    res.json({ success: true, data: key });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update API key' });
  }
});

app.delete('/admin/api/keys/:id', requireAuth, async (req, res) => {
  try {
    await ApiKey.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'API key deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete API key' });
  }
});

// Payment Routes
app.get('/admin/api/payments', requireAuth, async (req, res) => {
  try {
    const payments = await Payment.find({}).sort({ createdAt: -1 });
    res.json({ success: true, data: payments });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to fetch payments' });
  }
});

// Payment Verification Webhook
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { paymentId, paymentMethod, email, amount, currency, status } = req.body;
    
    // In a real application, verify payment with payment gateway here
    const paymentVerified = true; // Placeholder
    
    if (paymentVerified) {
      // Create payment record
      const payment = new Payment({
        email,
        amount,
        currency,
        paymentId,
        paymentMethod,
        status: status || 'completed'
      });
      
      await payment.save();
      
      // Generate API key
      const key = crypto.randomBytes(32).toString('hex');
      const newKey = new ApiKey({
        key,
        owner: email.split('@')[0],
        email,
        tier: getTierFromAmount(amount),
        paymentId,
        paymentMethod,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
      });
      
      await newKey.save();
      
      // Link payment to API key
      payment.apiKeyId = newKey._id;
      await payment.save();
      
      return res.json({ 
        success: true, 
        key,
        tier: newKey.tier,
        expiresAt: newKey.expiresAt
      });
    } else {
      return res.status(400).json({ success: false, message: 'Payment verification failed' });
    }
  } catch (err) {
    console.error('Payment verification error:', err);
    res.status(500).json({ success: false, message: 'Payment verification error' });
  }
});

// Helper function to determine tier based on payment amount
function getTierFromAmount(amount) {
  if (amount >= 2500) return 'enterprise';
  if (amount >= 1200) return 'pro';
  if (amount >= 500) return 'basic';
  return 'free';
}

// API Key Validation Middleware
app.use('/api', async (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;
  
  if (!apiKey) {
    return res.status(401).json({ 
      success: false,
      message: 'API key is required'
    });
  }
  
  try {
    const keyRecord = await ApiKey.findOne({ key: apiKey, isActive: true });
    
    if (!keyRecord) {
      return res.status(403).json({ 
        success: false,
        message: 'Invalid API key'
      });
    }
    
    // Check if key has expired
    if (keyRecord.expiresAt && new Date() > keyRecord.expiresAt) {
      return res.status(403).json({ 
        success: false,
        message: 'API key has expired'
      });
    }
    
    // Update usage stats
    keyRecord.lastUsed = new Date();
    keyRecord.usageCount += 1;
    await keyRecord.save();
    
    // Attach key info to request
    req.apiKey = {
      tier: keyRecord.tier,
      rateLimit: keyRecord.rateLimit,
      owner: keyRecord.owner
    };
    
    next();
  } catch (err) {
    console.error('API key validation error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error'
    });
  }
});

// Rate Limiting Middleware
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: (req) => req.apiKey?.rateLimit || 100, // Use key's rate limit or default
  message: {
    success: false,
    message: 'Too many requests, please try again later.'
  }
});
app.use('/api', apiLimiter);

// Example API Endpoint
app.get('/api/data', (req, res) => {
  res.json({
    success: true,
    data: {
      message: 'This is protected data',
      tier: req.apiKey.tier,
      owner: req.apiKey.owner
    }
  });
});

// Initialize and Start Server
async function startServer() {
  await initializeAdminAccount();
  
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin dashboard: http://localhost:${PORT}/admin/login`);
    console.log(`Payment page: http://localhost:${PORT}/payment-page`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
