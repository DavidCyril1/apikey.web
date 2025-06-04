require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const crypto = require('crypto');
const path = require('path');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const jwt = require('jsonwebtoken');
const winston = require('winston');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ],
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => logger.info('Connected to MongoDB Database'))
.catch(err => logger.error('MongoDB connection error:', err));

// API Key Schema
const apiKeySchema = new mongoose.Schema({
  key: { 
    type: String, 
    required: true, 
    unique: true 
  },
  owner: { 
    type: String, 
    required: true 
  },
  ownerName: {
    type: String,
    required: true
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  lastUsed: Date,
  isActive: { 
    type: Boolean, 
    default: true 
  },
  usageCount: { 
    type: Number, 
    default: 0 
  },
  rateLimit: { 
    type: Number, 
    default: 100 
  },
  plan: {
    type: String,
    enum: ['basic', 'pro', 'enterprise', 'custom'],
    default: 'basic'
  },
  paymentReference: String,
  description: String
});

const ApiKey = mongoose.model('ApiKey', apiKeySchema);

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    creator: "David Cyril",
    success: false,
    status: 429,
    message: "Too many requests, please try again later."
  }
});

// Session configuration for admin panel
app.use(session({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Passport configuration for admin authentication
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
        return done(null, {
          email: process.env.ADMIN_EMAIL,
          name: 'David Cyril',
          role: 'admin'
        });
      } else {
        return done(null, false, { message: 'Invalid email or password' });
      }
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.email);
});

passport.deserializeUser(async (email, done) => {
  if (email === process.env.ADMIN_EMAIL) {
    done(null, {
      email: process.env.ADMIN_EMAIL,
      name: 'David Cyril',
      role: 'admin'
    });
  } else {
    done(new Error('User not found'));
  }
});

app.use(passport.initialize());
app.use(passport.session());

// API Routes
app.use('/api', apiLimiter);

// API Key verification middleware
app.use('/api', async (req, res, next) => {
  try {
    const apiKey = req.query.apikey || req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({
        creator: "David Cyril",
        success: false,
        status: 401,
        message: "API key is required. Please include an apikey parameter or x-api-key header."
      });
    }

    const keyRecord = await ApiKey.findOne({ key: apiKey, isActive: true });
    
    if (!keyRecord) {
      return res.status(403).json({
        creator: "David Cyril",
        success: false,
        status: 403,
        message: "Invalid API key. Please provide a valid key."
      });
    }

    // Update usage statistics
    keyRecord.lastUsed = new Date();
    keyRecord.usageCount += 1;
    await keyRecord.save();

    // Attach key info to request for later use
    req.apiKeyInfo = {
      owner: keyRecord.owner,
      rateLimit: keyRecord.rateLimit
    };

    next();
  } catch (err) {
    logger.error('API key verification error:', err);
    return res.status(500).json({
      creator: "David Cyril",
      success: false,
      status: 500,
      message: "Internal server error during API key verification."
    });
  }
});

// Payment verification endpoint
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { transactionId, gateway, plan } = req.body;
    
    // In a real implementation, verify with payment provider's API
    // This is a simplified version
    logger.info(`Verifying ${gateway} payment: ${transactionId}`);
    
    let verified = false;
    
    if (gateway === 'paystack' || gateway === 'flutterwave') {
      // Simulate verification for demo
      verified = true;
    }
    
    if (verified) {
      res.json({
        success: true,
        plan: plan
      });
    } else {
      res.status(400).json({
        success: false,
        message: "Payment verification failed"
      });
    }
  } catch (err) {
    logger.error('Payment verification error:', err);
    res.status(500).json({
      success: false,
      message: 'Payment verification failed'
    });
  }
});

// Generate API key endpoint
app.post('/api/generate-key', async (req, res) => {
  try {
    const { email, name, rateLimit, plan, paymentReference } = req.body;
    
    // Generate a secure API key
    const apiKeyValue = `api_${crypto.randomBytes(16).toString('hex')}`;
    
    // Create key record
    const newKey = new ApiKey({
      key: apiKeyValue,
      owner: email,
      ownerName: name,
      rateLimit: rateLimit,
      plan: plan,
      paymentReference: paymentReference
    });
    
    await newKey.save();
    
    logger.info(`Generated new API key for ${email}`);
    
    res.json({
      success: true,
      apiKey: newKey
    });
  } catch (err) {
    logger.error('Error generating API key:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to generate API key'
    });
  }
});

// Get API key details
app.get('/api/key-details', async (req, res) => {
  try {
    const keyId = req.query.id;
    const key = await ApiKey.findOne({ _id: keyId });
    
    if (!key) {
      return res.status(404).json({
        success: false,
        message: 'API key not found'
      });
    }
    
    res.json({
      success: true,
      apiKey: key
    });
  } catch (err) {
    logger.error('Error fetching API key details:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch API key details'
    });
  }
});

// Admin routes
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ success: false, message: 'Unauthorized' });
};

// Admin login
app.post('/admin/login', passport.authenticate('local'), (req, res) => {
  const token = jwt.sign(
    { email: req.user.email, role: req.user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );
  
  res.json({
    success: true,
    token,
    user: req.user
  });
});

// Admin logout
app.post('/admin/logout', (req, res) => {
  req.logout();
  res.json({ success: true, message: 'Logged out successfully' });
});

// Admin API key management
app.get('/admin/api-keys', ensureAuthenticated, async (req, res) => {
  try {
    const keys = await ApiKey.find({});
    res.json({
      success: true,
      data: keys
    });
  } catch (err) {
    logger.error('Error fetching API keys:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve API keys'
    });
  }
});

app.post('/admin/api-keys', ensureAuthenticated, async (req, res) => {
  try {
    const newKey = new ApiKey({
      key: `api_${crypto.randomBytes(16).toString('hex')}`,
      owner: req.body.owner,
      ownerName: req.body.ownerName,
      description: req.body.description,
      rateLimit: req.body.rateLimit || 100,
      plan: req.body.plan || 'custom'
    });
    
    await newKey.save();
    
    logger.info(`Admin created new API key for ${req.body.owner}`);
    
    res.status(201).json({
      success: true,
      data: newKey
    });
  } catch (err) {
    logger.error('Error creating API key:', err);
    res.status(400).json({
      success: false,
      message: "Failed to create API key"
    });
  }
});

// Serve static files for the frontend
app.use(express.static(path.join(__dirname, 'public')));

// Serve admin panel
app.get('/admin*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something broke!',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV}`);
});
