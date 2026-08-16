// server.js - BIU BedCheck with InsightFace Face Recognition
// SECURE PRODUCTION VERSION v4.3.0 - COMPLETE WITH ALL ENDPOINTS

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');
const { body, validationResult, param, query } = require('express-validator');
const crypto = require('crypto');
require('dotenv').config();

// =====================================================
// DASHBOARD ROUTES - Role to Page Mapping (Server Side)
// =====================================================

const DASHBOARD_ROUTES = {
    'Administrator': '/admin/index.html',
    'RASD': '/RASD/rasd-index.html',
    'HRA': '/HRA/hra-index.html',
    'RA': '/RA/ra-index.html',
    'System Owner': '/system-owner/index.html'
};

// =====================================================
// CONFIGURATION & VALIDATION
// =====================================================

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;

// Trust proxy - Required for Render.com
app.set('trust proxy', 1);

// Validate required environment variables
const requiredEnvVars = [
    'SUPABASE_URL',
    'SUPABASE_SERVICE_KEY',
    'JWT_SECRET',
    'FACE_API_URL'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:');
    missingVars.forEach(v => console.error(`   - ${v}`));
    if (process.env.NODE_ENV === 'production') {
        process.exit(1);
    }
}

// Validate JWT secret strength
if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    console.warn('⚠️ JWT_SECRET is too short. Use at least 32 characters.');
}

// =====================================================
// SUPABASE CONNECTION
// =====================================================

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ Missing Supabase credentials in .env file');
    console.error('Please set SUPABASE_URL and SUPABASE_SERVICE_KEY');
    if (process.env.NODE_ENV === 'production') {
        process.exit(1);
    }
}

const supabase = createClient(supabaseUrl, supabaseKey, {
    auth: {
        autoRefreshToken: false,
        persistSession: false
    }
});

// =====================================================
// CAMPUS CONTEXT HELPER
// =====================================================

const getCampusContext = (req) => {
    const headerCampus = req.headers['x-campus'];
    if (headerCampus && ['Legacy', 'Heritage'].includes(headerCampus)) {
        return headerCampus;
    }
    if (req.user && req.user.campus) {
        return req.user.campus;
    }
    return 'Legacy';
};

// =====================================================
// INSIGHTFACE CONFIGURATION
// =====================================================

const FACE_API_URL = process.env.FACE_API_URL || 'http://localhost:8000';
const FACE_API_TIMEOUT = 30000;

console.log('🔐 Environment:', process.env.NODE_ENV || 'production');
console.log('🔐 Face API URL:', FACE_API_URL);

// =====================================================
// INSIGHTFACE SERVICE
// =====================================================

class InsightFaceService {
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
    }

    async checkHealth() {
        try {
            const response = await axios.get(`${this.apiUrl}/health`, {
                timeout: 5000,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Face API health check error:', error.message);
            return { status: 'unhealthy', error: error.message };
        }
    }

    async detectFace(imageBase64) {
        try {
            const imageData = this._sanitizeImage(imageBase64);
            const response = await axios.post(`${this.apiUrl}/detect-face`, {
                image: imageData
            }, {
                timeout: FACE_API_TIMEOUT,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Face detection error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.detail || error.message };
        }
    }

    async enrollFace(imageBase64, studentId, hostel, room, name) {
        try {
            const imageData = this._sanitizeImage(imageBase64);
            const response = await axios.post(`${this.apiUrl}/enroll-face`, {
                image: imageData,
                student_id: studentId,
                hostel: hostel,
                room: room,
                name: name
            }, {
                timeout: FACE_API_TIMEOUT,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Face enrollment error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.detail || error.message };
        }
    }

    async enrollBulk(frames, studentId, hostel, room, name) {
        try {
            const imageDataList = frames.map(frame => this._sanitizeImage(frame));
            const response = await axios.post(`${this.apiUrl}/enroll-bulk`, {
                frames: imageDataList,
                student_id: studentId,
                hostel: hostel,
                room: room,
                name: name
            }, {
                timeout: FACE_API_TIMEOUT * 2,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Bulk enrollment error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.detail || error.message };
        }
    }

    async verifyFace(imageBase64, storedEmbedding, threshold = 0.55) {
        try {
            const imageData = this._sanitizeImage(imageBase64);
            const response = await axios.post(`${this.apiUrl}/verify-face`, {
                image: imageData,
                stored_embedding: storedEmbedding,
                threshold: threshold
            }, {
                timeout: FACE_API_TIMEOUT,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Face verification error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.detail || error.message };
        }
    }

    async verifyMultiple(imageBase64, embeddings, studentIds, threshold = 0.55) {
        try {
            const imageData = this._sanitizeImage(imageBase64);
            const response = await axios.post(`${this.apiUrl}/verify-multiple`, {
                image: imageData,
                embeddings: embeddings,
                student_ids: studentIds,
                threshold: threshold
            }, {
                timeout: FACE_API_TIMEOUT,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Multiple verification error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.detail || error.message };
        }
    }

    async checkLiveness(imageBase64) {
        try {
            const imageData = this._sanitizeImage(imageBase64);
            const response = await axios.post(`${this.apiUrl}/check-liveness`, {
                image: imageData
            }, {
                timeout: FACE_API_TIMEOUT,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Liveness check error:', error.response?.data || error.message);
            return { is_live: false, error: error.response?.data?.detail || error.message };
        }
    }

    async resetLiveness() {
        try {
            const response = await axios.post(`${this.apiUrl}/reset-liveness`, {}, {
                timeout: 5000,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Reset liveness error:', error.message);
            return { success: false, error: error.message };
        }
    }

    async compareEmbeddings(embedding1, embedding2) {
        try {
            const response = await axios.post(`${this.apiUrl}/compare-embeddings`, {
                embedding1: embedding1,
                embedding2: embedding2
            }, {
                timeout: FACE_API_TIMEOUT,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Compare embeddings error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.detail || error.message };
        }
    }

    async extractEmbedding(imageBase64) {
        try {
            const imageData = this._sanitizeImage(imageBase64);
            const response = await axios.post(`${this.apiUrl}/extract-embedding`, {
                image: imageData
            }, {
                timeout: FACE_API_TIMEOUT,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            return response.data;
        } catch (error) {
            console.error('Extract embedding error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.detail || error.message };
        }
    }

    _sanitizeImage(imageBase64) {
        return imageBase64.replace(/^data:image\/\w+;base64,/, '');
    }
}

const faceService = new InsightFaceService(FACE_API_URL);

// =====================================================
// SECURITY MIDDLEWARE
// =====================================================

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: true,
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true
}));

// CORS - Updated for Vercel frontend
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(o => o.length > 0)
    : [];

// Add default origins for development and Vercel
const defaultOrigins = [
    'https://bed-check-biu.vercel.app',
    'https://bed-check-biu-*.vercel.app',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173'
];

// Combine origins
const allOrigins = [...allowedOrigins, ...defaultOrigins];

if (allOrigins.length === 0 && process.env.NODE_ENV === 'production') {
    console.warn('⚠️ ALLOWED_ORIGINS not set in production - CORS will be restrictive');
}

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) {
            return callback(null, true);
        }
        
        if (process.env.NODE_ENV === 'development' && origin.includes('localhost')) {
            return callback(null, true);
        }
        
        const isAllowed = allOrigins.some(allowed => {
            if (allowed.includes('*')) {
                const pattern = allowed.replace(/\*/g, '.*');
                const regex = new RegExp(`^${pattern}$`);
                return regex.test(origin);
            }
            return allowed === origin;
        });
        
        if (isAllowed) {
            callback(null, true);
        } else {
            console.warn(`❌ CORS blocked: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Staff-ID', 'X-Staff-Name', 'X-Staff-Role', 'X-Campus'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining'],
    credentials: true,
    optionsSuccessStatus: 200,
    maxAge: 86400
};

app.use(cors(corsOptions));

// Rate limiting - Updated to handle proxy
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    },
    validate: {
        xForwardedForHeader: false,
    }
});
app.use('/api', globalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { success: false, message: 'Too many login attempts. Please try again after 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    },
    validate: {
        xForwardedForHeader: false,
    }
});

const faceLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { success: false, message: 'Too many verification attempts. Please wait.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.ip || req.headers['x-forwarded-for'] || 'unknown';
    },
    validate: {
        xForwardedForHeader: false,
    }
});

app.use(express.json({ 
    limit: '5mb',
    verify: (req, res, buf) => {
        try {
            JSON.parse(buf);
        } catch (e) {
            res.status(400).json({ success: false, message: 'Invalid JSON payload' });
            throw new Error('Invalid JSON');
        }
    }
}));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// Request logging middleware - Minimal for security
app.use((req, res, next) => {
    req.clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
    req.userAgent = req.headers['user-agent'] || 'unknown';
    if (process.env.NODE_ENV === 'development') {
        const sanitizedPath = req.path.replace(/\d+/g, '[id]');
        console.log(`📨 ${req.method} ${sanitizedPath}`);
    }
    next();
});

// =====================================================
// JWT AUTHENTICATION MIDDLEWARE
// =====================================================

const JWT_SECRET = process.env.JWT_SECRET;

const generateToken = (user) => {
    return jwt.sign(
        { 
            id: user.id,
            username: user.username,
            role: user.role,
            hostel_id: user.hostel_id,
            campus: user.campus
        },
        JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRY || '8h' }
    );
};

const verifyToken = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
};

const authMiddleware = async (req, res, next) => {
    const publicPaths = ['/api/auth/login', '/api/face/health', '/health', '/'];
    if (publicPaths.includes(req.path)) {
        return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
            success: false, 
            message: 'Authentication required. Please provide a valid token.' 
        });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);
    
    if (!decoded) {
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid or expired token. Please login again.' 
        });
    }

    const { data: user, error } = await supabase
        .from('staff')
        .select('id, role, status, hostel_id, name, username, campus')
        .eq('id', decoded.id)
        .single();

    if (error || !user || user.status !== 'Active') {
        return res.status(401).json({ 
            success: false, 
            message: 'User account not found or inactive.' 
        });
    }

    req.user = { ...decoded, ...user };
    req.campus = user.campus || 'Legacy';
    next();
};

const requireRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Authentication required' });
        }
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                success: false, 
                message: `Access denied. Required role: ${roles.join(' or ')}` 
            });
        }
        next();
    };
};

const campusIsolation = (req, res, next) => {
    const campus = getCampusContext(req);
    if (!campus || !['Legacy', 'Heritage'].includes(campus)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid campus context'
        });
    }
    req.campus = campus;
    next();
};

// =====================================================
// INPUT VALIDATION HELPERS
// =====================================================

const validate = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        const errors = validationResult(req);
        if (errors.isEmpty()) {
            return next();
        }
        const sanitizedErrors = errors.array().map(err => ({
            field: err.param,
            message: err.msg
        }));
        return res.status(400).json({ 
            success: false, 
            message: 'Validation error',
            errors: sanitizedErrors
        });
    };
};

// =====================================================
// VALIDATORS
// =====================================================

const validators = {
    login: [
        body('username').trim().notEmpty().withMessage('Username is required'),
        body('password').notEmpty().withMessage('Password is required')
    ],
    createStaff: [
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('username').trim().notEmpty().withMessage('Username is required')
            .isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
        body('role').isIn(['RA', 'HRA', 'Admin', 'RASD', 'System Owner']).withMessage('Invalid role'),
        body('email').optional().isEmail().withMessage('Invalid email address'),
        body('campus').optional().isIn(['Legacy', 'Heritage']).withMessage('Invalid campus')
    ],
    updateStaff: [
        body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
        body('role').optional().isIn(['RA', 'HRA', 'Admin', 'RASD', 'System Owner']).withMessage('Invalid role'),
        body('email').optional().isEmail().withMessage('Invalid email address'),
        body('campus').optional().isIn(['Legacy', 'Heritage']).withMessage('Invalid campus')
    ],
    changePassword: [
        body('currentPassword').notEmpty().withMessage('Current password is required'),
        body('newPassword')
            .notEmpty().withMessage('New password is required')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
            .withMessage('Password must contain uppercase, lowercase, number, and special character')
    ],
    createStudent: [
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('matric').trim().notEmpty().withMessage('Matric number is required'),
        body('gender').optional().isIn(['Male', 'Female']).withMessage('Invalid gender'),
        body('phone').optional().isMobilePhone().withMessage('Invalid phone number'),
        body('email').optional().isEmail().withMessage('Invalid email address'),
        body('campus').optional().isIn(['Legacy', 'Heritage']).withMessage('Invalid campus')
    ],
    updateStudent: [
        body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
        body('matric').optional().trim().notEmpty().withMessage('Matric number cannot be empty'),
        body('gender').optional().isIn(['Male', 'Female']).withMessage('Invalid gender'),
        body('phone').optional().isMobilePhone().withMessage('Invalid phone number'),
        body('email').optional().isEmail().withMessage('Invalid email address'),
        body('status').optional().isIn(['Present', 'Absent', 'Late', 'Completed']).withMessage('Invalid status'),
        body('campus').optional().isIn(['Legacy', 'Heritage']).withMessage('Invalid campus')
    ],
    faceImage: [
        body('image').notEmpty().withMessage('Image is required')
            .custom(value => {
                if (value.length > 10 * 1024 * 1024) {
                    throw new Error('Image too large (max 10MB)');
                }
                return true;
            })
    ],
    faceVerify: [
        body('image').notEmpty().withMessage('Image is required'),
        body('student_id').optional().isInt().withMessage('Invalid student ID'),
        body('matric').optional().isString().withMessage('Invalid matric number'),
        body('threshold').optional().isFloat({ min: 0.3, max: 0.9 }).withMessage('Threshold must be between 0.3 and 0.9')
    ],
    hostelId: [
        param('id').isInt().withMessage('Invalid hostel ID')
    ],
    studentId: [
        param('id').isInt().withMessage('Invalid student ID')
    ],
    staffId: [
        param('id').isInt().withMessage('Invalid staff ID')
    ],
    floorFlatId: [
        param('id').isInt().withMessage('Invalid floor/flat ID')
    ],
    roomId: [
        param('id').isInt().withMessage('Invalid room ID')
    ],
    bedSpaceId: [
        param('id').isInt().withMessage('Invalid bed space ID')
    ],
    sessionId: [
        param('id').isInt().withMessage('Invalid session ID')
    ],
    pagination: [
        query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
        query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be 0 or greater')
    ],
    hostelCreate: [
        body('name').trim().notEmpty().withMessage('Hostel name is required'),
        body('gender').optional().isIn(['Male', 'Female', 'Mixed']).withMessage('Invalid gender'),
        body('type').optional().isIn(['floor', 'flat']).withMessage('Invalid type'),
        body('campus').optional().isIn(['Legacy', 'Heritage']).withMessage('Invalid campus')
    ],
    roomCreate: [
        body('floor_flat_id').isInt().withMessage('Invalid floor/flat ID'),
        body('room_code').trim().notEmpty().withMessage('Room code is required')
    ],
    bedSpaceCreate: [
        body('room_id').isInt().withMessage('Invalid room ID'),
        body('bed_code').trim().notEmpty().withMessage('Bed code is required')
    ],
    floorFlatCreate: [
        body('hostel_id').isInt().withMessage('Invalid hostel ID'),
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('type').optional().isIn(['floor', 'flat']).withMessage('Invalid type')
    ],
    bedcheckScan: [
        body('session_id').optional().isInt().withMessage('Invalid session ID'),
        body('student_id').optional().isInt().withMessage('Invalid student ID'),
        body('room').optional().isString().withMessage('Invalid room'),
        body('status').optional().isIn(['Verified', 'Failed']).withMessage('Invalid status')
    ],
    bedcheckSession: [
        body('hostel_id').isInt().withMessage('Invalid hostel ID'),
        body('date').optional().isISO8601().withMessage('Invalid date format'),
        body('status').optional().isIn(['Active', 'Submitted', 'Approved', 'Rejected']).withMessage('Invalid status')
    ],
    sessionCreate: [
        body('date').optional().isISO8601().withMessage('Invalid date format'),
        body('status').optional().isIn(['active', 'archived']).withMessage('Invalid status'),
        body('campus').optional().isIn(['Legacy', 'Heritage']).withMessage('Invalid campus')
    ],
    submissionState: [
        body('state').isIn(['Open', 'Closed']).withMessage('Invalid state'),
        body('notice').optional().isString().withMessage('Invalid notice')
    ],
    campus: [
        query('campus').optional().isIn(['Legacy', 'Heritage']).withMessage('Invalid campus')
    ],
    raRoomAssignment: [
        body('ra_id').isInt().withMessage('Invalid RA ID'),
        body('room_ids').isArray({ min: 1 }).withMessage('At least one room is required')
    ],
    bedcheckStart: [
        body('session_id').isInt().withMessage('session_id is required')
    ],
    suspiciousResolve: [
        body('resolution').isIn(['cleared', 'warning', 'escalated']).withMessage('Invalid resolution status'),
        body('notes').optional().isString().withMessage('notes must be a string')
    ]
};

// =====================================================
// HELPER FUNCTIONS
// =====================================================

function getStaffId(req) {
    const headerId = req.headers['x-staff-id'];
    if (headerId) return parseInt(headerId);
    const queryId = req.query.staff_id;
    if (queryId) return parseInt(queryId);
    const bodyId = req.body?.staff_id;
    if (bodyId) return parseInt(bodyId);
    return null;
}

// =====================================================
// AUDIT SERVICE
// =====================================================

const auditService = {
    async log(params) {
        try {
            const sanitized = {
                actor: params.actor || 'System',
                actor_id: params.actor_id || null,
                actor_role: params.actor_role || 'System',
                action: params.action || 'Unknown Action',
                module: params.module || 'system',
                details: (params.details || '').substring(0, 2000),
                context: (params.context || params.action || '').substring(0, 500),
                result: params.result || 'success',
                category: params.category || 'system',
                tone: params.tone || 'blue',
                hostel_id: params.hostel_id || null,
                floor_flat_id: params.floor_flat_id || null,
                room_id: params.room_id || null,
                student_id: params.student_id || null,
                session_id: params.session_id || null,
                ip_address: params.ip_address || null,
                user_agent: params.user_agent || null,
                metadata: params.metadata || {},
                time: params.time || new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
                created_at: new Date().toISOString(),
                campus: params.campus || null
            };

            const { data, error } = await supabase
                .from('audit_logs')
                .insert(sanitized)
                .select()
                .single();

            if (error) throw error;
            console.log(`📝 Audit Log: ${params.actor} (${params.actor_role}) - ${params.action} [${params.result}]`);
            return data;
        } catch (error) {
            console.error('❌ Failed to create audit log:', error);
            return null;
        }
    },

    async getLogs(filters = {}) {
        try {
            let query = supabase.from('audit_logs').select('*', { count: 'exact' });
            if (filters.hostel_id) query = query.eq('hostel_id', parseInt(filters.hostel_id));
            if (filters.actor) query = query.ilike('actor', `%${filters.actor}%`);
            if (filters.action) query = query.ilike('action', `%${filters.action}%`);
            if (filters.module) query = query.eq('module', filters.module);
            if (filters.category) query = query.eq('category', filters.category);
            if (filters.result) query = query.eq('result', filters.result);
            if (filters.actor_role) query = query.eq('actor_role', filters.actor_role);
            if (filters.campus) query = query.eq('campus', filters.campus);
            if (filters.from_date) query = query.gte('created_at', new Date(filters.from_date).toISOString());
            if (filters.to_date) query = query.lte('created_at', new Date(filters.to_date).toISOString());
            if (filters.search) {
                const searchTerm = `%${filters.search}%`;
                query = query.or(`actor.ilike.${searchTerm},action.ilike.${searchTerm},details.ilike.${searchTerm},context.ilike.${searchTerm}`);
            }

            const limit = Math.min(parseInt(filters.limit) || 50, 100);
            const offset = parseInt(filters.offset) || 0;
            query = query.order('created_at', { ascending: false }).range(offset, offset + limit - 1);

            const { data, error, count } = await query;
            if (error) throw error;

            return { success: true, data, total: count || 0, limit, offset };
        } catch (error) {
            console.error('❌ Failed to get audit logs:', error);
            return { success: false, error: error.message, data: [] };
        }
    },

    async getRecentActivity(hostel_id = null, limit = 10) {
        try {
            let query = supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(limit);
            if (hostel_id) query = query.eq('hostel_id', hostel_id);
            const { data, error } = await query;
            if (error) throw error;
            return data.map(log => ({
                time: new Date(log.created_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
                actor: log.actor,
                action: log.action,
                context: log.context || '',
                tone: log.tone || 'blue',
                details: log.details || '',
                result: log.result || 'success'
            }));
        } catch (error) {
            console.error('❌ Failed to get recent activity:', error);
            return [];
        }
    },

    async getStats(filters = {}) {
        try {
            let query = supabase.from('audit_logs').select('*', { count: 'exact' });
            if (filters.hostel_id) query = query.eq('hostel_id', parseInt(filters.hostel_id));
            if (filters.campus) query = query.eq('campus', filters.campus);
            if (filters.from_date) query = query.gte('created_at', new Date(filters.from_date).toISOString());
            if (filters.to_date) query = query.lte('created_at', new Date(filters.to_date).toISOString());

            const { data, error } = await query;
            if (error) throw error;

            const stats = {
                total: data.length,
                byResult: {},
                byCategory: {},
                byModule: {},
                byActor: {},
                today: 0,
                thisWeek: 0,
                thisMonth: 0
            };

            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const weekAgo = new Date(today);
            weekAgo.setDate(weekAgo.getDate() - 7);
            const monthAgo = new Date(today);
            monthAgo.setMonth(monthAgo.getMonth() - 1);

            data.forEach(log => {
                const date = new Date(log.created_at);
                stats.byResult[log.result] = (stats.byResult[log.result] || 0) + 1;
                stats.byCategory[log.category] = (stats.byCategory[log.category] || 0) + 1;
                stats.byModule[log.module] = (stats.byModule[log.module] || 0) + 1;
                stats.byActor[log.actor] = (stats.byActor[log.actor] || 0) + 1;
                if (date >= today) stats.today++;
                if (date >= weekAgo) stats.thisWeek++;
                if (date >= monthAgo) stats.thisMonth++;
            });

            return { success: true, data: stats };
        } catch (error) {
            console.error('❌ Failed to get audit stats:', error);
            return { success: false, error: error.message };
        }
    }
};

// =====================================================
// AUDIT EVENTS
// =====================================================

const auditEvents = {
    async loginSuccess(user, req) {
        return auditService.log({
            actor: user.name,
            actor_id: user.id,
            actor_role: user.role,
            action: 'Login Success',
            module: 'auth',
            details: `${user.name} (${user.username}) logged in successfully`,
            context: `User logged in with role ${user.role}`,
            result: 'success',
            category: 'auth',
            tone: 'green',
            hostel_id: user.hostel_id,
            campus: user.campus || 'Legacy',
            ip_address: req?.clientIp,
            user_agent: req?.userAgent
        });
    },

    async loginFailed(username, req) {
        return auditService.log({
            actor: username || 'Unknown',
            action: 'Login Failed',
            module: 'auth',
            details: `Failed login attempt for ${username || 'unknown user'}`,
            context: `Login failed from ${req?.clientIp || 'unknown IP'}`,
            result: 'failed',
            category: 'auth',
            tone: 'red',
            campus: req?.campus || 'Legacy',
            ip_address: req?.clientIp,
            user_agent: req?.userAgent
        });
    },

    async sessionCreated(session, hostel, actor) {
        return auditService.log({
            actor: actor?.name || 'System',
            actor_id: actor?.id,
            actor_role: actor?.role || 'System',
            action: 'Created BedCheck Session',
            module: 'bedcheck',
            details: `BedCheck session created for ${hostel?.name || 'Unknown Hostel'}`,
            context: `Session ID: ${session?.id}`,
            result: 'success',
            category: 'bedcheck',
            tone: 'blue',
            hostel_id: hostel?.id,
            session_id: session?.id,
            campus: hostel?.campus || 'Legacy'
        });
    },

    async sessionStarted(session, hostel, actor) {
        return auditService.log({
            actor: actor?.name || 'RA',
            actor_id: actor?.id,
            actor_role: actor?.role || 'RA',
            action: 'Started BedCheck Session',
            module: 'bedcheck',
            details: `RA ${actor?.name} started BedCheck for ${hostel?.name}`,
            context: `Session ID: ${session?.id}`,
            result: 'success',
            category: 'bedcheck',
            tone: 'green',
            hostel_id: hostel?.id,
            session_id: session?.id,
            campus: hostel?.campus || 'Legacy'
        });
    },

    async sessionSubmitted(session, hostel, actor, floor) {
        return auditService.log({
            actor: actor?.name || 'RA',
            actor_id: actor?.id,
            actor_role: actor?.role || 'RA',
            action: 'Submitted BedCheck',
            module: 'bedcheck',
            details: `RA ${actor?.name} submitted BedCheck for ${hostel?.name} - ${floor?.name || 'All Floors'}`,
            context: `Session ID: ${session?.id}`,
            result: 'success',
            category: 'bedcheck',
            tone: 'gold',
            hostel_id: hostel?.id,
            floor_flat_id: floor?.id,
            session_id: session?.id,
            campus: hostel?.campus || 'Legacy'
        });
    },

    async sessionApproved(session, hostel, actor) {
        return auditService.log({
            actor: actor?.name || 'HRA',
            actor_id: actor?.id,
            actor_role: actor?.role || 'HRA',
            action: 'Approved BedCheck',
            module: 'bedcheck',
            details: `HRA ${actor?.name} approved BedCheck for ${hostel?.name}`,
            context: `Session ID: ${session?.id}`,
            result: 'success',
            category: 'bedcheck',
            tone: 'green',
            hostel_id: hostel?.id,
            session_id: session?.id,
            campus: hostel?.campus || 'Legacy'
        });
    },

    async sessionRejected(session, hostel, actor, reason) {
        return auditService.log({
            actor: actor?.name || 'HRA',
            actor_id: actor?.id,
            actor_role: actor?.role || 'HRA',
            action: 'Rejected BedCheck',
            module: 'bedcheck',
            details: `HRA ${actor?.name} rejected BedCheck for ${hostel?.name}: ${reason || 'No reason provided'}`,
            context: `Session ID: ${session?.id}`,
            result: 'failed',
            category: 'bedcheck',
            tone: 'red',
            hostel_id: hostel?.id,
            session_id: session?.id,
            campus: hostel?.campus || 'Legacy'
        });
    },

    async sessionReturned(session, hostel, actor, reason) {
        return auditService.log({
            actor: actor?.name || 'HRA',
            actor_id: actor?.id,
            actor_role: actor?.role || 'HRA',
            action: 'Returned BedCheck',
            module: 'bedcheck',
            details: `HRA ${actor?.name} returned BedCheck to RA: ${reason || 'No reason provided'}`,
            context: `Session ID: ${session?.id}`,
            result: 'pending',
            category: 'bedcheck',
            tone: 'gold',
            hostel_id: hostel?.id,
            session_id: session?.id,
            campus: hostel?.campus || 'Legacy'
        });
    },

    async studentRegistered(student, hostel, actor) {
        return auditService.log({
            actor: actor?.name || 'System',
            actor_id: actor?.id,
            actor_role: actor?.role || 'System',
            action: 'Student Registered',
            module: 'students',
            details: `${student?.name} (${student?.matric}) registered in ${hostel?.name} - Room ${student?.room_code} (${student?.bed_code})`,
            context: `Student ID: ${student?.id}`,
            result: 'success',
            category: 'student',
            tone: 'blue',
            hostel_id: hostel?.id,
            room_id: student?.room_id,
            student_id: student?.id,
            campus: student?.campus || hostel?.campus || 'Legacy'
        });
    },

    async userCreated(user, actor) {
        return auditService.log({
            actor: actor?.name || 'System',
            actor_id: actor?.id,
            actor_role: actor?.role || 'Admin',
            action: 'User Created',
            module: 'staff',
            details: `Created ${user?.role} account for ${user?.name} (${user?.username})`,
            context: `User ID: ${user?.id}`,
            result: 'success',
            category: 'staff',
            tone: 'blue',
            hostel_id: user?.hostel_id,
            campus: user?.campus || 'Legacy'
        });
    },

    async userRoleChanged(user, oldRole, newRole, actor) {
        return auditService.log({
            actor: actor?.name || 'Admin',
            actor_id: actor?.id,
            actor_role: actor?.role || 'Admin',
            action: 'User Role Changed',
            module: 'staff',
            details: `${user?.name} role changed from ${oldRole} to ${newRole}`,
            context: `User ID: ${user?.id}`,
            result: 'success',
            category: 'staff',
            tone: 'gold',
            hostel_id: user?.hostel_id,
            campus: user?.campus || 'Legacy'
        });
    },

    async passwordChanged(user, actor) {
        return auditService.log({
            actor: actor?.name || user?.name,
            actor_id: actor?.id || user?.id,
            actor_role: actor?.role || user?.role,
            action: 'Password Changed',
            module: 'auth',
            details: `${user?.name} changed their password`,
            context: `User ID: ${user?.id}`,
            result: 'success',
            category: 'auth',
            tone: 'blue',
            hostel_id: user?.hostel_id,
            campus: user?.campus || 'Legacy'
        });
    },

    async hostelUpdated(hostel, changes, actor) {
        return auditService.log({
            actor: actor?.name || 'Admin',
            actor_id: actor?.id,
            actor_role: actor?.role || 'Admin',
            action: 'Hostel Updated',
            module: 'hostel',
            details: `Updated ${hostel?.name}: ${Object.keys(changes).join(', ')}`,
            context: `Hostel ID: ${hostel?.id}`,
            result: 'success',
            category: 'hostel',
            tone: 'blue',
            hostel_id: hostel?.id,
            campus: hostel?.campus || 'Legacy'
        });
    },

    async systemSettingsUpdated(setting, oldValue, newValue, actor) {
        return auditService.log({
            actor: actor?.name || 'Admin',
            actor_id: actor?.id,
            actor_role: actor?.role || 'Admin',
            action: 'System Settings Updated',
            module: 'system',
            details: `Updated ${setting} from ${oldValue} to ${newValue}`,
            context: `Setting: ${setting}`,
            result: 'success',
            category: 'system',
            tone: 'gold',
            campus: actor?.campus || 'Legacy'
        });
    },

    async faceEnrolled(student, result, req) {
        return auditService.log({
            actor: req?.headers['x-staff-name'] || req?.user?.name || 'Student',
            actor_id: student.id,
            actor_role: req?.headers['x-staff-role'] || req?.user?.role || 'Student',
            action: 'Face Enrolled',
            module: 'face',
            details: `${student.name} (${student.matric}) enrolled face successfully with ${result.confidence || 'N/A'} confidence`,
            context: `Embedding dimension: 512`,
            result: 'success',
            category: 'face',
            tone: 'green',
            hostel_id: student.hostel_id,
            room_id: student.room_id,
            student_id: student.id,
            campus: student.campus || 'Legacy',
            ip_address: req?.clientIp,
            user_agent: req?.userAgent
        });
    },

    async faceVerified(student, result, req) {
        return auditService.log({
            actor: req?.headers['x-staff-name'] || req?.user?.name || 'RA',
            actor_id: getStaffId(req) || req?.user?.id,
            actor_role: req?.headers['x-staff-role'] || req?.user?.role || 'RA',
            action: result.success ? 'Face Verified' : 'Face Verification Failed',
            module: 'face',
            details: result.success 
                ? `${student.name} (${student.matric}) verified with ${(result.confidence * 100).toFixed(1)}% confidence`
                : `Verification failed for ${student.name} (${student.matric})`,
            context: `Threshold: ${result.threshold || 0.55}`,
            result: result.success ? 'success' : 'failed',
            category: 'face',
            tone: result.success ? 'green' : 'red',
            hostel_id: student.hostel_id,
            room_id: student.room_id,
            student_id: student.id,
            campus: student.campus || 'Legacy',
            ip_address: req?.clientIp,
            user_agent: req?.userAgent
        });
    },

    async livenessVerified(req) {
        return auditService.log({
            actor: req?.headers['x-staff-name'] || req?.user?.name || 'Student',
            actor_id: getStaffId(req) || req?.user?.id,
            actor_role: req?.headers['x-staff-role'] || req?.user?.role || 'Student',
            action: 'Liveness Verified',
            module: 'face',
            details: 'Liveness verified successfully',
            context: 'Liveness check passed',
            result: 'success',
            category: 'face',
            tone: 'green',
            campus: req?.campus || 'Legacy',
            ip_address: req?.clientIp,
            user_agent: req?.userAgent
        });
    },

    async raRoomAssigned(ra, rooms, hra, req) {
        return auditService.log({
            actor: hra?.name || 'HRA',
            actor_id: hra?.id,
            actor_role: 'HRA',
            action: 'RA Room Assignment',
            module: 'ra_assignments',
            details: `Assigned ${rooms.length} rooms to RA ${ra.name}`,
            context: `Rooms: ${rooms.map(r => r.room_code).join(', ')}`,
            result: 'success',
            category: 'staff',
            tone: 'blue',
            hostel_id: ra.hostel_id,
            campus: req?.campus || 'Legacy',
            ip_address: req?.clientIp,
            user_agent: req?.userAgent
        });
    },

    async raSessionStarted(ra, session, req) {
        return auditService.log({
            actor: ra.name,
            actor_id: ra.id,
            actor_role: 'RA',
            action: 'RA BedCheck Started',
            module: 'bedcheck',
            details: `${ra.name} started BedCheck session`,
            context: `Session ID: ${session.id}`,
            result: 'success',
            category: 'bedcheck',
            tone: 'green',
            hostel_id: ra.hostel_id,
            session_id: session.id,
            campus: req?.campus || 'Legacy',
            ip_address: req?.clientIp,
            user_agent: req?.userAgent
        });
    },

    async raSessionCompleted(ra, session, req) {
        return auditService.log({
            actor: ra.name,
            actor_id: ra.id,
            actor_role: 'RA',
            action: 'RA BedCheck Completed',
            module: 'bedcheck',
            details: `${ra.name} completed BedCheck session`,
            context: `Session ID: ${session.id}`,
            result: 'success',
            category: 'bedcheck',
            tone: 'green',
            hostel_id: ra.hostel_id,
            session_id: session.id,
            campus: req?.campus || 'Legacy',
            ip_address: req?.clientIp,
            user_agent: req?.userAgent
        });
    },

    async raSuspiciousFlagged(ra, session, reason, req) {
        return auditService.log({
            actor: req?.user?.name || 'System',
            actor_id: req?.user?.id,
            actor_role: req?.user?.role || 'System',
            action: 'RA Flagged Suspicious',
            module: 'security',
            details: `${ra.name} flagged for suspicious activity: ${reason}`,
            context: `Session ID: ${session.id}`,
            result: 'warning',
            category: 'security',
            tone: 'red',
            hostel_id: ra.hostel_id,
            session_id: session.id,
            campus: req?.campus || 'Legacy',
            ip_address: req?.clientIp,
            user_agent: req?.userAgent
        });
    }
};

// =====================================================
// 🔓 PUBLIC ENDPOINTS
// =====================================================

// =====================================================
// HEALTH & STATUS ENDPOINTS (Public)
// =====================================================

app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'production'
    });
});

app.get('/', (req, res) => {
    res.json({
        name: 'BIU BedCheck API',
        version: '4.3.0',
        status: 'running',
        environment: process.env.NODE_ENV || 'production'
    });
});

// =====================================================
// AUTHENTICATION ENDPOINTS
// =====================================================

app.post('/api/auth/login', authLimiter, validate(validators.login), async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const { data, error } = await supabase
            .from('staff')
            .select('id, username, role, name, initials, scope, hostel_id, assigned_floor, assigned_room, is_admin, email, phone, department, staff_id, joined, status, password, campus, campus_code')
            .eq('username', username)
            .maybeSingle();
        
        if (error) {
            console.error('Login error:', error);
            await auditEvents.loginFailed(username, req);
            return res.status(500).json({ 
                success: false, 
                message: 'An error occurred during login. Please try again.' 
            });
        }
        
        if (!data) {
            await auditEvents.loginFailed(username, req);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        const user = data;

        let validPassword = false;
        try {
            validPassword = await bcrypt.compare(password, user.password);
        } catch (e) {
            console.error('Password verification error:', e);
            validPassword = false;
        }

        if (!validPassword) {
            await auditEvents.loginFailed(username, req);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }

        if (user.status !== 'Active') {
            await auditEvents.loginFailed(username, req);
            return res.status(401).json({ 
                success: false, 
                message: 'Account is inactive. Please contact administrator.' 
            });
        }

        req.campus = user.campus || 'Legacy';

        await supabase
            .from('staff')
            .update({ last_login: new Date().toISOString() })
            .eq('id', user.id);

        const token = generateToken(user);

        await auditEvents.loginSuccess(user, req);

        const { password: _, ...userWithoutPassword } = user;

        // ============================================================
        // Determine the redirect URL on the server
        // ============================================================
        const redirectUrl = DASHBOARD_ROUTES[user.role] || '/index.html';

        res.json({ 
            success: true, 
            data: {
                user: userWithoutPassword,
                token: token,
                expiresIn: process.env.JWT_EXPIRY || '8h',
                campus: user.campus || 'Legacy',
                redirect: redirectUrl
            },
            role: user.role
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'An unexpected error occurred. Please try again.' 
        });
    }
});

// =====================================================
// 🔐 AUTH MIDDLEWARE
// =====================================================

app.use(authMiddleware);

// =====================================================
// AUTHENTICATION ENDPOINTS
// =====================================================

app.post('/api/auth/logout', async (req, res) => {
    await auditService.log({
        actor: req.user.name || req.user.username,
        actor_id: req.user.id,
        actor_role: req.user.role,
        action: 'Logout',
        module: 'auth',
        details: `${req.user.name || req.user.username} logged out`,
        result: 'success',
        category: 'auth',
        campus: req.campus || 'Legacy',
        ip_address: req.clientIp,
        user_agent: req.userAgent
    });

    res.json({ 
        success: true, 
        message: 'Logged out successfully' 
    });
});

app.get('/api/auth/verify', async (req, res) => {
    res.json({ 
        success: true, 
        data: {
            user: {
                id: req.user.id,
                username: req.user.username,
                name: req.user.name,
                role: req.user.role,
                hostel_id: req.user.hostel_id,
                campus: req.user.campus || 'Legacy'
            },
            expiresIn: process.env.JWT_EXPIRY || '8h'
        }
    });
});

app.get('/api/me', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('staff')
            .select('id, username, role, name, initials, scope, hostel_id, assigned_floor, assigned_room, is_admin, email, phone, department, status, campus, campus_code')
            .eq('id', req.user.id)
            .single();
        
        if (error || !data) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({ success: true, data: data });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.'
        });
    }
});

// =====================================================
// CHANGE PASSWORD
// =====================================================

app.put('/api/staff/:id/change-password', 
    validate(validators.changePassword),
    async (req, res) => {
        try {
            const staffId = parseInt(req.params.id);
            const { currentPassword, newPassword } = req.body;

            if (req.user.id !== staffId && req.user.role !== 'Admin' && req.user.role !== 'System Owner') {
                return res.status(403).json({
                    success: false,
                    message: 'You can only change your own password'
                });
            }

            const { data: staff, error: staffError } = await supabase
                .from('staff')
                .select('id, password, name, username, campus')
                .eq('id', staffId)
                .maybeSingle();

            if (staffError || !staff) {
                return res.status(404).json({
                    success: false,
                    message: 'Staff not found'
                });
            }

            let validPassword = false;
            try {
                validPassword = await bcrypt.compare(currentPassword, staff.password);
            } catch (e) {
                validPassword = false;
            }

            if (!validPassword) {
                await auditService.log({
                    actor: staff.name || staff.username,
                    actor_id: staffId,
                    action: 'Password Change Failed',
                    module: 'security',
                    details: 'Incorrect current password',
                    result: 'failed',
                    category: 'security',
                    campus: staff.campus || 'Legacy',
                    ip_address: req.clientIp,
                    user_agent: req.userAgent
                });
                return res.status(400).json({
                    success: false,
                    message: 'Current password is incorrect'
                });
            }

            const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

            const { error: updateError } = await supabase
                .from('staff')
                .update({
                    password: hashedPassword,
                    updated_at: new Date().toISOString()
                })
                .eq('id', staffId);

            if (updateError) {
                throw updateError;
            }

            await auditService.log({
                actor: staff.name || staff.username,
                actor_id: staffId,
                actor_role: req.user.role,
                action: 'Password Changed',
                module: 'security',
                details: 'Password updated successfully',
                result: 'success',
                category: 'security',
                campus: staff.campus || 'Legacy',
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                message: 'Password changed successfully'
            });

        } catch (error) {
            console.error('Change password error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

// =====================================================
// CAMPUS CONTEXT ENDPOINTS
// =====================================================

app.get('/api/campus/current', async (req, res) => {
    res.json({
        success: true,
        data: {
            campus: req.campus || 'Legacy',
            user_campus: req.user?.campus || 'Legacy',
            supported_campuses: ['Legacy', 'Heritage']
        }
    });
});

app.post('/api/campus/switch', requireRole('Admin', 'System Owner'), validate([
    body('campus').isIn(['Legacy', 'Heritage']).withMessage('Invalid campus')
]), async (req, res) => {
    const { campus } = req.body;
    
    try {
        const { error } = await supabase
            .from('staff')
            .update({ campus: campus })
            .eq('id', req.user.id);
        
        if (error) throw error;
        
        const updatedUser = { ...req.user, campus: campus };
        const token = generateToken(updatedUser);
        
        await auditService.log({
            actor: req.user.name || req.user.username,
            actor_id: req.user.id,
            actor_role: req.user.role,
            action: 'Campus Switched',
            module: 'system',
            details: `Switched to ${campus} campus`,
            result: 'success',
            category: 'system',
            campus: campus,
            ip_address: req.clientIp,
            user_agent: req.userAgent
        });
        
        res.json({
            success: true,
            data: {
                campus: campus,
                token: token,
                message: `Switched to ${campus} campus`
            }
        });
    } catch (error) {
        console.error('Error switching campus:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.'
        });
    }
});

app.get('/api/campus/stats', requireRole('Admin', 'HRA', 'System Owner'), async (req, res) => {
    try {
        const campus = req.query.campus || req.campus || 'Legacy';
        
        const { data: occupancyData } = await supabase
            .from('bed_occupancy')
            .select('*')
            .eq('campus', campus);
        
        const { data: structureData } = await supabase
            .from('hostel_structure')
            .select('*')
            .eq('campus', campus);
        
        const { data: students } = await supabase
            .from('students')
            .select('status, face_enrolled')
            .eq('campus', campus);
        
        const totalStudents = students?.length || 0;
        const present = students?.filter(s => s.status === 'Present').length || 0;
        const absent = students?.filter(s => s.status === 'Absent').length || 0;
        const faceEnrolled = students?.filter(s => s.face_enrolled === true).length || 0;
        
        res.json({
            success: true,
            data: {
                campus: campus,
                hostels: structureData || [],
                occupancy: occupancyData || [],
                students: {
                    total: totalStudents,
                    present: present,
                    absent: absent,
                    faceEnrolled: faceEnrolled
                },
                summary: {
                    totalHostels: structureData?.length || 0,
                    totalBeds: structureData?.reduce((sum, h) => sum + (h.total_beds || 0), 0) || 0,
                    occupiedBeds: structureData?.reduce((sum, h) => sum + (h.occupied_beds || 0), 0) || 0,
                    occupancyRate: structureData?.length > 0 
                        ? Math.round(structureData.reduce((sum, h) => sum + (h.occupancy_rate || 0), 0) / structureData.length)
                        : 0
                }
            }
        });
    } catch (error) {
        console.error('Error fetching campus stats:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.'
        });
    }
});

// =====================================================
// INSIGHTFACE ENDPOINTS
// =====================================================

app.get('/api/face/health', async (req, res) => {
    try {
        const health = await faceService.checkHealth();
        res.json({
            success: true,
            data: health,
            api_url: FACE_API_URL
        });
    } catch (error) {
        console.error('Face API health check error:', error);
        res.status(500).json({
            success: false,
            message: 'Face API is unreachable',
            error: error.message
        });
    }
});

app.post('/api/face/detect', 
    campusIsolation,
    validate(validators.faceImage),
    async (req, res) => {
        try {
            const { image, student_id } = req.body;
            const result = await faceService.detectFace(image);
            if (result.success) {
                if (student_id) {
                    await supabase
                        .from('students')
                        .update({ face_enrolled: true, updated_at: new Date().toISOString() })
                        .eq('id', student_id)
                        .eq('campus', req.campus);
                }
                res.json({ ...result, campus: req.campus });
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Face detection error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/face/enroll', 
    campusIsolation,
    validate([...validators.faceImage, ...validators.faceVerify]),
    async (req, res) => {
        try {
            const { image, student_id, matric } = req.body;

            if (!student_id && !matric) {
                return res.status(400).json({
                    success: false,
                    message: 'student_id or matric is required'
                });
            }

            let studentQuery = supabase.from('students').select('*').eq('campus', req.campus);
            if (student_id) {
                studentQuery = studentQuery.eq('id', student_id);
            } else if (matric) {
                studentQuery = studentQuery.eq('matric', matric);
            }
            
            const { data: student, error: studentError } = await studentQuery.maybeSingle();
            
            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only enroll students in your hostel.'
                });
            }

            const result = await faceService.enrollFace(
                image,
                student.id,
                student.hostel_id,
                student.room_id,
                student.name
            );
            
            if (!result.success) {
                return res.status(400).json(result);
            }

            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .upsert({
                    student_id: student.id,
                    campus: student.campus || req.campus,
                    campus_code: student.campus === 'Legacy' ? 'LEG' : 'HER',
                    face_embedding: result.embedding,
                    face_image_url: result.image_url || null,
                    enrollment_status: 'enrolled',
                    enrollment_date: new Date().toISOString(),
                    is_active: true,
                    enrolled_by: req.user.id,
                    confidence_score: result.confidence || null,
                    updated_at: new Date().toISOString()
                }, {
                    onConflict: 'student_id'
                })
                .select()
                .single();

            if (faceError) {
                console.error('Save face error:', faceError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to save face data'
                });
            }

            const { data: updatedStudent, error: updateError } = await supabase
                .from('students')
                .update({
                    face_enrolled: true,
                    updated_at: new Date().toISOString()
                })
                .eq('id', student.id)
                .select()
                .single();

            if (updateError) {
                console.error('Update student error:', updateError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to update student record'
                });
            }

            await auditEvents.faceEnrolled(student, result, req);

            res.json({
                success: true,
                data: {
                    student: {
                        id: updatedStudent.id,
                        name: updatedStudent.name,
                        matric: updatedStudent.matric
                    },
                    face: {
                        id: faceData.id,
                        enrollment_status: faceData.enrollment_status,
                        enrollment_date: faceData.enrollment_date,
                        confidence: result.confidence
                    },
                    message: 'Face enrolled successfully'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Face enrollment error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/face/enroll-bulk', 
    campusIsolation,
    validate([
        body('frames').isArray({ min: 1 }).withMessage('At least one frame is required'),
        body('student_id').optional().isInt(),
        body('matric').optional().isString()
    ]),
    async (req, res) => {
        try {
            const { frames, student_id, matric } = req.body;

            if (!student_id && !matric) {
                return res.status(400).json({
                    success: false,
                    message: 'student_id or matric is required'
                });
            }

            let studentQuery = supabase.from('students').select('*').eq('campus', req.campus);
            if (student_id) {
                studentQuery = studentQuery.eq('id', student_id);
            } else if (matric) {
                studentQuery = studentQuery.eq('matric', matric);
            }
            
            const { data: student, error: studentError } = await studentQuery.maybeSingle();
            
            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only enroll students in your hostel.'
                });
            }

            const result = await faceService.enrollBulk(
                frames,
                student.id,
                student.hostel_id,
                student.room_id,
                student.name
            );
            
            if (!result.success) {
                return res.status(400).json(result);
            }

            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .upsert({
                    student_id: student.id,
                    campus: student.campus || req.campus,
                    campus_code: student.campus === 'Legacy' ? 'LEG' : 'HER',
                    face_embedding: result.embedding,
                    face_image_url: result.image_url || null,
                    enrollment_status: 'enrolled',
                    enrollment_date: new Date().toISOString(),
                    is_active: true,
                    enrolled_by: req.user.id,
                    confidence_score: result.confidence || null,
                    updated_at: new Date().toISOString()
                }, {
                    onConflict: 'student_id'
                })
                .select()
                .single();

            if (faceError) {
                console.error('Save face error:', faceError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to save face data'
                });
            }

            const { data: updatedStudent, error: updateError } = await supabase
                .from('students')
                .update({
                    face_enrolled: true,
                    updated_at: new Date().toISOString()
                })
                .eq('id', student.id)
                .select()
                .single();

            if (updateError) {
                console.error('Update student error:', updateError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to update student record'
                });
            }

            await auditEvents.faceEnrolled(student, result, req);

            res.json({
                success: true,
                data: {
                    student: {
                        id: updatedStudent.id,
                        name: updatedStudent.name,
                        matric: updatedStudent.matric
                    },
                    face: {
                        id: faceData.id,
                        enrollment_status: faceData.enrollment_status,
                        enrollment_date: faceData.enrollment_date,
                        confidence: result.confidence
                    },
                    frames_used: result.frames_used,
                    message: 'Face enrolled successfully'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Bulk enrollment error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/face/verify', 
    campusIsolation,
    faceLimiter,
    validate(validators.faceVerify),
    async (req, res) => {
        try {
            const { image, student_id, matric, threshold = 0.55 } = req.body;

            if (!student_id && !matric) {
                return res.status(400).json({
                    success: false,
                    message: 'student_id or matric is required'
                });
            }

            let studentQuery = supabase
                .from('students')
                .select('id, name, matric, face_enrolled, hostel_id, room_id, campus')
                .eq('campus', req.campus);
            
            if (student_id) {
                studentQuery = studentQuery.eq('id', student_id);
            } else if (matric) {
                studentQuery = studentQuery.eq('matric', matric);
            }
            
            const { data: student, error: studentError } = await studentQuery.maybeSingle();
            
            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied.'
                });
            }

            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('face_embedding, enrollment_status, verification_count')
                .eq('student_id', student.id)
                .eq('campus', req.campus)
                .eq('is_active', true)
                .maybeSingle();

            if (faceError || !faceData || !faceData.face_embedding) {
                return res.status(404).json({
                    success: false,
                    message: 'No face enrollment found for this student'
                });
            }

            const result = await faceService.verifyFace(
                image,
                faceData.face_embedding,
                threshold
            );

            if (result.success) {
                await supabase
                    .from('student_face')
                    .update({
                        last_verified: new Date().toISOString(),
                        verification_count: (faceData.verification_count || 0) + 1,
                        confidence_score: result.confidence || null,
                        updated_at: new Date().toISOString()
                    })
                    .eq('student_id', student.id);
            }

            await auditEvents.faceVerified(student, result, req);

            res.json({
                success: true,
                data: {
                    student: {
                        id: student.id,
                        name: student.name,
                        matric: student.matric
                    },
                    verified: result.success,
                    confidence: result.confidence,
                    threshold: result.threshold || threshold,
                    message: result.success ? 'Face verified successfully' : 'Face verification failed'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Face verification error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/face/verify-room', 
    campusIsolation,
    faceLimiter,
    validate([
        ...validators.faceImage,
        body('room_id').optional().isInt(),
        body('hostel_id').optional().isInt(),
        body('threshold').optional().isFloat({ min: 0.3, max: 0.9 })
    ]),
    async (req, res) => {
        try {
            const { image, room_id, hostel_id, threshold = 0.55 } = req.body;

            if (!room_id && !hostel_id) {
                return res.status(400).json({
                    success: false,
                    message: 'room_id or hostel_id is required'
                });
            }

            let query = supabase.from('students')
                .select('id, name, matric, face_enrolled, hostel_id, room_id, room_code, campus')
                .eq('campus', req.campus)
                .eq('face_enrolled', true);
            
            if (room_id) {
                query = query.eq('room_id', room_id);
            } else if (hostel_id) {
                query = query.eq('hostel_id', hostel_id);
            }
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            const { data: students, error: studentsError } = await query;
            
            if (studentsError) {
                console.error('Fetch students error:', studentsError);
                return res.status(500).json({
                    success: false,
                    message: 'An error occurred. Please try again.'
                });
            }

            if (!students || students.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No students found with face enrolled in this room'
                });
            }

            const studentIds = students.map(s => s.id);
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('student_id, face_embedding, verification_count')
                .in('student_id', studentIds)
                .eq('campus', req.campus)
                .eq('is_active', true);

            if (faceError || !faceData || faceData.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No face embeddings found for students in this room'
                });
            }

            const embeddings = faceData.map(f => f.face_embedding);
            const faceStudentIds = faceData.map(f => f.student_id);

            const result = await faceService.verifyMultiple(
                image,
                embeddings,
                faceStudentIds,
                threshold
            );

            let matchedStudent = null;
            if (result.success && result.student_id) {
                matchedStudent = students.find(s => s.id === result.student_id);
                
                if (matchedStudent) {
                    const studentFace = faceData.find(f => f.student_id === matchedStudent.id);
                    await supabase
                        .from('student_face')
                        .update({
                            last_verified: new Date().toISOString(),
                            verification_count: (studentFace?.verification_count || 0) + 1,
                            confidence_score: result.confidence || null,
                            updated_at: new Date().toISOString()
                        })
                        .eq('student_id', matchedStudent.id);
                }
            }

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: matchedStudent ? 'Room Face Verified' : 'Room Face Verification Failed',
                module: 'face',
                details: matchedStudent 
                    ? `${matchedStudent.name} (${matchedStudent.matric}) verified in room ${matchedStudent.room_code || 'N/A'} with ${(result.confidence * 100).toFixed(1)}% confidence`
                    : `No match found in room ${room_id || hostel_id}`,
                context: `Threshold: ${threshold}, Students checked: ${students.length}`,
                result: matchedStudent ? 'success' : 'failed',
                category: 'face',
                tone: matchedStudent ? 'green' : 'red',
                hostel_id: hostel_id || matchedStudent?.hostel_id,
                room_id: room_id || matchedStudent?.room_id,
                student_id: matchedStudent?.id || null,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: {
                    matched_student: matchedStudent ? {
                        id: matchedStudent.id,
                        name: matchedStudent.name,
                        matric: matchedStudent.matric,
                        room_code: matchedStudent.room_code
                    } : null,
                    verified: !!matchedStudent,
                    confidence: result.confidence || 0,
                    threshold: result.threshold || threshold,
                    students_checked: students.length,
                    message: matchedStudent ? 'Match found' : 'No match found'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Room verification error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/face/liveness', 
    campusIsolation,
    validate(validators.faceImage),
    async (req, res) => {
        try {
            const { image } = req.body;
            const result = await faceService.checkLiveness(image);
            if (result.is_live) {
                await auditEvents.livenessVerified(req);
            }
            res.json({ ...result, campus: req.campus });
        } catch (error) {
            console.error('Liveness check error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/face/liveness/reset', 
    campusIsolation,
    requireRole('Admin', 'System Owner'),
    async (req, res) => {
        try {
            const result = await faceService.resetLiveness();
            res.json({ ...result, campus: req.campus });
        } catch (error) {
            console.error('Reset liveness error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.get('/api/face/status/:studentId',
    campusIsolation,
    validate(validators.studentId),
    async (req, res) => {
        try {
            const studentId = parseInt(req.params.id);
            const { data: student, error } = await supabase
                .from('students')
                .select('id, name, matric, face_enrolled, updated_at, hostel_id, campus')
                .eq('id', studentId)
                .eq('campus', req.campus)
                .single();
            
            if (error || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('id, enrollment_status, face_embedding, face_image_url, last_verified, verification_count, confidence_score')
                .eq('student_id', studentId)
                .eq('campus', req.campus)
                .eq('is_active', true)
                .maybeSingle();

            if (faceError) throw faceError;

            res.json({
                success: true,
                data: {
                    student: {
                        id: student.id,
                        name: student.name,
                        matric: student.matric
                    },
                    face_enrolled: !!faceData && faceData.enrollment_status === 'enrolled',
                    enrollment_status: faceData?.enrollment_status || 'pending',
                    face_image_url: faceData?.face_image_url || null,
                    last_verified: faceData?.last_verified || null,
                    verification_count: faceData?.verification_count || 0,
                    confidence_score: faceData?.confidence_score || null,
                    has_embedding: !!faceData?.face_embedding,
                    embedding_dimension: faceData?.face_embedding ? faceData.face_embedding.length : 0,
                    updated_at: student.updated_at
                },
                campus: req.campus
            });
        } catch (error) {
            console.error('Get face status error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/face/compare', 
    campusIsolation,
    validate([
        body('embedding1').isArray().withMessage('Embedding 1 must be an array'),
        body('embedding2').isArray().withMessage('Embedding 2 must be an array')
    ]),
    async (req, res) => {
        try {
            const { embedding1, embedding2 } = req.body;
            const result = await faceService.compareEmbeddings(embedding1, embedding2);
            res.json({ ...result, campus: req.campus });
        } catch (error) {
            console.error('Compare embeddings error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/face/extract', 
    campusIsolation,
    validate(validators.faceImage),
    async (req, res) => {
        try {
            const { image } = req.body;
            const result = await faceService.extractEmbedding(image);
            res.json({ ...result, campus: req.campus });
        } catch (error) {
            console.error('Extract embedding error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

// =====================================================
// STUDENT FACE ENDPOINTS (Legacy)
// =====================================================

app.get('/api/students/:id/face-status',
    campusIsolation,
    validate(validators.studentId),
    async (req, res) => {
        try {
            const studentId = parseInt(req.params.id);
            const { data: student, error: studentError } = await supabase
                .from('students')
                .select('id, name, matric, hostel_id, campus')
                .eq('id', studentId)
                .eq('campus', req.campus)
                .single();
            
            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('*')
                .eq('student_id', studentId)
                .eq('campus', req.campus)
                .maybeSingle();

            if (faceError) throw faceError;

            res.json({
                success: true,
                data: {
                    student: {
                        id: student.id,
                        name: student.name,
                        matric: student.matric
                    },
                    face_enrolled: !!faceData && faceData.enrollment_status === 'enrolled',
                    enrollment_status: faceData?.enrollment_status || 'pending',
                    face_image_url: faceData?.face_image_url || null,
                    last_verified: faceData?.last_verified || null,
                    verification_count: faceData?.verification_count || 0,
                    confidence_score: faceData?.confidence_score || null,
                    has_embedding: !!faceData?.face_embedding,
                    embedding_dimension: faceData?.face_embedding ? faceData.face_embedding.length : 0
                },
                campus: req.campus
            });
        } catch (error) {
            console.error('Get face status error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/students/:id/face/enroll',
    campusIsolation,
    validate([validators.studentId, ...validators.faceImage]),
    async (req, res) => {
        try {
            const studentId = parseInt(req.params.id);
            const { image } = req.body;

            const { data: student, error: studentError } = await supabase
                .from('students')
                .select('id, name, matric, hostel_id, room_id, campus')
                .eq('id', studentId)
                .eq('campus', req.campus)
                .single();

            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const result = await faceService.enrollFace(
                image,
                student.id,
                student.hostel_id,
                student.room_id,
                student.name
            );

            if (!result.success) {
                return res.status(400).json(result);
            }

            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .upsert({
                    student_id: student.id,
                    campus: student.campus || req.campus,
                    campus_code: student.campus === 'Legacy' ? 'LEG' : 'HER',
                    face_embedding: result.embedding,
                    face_image_url: result.image_url || null,
                    enrollment_status: 'enrolled',
                    enrollment_date: new Date().toISOString(),
                    is_active: true,
                    enrolled_by: req.user.id,
                    confidence_score: result.confidence || null,
                    updated_at: new Date().toISOString()
                }, {
                    onConflict: 'student_id'
                })
                .select()
                .single();

            if (faceError) {
                console.error('Save face error:', faceError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to save face data'
                });
            }

            await supabase
                .from('students')
                .update({ face_enrolled: true, updated_at: new Date().toISOString() })
                .eq('id', student.id);

            await auditEvents.faceEnrolled(student, result, req);

            res.json({
                success: true,
                data: {
                    student: {
                        id: student.id,
                        name: student.name,
                        matric: student.matric
                    },
                    face: {
                        id: faceData.id,
                        enrollment_status: faceData.enrollment_status,
                        enrollment_date: faceData.enrollment_date,
                        confidence: result.confidence
                    },
                    message: 'Face enrolled successfully'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Face enrollment error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/students/:id/face/verify',
    campusIsolation,
    faceLimiter,
    validate([
        validators.studentId,
        ...validators.faceImage,
        body('threshold').optional().isFloat({ min: 0.3, max: 0.9 })
    ]),
    async (req, res) => {
        try {
            const studentId = parseInt(req.params.id);
            const { image, threshold = 0.55 } = req.body;

            const { data: student, error: studentError } = await supabase
                .from('students')
                .select('id, name, matric, hostel_id, room_id, campus')
                .eq('id', studentId)
                .eq('campus', req.campus)
                .single();

            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('face_embedding, enrollment_status, verification_count')
                .eq('student_id', studentId)
                .eq('campus', req.campus)
                .eq('is_active', true)
                .maybeSingle();

            if (faceError || !faceData || !faceData.face_embedding) {
                return res.status(404).json({
                    success: false,
                    message: 'No face enrollment found for this student'
                });
            }

            const result = await faceService.verifyFace(
                image,
                faceData.face_embedding,
                threshold
            );

            if (result.success) {
                await supabase
                    .from('student_face')
                    .update({
                        last_verified: new Date().toISOString(),
                        verification_count: (faceData.verification_count || 0) + 1,
                        confidence_score: result.confidence || null,
                        updated_at: new Date().toISOString()
                    })
                    .eq('student_id', studentId);
            }

            await auditEvents.faceVerified(student, result, req);

            res.json({
                success: true,
                data: {
                    student: {
                        id: student.id,
                        name: student.name,
                        matric: student.matric
                    },
                    verified: result.success,
                    confidence: result.confidence,
                    threshold: threshold,
                    message: result.success ? 'Face verified successfully' : 'Face verification failed'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Face verification error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.get('/api/students/face-status/all',
    campusIsolation,
    async (req, res) => {
        try {
            const { hostel_id, room_id } = req.query;
            
            let query = supabase
                .from('students')
                .select('id, name, matric, hostel_id, room_id, room_code, face_enrolled, campus')
                .eq('campus', req.campus);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            if (hostel_id) query = query.eq('hostel_id', parseInt(hostel_id));
            if (room_id) query = query.eq('room_id', parseInt(room_id));
            
            const { data: students, error } = await query;
            
            if (error) throw error;
            
            const studentIds = students.map(s => s.id);
            let faceData = [];
            if (studentIds.length > 0) {
                const { data: faces } = await supabase
                    .from('student_face')
                    .select('student_id, enrollment_status, last_verified, verification_count')
                    .in('student_id', studentIds)
                    .eq('campus', req.campus)
                    .eq('is_active', true);
                
                faceData = faces || [];
            }
            
            const enrichedData = students.map(student => {
                const face = faceData.find(f => f.student_id === student.id);
                return {
                    ...student,
                    face_enrolled: !!face && face.enrollment_status === 'enrolled',
                    enrollment_status: face?.enrollment_status || 'pending',
                    last_verified: face?.last_verified || null,
                    verification_count: face?.verification_count || 0
                };
            });
            
            const stats = {
                total: enrichedData.length,
                enrolled: enrichedData.filter(s => s.face_enrolled).length,
                not_enrolled: enrichedData.filter(s => !s.face_enrolled).length,
                pending: enrichedData.filter(s => s.enrollment_status === 'pending').length
            };
            
            res.json({
                success: true,
                data: enrichedData,
                stats: stats,
                campus: req.campus
            });
        } catch (error) {
            console.error('Get face status error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

// =====================================================
// STUDENT CRUD
// =====================================================

app.get('/api/students', 
    campusIsolation,
    validate(validators.pagination),
    async (req, res) => {
        const { hostel, search, status, room_id } = req.query;
        try {
            let query = supabase.from('students').select('*').eq('campus', req.campus);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            if (hostel && hostel !== 'all') query = query.eq('hostel', hostel);
            if (room_id) query = query.eq('room_id', parseInt(room_id));
            if (search) {
                const searchTerm = `%${search}%`;
                query = query.or(`name.ilike.${searchTerm},matric.ilike.${searchTerm}`);
            }
            if (status && status !== 'all') query = query.eq('status', status);
            
            const limit = Math.min(parseInt(req.query.limit) || 50, 100);
            const offset = parseInt(req.query.offset) || 0;
            query = query.order('id', { ascending: true }).range(offset, offset + limit - 1);

            const { data, error, count } = await query;
            if (error) throw error;

            res.json({ 
                success: true, 
                data: data,
                pagination: { limit, offset, total: count || data.length },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching students:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/students', 
    campusIsolation,
    validate(validators.createStudent),
    async (req, res) => {
        const { 
            name, matric, faculty, department, level, session, 
            hostel_id, hostel_name, floor_flat_id, floor_name, 
            room_id, room_code, bed_space_id, bed_code, 
            status, gender, phone, email, 
            emergency_name, emergency_relation, emergency_phone,
            registration_date, campus
        } = req.body;
        
        try {
            const studentCampus = campus || req.campus || 'Legacy';
            
            const { data: existingStudent } = await supabase
                .from('students')
                .select('id')
                .eq('matric', matric)
                .eq('campus', studentCampus)
                .maybeSingle();

            if (existingStudent) {
                return res.status(400).json({
                    success: false,
                    message: 'Student with this matric number already exists in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only add students to your hostel.'
                });
            }

            const newStudent = {
                name, matric, gender: gender || 'Male', phone: phone || null, email: email || null,
                faculty: faculty || 'Engineering', department: department || 'General', level: level || '300',
                session: session || '2026/2027', 
                hostel_id: hostel_id || null, hostel_name: hostel_name || null,
                floor_flat_id: floor_flat_id || null, floor_name: floor_name || null,
                room_id: room_id || null, room_code: room_code || null,
                bed_space_id: bed_space_id || null, bed_code: bed_code || null,
                status: status || 'Present',
                emergency_name: emergency_name || null, emergency_relation: emergency_relation || null,
                emergency_phone: emergency_phone || null,
                photo: null,
                registration_date: registration_date || new Date().toISOString(),
                face_enrolled: false, face_embedding: null,
                created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
                campus: studentCampus, campus_code: studentCampus === 'Legacy' ? 'LEG' : 'HER'
            };
            
            const { data, error } = await supabase
                .from('students')
                .insert(newStudent)
                .select()
                .single();

            if (error) throw error;
            
            if (bed_space_id) {
                await supabase
                    .from('bed_spaces')
                    .update({ 
                        status: 'occupied', 
                        student_id: data.id, 
                        updated_at: new Date().toISOString(),
                        campus: studentCampus
                    })
                    .eq('id', parseInt(bed_space_id));
            }

            const hostel = { id: hostel_id, name: hostel_name, campus: studentCampus };
            await auditEvents.studentRegistered(data, hostel, { 
                name: req.user.name || req.user.username,
                id: req.user.id,
                role: req.user.role
            });
            
            res.json({ success: true, data: data, campus: studentCampus });
        } catch (error) {
            console.error('Error creating student:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/students/:id',
    campusIsolation,
    validate(validators.studentId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data, error } = await supabase
                .from('students')
                .select('*')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (error || !data) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Student not found in this campus' 
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== data.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching student:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.put('/api/students/:id', 
    campusIsolation,
    validate(validators.updateStudent),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const updateData = {};
        const allowedFields = [
            'name', 'matric', 'gender', 'phone', 'email', 'faculty', 'department', 
            'level', 'session', 'hostel_id', 'hostel_name', 'floor_flat_id', 'floor_name',
            'room_id', 'room_code', 'bed_space_id', 'bed_code', 'status', 'photo',
            'emergency_name', 'emergency_relation', 'emergency_phone', 'face_enrolled',
            'face_embedding', 'registration_date', 'campus'
        ];
        
        const { data: existingStudent } = await supabase
            .from('students')
            .select('hostel_id, campus')
            .eq('id', id)
            .eq('campus', req.campus)
            .single();
        
        if (!existingStudent) {
            return res.status(404).json({
                success: false,
                message: 'Student not found in this campus'
            });
        }
        
        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== existingStudent.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                updateData[field] = req.body[field];
            }
        }
        
        updateData.updated_at = new Date().toISOString();
        
        try {
            const { data, error } = await supabase
                .from('students')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Student Updated',
                module: 'students',
                details: `Updated ${data?.name} (${data?.matric})`,
                result: 'success',
                category: 'student',
                hostel_id: data?.hostel_id,
                room_id: data?.room_id,
                student_id: id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error updating student:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.patch('/api/students/:id', 
    campusIsolation,
    validate(validators.updateStudent),
    async (req, res) => {
        const id = parseInt(req.params.id);
        
        if (isNaN(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid student ID'
            });
        }
        
        try {
            const { data: existingStudent, error: checkError } = await supabase
                .from('students')
                .select('id, name, hostel_id, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();
            
            if (checkError || !existingStudent) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== existingStudent.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }
            
            const updateData = {};
            const allowedFields = [
                'name', 'matric', 'gender', 'phone', 'email', 'faculty', 'department',
                'level', 'session', 'hostel_id', 'hostel_name', 'floor_flat_id', 'floor_name',
                'room_id', 'room_code', 'bed_space_id', 'bed_code', 'status', 'photo',
                'emergency_name', 'emergency_relation', 'emergency_phone', 'face_enrolled',
                'face_embedding', 'registration_date', 'campus'
            ];
            
            for (const field of allowedFields) {
                if (req.body[field] !== undefined) {
                    updateData[field] = req.body[field];
                }
            }
            
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'No fields to update'
                });
            }
            
            updateData.updated_at = new Date().toISOString();
            
            const { data, error } = await supabase
                .from('students')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();
            
            if (error) {
                console.error('PATCH student error:', error);
                return res.status(500).json({
                    success: false,
                    message: 'An error occurred. Please try again.'
                });
            }
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Student Updated (Partial)',
                module: 'students',
                details: `${data?.name} (${data?.matric}) updated: ${Object.keys(updateData).join(', ')}`,
                result: 'success',
                category: 'student',
                hostel_id: data?.hostel_id,
                room_id: data?.room_id,
                student_id: id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({
                success: true,
                data: data,
                campus: req.campus,
                message: 'Student updated successfully'
            });
            
        } catch (error) {
            console.error('PATCH student error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.put('/api/students/:id/status', 
    campusIsolation,
    validate([
        body('status').isIn(['Present', 'Absent', 'Late', 'Verified', 'Completed']).withMessage('Invalid status')
    ]),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const { status } = req.body;
        
        try {
            const { data: student } = await supabase
                .from('students')
                .select('name, matric, hostel_id, room_id, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (!student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const { data, error } = await supabase
                .from('students')
                .update({ status: status, updated_at: new Date().toISOString() })
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Student Status Updated',
                module: 'students',
                details: `Updated ${data?.name} (${data?.matric}) status to ${status}`,
                result: 'success',
                category: 'student',
                tone: status === 'Present' ? 'green' : status === 'Absent' ? 'red' : 'gold',
                hostel_id: data?.hostel_id,
                room_id: data?.room_id,
                student_id: data?.id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error updating student status:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.delete('/api/students/:id', 
    campusIsolation,
    validate(validators.studentId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data: student } = await supabase
                .from('students')
                .select('name, matric, bed_space_id, hostel_id, room_id, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (!student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }
            
            await supabase
                .from('student_face')
                .delete()
                .eq('student_id', id)
                .eq('campus', req.campus);
            
            if (student && student.bed_space_id) {
                await supabase
                    .from('bed_spaces')
                    .update({ 
                        status: 'available', 
                        student_id: null, 
                        updated_at: new Date().toISOString() 
                    })
                    .eq('id', student.bed_space_id);
            }
            
            const { error } = await supabase
                .from('students')
                .delete()
                .eq('id', id)
                .eq('campus', req.campus);
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Student Deleted',
                module: 'students',
                details: `Deleted ${student?.name} (${student?.matric})`,
                result: 'success',
                category: 'student',
                tone: 'red',
                hostel_id: student?.hostel_id,
                room_id: student?.room_id,
                student_id: id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                message: 'Student deleted successfully',
                campus: req.campus
            });
        } catch (error) {
            console.error('Error deleting student:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// STAFF CRUD
// =====================================================

app.get('/api/staff', 
    campusIsolation,
    validate(validators.pagination),
    async (req, res) => {
        try {
            const limit = Math.min(parseInt(req.query.limit) || 50, 100);
            const offset = parseInt(req.query.offset) || 0;
            
            let query = supabase
                .from('staff')
                .select('id, name, username, role, hostel_id, assigned_floor, assigned_room, status, email, phone, department, initials, joined, last_login, campus, campus_code')
                .eq('campus', req.campus)
                .order('name', { ascending: true })
                .range(offset, offset + limit - 1);

            // ============================================================
            // Hide System Owner from non-System Owner users
            // ============================================================
            if (req.user.role !== 'System Owner') {
                query = query.neq('role', 'System Owner');
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }

            const { data, error, count } = await query;
            if (error) throw error;

            const sanitizedData = data.map(item => ({
                ...item,
                staff_id: item.id
            }));

            res.json({ 
                success: true, 
                data: sanitizedData,
                pagination: { limit, offset, total: count || data.length },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching staff:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/staff/:id', 
    campusIsolation,
    validate(validators.staffId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data, error } = await supabase
                .from('staff')
                .select('id, name, username, role, hostel_id, assigned_floor, assigned_room, status, email, phone, department, initials, joined, last_login, campus, campus_code')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (error || !data) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Staff not found in this campus' 
                });
            }

            // ============================================================
            // Hide System Owner from non-System Owner users
            // ============================================================
            if (data.role === 'System Owner' && req.user.role !== 'System Owner') {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Staff not found in this campus' 
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== data.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            res.json({ 
                success: true, 
                data: { ...data, staff_id: data.id },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching staff:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/staff', 
    campusIsolation,
    requireRole('Admin', 'System Owner'),
    validate(validators.createStaff),
    async (req, res) => {
        const { name, username, role, hostel_id, email, phone, department, assigned_floor, assigned_room, campus } = req.body;
        
        try {
            const staffCampus = campus || req.campus || 'Legacy';
            
            const { data: existingStaff } = await supabase
                .from('staff')
                .select('id')
                .eq('username', username)
                .eq('campus', staffCampus)
                .maybeSingle();

            if (existingStaff) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Username already exists in this campus' 
                });
            }
            
            const initials = name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase();
            
            const tempPassword = crypto.randomBytes(12).toString('base64').slice(0, 16);
            const hashedPassword = await bcrypt.hash(tempPassword, SALT_ROUNDS);
            
            const newStaff = { 
                name, username, password: hashedPassword, role, 
                hostel_id: hostel_id || null, 
                assigned_floor: assigned_floor || null, 
                assigned_room: assigned_room || null, 
                status: 'Active', 
                initials, 
                email: email || null, 
                phone: phone || null, 
                department: department || null, 
                joined: new Date().toISOString().split('T')[0],
                campus: staffCampus,
                campus_code: staffCampus === 'Legacy' ? 'LEG' : 'HER'
            };

            const { data, error } = await supabase
                .from('staff')
                .insert(newStaff)
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Staff Created',
                module: 'staff',
                details: `Created ${role} account for ${name} (${username}) in ${staffCampus} campus`,
                result: 'success',
                category: 'staff',
                hostel_id: data.hostel_id,
                campus: staffCampus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            const { password: _, ...staffWithoutPassword } = data;

            res.json({ 
                success: true, 
                data: staffWithoutPassword,
                campus: staffCampus,
                message: `Staff created successfully. Temporary password: ${tempPassword} (Please change on first login)`
            });
        } catch (error) {
            console.error('Error creating staff:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.put('/api/staff/:id', 
    campusIsolation,
    requireRole('Admin', 'System Owner'),
    validate(validators.updateStaff),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const { name, username, role, hostel_id, status, email, phone, department, assigned_floor, assigned_room, campus } = req.body;
        
        try {
            const { data: existing } = await supabase
                .from('staff')
                .select('hostel_id, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (!existing) {
                return res.status(404).json({
                    success: false,
                    message: 'Staff not found in this campus'
                });
            }

            const updateData = {};
            const changes = [];

            if (name !== undefined) { updateData.name = name; changes.push('name'); }
            if (username !== undefined) { updateData.username = username; changes.push('username'); }
            if (role !== undefined) { updateData.role = role; changes.push('role'); }
            if (hostel_id !== undefined) { updateData.hostel_id = hostel_id || null; changes.push('hostel_id'); }
            if (assigned_floor !== undefined) { updateData.assigned_floor = assigned_floor || null; changes.push('assigned_floor'); }
            if (assigned_room !== undefined) { updateData.assigned_room = assigned_room || null; changes.push('assigned_room'); }
            if (status !== undefined) { updateData.status = status; changes.push('status'); }
            if (email !== undefined) { updateData.email = email; changes.push('email'); }
            if (phone !== undefined) { updateData.phone = phone; changes.push('phone'); }
            if (department !== undefined) { updateData.department = department; changes.push('department'); }
            if (campus !== undefined) { 
                updateData.campus = campus; 
                updateData.campus_code = campus === 'Legacy' ? 'LEG' : 'HER';
                changes.push('campus'); 
            }

            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update' 
                });
            }

            updateData.updated_at = new Date().toISOString();

            const { data, error } = await supabase
                .from('staff')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Staff Updated',
                module: 'staff',
                details: `Updated ${data?.name}: ${changes.join(', ')}`,
                result: 'success',
                category: 'staff',
                hostel_id: data?.hostel_id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            const { password: _, ...staffWithoutPassword } = data;
            res.json({ success: true, data: staffWithoutPassword, campus: req.campus });
        } catch (error) {
            console.error('Error updating staff:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.delete('/api/staff/:id', 
    campusIsolation,
    requireRole('Admin', 'System Owner'),
    validate(validators.staffId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data: user } = await supabase
                .from('staff')
                .select('name, role, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'Staff not found in this campus'
                });
            }
            
            const { error } = await supabase
                .from('staff')
                .delete()
                .eq('id', id)
                .eq('campus', req.campus);
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Staff Deleted',
                module: 'staff',
                details: `Deleted ${user?.name} (${user?.role})`,
                result: 'success',
                category: 'staff',
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                message: 'Staff deleted successfully',
                campus: req.campus
            });
        } catch (error) {
            console.error('Error deleting staff:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// SYSTEM OWNER STAFF MANAGEMENT (Hidden from other roles)
// =====================================================

// System Owner only - Get all staff including System Owner
app.get('/api/system-owner/staff',
    campusIsolation,
    requireRole('System Owner'),
    validate(validators.pagination),
    async (req, res) => {
        try {
            const limit = Math.min(parseInt(req.query.limit) || 50, 100);
            const offset = parseInt(req.query.offset) || 0;
            
            const { data, error, count } = await supabase
                .from('staff')
                .select('id, name, username, role, hostel_id, assigned_floor, assigned_room, status, email, phone, department, initials, joined, last_login, campus, campus_code')
                .eq('campus', req.campus)
                .order('name', { ascending: true })
                .range(offset, offset + limit - 1);
            
            if (error) throw error;

            const sanitizedData = data.map(item => ({
                ...item,
                staff_id: item.id
            }));

            res.json({ 
                success: true, 
                data: sanitizedData,
                pagination: { limit, offset, total: count || data.length },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching staff for System Owner:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// System Owner only - Create new System Owner accounts
app.post('/api/system-owner/staff',
    campusIsolation,
    requireRole('System Owner'),
    validate(validators.createStaff),
    async (req, res) => {
        const { name, username, role, hostel_id, email, phone, department, assigned_floor, assigned_room, campus } = req.body;
        
        // Only allow System Owner role to be created through this endpoint
        if (role !== 'System Owner') {
            return res.status(403).json({
                success: false,
                message: 'This endpoint can only create System Owner accounts.'
            });
        }
        
        try {
            const staffCampus = campus || req.campus || 'Legacy';
            
            const { data: existingStaff } = await supabase
                .from('staff')
                .select('id')
                .eq('username', username)
                .eq('campus', staffCampus)
                .maybeSingle();

            if (existingStaff) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Username already exists in this campus' 
                });
            }
            
            const initials = name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase();
            
            const tempPassword = crypto.randomBytes(12).toString('base64').slice(0, 16);
            const hashedPassword = await bcrypt.hash(tempPassword, SALT_ROUNDS);
            
            const newStaff = { 
                name, username, password: hashedPassword, role, 
                hostel_id: hostel_id || null, 
                assigned_floor: assigned_floor || null, 
                assigned_room: assigned_room || null, 
                status: 'Active', 
                initials, 
                email: email || null, 
                phone: phone || null, 
                department: department || null, 
                joined: new Date().toISOString().split('T')[0],
                campus: staffCampus,
                campus_code: staffCampus === 'Legacy' ? 'LEG' : 'HER'
            };

            const { data, error } = await supabase
                .from('staff')
                .insert(newStaff)
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'System Owner Created',
                module: 'staff',
                details: `Created System Owner account for ${name} (${username})`,
                result: 'success',
                category: 'staff',
                campus: staffCampus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            const { password: _, ...staffWithoutPassword } = data;

            res.json({ 
                success: true, 
                data: staffWithoutPassword,
                campus: staffCampus,
                message: `System Owner created successfully. Temporary password: ${tempPassword} (Please change on first login)`
            });
        } catch (error) {
            console.error('Error creating System Owner:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// System Owner only - Update System Owner accounts
app.put('/api/system-owner/staff/:id',
    campusIsolation,
    requireRole('System Owner'),
    validate(validators.updateStaff),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const { name, username, role, hostel_id, status, email, phone, department, assigned_floor, assigned_room, campus } = req.body;
        
        try {
            const { data: existing } = await supabase
                .from('staff')
                .select('role, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (!existing) {
                return res.status(404).json({
                    success: false,
                    message: 'Staff not found in this campus'
                });
            }

            // Only System Owners can update System Owner accounts
            if (existing.role === 'System Owner' && req.user.role !== 'System Owner') {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. Only System Owners can update System Owner accounts.'
                });
            }

            const updateData = {};
            const changes = [];

            if (name !== undefined) { updateData.name = name; changes.push('name'); }
            if (username !== undefined) { updateData.username = username; changes.push('username'); }
            if (role !== undefined) { 
                // Prevent changing System Owner role to something else
                if (existing.role === 'System Owner' && role !== 'System Owner') {
                    return res.status(403).json({
                        success: false,
                        message: 'Cannot change System Owner role.'
                    });
                }
                updateData.role = role; 
                changes.push('role'); 
            }
            if (hostel_id !== undefined) { updateData.hostel_id = hostel_id || null; changes.push('hostel_id'); }
            if (assigned_floor !== undefined) { updateData.assigned_floor = assigned_floor || null; changes.push('assigned_floor'); }
            if (assigned_room !== undefined) { updateData.assigned_room = assigned_room || null; changes.push('assigned_room'); }
            if (status !== undefined) { updateData.status = status; changes.push('status'); }
            if (email !== undefined) { updateData.email = email; changes.push('email'); }
            if (phone !== undefined) { updateData.phone = phone; changes.push('phone'); }
            if (department !== undefined) { updateData.department = department; changes.push('department'); }
            if (campus !== undefined) { 
                updateData.campus = campus; 
                updateData.campus_code = campus === 'Legacy' ? 'LEG' : 'HER';
                changes.push('campus'); 
            }

            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update' 
                });
            }

            updateData.updated_at = new Date().toISOString();

            const { data, error } = await supabase
                .from('staff')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'System Owner Updated',
                module: 'staff',
                details: `Updated System Owner ${data?.name}: ${changes.join(', ')}`,
                result: 'success',
                category: 'staff',
                hostel_id: data?.hostel_id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            const { password: _, ...staffWithoutPassword } = data;
            res.json({ success: true, data: staffWithoutPassword, campus: req.campus });
        } catch (error) {
            console.error('Error updating System Owner:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// System Owner only - Delete System Owner accounts
app.delete('/api/system-owner/staff/:id',
    campusIsolation,
    requireRole('System Owner'),
    validate(validators.staffId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data: user } = await supabase
                .from('staff')
                .select('name, role, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'Staff not found in this campus'
                });
            }

            // Only System Owners can delete System Owner accounts
            if (user.role === 'System Owner' && req.user.role !== 'System Owner') {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. Only System Owners can delete System Owner accounts.'
                });
            }

            // Prevent deleting your own account
            if (id === req.user.id) {
                return res.status(403).json({
                    success: false,
                    message: 'You cannot delete your own account.'
                });
            }
            
            const { error } = await supabase
                .from('staff')
                .delete()
                .eq('id', id)
                .eq('campus', req.campus);
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'System Owner Deleted',
                module: 'staff',
                details: `Deleted System Owner: ${user?.name}`,
                result: 'success',
                category: 'staff',
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                message: 'System Owner deleted successfully',
                campus: req.campus
            });
        } catch (error) {
            console.error('Error deleting System Owner:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// RA ROOM ASSIGNMENTS (HRA Only)
// =====================================================

app.get('/api/hra/ras',
    campusIsolation,
    requireRole('HRA', 'Admin', 'System Owner'),
    async (req, res) => {
        try {
            let hostelId = req.user.hostel_id;
            if ((req.user.role === 'Admin' || req.user.role === 'System Owner') && req.query.hostel_id) {
                hostelId = parseInt(req.query.hostel_id);
            }

            if (!hostelId) {
                return res.status(400).json({
                    success: false,
                    message: 'No hostel assigned to this HRA'
                });
            }

            const { data: hostel } = await supabase
                .from('hostels')
                .select('id, name, assignment_type')
                .eq('id', hostelId)
                .eq('campus', req.campus)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Hostel not found in this campus'
                });
            }

            const { data: ras, error: rasError } = await supabase
                .from('staff')
                .select('id, name, username, email, phone, status')
                .eq('hostel_id', hostelId)
                .eq('role', 'RA')
                .eq('status', 'Active')
                .eq('campus', req.campus)
                .order('name');

            if (rasError) throw rasError;

            const raIds = ras.map(ra => ra.id);
            let assignments = [];
            if (raIds.length > 0) {
                const { data: assignData } = await supabase
                    .from('ra_room_assignments')
                    .select('ra_id, room_id, rooms(room_code, id)')
                    .in('ra_id', raIds)
                    .eq('status', 'active')
                    .eq('campus', req.campus);
                assignments = assignData || [];
            }

            const { data: rooms, error: roomsError } = await supabase
                .from('rooms')
                .select('id, room_code, capacity, occupied, status, floor_flat_id, floors_flats(name)')
                .eq('hostel_id', hostelId)
                .eq('status', 'active');

            if (roomsError) throw roomsError;

            const enrichedRas = ras.map(ra => {
                const raAssignments = assignments.filter(a => a.ra_id === ra.id);
                const assignedRoomIds = raAssignments.map(a => a.room_id);
                const assignedRoomCodes = raAssignments
                    .map(a => a.rooms?.room_code)
                    .filter(Boolean)
                    .sort();

                return {
                    ...ra,
                    assigned_rooms: assignedRoomIds,
                    assigned_room_codes: assignedRoomCodes,
                    assigned_count: assignedRoomIds.length
                };
            });

            res.json({
                success: true,
                data: {
                    hostel: { id: hostel.id, name: hostel.name, assignment_type: hostel.assignment_type || 'room_range' },
                    ras: enrichedRas,
                    rooms: rooms || [],
                    total_ras: ras.length,
                    total_rooms: rooms?.length || 0
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Error fetching RAs:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/hra/assign-rooms',
    campusIsolation,
    requireRole('HRA', 'Admin', 'System Owner'),
    validate(validators.raRoomAssignment),
    async (req, res) => {
        try {
            const { ra_id, room_ids } = req.body;
            const hraId = req.user.id;

            const { data: ra, error: raError } = await supabase
                .from('staff')
                .select('id, name, hostel_id, campus')
                .eq('id', ra_id)
                .eq('role', 'RA')
                .eq('status', 'Active')
                .eq('campus', req.campus)
                .single();

            if (raError || !ra) {
                return res.status(404).json({
                    success: false,
                    message: 'RA not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== ra.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only assign rooms in your hostel.'
                });
            }

            const { data: rooms, error: roomsError } = await supabase
                .from('rooms')
                .select('id, room_code, hostel_id')
                .in('id', room_ids)
                .eq('hostel_id', ra.hostel_id)
                .eq('status', 'active');

            if (roomsError) throw roomsError;

            if (!rooms || rooms.length !== room_ids.length) {
                return res.status(400).json({
                    success: false,
                    message: 'One or more rooms not found or not in this hostel'
                });
            }

            await supabase
                .from('ra_room_assignments')
                .delete()
                .eq('ra_id', ra_id)
                .eq('campus', req.campus);

            const assignments = room_ids.map(roomId => ({
                ra_id: ra_id,
                room_id: roomId,
                assigned_by: hraId,
                assigned_at: new Date().toISOString(),
                status: 'active',
                campus: req.campus,
                campus_code: req.campus === 'Legacy' ? 'LEG' : 'HER'
            }));

            const { data: assignedData, error: assignError } = await supabase
                .from('ra_room_assignments')
                .insert(assignments)
                .select();

            if (assignError) throw assignError;

            await auditEvents.raRoomAssigned(ra, rooms, req.user, req);

            res.json({
                success: true,
                data: {
                    ra: { id: ra.id, name: ra.name },
                    assigned_rooms: rooms,
                    count: rooms.length,
                    message: `Successfully assigned ${rooms.length} rooms to ${ra.name}`
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Error assigning rooms:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.get('/api/ra/rooms',
    campusIsolation,
    requireRole('RA'),
    async (req, res) => {
        try {
            const raId = req.user.id;

            const { data: assignments, error } = await supabase
                .from('ra_room_assignments')
                .select('room_id, rooms(room_code, id, capacity, occupied, status, floor_flat_id, floors_flats(name))')
                .eq('ra_id', raId)
                .eq('status', 'active')
                .eq('campus', req.campus);

            if (error) throw error;

            const rooms = assignments.map(a => a.rooms).filter(Boolean);

            res.json({
                success: true,
                data: {
                    rooms: rooms,
                    count: rooms.length,
                    room_codes: rooms.map(r => r.room_code).sort()
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Error fetching RA rooms:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.get('/api/ra/dashboard',
    campusIsolation,
    requireRole('RA'),
    async (req, res) => {
        try {
            const raId = req.user.id;

            const { data: assignments, error: roomsError } = await supabase
                .from('ra_room_assignments')
                .select('room_id, rooms(room_code, id, capacity, occupied, status, floor_flat_id, floors_flats(name))')
                .eq('ra_id', raId)
                .eq('status', 'active')
                .eq('campus', req.campus);

            if (roomsError) throw roomsError;

            const rooms = assignments.map(a => a.rooms).filter(Boolean);

            const today = new Date().toISOString().split('T')[0];
            const { data: sessions, error: sessionsError } = await supabase
                .from('ra_bedcheck_sessions')
                .select('*, staff(name)')
                .eq('ra_id', raId)
                .eq('campus', req.campus)
                .order('created_at', { ascending: false })
                .limit(5);

            if (sessionsError) throw sessionsError;

            const activeSession = sessions?.find(s => s.status === 'started');
            const completedToday = sessions?.some(s => {
                const completedDate = s.completed_at ? new Date(s.completed_at).toISOString().split('T')[0] : null;
                return s.status === 'completed' && completedDate === today;
            });
            const hasSuspicious = sessions?.some(s => s.is_suspicious);

            res.json({
                success: true,
                data: {
                    assigned_rooms: rooms || [],
                    room_count: rooms?.length || 0,
                    room_codes: rooms.map(r => r.room_code).sort(),
                    active_session: activeSession || null,
                    has_active_session: !!activeSession,
                    has_completed_today: completedToday || false,
                    is_suspicious: hasSuspicious || false,
                    recent_sessions: sessions || [],
                    can_start_new: !activeSession && !completedToday && !hasSuspicious,
                    message: !activeSession && !completedToday && !hasSuspicious 
                        ? 'You can start your BedCheck now' 
                        : activeSession 
                            ? 'You have an active BedCheck session' 
                            : completedToday 
                                ? 'You have already completed today\'s BedCheck' 
                                : 'Your account has been flagged for review'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Error fetching RA dashboard:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

// =====================================================
// RA BEDCHECK SESSION MANAGEMENT
// =====================================================

app.post('/api/ra/bedcheck/start',
    campusIsolation,
    requireRole('RA'),
    validate(validators.bedcheckStart),
    async (req, res) => {
        try {
            const { session_id } = req.body;
            const raId = req.user.id;

            const { data: existing, error: checkError } = await supabase
                .from('ra_bedcheck_sessions')
                .select('id, status, started_at, completed_at, is_suspicious, suspicious_reason, flagged_at')
                .eq('ra_id', raId)
                .eq('session_id', session_id)
                .eq('campus', req.campus)
                .maybeSingle();

            if (checkError) throw checkError;

            if (existing) {
                if (existing.status === 'completed') {
                    await supabase
                        .from('ra_bedcheck_sessions')
                        .update({
                            is_suspicious: true,
                            suspicious_reason: 'RA attempted to start a completed session',
                            flagged_at: new Date().toISOString(),
                            status: 'flagged',
                            updated_at: new Date().toISOString()
                        })
                        .eq('id', existing.id);

                    const { data: raData } = await supabase
                        .from('staff')
                        .select('name, hostel_id')
                        .eq('id', raId)
                        .single();

                    await supabase
                        .from('notifications')
                        .insert({
                            title: '⚠️ Suspicious Activity: RA Login Attempt',
                            detail: `RA ${raData?.name || 'Unknown'} attempted to start BedCheck after completion`,
                            body: `RA tried to log in again after completing tonight's BedCheck. This has been flagged for review.`,
                            type: 'security',
                            priority: 'high',
                            hostel_id: raData?.hostel_id,
                            campus: req.campus,
                            recipient_role: 'HRA',
                            actor: 'System',
                            action: 'Suspicious Login',
                            tone: 'red',
                            read: false,
                            created_at: new Date().toISOString()
                        });

                    await supabase
                        .from('notifications')
                        .insert({
                            title: '⚠️ Suspicious Activity: RA Login Attempt',
                            detail: `RA ${raData?.name || 'Unknown'} attempted to start BedCheck after completion`,
                            body: `RA tried to log in again after completing tonight's BedCheck. HRA has been notified.`,
                            type: 'security',
                            priority: 'high',
                            campus: req.campus,
                            recipient_role: 'RASD',
                            actor: 'System',
                            action: 'Suspicious Login',
                            tone: 'red',
                            read: false,
                            created_at: new Date().toISOString()
                        });

                    await auditEvents.raSuspiciousFlagged(
                        { name: raData?.name || 'Unknown', hostel_id: raData?.hostel_id },
                        { id: session_id },
                        'RA attempted to start a completed session',
                        req
                    );

                    return res.status(403).json({
                        success: false,
                        message: 'This BedCheck session has already been completed. This activity has been flagged.',
                        data: {
                            is_suspicious: true,
                            flagged: true,
                            completed_at: existing.completed_at
                        }
                    });
                }

                if (existing.is_suspicious) {
                    return res.status(403).json({
                        success: false,
                        message: 'This session has been flagged for suspicious activity. Please contact your HRA.',
                        data: {
                            is_suspicious: true,
                            reason: existing.suspicious_reason,
                            flagged_at: existing.flagged_at
                        }
                    });
                }

                if (existing.status === 'started') {
                    return res.json({
                        success: true,
                        data: {
                            session_id: session_id,
                            status: existing.status,
                            started_at: existing.started_at,
                            message: 'Session already started',
                            is_new_session: false
                        },
                        campus: req.campus
                    });
                }
            }

            const { data: assignedRooms, error: roomsError } = await supabase
                .from('ra_room_assignments')
                .select('room_id, rooms(room_code, id, floor_flat_id)')
                .eq('ra_id', raId)
                .eq('status', 'active')
                .eq('campus', req.campus);

            if (roomsError) throw roomsError;

            if (!assignedRooms || assignedRooms.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'No rooms assigned to you for this BedCheck.'
                });
            }

            const { data: sessionData, error: sessionError } = await supabase
                .from('ra_bedcheck_sessions')
                .insert({
                    ra_id: raId,
                    session_id: session_id,
                    hostel_id: req.user.hostel_id,
                    status: 'started',
                    started_at: new Date().toISOString(),
                    campus: req.campus,
                    campus_code: req.campus === 'Legacy' ? 'LEG' : 'HER'
                })
                .select()
                .single();

            if (sessionError) throw sessionError;

            await auditEvents.raSessionStarted(req.user, { id: session_id }, req);

            res.json({
                success: true,
                data: {
                    session: sessionData,
                    assigned_rooms: assignedRooms.map(a => a.rooms).filter(Boolean),
                    room_count: assignedRooms.length,
                    is_new_session: true,
                    message: 'BedCheck session started successfully'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Start RA BedCheck error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.post('/api/ra/bedcheck/complete',
    campusIsolation,
    requireRole('RA'),
    validate(validators.bedcheckStart),
    async (req, res) => {
        try {
            const { session_id } = req.body;
            const raId = req.user.id;

            const { data: sessionData, error: sessionError } = await supabase
                .from('ra_bedcheck_sessions')
                .select('id, status, is_suspicious')
                .eq('ra_id', raId)
                .eq('session_id', session_id)
                .eq('campus', req.campus)
                .single();

            if (sessionError || !sessionData) {
                return res.status(404).json({
                    success: false,
                    message: 'BedCheck session not found'
                });
            }

            if (sessionData.status === 'completed') {
                return res.status(400).json({
                    success: false,
                    message: 'This session is already completed'
                });
            }

            if (sessionData.is_suspicious) {
                return res.status(403).json({
                    success: false,
                    message: 'This session has been flagged. Cannot complete.'
                });
            }

            const { data: updated, error: updateError } = await supabase
                .from('ra_bedcheck_sessions')
                .update({
                    status: 'completed',
                    completed_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                })
                .eq('id', sessionData.id)
                .select()
                .single();

            if (updateError) throw updateError;

            await auditEvents.raSessionCompleted(req.user, { id: session_id }, req);

            res.json({
                success: true,
                data: {
                    session: updated,
                    message: 'BedCheck completed successfully'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Complete RA BedCheck error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.get('/api/ra/bedcheck/status',
    campusIsolation,
    requireRole('RA'),
    async (req, res) => {
        try {
            const raId = req.user.id;
            const { session_id } = req.query;

            let query = supabase
                .from('ra_bedcheck_sessions')
                .select('*, staff(name)')
                .eq('ra_id', raId)
                .eq('campus', req.campus);

            if (session_id) {
                query = query.eq('session_id', parseInt(session_id));
            }

            const { data, error } = await query
                .order('created_at', { ascending: false })
                .limit(10);

            if (error) throw error;

            const { data: roomsData, error: roomsError } = await supabase
                .from('ra_room_assignments')
                .select('room_id', { count: 'exact' })
                .eq('ra_id', raId)
                .eq('status', 'active')
                .eq('campus', req.campus);

            if (roomsError) throw roomsError;

            const { data: activeSession } = await supabase
                .from('ra_bedcheck_sessions')
                .select('*')
                .eq('ra_id', raId)
                .eq('campus', req.campus)
                .eq('status', 'started')
                .maybeSingle();

            res.json({
                success: true,
                data: {
                    sessions: data || [],
                    assigned_rooms: roomsData?.length || 0,
                    active_session: activeSession || null,
                    has_active_session: !!activeSession,
                    has_completed_today: data?.some(s => {
                        const today = new Date().toDateString();
                        const completedAt = s.completed_at ? new Date(s.completed_at).toDateString() : null;
                        return s.status === 'completed' && completedAt === today;
                    })
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Get RA BedCheck status error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

// =====================================================
// SECURITY - SUSPICIOUS ACTIVITY
// =====================================================

app.get('/api/security/suspicious',
    campusIsolation,
    requireRole('Admin', 'HRA', 'RASD', 'System Owner'),
    async (req, res) => {
        try {
            let query = supabase
                .from('ra_bedcheck_sessions')
                .select('*, staff(name, username)')
                .eq('campus', req.campus)
                .eq('is_suspicious', true)
                .eq('status', 'flagged')
                .order('flagged_at', { ascending: false });

            if (req.user.role === 'HRA' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }

            const { data, error } = await query;
            if (error) throw error;

            const { data: counts } = await supabase
                .from('ra_bedcheck_sessions')
                .select('status', { count: 'exact' })
                .eq('campus', req.campus)
                .eq('is_suspicious', true);

            res.json({
                success: true,
                data: {
                    suspicious_sessions: data || [],
                    total_suspicious: counts?.length || 0,
                    pending_review: data?.filter(d => d.status === 'flagged').length || 0,
                    campus: req.campus
                }
            });

        } catch (error) {
            console.error('Get suspicious activity error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.put('/api/security/resolve/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'RASD', 'System Owner'),
    validate(validators.suspiciousResolve),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const { resolution, notes } = req.body;

            const { data: session, error: fetchError } = await supabase
                .from('ra_bedcheck_sessions')
                .select('*, staff(name, hostel_id)')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (fetchError || !session) {
                return res.status(404).json({
                    success: false,
                    message: 'Session not found in this campus'
                });
            }

            const updateData = {
                status: resolution === 'cleared' ? 'completed' : 'flagged',
                is_suspicious: resolution !== 'cleared',
                suspicious_reason: notes || session.suspicious_reason,
                updated_at: new Date().toISOString()
            };

            if (resolution === 'cleared') {
                updateData.is_suspicious = false;
                updateData.status = 'completed';
                updateData.completed_at = new Date().toISOString();
            }

            const { data: updated, error: updateError } = await supabase
                .from('ra_bedcheck_sessions')
                .update(updateData)
                .eq('id', id)
                .select()
                .single();

            if (updateError) throw updateError;

            await supabase
                .from('notifications')
                .insert({
                    title: `Suspicious Activity ${resolution === 'cleared' ? 'Cleared' : 'Action Taken'}`,
                    detail: `Your BedCheck session has been ${resolution === 'cleared' ? 'cleared' : 'reviewed'}`,
                    body: resolution === 'cleared' 
                        ? 'The suspicious activity flag has been cleared. You can continue with your BedCheck.'
                        : `Action taken on your flagged session: ${resolution}`,
                    type: 'security',
                    priority: 'medium',
                    hostel_id: session.hostel_id,
                    campus: req.campus,
                    recipient_role: 'RA',
                    recipient_id: session.ra_id,
                    actor: req.user.name || req.user.username,
                    action: `Suspicious Activity ${resolution === 'cleared' ? 'Cleared' : 'Reviewed'}`,
                    tone: resolution === 'cleared' ? 'green' : 'gold',
                    read: false,
                    created_at: new Date().toISOString()
                });

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: `Suspicious Activity ${resolution === 'cleared' ? 'Cleared' : 'Reviewed'}`,
                module: 'security',
                details: `${session.staff?.name || 'RA'} session ${resolution === 'cleared' ? 'cleared' : 'reviewed as ' + resolution}`,
                context: `Session ID: ${id}`,
                result: resolution === 'cleared' ? 'success' : 'warning',
                category: 'security',
                tone: resolution === 'cleared' ? 'green' : 'gold',
                hostel_id: session.hostel_id,
                session_id: session.session_id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: updated,
                message: `Suspicious activity ${resolution === 'cleared' ? 'cleared' : 'reviewed'} successfully`,
                campus: req.campus
            });

        } catch (error) {
            console.error('Resolve suspicious error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

// =====================================================
// HOSTEL CRUD (Protected) - WITH CAMPUS SUPPORT
// =====================================================

app.get('/api/hostels',
    campusIsolation,
    async (req, res) => {
        try {
            let query = supabase
                .from('hostels')
                .select('*')
                .eq('campus', req.campus)
                .order('name', { ascending: true });
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                query = query.eq('id', req.user.hostel_id);
            }

            const { data: hostelsData, error: hostelsError } = await query;
            if (hostelsError) throw hostelsError;

            const hostelIds = hostelsData.map(h => h.id);
            let floorsData = [];
            let staffData = [];
            
            if (hostelIds.length > 0) {
                const { data: floors } = await supabase
                    .from('floors_flats')
                    .select('id, hostel_id, name, type')
                    .in('hostel_id', hostelIds);
                floorsData = floors || [];

                const { data: staff } = await supabase
                    .from('staff')
                    .select('id, name, role, hostel_id')
                    .in('hostel_id', hostelIds)
                    .eq('status', 'Active')
                    .eq('campus', req.campus);
                staffData = staff || [];
            }

            const enrichedHostels = hostelsData.map(hostel => {
                const hostelFloors = floorsData.filter(f => f.hostel_id === hostel.id);
                const hostelStaff = staffData.filter(s => s.hostel_id === hostel.id);
                const hraStaff = hostelStaff.find(s => s.role === 'HRA');
                const raStaff = hostelStaff.filter(s => s.role === 'RA');

                return {
                    ...hostel,
                    floors: hostelFloors.length,
                    hra_name: hraStaff ? hraStaff.name : null,
                    hra_id: hraStaff ? hraStaff.id : null,
                    ra_count: raStaff.length,
                    ra_names: raStaff.map(s => s.name).join(', ')
                };
            });

            res.json({ 
                success: true, 
                data: enrichedHostels,
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching hostels:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/hostels/:id',
    campusIsolation,
    validate(validators.hostelId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data: hostelData, error: hostelError } = await supabase
                .from('hostels')
                .select('*')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (hostelError || !hostelData) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Hostel not found in this campus' 
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const { data: staffData } = await supabase
                .from('staff')
                .select('id, name, role, username, email, phone')
                .eq('hostel_id', id)
                .eq('status', 'Active')
                .eq('campus', req.campus);

            const hraStaff = staffData?.find(s => s.role === 'HRA');
            const raStaff = staffData?.filter(s => s.role === 'RA') || [];

            const enrichedHostel = {
                ...hostelData,
                hra_name: hraStaff ? hraStaff.name : hostelData.hra,
                hra_id: hraStaff ? hraStaff.id : null,
                ra_count: raStaff.length,
                ra_list: raStaff.map(s => ({
                    id: s.id,
                    name: s.name,
                    username: s.username,
                    email: s.email,
                    phone: s.phone
                }))
            };

            res.json({ 
                success: true, 
                data: enrichedHostel,
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching hostel:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/hostels',
    campusIsolation,
    requireRole('Admin', 'System Owner'),
    validate(validators.hostelCreate),
    async (req, res) => {
        const { name, gender, type, total_floors, rooms_per_floor, total_flats, rooms_per_flat, beds_per_room, campus } = req.body;
        try {
            const hostelCampus = campus || req.campus || 'Legacy';
            
            const newHostel = {
                name, gender: gender || 'Male', type: type || 'floor',
                total_floors: total_floors || 0, rooms_per_floor: rooms_per_floor || 18,
                total_flats: total_flats || 0, rooms_per_flat: rooms_per_flat || 4,
                beds_per_room: beds_per_room || 4,
                progress: 0, state: 'Active',
                assignment_type: type === 'flat' ? 'flat' : 'room_range',
                campus: hostelCampus, campus_code: hostelCampus === 'Legacy' ? 'LEG' : 'HER',
                created_at: new Date().toISOString(), updated_at: new Date().toISOString()
            };

            const { data, error } = await supabase
                .from('hostels')
                .insert(newHostel)
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Hostel Created',
                module: 'hostel',
                details: `Created hostel: ${data.name} in ${hostelCampus} campus`,
                result: 'success',
                category: 'hostel',
                hostel_id: data.id,
                campus: hostelCampus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({ 
                success: true, 
                data: data,
                campus: hostelCampus
            });
        } catch (error) {
            console.error('Error creating hostel:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.put('/api/hostels/:id',
    campusIsolation,
    requireRole('Admin', 'System Owner'),
    validate(validators.hostelId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const { name, gender, type, total_floors, rooms_per_floor, total_flats, rooms_per_flat, beds_per_room, progress, state, ra, hra, campus, assignment_type } = req.body;
        try {
            const { data: existing } = await supabase
                .from('hostels')
                .select('id, name')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (!existing) {
                return res.status(404).json({
                    success: false,
                    message: 'Hostel not found in this campus'
                });
            }

            const updateData = {};
            const changes = [];
            if (name !== undefined) { updateData.name = name; changes.push('name'); }
            if (gender !== undefined) { updateData.gender = gender; changes.push('gender'); }
            if (type !== undefined) { updateData.type = type; changes.push('type'); }
            if (assignment_type !== undefined) { updateData.assignment_type = assignment_type; changes.push('assignment_type'); }
            if (total_floors !== undefined && total_floors !== null) { updateData.total_floors = total_floors; changes.push('total_floors'); }
            if (rooms_per_floor !== undefined && rooms_per_floor !== null) { updateData.rooms_per_floor = rooms_per_floor; changes.push('rooms_per_floor'); }
            if (total_flats !== undefined && total_flats !== null) { updateData.total_flats = total_flats; changes.push('total_flats'); }
            if (rooms_per_flat !== undefined && rooms_per_flat !== null) { updateData.rooms_per_flat = rooms_per_flat; changes.push('rooms_per_flat'); }
            if (beds_per_room !== undefined) { updateData.beds_per_room = beds_per_room; changes.push('beds_per_room'); }
            if (progress !== undefined) { updateData.progress = progress; changes.push('progress'); }
            if (state !== undefined) { updateData.state = state; changes.push('state'); }
            if (ra !== undefined) { updateData.ra = ra; changes.push('ra'); }
            if (hra !== undefined) { updateData.hra = hra; changes.push('hra'); }
            if (campus !== undefined) { 
                updateData.campus = campus; 
                updateData.campus_code = campus === 'Legacy' ? 'LEG' : 'HER';
                changes.push('campus'); 
            }
            updateData.updated_at = new Date().toISOString();
            
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update' 
                });
            }
            
            const { data, error } = await supabase
                .from('hostels')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();
            
            if (error) throw error;
            
            await auditEvents.hostelUpdated({ id, name: data?.name, campus: req.campus }, changes, { 
                name: req.user.name || req.user.username,
                id: req.user.id,
                role: req.user.role
            });
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error updating hostel:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.delete('/api/hostels/:id',
    campusIsolation,
    requireRole('Admin', 'System Owner'),
    validate(validators.hostelId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data: hostel } = await supabase
                .from('hostels')
                .select('name, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Hostel not found in this campus'
                });
            }

            const { error } = await supabase
                .from('hostels')
                .delete()
                .eq('id', id)
                .eq('campus', req.campus);
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Hostel Deleted',
                module: 'hostel',
                details: `Deleted hostel: ${hostel?.name}`,
                result: 'success',
                category: 'hostel',
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                message: 'Hostel deleted successfully',
                campus: req.campus
            });
        } catch (error) {
            console.error('Error deleting hostel:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/hostels/:id/alerts',
    campusIsolation,
    validate(validators.hostelId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        
        const { data: hostel } = await supabase
            .from('hostels')
            .select('id, name, campus')
            .eq('id', id)
            .eq('campus', req.campus)
            .single();

        if (!hostel) {
            return res.status(404).json({ 
                success: false, 
                message: 'Hostel not found in this campus' 
            });
        }
        
        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const alerts = [];
            
            const { data: absentStudents, error: absentError } = await supabase
                .from('students')
                .select('id, name, matric, status, room_code')
                .eq('hostel_id', id)
                .eq('campus', req.campus)
                .eq('status', 'Absent');
            
            if (!absentError && absentStudents && absentStudents.length > 0) {
                const roomGroups = {};
                absentStudents.forEach(s => {
                    const room = s.room_code || 'Unknown';
                    if (!roomGroups[room]) roomGroups[room] = [];
                    roomGroups[room].push(s);
                });
                
                Object.keys(roomGroups).forEach(room => {
                    const students = roomGroups[room];
                    if (students.length >= 3) {
                        alerts.push({
                            type: 'warning',
                            severity: 'high',
                            title: `${students.length} students absent in ${room}`,
                            description: `Students in ${room} have been marked absent.`,
                            room: room,
                            studentCount: students.length
                        });
                    }
                });
                
                if (absentStudents.length > 10) {
                    alerts.push({
                        type: 'warning',
                        severity: 'high',
                        title: `${absentStudents.length} students marked absent`,
                        description: `High number of absent students in this hostel.`
                    });
                }
            }
            
            const { data: pendingRA, error: raError } = await supabase
                .from('staff')
                .select('id, name, submission_status')
                .eq('hostel_id', id)
                .eq('campus', req.campus)
                .eq('role', 'RA')
                .eq('submission_status', 'Not Started');
            
            if (!raError && pendingRA && pendingRA.length > 0) {
                alerts.push({
                    type: 'warning',
                    severity: 'medium',
                    title: `${pendingRA.length} RA submission${pendingRA.length > 1 ? 's' : ''} pending`,
                    description: `${pendingRA.map(s => s.name).join(', ')} have not started submission.`
                });
            }
            
            if (alerts.length === 0) {
                alerts.push({
                    type: 'success',
                    severity: 'low',
                    title: 'All systems normal',
                    description: 'No alerts for this hostel.'
                });
            }
            
            res.json({ 
                success: true, 
                data: alerts,
                hostel: hostel.name,
                campus: req.campus
            });
            
        } catch (error) {
            console.error('Error fetching hostel alerts:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/hostels/:id/occupancy',
    campusIsolation,
    validate(validators.hostelId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        
        const { data: hostel } = await supabase
            .from('hostels')
            .select('id, name, campus')
            .eq('id', id)
            .eq('campus', req.campus)
            .single();

        if (!hostel) {
            return res.status(404).json({ 
                success: false, 
                message: 'Hostel not found in this campus' 
            });
        }
        
        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const { data: bedSpaces, error: bedError } = await supabase
                .from('bed_spaces')
                .select('id, status, room_id')
                .eq('hostel_id', id)
                .eq('campus', req.campus);
            
            if (bedError) throw bedError;
            
            const total = bedSpaces?.length || 0;
            const available = bedSpaces?.filter(b => b.status === 'available').length || 0;
            const occupied = bedSpaces?.filter(b => b.status === 'occupied').length || 0;
            const maintenance = bedSpaces?.filter(b => b.status === 'maintenance').length || 0;
            const occupancyRate = total > 0 ? Math.round((occupied / total) * 100) : 0;
            
            res.json({
                success: true,
                data: {
                    hostel: hostel.name,
                    totalBeds: total,
                    availableBeds: available,
                    occupiedBeds: occupied,
                    maintenanceBeds: maintenance,
                    occupancyRate: occupancyRate
                },
                campus: req.campus
            });
            
        } catch (error) {
            console.error('Error fetching hostel occupancy:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/hostels/:id/summary',
    campusIsolation,
    validate(validators.hostelId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        
        const { data: hostel } = await supabase
            .from('hostels')
            .select('id, name, campus')
            .eq('id', id)
            .eq('campus', req.campus)
            .single();

        if (!hostel) {
            return res.status(404).json({ 
                success: false, 
                message: 'Hostel not found in this campus' 
            });
        }
        
        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const { data: students, error: studentError } = await supabase
                .from('students')
                .select('status, room_id, face_enrolled')
                .eq('hostel_id', id)
                .eq('campus', req.campus);
            
            if (studentError) throw studentError;
            
            const totalStudents = students?.length || 0;
            const present = students?.filter(s => s.status === 'Present').length || 0;
            const absent = students?.filter(s => s.status === 'Absent').length || 0;
            const late = students?.filter(s => s.status === 'Late').length || 0;
            const assigned = students?.filter(s => s.room_id !== null && s.room_id > 0).length || 0;
            const faceEnrolled = students?.filter(s => s.face_enrolled === true).length || 0;
            
            const { data: bedSpaces, error: bedError } = await supabase
                .from('bed_spaces')
                .select('status')
                .eq('hostel_id', id)
                .eq('campus', req.campus);
            
            if (bedError) throw bedError;
            
            const totalBeds = bedSpaces?.length || 0;
            const availableBeds = bedSpaces?.filter(b => b.status === 'available').length || 0;
            const occupiedBeds = bedSpaces?.filter(b => b.status === 'occupied').length || 0;
            
            res.json({
                success: true,
                data: {
                    hostel: { id: hostel.id, name: hostel.name, gender: hostel.gender, type: hostel.type },
                    students: { total: totalStudents, present, absent, late, assigned, faceEnrolled },
                    beds: {
                        total: totalBeds,
                        available: availableBeds,
                        occupied: occupiedBeds,
                        occupancyRate: totalBeds > 0 ? Math.round((occupiedBeds / totalBeds) * 100) : 0
                    }
                },
                campus: req.campus
            });
            
        } catch (error) {
            console.error('Error fetching hostel summary:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// FLOORS_FLATS CRUD (Protected)
// =====================================================

app.get('/api/floors-flats',
    campusIsolation,
    async (req, res) => {
        const { hostel_id } = req.query;
        try {
            let hostelQuery = supabase
                .from('hostels')
                .select('id')
                .eq('campus', req.campus);
            
            if (hostel_id) {
                hostelQuery = hostelQuery.eq('id', parseInt(hostel_id));
            }
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                hostelQuery = hostelQuery.eq('id', req.user.hostel_id);
            }
            
            const { data: hostels, error: hostelError } = await hostelQuery;
            if (hostelError) throw hostelError;
            
            const hostelIds = hostels.map(h => h.id);
            
            if (hostelIds.length === 0) {
                return res.json({ success: true, data: [], campus: req.campus });
            }
            
            let query = supabase
                .from('floors_flats')
                .select('*')
                .in('hostel_id', hostelIds)
                .order('name', { ascending: true });
            
            const { data, error } = await query;
            if (error) throw error;
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching floors/flats:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/floors-flats/:id',
    campusIsolation,
    validate(validators.floorFlatId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data, error } = await supabase
                .from('floors_flats')
                .select('*')
                .eq('id', id)
                .single();
            
            if (error || !data) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Floor/Flat not found' 
                });
            }

            const { data: hostel } = await supabase
                .from('hostels')
                .select('id, campus')
                .eq('id', data.hostel_id)
                .eq('campus', req.campus)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Floor/Flat not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== data.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching floor/flat:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/floors-flats',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.floorFlatCreate),
    async (req, res) => {
        const { hostel_id, name, type } = req.body;
        
        const { data: hostel } = await supabase
            .from('hostels')
            .select('id, campus')
            .eq('id', hostel_id)
            .eq('campus', req.campus)
            .single();

        if (!hostel) {
            return res.status(404).json({
                success: false,
                message: 'Hostel not found in this campus'
            });
        }

        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const newFloor = { hostel_id: parseInt(hostel_id), name, type: type || 'floor' };
            const { data, error } = await supabase
                .from('floors_flats')
                .insert(newFloor)
                .select()
                .single();
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Floor/Flat Created',
                module: 'hostel',
                details: `Created ${type || 'floor'}: ${name}`,
                result: 'success',
                category: 'hostel',
                hostel_id: hostel_id,
                floor_flat_id: data.id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error creating floor/flat:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.put('/api/floors-flats/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.floorFlatId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const { hostel_id, name, type } = req.body;
        try {
            const { data: existing } = await supabase
                .from('floors_flats')
                .select('hostel_id')
                .eq('id', id)
                .single();

            if (!existing) {
                return res.status(404).json({
                    success: false,
                    message: 'Floor/Flat not found'
                });
            }

            const { data: hostel } = await supabase
                .from('hostels')
                .select('id, campus')
                .eq('id', existing.hostel_id)
                .eq('campus', req.campus)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Floor/Flat not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== existing.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const updateData = {};
            if (hostel_id !== undefined) {
                const { data: newHostel } = await supabase
                    .from('hostels')
                    .select('id')
                    .eq('id', hostel_id)
                    .eq('campus', req.campus)
                    .single();
                
                if (!newHostel) {
                    return res.status(404).json({
                        success: false,
                        message: 'Target hostel not found in this campus'
                    });
                }
                updateData.hostel_id = parseInt(hostel_id);
            }
            if (name !== undefined) updateData.name = name;
            if (type !== undefined) updateData.type = type;
            
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update' 
                });
            }
            
            const { data, error } = await supabase
                .from('floors_flats')
                .update(updateData)
                .eq('id', id)
                .select()
                .single();
            
            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error updating floor/flat:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.delete('/api/floors-flats/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.floorFlatId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data: existing } = await supabase
                .from('floors_flats')
                .select('hostel_id, name, type')
                .eq('id', id)
                .single();

            if (!existing) {
                return res.status(404).json({
                    success: false,
                    message: 'Floor/Flat not found'
                });
            }

            const { data: hostel } = await supabase
                .from('hostels')
                .select('id, campus')
                .eq('id', existing.hostel_id)
                .eq('campus', req.campus)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Floor/Flat not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== existing.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const { error } = await supabase
                .from('floors_flats')
                .delete()
                .eq('id', id);
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Floor/Flat Deleted',
                module: 'hostel',
                details: `Deleted ${existing?.type || 'floor'}: ${existing?.name}`,
                result: 'success',
                category: 'hostel',
                hostel_id: existing?.hostel_id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                message: 'Floor/Flat deleted successfully',
                campus: req.campus
            });
        } catch (error) {
            console.error('Error deleting floor/flat:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// ROOMS CRUD (Protected)
// =====================================================

app.get('/api/rooms',
    campusIsolation,
    async (req, res) => {
        const { floor_flat_id, hostel_id } = req.query;
        try {
            let hostelQuery = supabase
                .from('hostels')
                .select('id')
                .eq('campus', req.campus);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                hostelQuery = hostelQuery.eq('id', req.user.hostel_id);
            }
            
            const { data: hostels, error: hostelError } = await hostelQuery;
            if (hostelError) throw hostelError;
            
            const hostelIds = hostels.map(h => h.id);
            
            if (hostelIds.length === 0) {
                return res.json({ success: true, data: [], campus: req.campus });
            }

            let query = supabase.from('rooms').select('*');
            
            if (floor_flat_id) {
                query = query.eq('floor_flat_id', parseInt(floor_flat_id));
            } else if (hostel_id) {
                const { data: floors, error: floorsError } = await supabase
                    .from('floors_flats')
                    .select('id')
                    .eq('hostel_id', parseInt(hostel_id))
                    .in('hostel_id', hostelIds);
                
                if (floorsError) {
                    console.error('Error fetching floors:', floorsError);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'An error occurred. Please try again.' 
                    });
                }
                
                if (floors && floors.length > 0) {
                    const floorIds = floors.map(f => f.id);
                    query = query.in('floor_flat_id', floorIds);
                } else {
                    return res.json({ success: true, data: [], campus: req.campus });
                }
            } else {
                const { data: floors, error: floorsError } = await supabase
                    .from('floors_flats')
                    .select('id')
                    .in('hostel_id', hostelIds);
                
                if (floorsError) {
                    console.error('Error fetching floors:', floorsError);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'An error occurred. Please try again.' 
                    });
                }
                
                if (floors && floors.length > 0) {
                    const floorIds = floors.map(f => f.id);
                    query = query.in('floor_flat_id', floorIds);
                } else {
                    return res.json({ success: true, data: [], campus: req.campus });
                }
            }
            
            const { data, error } = await query.order('room_code', { ascending: true });
            if (error) throw error;
            
            const enrichedData = await Promise.all(data.map(async (room) => {
                const { data: floorData } = await supabase
                    .from('floors_flats')
                    .select('name, hostel_id')
                    .eq('id', room.floor_flat_id)
                    .maybeSingle();
                
                const { data: bedData } = await supabase
                    .from('bed_spaces')
                    .select('id, status')
                    .eq('room_id', room.id);
                
                const capacity = bedData?.length || 4;
                const occupiedCount = bedData?.filter(b => b.status === 'occupied').length || 0;
                
                return {
                    ...room,
                    floor_label: floorData?.name || null,
                    hostel_id: floorData?.hostel_id || null,
                    capacity: capacity,
                    occupied: occupiedCount,
                    available: capacity - occupiedCount
                };
            }));
            
            res.json({ success: true, data: enrichedData, campus: req.campus });
        } catch (error) {
            console.error('Error fetching rooms:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/rooms/:id',
    campusIsolation,
    validate(validators.roomId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data, error } = await supabase
                .from('rooms')
                .select('*')
                .eq('id', id)
                .single();
            
            if (error || !data) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Room not found' 
                });
            }

            const { data: floorData } = await supabase
                .from('floors_flats')
                .select('hostel_id')
                .eq('id', data.floor_flat_id)
                .single();

            const { data: hostel } = await supabase
                .from('hostels')
                .select('id, campus')
                .eq('id', floorData?.hostel_id)
                .eq('campus', req.campus)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Room not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== floorData?.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }
            
            const { data: bedData } = await supabase
                .from('bed_spaces')
                .select('id, status')
                .eq('room_id', id);
            
            const capacity = bedData?.length || 4;
            const occupiedCount = bedData?.filter(b => b.status === 'occupied').length || 0;
            
            res.json({ 
                success: true, 
                data: { ...data, capacity, occupied: occupiedCount, available: capacity - occupiedCount },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching room:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/rooms',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.roomCreate),
    async (req, res) => {
        const { floor_flat_id, room_code } = req.body;
        try {
            const { data: floorData } = await supabase
                .from('floors_flats')
                .select('hostel_id')
                .eq('id', parseInt(floor_flat_id))
                .single();

            const { data: hostel } = await supabase
                .from('hostels')
                .select('id, campus')
                .eq('id', floorData?.hostel_id)
                .eq('campus', req.campus)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Floor/Flat not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== floorData?.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const newRoom = { floor_flat_id: parseInt(floor_flat_id), room_code };
            const { data, error } = await supabase
                .from('rooms')
                .insert(newRoom)
                .select()
                .single();
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Room Created',
                module: 'hostel',
                details: `Created room: ${room_code}`,
                result: 'success',
                category: 'hostel',
                hostel_id: floorData?.hostel_id,
                room_id: data.id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                data: { ...data, capacity: 4, occupied: 0, available: 4 },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error creating room:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.put('/api/rooms/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.roomId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const { floor_flat_id, room_code } = req.body;
        try {
            const { data: existing } = await supabase
                .from('rooms')
                .select('floor_flat_id')
                .eq('id', id)
                .single();

            const { data: floorData } = await supabase
                .from('floors_flats')
                .select('hostel_id')
                .eq('id', existing?.floor_flat_id)
                .single();

            const { data: hostel } = await supabase
                .from('hostels')
                .select('id, campus')
                .eq('id', floorData?.hostel_id)
                .eq('campus', req.campus)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Room not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== floorData?.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            const updateData = {};
            if (floor_flat_id !== undefined) {
                const { data: newFloor } = await supabase
                    .from('floors_flats')
                    .select('hostel_id')
                    .eq('id', parseInt(floor_flat_id))
                    .single();
                
                const { data: newHostel } = await supabase
                    .from('hostels')
                    .select('id')
                    .eq('id', newFloor?.hostel_id)
                    .eq('campus', req.campus)
                    .single();
                
                if (!newHostel) {
                    return res.status(404).json({
                        success: false,
                        message: 'Target floor not found in this campus'
                    });
                }
                updateData.floor_flat_id = parseInt(floor_flat_id);
            }
            if (room_code !== undefined) updateData.room_code = room_code;
            
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update' 
                });
            }
            
            const { data, error } = await supabase
                .from('rooms')
                .update(updateData)
                .eq('id', id)
                .select()
                .single();
            
            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error updating room:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.delete('/api/rooms/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.roomId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data: room } = await supabase
                .from('rooms')
                .select('room_code, floor_flat_id')
                .eq('id', id)
                .single();

            const { data: floorData } = await supabase
                .from('floors_flats')
                .select('hostel_id')
                .eq('id', room?.floor_flat_id)
                .single();

            const { data: hostel } = await supabase
                .from('hostels')
                .select('id, campus')
                .eq('id', floorData?.hostel_id)
                .eq('campus', req.campus)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Room not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== floorData?.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }

            await supabase
                .from('bed_spaces')
                .delete()
                .eq('room_id', id);

            const { error } = await supabase
                .from('rooms')
                .delete()
                .eq('id', id);
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Room Deleted',
                module: 'hostel',
                details: `Deleted room: ${room?.room_code}`,
                result: 'success',
                category: 'hostel',
                hostel_id: floorData?.hostel_id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                message: 'Room deleted successfully',
                campus: req.campus
            });
        } catch (error) {
            console.error('Error deleting room:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// BED SPACES CRUD (Protected)
// =====================================================

app.get('/api/bed-spaces',
    campusIsolation,
    async (req, res) => {
        const { room_id, hostel_id } = req.query;
        try {
            let hostelQuery = supabase
                .from('hostels')
                .select('id')
                .eq('campus', req.campus);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                hostelQuery = hostelQuery.eq('id', req.user.hostel_id);
            }
            
            const { data: hostels, error: hostelError } = await hostelQuery;
            if (hostelError) throw hostelError;
            
            const hostelIds = hostels.map(h => h.id);
            
            if (hostelIds.length === 0) {
                return res.json({ success: true, data: [], campus: req.campus });
            }

            let query = supabase.from('bed_spaces').select('*');
            
            if (room_id) {
                query = query.eq('room_id', parseInt(room_id));
            } else if (hostel_id) {
                const { data: floors, error: floorsError } = await supabase
                    .from('floors_flats')
                    .select('id')
                    .eq('hostel_id', parseInt(hostel_id))
                    .in('hostel_id', hostelIds);
                
                if (floorsError) {
                    console.error('Error fetching floors:', floorsError);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'An error occurred. Please try again.' 
                    });
                }
                
                if (floors && floors.length > 0) {
                    const floorIds = floors.map(f => f.id);
                    const { data: rooms, error: roomsError } = await supabase
                        .from('rooms')
                        .select('id')
                        .in('floor_flat_id', floorIds);
                    
                    if (roomsError) {
                        console.error('Error fetching rooms:', roomsError);
                        return res.status(500).json({ 
                            success: false, 
                            message: 'An error occurred. Please try again.' 
                        });
                    }
                    
                    if (rooms && rooms.length > 0) {
                        const roomIds = rooms.map(r => r.id);
                        query = query.in('room_id', roomIds);
                    } else {
                        return res.json({ success: true, data: [], campus: req.campus });
                    }
                } else {
                    return res.json({ success: true, data: [], campus: req.campus });
                }
            } else {
                const { data: floors, error: floorsError } = await supabase
                    .from('floors_flats')
                    .select('id')
                    .in('hostel_id', hostelIds);
                
                if (floorsError) {
                    console.error('Error fetching floors:', floorsError);
                    return res.status(500).json({ 
                        success: false, 
                        message: 'An error occurred. Please try again.' 
                    });
                }
                
                if (floors && floors.length > 0) {
                    const floorIds = floors.map(f => f.id);
                    const { data: rooms, error: roomsError } = await supabase
                        .from('rooms')
                        .select('id')
                        .in('floor_flat_id', floorIds);
                    
                    if (roomsError) {
                        console.error('Error fetching rooms:', roomsError);
                        return res.status(500).json({ 
                            success: false, 
                            message: 'An error occurred. Please try again.' 
                        });
                    }
                    
                    if (rooms && rooms.length > 0) {
                        const roomIds = rooms.map(r => r.id);
                        query = query.in('room_id', roomIds);
                    } else {
                        return res.json({ success: true, data: [], campus: req.campus });
                    }
                } else {
                    return res.json({ success: true, data: [], campus: req.campus });
                }
            }
            
            const { data, error } = await query.order('bed_code', { ascending: true });
            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching bed spaces:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/bed-spaces/:id',
    campusIsolation,
    validate(validators.bedSpaceId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data, error } = await supabase
                .from('bed_spaces')
                .select('*')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();
            
            if (error || !data) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Bed space not found in this campus' 
                });
            }
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching bed space:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/bed-spaces',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.bedSpaceCreate),
    async (req, res) => {
        const { room_id, bed_code, full_bed_code, status } = req.body;
        
        const { data: roomData } = await supabase
            .from('rooms')
            .select('floor_flat_id')
            .eq('id', parseInt(room_id))
            .single();
        
        const { data: floorData } = await supabase
            .from('floors_flats')
            .select('hostel_id')
            .eq('id', roomData?.floor_flat_id)
            .single();

        const { data: hostel } = await supabase
            .from('hostels')
            .select('id, campus')
            .eq('id', floorData?.hostel_id)
            .eq('campus', req.campus)
            .single();

        if (!hostel) {
            return res.status(404).json({
                success: false,
                message: 'Room not found in this campus'
            });
        }

        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== floorData?.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const newBed = { 
                room_id: parseInt(room_id), 
                bed_code, 
                full_bed_code: full_bed_code || null, 
                status: status || 'available', 
                student_id: null,
                campus: req.campus,
                created_at: new Date().toISOString(), 
                updated_at: new Date().toISOString() 
            };
            
            const { data, error } = await supabase
                .from('bed_spaces')
                .insert(newBed)
                .select()
                .single();
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Bed Space Created',
                module: 'hostel',
                details: `Created bed space: ${bed_code}`,
                result: 'success',
                category: 'hostel',
                hostel_id: floorData?.hostel_id,
                room_id: parseInt(room_id),
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error creating bed space:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.put('/api/bed-spaces/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.bedSpaceId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const { room_id, bed_code, full_bed_code, status, student_id } = req.body;
        
        const { data: bed } = await supabase
            .from('bed_spaces')
            .select('room_id, campus')
            .eq('id', id)
            .eq('campus', req.campus)
            .single();

        if (!bed) {
            return res.status(404).json({
                success: false,
                message: 'Bed space not found in this campus'
            });
        }

        const { data: roomData } = await supabase
            .from('rooms')
            .select('floor_flat_id')
            .eq('id', bed?.room_id)
            .single();
        
        const { data: floorData } = await supabase
            .from('floors_flats')
            .select('hostel_id')
            .eq('id', roomData?.floor_flat_id)
            .single();

        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== floorData?.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const updateData = {};
            if (room_id !== undefined) updateData.room_id = parseInt(room_id);
            if (bed_code !== undefined) updateData.bed_code = bed_code;
            if (full_bed_code !== undefined) updateData.full_bed_code = full_bed_code;
            if (status !== undefined) updateData.status = status;
            if (student_id !== undefined) updateData.student_id = student_id;
            updateData.updated_at = new Date().toISOString();
            
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update' 
                });
            }
            
            const { data, error } = await supabase
                .from('bed_spaces')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();
            
            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error updating bed space:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.patch('/api/bed-spaces/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.bedSpaceId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const { status, student_id } = req.body;
        
        const { data: bed } = await supabase
            .from('bed_spaces')
            .select('room_id, campus')
            .eq('id', id)
            .eq('campus', req.campus)
            .single();

        if (!bed) {
            return res.status(404).json({
                success: false,
                message: 'Bed space not found in this campus'
            });
        }

        const { data: roomData } = await supabase
            .from('rooms')
            .select('floor_flat_id')
            .eq('id', bed?.room_id)
            .single();
        
        const { data: floorData } = await supabase
            .from('floors_flats')
            .select('hostel_id')
            .eq('id', roomData?.floor_flat_id)
            .single();

        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== floorData?.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const updateData = {};
            if (status !== undefined) updateData.status = status;
            if (student_id !== undefined) updateData.student_id = student_id;
            updateData.updated_at = new Date().toISOString();
            
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update' 
                });
            }
            
            const { data, error } = await supabase
                .from('bed_spaces')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();
            
            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error patching bed space:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.delete('/api/bed-spaces/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.bedSpaceId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        
        const { data: bed } = await supabase
            .from('bed_spaces')
            .select('room_id, bed_code, campus')
            .eq('id', id)
            .eq('campus', req.campus)
            .single();

        if (!bed) {
            return res.status(404).json({
                success: false,
                message: 'Bed space not found in this campus'
            });
        }

        const { data: roomData } = await supabase
            .from('rooms')
            .select('floor_flat_id')
            .eq('id', bed?.room_id)
            .single();
        
        const { data: floorData } = await supabase
            .from('floors_flats')
            .select('hostel_id')
            .eq('id', roomData?.floor_flat_id)
            .single();

        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== floorData?.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const { error } = await supabase
                .from('bed_spaces')
                .delete()
                .eq('id', id)
                .eq('campus', req.campus);
            
            if (error) throw error;
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Bed Space Deleted',
                module: 'hostel',
                details: `Deleted bed space: ${bed?.bed_code}`,
                result: 'success',
                category: 'hostel',
                hostel_id: floorData?.hostel_id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                message: 'Bed space deleted successfully',
                campus: req.campus
            });
        } catch (error) {
            console.error('Error deleting bed space:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// BEDCHECK SESSIONS (Protected)
// =====================================================

app.get('/api/bedcheck/sessions',
    campusIsolation,
    async (req, res) => {
        const { hostel_id, date } = req.query;
        try {
            let query = supabase.from('bedcheck_sessions').select('*').eq('campus', req.campus);
            
            if (hostel_id) query = query.eq('hostel_id', parseInt(hostel_id));
            if (date) query = query.eq('date', date);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            const { data, error } = await query.order('created_at', { ascending: false });
            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching bedcheck sessions:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/bedcheck/sessions',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.bedcheckSession),
    async (req, res) => {
        const { hostel_id, date, start_time, end_time, status, scanner_id, battery } = req.body;
        
        const { data: hostel } = await supabase
            .from('hostels')
            .select('id, campus')
            .eq('id', hostel_id)
            .eq('campus', req.campus)
            .single();

        if (!hostel) {
            return res.status(404).json({
                success: false,
                message: 'Hostel not found in this campus'
            });
        }

        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const newSession = { 
                hostel_id: hostel_id || null, 
                date: date || new Date().toISOString().split('T')[0], 
                start_time: start_time || '10:00 PM', 
                end_time: end_time || '12:00 AM', 
                status: status || 'Active', 
                scanner_id: scanner_id || 'FP-027', 
                battery: battery || 94,
                campus: req.campus,
                created_at: new Date().toISOString(), 
                updated_at: new Date().toISOString() 
            };
            
            const { data, error } = await supabase
                .from('bedcheck_sessions')
                .insert(newSession)
                .select()
                .single();
            
            if (error) throw error;
            
            const { data: hostelData } = await supabase
                .from('hostels')
                .select('name')
                .eq('id', hostel_id)
                .single();
            
            await auditEvents.sessionCreated(data, { id: hostel_id, name: hostelData?.name || 'Unknown', campus: req.campus }, {
                name: req.user.name || req.user.username,
                id: req.user.id,
                role: req.user.role
            });
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error creating bedcheck session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.put('/api/bedcheck/sessions/:id',
    campusIsolation,
    validate(validators.sessionId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        const { status, scanner_id, battery, completed_at } = req.body;
        
        const { data: session } = await supabase
            .from('bedcheck_sessions')
            .select('hostel_id, campus')
            .eq('id', id)
            .eq('campus', req.campus)
            .single();

        if (!session) {
            return res.status(404).json({
                success: false,
                message: 'Session not found in this campus'
            });
        }

        if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== session.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        try {
            const updateData = {};
            if (status !== undefined) updateData.status = status;
            if (scanner_id !== undefined) updateData.scanner_id = scanner_id;
            if (battery !== undefined) updateData.battery = battery;
            if (completed_at !== undefined) updateData.completed_at = completed_at;
            updateData.updated_at = new Date().toISOString();
            
            const { data, error } = await supabase
                .from('bedcheck_sessions')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();
            
            if (error) throw error;
            
            if (status === 'Active') {
                const { data: hostelData } = await supabase
                    .from('hostels')
                    .select('name')
                    .eq('id', data.hostel_id)
                    .single();
                    
                await auditEvents.sessionStarted(data, { id: data.hostel_id, name: hostelData?.name || 'Unknown', campus: req.campus }, {
                    name: req.user.name || req.user.username,
                    id: req.user.id,
                    role: req.user.role
                });
            }
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error updating bedcheck session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// BEDCHECK SCANS (Protected)
// =====================================================

app.get('/api/bedcheck/scans',
    campusIsolation,
    async (req, res) => {
        const { session_id, room, student_id } = req.query;
        try {
            let query = supabase.from('bedcheck_scans').select('*, students(name, matric)').eq('campus', req.campus);
            
            if (session_id) query = query.eq('session_id', parseInt(session_id));
            if (room) query = query.eq('room', room);
            if (student_id) query = query.eq('student_id', parseInt(student_id));
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                const { data: hostelStudents } = await supabase
                    .from('students')
                    .select('id')
                    .eq('hostel_id', req.user.hostel_id)
                    .eq('campus', req.campus);
                
                if (hostelStudents && hostelStudents.length > 0) {
                    const studentIds = hostelStudents.map(s => s.id);
                    query = query.in('student_id', studentIds);
                } else {
                    return res.json({ success: true, data: [], campus: req.campus });
                }
            }
            
            const { data, error } = await query.order('created_at', { ascending: false });
            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching bedcheck scans:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/bedcheck/scans',
    campusIsolation,
    validate(validators.bedcheckScan),
    async (req, res) => {
        const { session_id, student_id, room, bed_number, status, scanner_id } = req.body;
        
        if (student_id) {
            const { data: student } = await supabase
                .from('students')
                .select('hostel_id, campus')
                .eq('id', student_id)
                .eq('campus', req.campus)
                .single();

            if (!student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }
        }
        
        try {
            const newScan = {
                session_id: session_id || null,
                student_id: student_id || null,
                room: room || null,
                bed_number: bed_number || null,
                status: status || 'Verified',
                scanner_id: scanner_id || 'FP-027',
                campus: req.campus,
                created_at: new Date().toISOString()
            };
            
            const { data, error } = await supabase
                .from('bedcheck_scans')
                .insert(newScan)
                .select()
                .single();
            
            if (error) throw error;
            
            if (student_id) {
                const { data: student } = await supabase
                    .from('students')
                    .select('name, matric, hostel_id, room_id, campus')
                    .eq('id', student_id)
                    .single();
                
                await supabase
                    .from('students')
                    .update({ 
                        status: status === 'Verified' ? 'Present' : status, 
                        updated_at: new Date().toISOString() 
                    })
                    .eq('id', student_id);
                
                await auditService.log({
                    actor: req.user.name || req.user.username,
                    actor_id: req.user.id,
                    actor_role: req.user.role,
                    action: status === 'Verified' ? 'QR Verification' : 'Verification Failed',
                    module: 'verification',
                    details: `${student?.name} (${student?.matric}) ${status === 'Verified' ? 'verified' : 'failed verification'} in ${room || 'Unknown Room'}`,
                    result: status === 'Verified' ? 'success' : 'failed',
                    category: 'verification',
                    tone: status === 'Verified' ? 'green' : 'red',
                    hostel_id: student?.hostel_id,
                    room_id: student?.room_id,
                    student_id: student?.id,
                    campus: req.campus,
                    ip_address: req.clientIp,
                    user_agent: req.userAgent
                });
            }
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error creating bedcheck scan:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/bedcheck/scan-with-face',
    campusIsolation,
    validate([
        ...validators.faceImage,
        body('room_id').isInt().withMessage('room_id is required'),
        body('session_id').optional().isInt()
    ]),
    async (req, res) => {
        try {
            const { session_id, image, room_id, threshold = 0.55, scanner_id } = req.body;

            let query = supabase.from('students')
                .select('id, name, matric, hostel_id, room_id, room_code, campus')
                .eq('campus', req.campus)
                .eq('face_enrolled', true)
                .eq('room_id', room_id);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            const { data: students, error: studentsError } = await query;
            
            if (studentsError) {
                console.error('Fetch students error:', studentsError);
                return res.status(500).json({
                    success: false,
                    message: 'An error occurred. Please try again.'
                });
            }

            if (!students || students.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No students found with face enrolled in this room'
                });
            }

            const studentIds = students.map(s => s.id);
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('student_id, face_embedding, verification_count')
                .in('student_id', studentIds)
                .eq('campus', req.campus)
                .eq('is_active', true);

            if (faceError || !faceData || faceData.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No face embeddings found for students in this room'
                });
            }

            const embeddings = faceData.map(f => f.face_embedding);
            const faceStudentIds = faceData.map(f => f.student_id);

            const result = await faceService.verifyMultiple(
                image,
                embeddings,
                faceStudentIds,
                threshold
            );

            let matchedStudent = null;
            let scanResult = null;
            
            if (result.success && result.student_id) {
                matchedStudent = students.find(s => s.id === result.student_id);
                
                if (matchedStudent) {
                    const studentFace = faceData.find(f => f.student_id === matchedStudent.id);
                    await supabase
                        .from('student_face')
                        .update({
                            last_verified: new Date().toISOString(),
                            verification_count: (studentFace?.verification_count || 0) + 1,
                            confidence_score: result.confidence || null,
                            updated_at: new Date().toISOString()
                        })
                        .eq('student_id', matchedStudent.id);

                    const newScan = {
                        session_id: session_id || null,
                        student_id: matchedStudent.id,
                        room: matchedStudent.room_code || null,
                        bed_number: null,
                        status: 'Verified',
                        scanner_id: scanner_id || 'Face-001',
                        campus: req.campus,
                        created_at: new Date().toISOString()
                    };
                    
                    const { data: scanData, error: scanError } = await supabase
                        .from('bedcheck_scans')
                        .insert(newScan)
                        .select()
                        .single();
                    
                    if (!scanError) {
                        scanResult = scanData;
                        
                        await supabase
                            .from('students')
                            .update({ 
                                status: 'Present',
                                updated_at: new Date().toISOString()
                            })
                            .eq('id', matchedStudent.id);
                    }
                }
            }

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: matchedStudent ? 'Face Scan Verified' : 'Face Scan Failed',
                module: 'bedcheck',
                details: matchedStudent 
                    ? `${matchedStudent.name} (${matchedStudent.matric}) verified via face scan`
                    : `Face verification failed in room ${room_id}`,
                context: `Session: ${session_id || 'N/A'}`,
                result: matchedStudent ? 'success' : 'failed',
                category: 'bedcheck',
                tone: matchedStudent ? 'green' : 'red',
                hostel_id: matchedStudent?.hostel_id || req.user.hostel_id,
                room_id: room_id,
                student_id: matchedStudent?.id || null,
                session_id: session_id || null,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: {
                    verified: !!matchedStudent,
                    student: matchedStudent ? {
                        id: matchedStudent.id,
                        name: matchedStudent.name,
                        matric: matchedStudent.matric,
                        room_code: matchedStudent.room_code
                    } : null,
                    confidence: result.confidence || 0,
                    threshold: result.threshold || threshold,
                    scan: scanResult,
                    message: matchedStudent ? 'Attendance recorded' : 'No match found'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Face scan error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

// =====================================================
// SESSIONS (Global BedCheck Sessions)
// =====================================================

app.get('/api/sessions',
    campusIsolation,
    validate(validators.pagination),
    async (req, res) => {
        try {
            const limit = Math.min(parseInt(req.query.limit) || 50, 100);
            const offset = parseInt(req.query.offset) || 0;
            
            const { data, error, count } = await supabase
                .from('sessions')
                .select('*', { count: 'exact' })
                .eq('campus', req.campus)
                .order('date', { ascending: false })
                .range(offset, offset + limit - 1);
            
            if (error) throw error;
            
            res.json({ 
                success: true, 
                data: data,
                pagination: { limit, offset, total: count || data.length },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching sessions:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/sessions/:id',
    campusIsolation,
    validate(validators.sessionId),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const { data, error } = await supabase
                .from('sessions')
                .select('*')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();
            
            if (error || !data) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Session not found in this campus' 
                });
            }
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.post('/api/sessions',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.sessionCreate),
    async (req, res) => {
        try {
            const { 
                name, date, start_time, end_time, status, 
                hostels_completed, total_hostels, completion,
                academic_session, grace_period, created_by, campus
            } = req.body;

            const sessionCampus = campus || req.campus || 'Legacy';

            let sessionName = name;
            if (!sessionName && date) {
                const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
                const d = new Date(date);
                const dayName = dayNames[d.getDay()] || 'Night';
                sessionName = `${dayName} Night BedCheck`;
            }

            const newSession = {
                name: sessionName || 'Night BedCheck',
                date: date || new Date().toISOString().split('T')[0],
                start_time: start_time || '22:00:00',
                end_time: end_time || '23:30:00',
                status: status || 'active',
                hostels_completed: hostels_completed || 0,
                total_hostels: total_hostels || 11,
                completion: completion || 0,
                academic_session: academic_session || '2026/2027',
                grace_period: grace_period || 15,
                created_by: req.user.id,
                campus: sessionCampus,
                campus_code: sessionCampus === 'Legacy' ? 'LEG' : 'HER',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };

            const { data, error } = await supabase
                .from('sessions')
                .insert(newSession)
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Created BedCheck Session',
                module: 'sessions',
                details: `Created session: ${data.name} for ${data.date} in ${sessionCampus} campus`,
                result: 'success',
                category: 'bedcheck',
                session_id: data.id,
                campus: sessionCampus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({ success: true, data: data, campus: sessionCampus });
        } catch (error) {
            console.error('Error creating session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.put('/api/sessions/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.sessionId),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const { 
                name, date, start_time, end_time, status, 
                hostels_completed, total_hostels, completion,
                academic_session, grace_period, campus
            } = req.body;

            const { data: existing } = await supabase
                .from('sessions')
                .select('id, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (!existing) {
                return res.status(404).json({
                    success: false,
                    message: 'Session not found in this campus'
                });
            }

            const updateData = {};
            const changes = [];

            if (name !== undefined) { updateData.name = name; changes.push('name'); }
            if (date !== undefined) { updateData.date = date; changes.push('date'); }
            if (start_time !== undefined) { updateData.start_time = start_time; changes.push('start_time'); }
            if (end_time !== undefined) { updateData.end_time = end_time; changes.push('end_time'); }
            if (status !== undefined) { 
                updateData.status = status.toLowerCase(); 
                changes.push('status'); 
                if (status.toLowerCase() === 'active') {
                    updateData.started_at = new Date().toISOString();
                }
                if (status.toLowerCase() === 'archived') {
                    updateData.completed_at = new Date().toISOString();
                }
            }
            if (hostels_completed !== undefined) { updateData.hostels_completed = hostels_completed; changes.push('hostels_completed'); }
            if (total_hostels !== undefined) { updateData.total_hostels = total_hostels; changes.push('total_hostels'); }
            if (completion !== undefined) { updateData.completion = completion; changes.push('completion'); }
            if (academic_session !== undefined) { updateData.academic_session = academic_session; changes.push('academic_session'); }
            if (grace_period !== undefined) { updateData.grace_period = grace_period; changes.push('grace_period'); }
            if (campus !== undefined) { 
                updateData.campus = campus;
                updateData.campus_code = campus === 'Legacy' ? 'LEG' : 'HER';
                changes.push('campus');
            }

            updateData.updated_at = new Date().toISOString();

            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update' 
                });
            }

            const { data, error } = await supabase
                .from('sessions')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Updated BedCheck Session',
                module: 'sessions',
                details: `Updated session #${id}: ${changes.join(', ')}`,
                result: 'success',
                category: 'bedcheck',
                session_id: id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error updating session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.delete('/api/sessions/:id',
    campusIsolation,
    requireRole('Admin', 'System Owner'),
    validate(validators.sessionId),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            
            const { data: session, error: fetchError } = await supabase
                .from('sessions')
                .select('name, date, status, campus')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();
            
            if (fetchError || !session) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Session not found in this campus' 
                });
            }

            const { error: deleteError } = await supabase
                .from('sessions')
                .delete()
                .eq('id', id)
                .eq('campus', req.campus);

            if (deleteError) throw deleteError;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Deleted BedCheck Session',
                module: 'sessions',
                details: `Deleted session: ${session.name} (${session.date})`,
                result: 'success',
                category: 'bedcheck',
                session_id: id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({ 
                success: true, 
                message: 'Session deleted successfully',
                campus: req.campus
            });
        } catch (error) {
            console.error('Error deleting session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/sessions/active',
    campusIsolation,
    async (req, res) => {
        try {
            const { data, error } = await supabase
                .from('sessions')
                .select('*')
                .eq('status', 'active')
                .eq('campus', req.campus)
                .order('date', { ascending: false })
                .limit(1)
                .maybeSingle();

            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching active session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/sessions/latest',
    campusIsolation,
    async (req, res) => {
        try {
            const { data, error } = await supabase
                .from('sessions')
                .select('*')
                .eq('campus', req.campus)
                .order('date', { ascending: false })
                .limit(1)
                .maybeSingle();

            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching latest session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/sessions/stats',
    campusIsolation,
    async (req, res) => {
        try {
            const { data: sessions, error } = await supabase
                .from('sessions')
                .select('status, hostels_completed, total_hostels, completion')
                .eq('campus', req.campus);

            if (error) throw error;

            const stats = {
                total: sessions.length,
                active: sessions.filter(s => s.status === 'active').length,
                archived: sessions.filter(s => s.status === 'archived').length,
                totalHostels: sessions.length > 0 ? sessions[0]?.total_hostels || 11 : 11,
                averageCompletion: sessions.length > 0 
                    ? Math.round(sessions.reduce((sum, s) => sum + (s.completion || 0), 0) / sessions.length) 
                    : 0
            };

            res.json({ success: true, data: stats, campus: req.campus });
        } catch (error) {
            console.error('Error fetching session stats:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// BED OCCUPANCY - USING VIEWS WITH CAMPUS
// =====================================================

app.get('/api/occupancy',
    campusIsolation,
    async (req, res) => {
        try {
            const { hostel_id } = req.query;
            
            let query = supabase
                .from('bed_occupancy')
                .select('*')
                .eq('campus', req.campus);
            
            if (hostel_id) query = query.eq('hostel_id', parseInt(hostel_id));
            
            const { data, error } = await query;
            if (error) throw error;
            
            res.json({
                success: true,
                data: data,
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching occupancy:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

app.get('/api/occupancy/floor-flat',
    campusIsolation,
    async (req, res) => {
        try {
            const { hostel_id } = req.query;
            
            let query = supabase
                .from('floor_flat_occupancy')
                .select('*')
                .eq('campus', req.campus);
            
            if (hostel_id) query = query.eq('hostel_id', parseInt(hostel_id));
            
            const { data, error } = await query;
            if (error) throw error;
            
            res.json({
                success: true,
                data: data,
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching floor/flat occupancy:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.'
            });
        }
    }
);

// =====================================================
// SUBMISSION STATE
// =====================================================

app.get('/api/submission', campusIsolation, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('submission_state')
            .select('state, notice')
            .order('id', { ascending: false })
            .limit(1);
        
        if (error) throw error;
        
        if (data && data.length > 0) {
            res.json({ success: true, data: data[0], campus: req.campus });
        } else {
            const { data: insertData, error: insertError } = await supabase
                .from('submission_state')
                .insert({ state: 'Open', notice: 'Tonight\'s BedCheck is active · 9:30 PM — 11:00 PM' })
                .select()
                .single();
            
            if (insertError) throw insertError;
            res.json({ success: true, data: insertData, campus: req.campus });
        }
    } catch (error) {
        console.error('Error fetching submission state:', error);
        res.status(500).json({ 
            success: false, 
            message: 'An error occurred. Please try again.' 
        });
    }
});

app.put('/api/submission',
    campusIsolation,
    requireRole('Admin', 'System Owner'),
    validate(validators.submissionState),
    async (req, res) => {
        const { state, notice } = req.body;
        try {
            const { data: existingData, error: fetchError } = await supabase
                .from('submission_state')
                .select('id, state')
                .order('id', { ascending: false })
                .limit(1);
            
            if (fetchError) throw fetchError;
            
            let result;
            if (existingData && existingData.length > 0) {
                const { data, error } = await supabase
                    .from('submission_state')
                    .update({ state, notice, updated_at: new Date().toISOString() })
                    .eq('id', existingData[0].id)
                    .select()
                    .single();
                
                if (error) throw error;
                result = data;
            } else {
                const { data, error } = await supabase
                    .from('submission_state')
                    .insert({ state, notice })
                    .select()
                    .single();
                
                if (error) throw error;
                result = data;
            }
            
            await auditEvents.systemSettingsUpdated(
                'submission_state', 
                existingData?.[0]?.state || 'Open', 
                state, 
                { name: req.user.name || req.user.username, id: req.user.id, role: req.user.role, campus: req.campus }
            );
            
            res.json({ success: true, data: result, campus: req.campus });
        } catch (error) {
            console.error('Error updating submission state:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// DASHBOARD STATISTICS
// =====================================================

app.get('/api/dashboard/stats',
    campusIsolation,
    async (req, res) => {
        try {
            const stats = {};
            
            let studentsQuery = supabase.from('students').select('*', { count: 'exact', head: true }).eq('campus', req.campus);
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                studentsQuery = studentsQuery.eq('hostel_id', req.user.hostel_id);
            }
            const { count: studentsCount, error: studentsError } = await studentsQuery;
            stats.totalStudents = studentsCount || 0;
            
            let hostelsQuery = supabase.from('hostels').select('*', { count: 'exact', head: true }).eq('campus', req.campus);
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                hostelsQuery = hostelsQuery.eq('id', req.user.hostel_id);
            }
            const { count: hostelsCount, error: hostelsError } = await hostelsQuery;
            stats.totalHostels = hostelsCount || 0;
            
            // ============================================================
            // Hide System Owner from counts for non-System Owner users
            // ============================================================
            let staffQuery = supabase.from('staff').select('role', { count: 'exact' }).eq('campus', req.campus);
            if (req.user.role !== 'System Owner') {
                staffQuery = staffQuery.neq('role', 'System Owner');
            }
            const { count: totalStaff, error: staffError } = await staffQuery;
            stats.totalStaff = totalStaff || 0;
            
            let statusQuery = supabase.from('students').select('status, face_enrolled').eq('campus', req.campus);
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                statusQuery = statusQuery.eq('hostel_id', req.user.hostel_id);
            }
            const { data: statusData, error: statusError } = await statusQuery;
            
            if (!statusError && statusData) {
                stats.present = statusData.filter(s => s.status === 'Present').length;
                stats.absent = statusData.filter(s => s.status === 'Absent').length;
                stats.late = statusData.filter(s => s.status === 'Late').length;
                stats.faceEnrolled = statusData.filter(s => s.face_enrolled === true).length;
            } else {
                stats.present = 0;
                stats.absent = 0;
                stats.late = 0;
                stats.faceEnrolled = 0;
            }
            
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('enrollment_status')
                .eq('campus', req.campus)
                .eq('is_active', true);
            
            if (!faceError && faceData) {
                stats.faceEnrolledCount = faceData.filter(f => f.enrollment_status === 'enrolled').length;
                stats.facePendingCount = faceData.filter(f => f.enrollment_status === 'pending').length;
            } else {
                stats.faceEnrolledCount = 0;
                stats.facePendingCount = 0;
            }
            
            res.json({ success: true, data: stats, campus: req.campus });
        } catch (error) {
            console.error('Error fetching dashboard stats:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/dashboard/activity',
    campusIsolation,
    async (req, res) => {
        const { hostel_id, limit } = req.query;
        try {
            let effectiveHostelId = hostel_id;
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                effectiveHostelId = req.user.hostel_id;
            }
            
            const activity = await auditService.getRecentActivity(
                effectiveHostelId || null, 
                parseInt(limit) || 10
            );
            res.json({ success: true, data: activity, campus: req.campus });
        } catch (error) {
            console.error('Error fetching recent activity:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// REGISTRATION MANAGEMENT - RASD ENDPOINTS
// =====================================================

app.get('/api/registration/stats',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    async (req, res) => {
        try {
            let query = supabase.from('students')
                .select('id, room_id, name, matric, hostel_id, hostel_name, room_code, status, created_at, face_enrolled, campus')
                .eq('campus', req.campus);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            const { data: students, error: studentsError } = await query;
            if (studentsError) throw studentsError;

            const { data: bedSpaces, error: bedError } = await supabase
                .from('bed_spaces')
                .select('id, room_id, status')
                .eq('campus', req.campus);
            if (bedError) throw bedError;

            let hostelsQuery = supabase.from('hostels').select('id, name, type, total_floors, rooms_per_floor, total_flats, rooms_per_flat').eq('campus', req.campus);
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                hostelsQuery = hostelsQuery.eq('id', req.user.hostel_id);
            }
            const { data: hostels, error: hostelsError } = await hostelsQuery;
            if (hostelsError) throw hostelsError;

            const totalRegistered = students.length || 0;
            const hostelAssigned = students.filter(s => s.room_id !== null && s.room_id > 0).length || 0;
            const completed = students.filter(s => s.status === 'Completed' || s.status === 'Registration Complete').length || 0;
            const faceEnrolled = students.filter(s => s.face_enrolled === true).length || 0;
            const issues = students.filter(s => !s.name || !s.matric || (s.room_id === null || s.room_id === 0)).length || 0;
            const totalBedSpaces = bedSpaces.length || 0;
            const availableBeds = bedSpaces.filter(b => b.status === 'available').length || 0;

            const pipeline = [
                { label: 'Online Registration', count: totalRegistered, icon: 'fa-globe', color: 'blue' },
                { label: 'Hostel Assignment', count: hostelAssigned, icon: 'fa-building', color: 'purple' },
                { label: 'Face Enrolled', count: faceEnrolled, icon: 'fa-user-check', color: 'gold' },
                { label: 'Registration Completed', count: completed, icon: 'fa-check-circle', color: 'green' },
                { label: 'Registration Issues', count: issues, icon: 'fa-exclamation-triangle', color: 'red' }
            ];

            const hostelProgress = hostels.map(h => {
                const hostelStudents = students.filter(s => s.hostel_id === h.id || s.hostel_name === h.name);
                const total = hostelStudents.length;
                const assigned = hostelStudents.filter(s => s.room_id !== null && s.room_id > 0).length;
                const faceEnrolledCount = hostelStudents.filter(s => s.face_enrolled === true).length;
                const progress = total > 0 ? Math.round((assigned / total) * 100) : 0;
                return { id: h.id, name: h.name || 'Unknown', registered: total, assigned: assigned, faceEnrolled: faceEnrolledCount, progress: progress, type: h.type || 'floor' };
            });

            const issueTypes = [
                { label: 'No Hostel Assigned', count: students.filter(s => s.room_id === null || s.room_id === 0).length },
                { label: 'Missing Phone Number', count: students.filter(s => !s.phone || s.phone === '').length },
                { label: 'Missing Name', count: students.filter(s => !s.name || s.name === '').length },
                { label: 'No Face Enrolled', count: students.filter(s => s.face_enrolled !== true).length }
            ];

            res.json({ 
                success: true, 
                data: { 
                    overview: { totalRegistered, hostelAssigned, completed, faceEnrolled, issues, totalBedSpaces, availableBeds }, 
                    pipeline, 
                    hostelProgress, 
                    issueTypes 
                },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching registration stats:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// HRA DASHBOARD ENDPOINTS
// =====================================================

app.get('/api/hra/hostel', 
    campusIsolation,
    requireRole('HRA', 'Admin', 'System Owner'),
    async (req, res) => {
        const staffId = req.user.id;
        
        try {
            const { data: staffData, error: staffError } = await supabase
                .from('staff')
                .select('hostel_id, role, name, username, email, phone, assigned_floor, assigned_room, campus')
                .eq('id', staffId)
                .eq('campus', req.campus)
                .single();
            
            if (staffError || !staffData) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Staff member not found in this campus' 
                });
            }
            
            if (!staffData.hostel_id) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'HRA not assigned to a hostel' 
                });
            }
            
            const { data: hostelData, error: hostelError } = await supabase
                .from('hostels')
                .select('*')
                .eq('id', staffData.hostel_id)
                .eq('campus', req.campus)
                .single();
            
            if (hostelError || !hostelData) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Hostel not found in this campus' 
                });
            }
            
            const { data: hostelStaff, error: staffListError } = await supabase
                .from('staff')
                .select('id, name, role, username, email, phone, status, assigned_floor, assigned_room, submission_status, level, campus')
                .eq('hostel_id', hostelData.id)
                .eq('campus', req.campus)
                .eq('status', 'Active');
            
            if (staffListError) throw staffListError;
            
            const hraStaff = hostelStaff?.find(s => s.role === 'HRA');
            const raStaff = hostelStaff?.filter(s => s.role === 'RA') || [];
            
            const { count: totalStudents, error: countError } = await supabase
                .from('students')
                .select('*', { count: 'exact', head: true })
                .eq('hostel_id', hostelData.id)
                .eq('campus', req.campus);
            
            if (countError) throw countError;
            
            const { data: studentStatuses, error: statusError } = await supabase
                .from('students')
                .select('status, face_enrolled')
                .eq('hostel_id', hostelData.id)
                .eq('campus', req.campus);
            
            let presentCount = 0, absentCount = 0, lateCount = 0, faceEnrolledCount = 0;
            if (!statusError && studentStatuses) {
                presentCount = studentStatuses.filter(s => s.status === 'Present' || s.status === 'Verified').length;
                absentCount = studentStatuses.filter(s => s.status === 'Absent').length;
                lateCount = studentStatuses.filter(s => s.status === 'Late').length;
                faceEnrolledCount = studentStatuses.filter(s => s.face_enrolled === true).length;
            }
            
            const { data: sessionData, error: sessionError } = await supabase
                .from('bedcheck_sessions')
                .select('*')
                .eq('hostel_id', hostelData.id)
                .eq('campus', req.campus)
                .order('created_at', { ascending: false })
                .limit(1);
            
            let currentSession = null;
            if (!sessionError && sessionData && sessionData.length > 0) {
                currentSession = sessionData[0];
            }
            
            let totalRooms = 0;
            if (hostelData.type === 'floor') {
                totalRooms = (hostelData.total_floors || 0) * (hostelData.rooms_per_floor || 0);
            } else if (hostelData.type === 'flat') {
                totalRooms = (hostelData.total_flats || 0) * (hostelData.rooms_per_flat || 0);
            }
            
            res.json({ 
                success: true, 
                data: {
                    ...hostelData,
                    total_rooms: totalRooms || hostelData.total_rooms || 0,
                    hra_name: hraStaff?.name || staffData.name,
                    hra_id: hraStaff?.id || staffId,
                    ra_count: raStaff.length,
                    ra_list: raStaff.map(ra => ({
                        id: ra.id,
                        name: ra.name,
                        role: ra.role,
                        username: ra.username,
                        email: ra.email,
                        phone: ra.phone,
                        status: ra.status,
                        assigned_floor: ra.assigned_floor || null,
                        assigned_room: ra.assigned_room || null,
                        submission_status: ra.submission_status || 'Not Started',
                        level: ra.level || null
                    })),
                    total_students: totalStudents || 0,
                    present_count: presentCount,
                    absent_count: absentCount,
                    late_count: lateCount,
                    face_enrolled_count: faceEnrolledCount,
                    current_session: currentSession
                },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching HRA hostel:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// AUDIT ENDPOINTS (Restricted)
// =====================================================

app.get('/api/audit',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate(validators.pagination),
    async (req, res) => {
        try {
            const { 
                hostel_id, 
                actor, 
                action, 
                module, 
                category, 
                result, 
                actor_role,
                from_date, 
                to_date, 
                search,
                limit = 50, 
                offset = 0 
            } = req.query;

            let effectiveHostelId = hostel_id;
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                if (hostel_id && parseInt(hostel_id) !== req.user.hostel_id) {
                    return res.status(403).json({
                        success: false,
                        message: 'Access denied. You can only view your hostel logs.'
                    });
                }
                effectiveHostelId = req.user.hostel_id;
            }
            
            const filters = {
                hostel_id: effectiveHostelId,
                actor,
                action,
                module,
                category,
                result,
                actor_role,
                from_date,
                to_date,
                search,
                campus: req.campus,
                limit: Math.min(parseInt(limit), 100),
                offset: parseInt(offset)
            };
            
            const auditResult = await auditService.getLogs(filters);
            auditResult.campus = req.campus;
            res.json(auditResult);
        } catch (error) {
            console.error('Error fetching audit logs:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/audit/stats',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    async (req, res) => {
        try {
            const { hostel_id, from_date, to_date } = req.query;
            
            let effectiveHostelId = hostel_id;
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                effectiveHostelId = req.user.hostel_id;
            }

            const filters = { 
                hostel_id: effectiveHostelId, 
                from_date, 
                to_date,
                campus: req.campus
            };
            const statsResult = await auditService.getStats(filters);
            statsResult.campus = req.campus;
            res.json(statsResult);
        } catch (error) {
            console.error('Error fetching audit stats:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/audit/recent',
    campusIsolation,
    async (req, res) => {
        try {
            const { hostel_id, limit = 10 } = req.query;
            
            let effectiveHostelId = hostel_id;
            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id) {
                effectiveHostelId = req.user.hostel_id;
            }
            
            const activity = await auditService.getRecentActivity(
                effectiveHostelId || null, 
                parseInt(limit)
            );
            res.json({ success: true, data: activity, campus: req.campus });
        } catch (error) {
            console.error('Error fetching recent activity:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

app.get('/api/audit/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'System Owner'),
    validate([param('id').isInt().withMessage('Invalid audit log ID')]),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const { data, error } = await supabase
                .from('audit_logs')
                .select('*')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();
            
            if (error || !data) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Audit log not found in this campus' 
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'System Owner' && req.user.hostel_id !== data.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied'
                });
            }
            
            res.json({ success: true, data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching audit log:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.' 
            });
        }
    }
);

// =====================================================
// CATCH-ALL 404 HANDLER
// =====================================================

app.use((req, res) => {
    console.log(`❌ Route not found: ${req.method} ${req.path}`);
    res.status(404).json({ 
        success: false, 
        message: 'Endpoint not found',
        path: req.path,
        method: req.method
    });
});

// =====================================================
// GLOBAL ERROR HANDLER
// =====================================================

app.use((err, req, res, next) => {
    console.error('❌ Server error:', err.stack);
    
    const errorMessage = process.env.NODE_ENV === 'development' 
        ? err.message 
        : 'An unexpected error occurred. Please try again later.';
    
    res.status(500).json({ 
        success: false, 
        message: errorMessage,
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// =====================================================
// START SERVER - SECURE VERSION
// =====================================================

const server = app.listen(PORT, '0.0.0.0', async () => {
    console.log(`✅ Server running on port ${PORT}`);
    
    try {
        const health = await faceService.checkHealth();
        if (health.status === 'healthy') {
            console.log(`✅ Face API available`);
        }
    } catch (error) {
        console.warn(`⚠️ Face API unavailable`);
    }
});

// Graceful shutdown
const shutdown = (signal) => {
    console.log(`\n📴 Shutting down...`);
    server.close(() => {
        console.log('✅ Server closed.');
        process.exit(0);
    });
    
    setTimeout(() => {
        console.error('⚠️ Force shutdown.');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection:', reason);
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
});

module.exports = app;