// server.js - BIU BedCheck with InsightFace Face Recognition
// Complete Face ID system with liveness detection
// Optimized for Render.com Deployment

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

// =====================================================
// SUPABASE CONNECTION
// =====================================================

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('❌ Missing Supabase credentials in .env file');
  console.error('Please set SUPABASE_URL and SUPABASE_KEY');
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
}

const supabase = createClient(supabaseUrl, supabaseKey);

// =====================================================
// INSIGHTFACE PYTHON API CONFIGURATION
// =====================================================

const FACE_API_URL = process.env.FACE_API_URL || 'http://localhost:8000';
const FACE_API_TIMEOUT = 30000;

console.log('🔐 Face API URL:', FACE_API_URL);
console.log('🔐 Face API Status:', FACE_API_URL ? '✅ Configured' : '❌ Missing');

// =====================================================
// INSIGHTFACE SERVICE (Python API Bridge)
// =====================================================

class InsightFaceService {
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
    }

    async checkHealth() {
        try {
            const response = await axios.get(`${this.apiUrl}/health`, {
                timeout: 5000
            });
            return response.data;
        } catch (error) {
            console.error('Face API health check error:', error.message);
            return { status: 'unhealthy', error: error.message };
        }
    }

    async detectFace(imageBase64) {
        try {
            const imageData = imageBase64.replace(/^data:image\/\w+;base64,/, '');
            
            const response = await axios.post(`${this.apiUrl}/detect-face`, {
                image: imageData
            }, {
                timeout: FACE_API_TIMEOUT
            });
            
            return response.data;
        } catch (error) {
            console.error('Face detection error:', error.response?.data || error.message);
            return {
                success: false,
                error: error.response?.data?.detail || error.message
            };
        }
    }

    async enrollFace(imageBase64, studentId, hostel, room, name) {
        try {
            const imageData = imageBase64.replace(/^data:image\/\w+;base64,/, '');
            
            const response = await axios.post(`${this.apiUrl}/enroll-face`, {
                image: imageData,
                student_id: studentId,
                hostel: hostel,
                room: room,
                name: name
            }, {
                timeout: FACE_API_TIMEOUT
            });
            
            return response.data;
        } catch (error) {
            console.error('Face enrollment error:', error.response?.data || error.message);
            return {
                success: false,
                error: error.response?.data?.detail || error.message
            };
        }
    }

    async enrollBulk(frames, studentId, hostel, room, name) {
        try {
            const imageDataList = frames.map(frame => 
                frame.replace(/^data:image\/\w+;base64,/, '')
            );
            
            const response = await axios.post(`${this.apiUrl}/enroll-bulk`, {
                frames: imageDataList,
                student_id: studentId,
                hostel: hostel,
                room: room,
                name: name
            }, {
                timeout: FACE_API_TIMEOUT * 2
            });
            
            return response.data;
        } catch (error) {
            console.error('Bulk enrollment error:', error.response?.data || error.message);
            return {
                success: false,
                error: error.response?.data?.detail || error.message
            };
        }
    }

    async verifyFace(imageBase64, storedEmbedding, threshold = 0.55) {
        try {
            const imageData = imageBase64.replace(/^data:image\/\w+;base64,/, '');
            
            const response = await axios.post(`${this.apiUrl}/verify-face`, {
                image: imageData,
                stored_embedding: storedEmbedding,
                threshold: threshold
            }, {
                timeout: FACE_API_TIMEOUT
            });
            
            return response.data;
        } catch (error) {
            console.error('Face verification error:', error.response?.data || error.message);
            return {
                success: false,
                error: error.response?.data?.detail || error.message
            };
        }
    }

    async verifyMultiple(imageBase64, embeddings, studentIds, threshold = 0.55) {
        try {
            const imageData = imageBase64.replace(/^data:image\/\w+;base64,/, '');
            
            const response = await axios.post(`${this.apiUrl}/verify-multiple`, {
                image: imageData,
                embeddings: embeddings,
                student_ids: studentIds,
                threshold: threshold
            }, {
                timeout: FACE_API_TIMEOUT
            });
            
            return response.data;
        } catch (error) {
            console.error('Multiple verification error:', error.response?.data || error.message);
            return {
                success: false,
                error: error.response?.data?.detail || error.message
            };
        }
    }

    async checkLiveness(imageBase64) {
        try {
            const imageData = imageBase64.replace(/^data:image\/\w+;base64,/, '');
            
            const response = await axios.post(`${this.apiUrl}/check-liveness`, {
                image: imageData
            }, {
                timeout: FACE_API_TIMEOUT
            });
            
            return response.data;
        } catch (error) {
            console.error('Liveness check error:', error.response?.data || error.message);
            return {
                is_live: false,
                error: error.response?.data?.detail || error.message
            };
        }
    }

    async resetLiveness() {
        try {
            const response = await axios.post(`${this.apiUrl}/reset-liveness`, {}, {
                timeout: 5000
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
                timeout: FACE_API_TIMEOUT
            });
            return response.data;
        } catch (error) {
            console.error('Compare embeddings error:', error.response?.data || error.message);
            return {
                success: false,
                error: error.response?.data?.detail || error.message
            };
        }
    }

    async extractEmbedding(imageBase64) {
        try {
            const imageData = imageBase64.replace(/^data:image\/\w+;base64,/, '');
            
            const response = await axios.post(`${this.apiUrl}/extract-embedding`, {
                image: imageData
            }, {
                timeout: FACE_API_TIMEOUT
            });
            
            return response.data;
        } catch (error) {
            console.error('Extract embedding error:', error.response?.data || error.message);
            return {
                success: false,
                error: error.response?.data?.detail || error.message
            };
        }
    }
}

// Initialize InsightFace service
const faceService = new InsightFaceService(FACE_API_URL);

// =====================================================
// MIDDLEWARE
// =====================================================

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) {
      return callback(null, true);
    }

    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) 
      : [];

    if (allowedOrigins.length === 0) {
      console.error('❌ ALLOWED_ORIGINS environment variable is not set in production');
      return callback(new Error('CORS configuration error'));
    }

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`❌ CORS blocked: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Staff-ID', 'X-Staff-Name', 'X-Staff-Role'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use((req, res, next) => {
  req.clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || req.connection?.remoteAddress || 'unknown';
  req.userAgent = req.headers['user-agent'] || 'unknown';
  console.log(`📨 ${req.method} ${req.path}`);
  next();
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

app.get('/', (req, res) => {
  res.json({
    name: 'BIU BedCheck API',
    version: '3.0.0',
    status: 'running',
    endpoints: '/api/*',
    health: '/health',
    face_api: FACE_API_URL
  });
});

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
// AUDIT SERVICE - Integrated
// =====================================================

const auditService = {
  async log(params) {
    try {
      const {
        actor = 'System',
        actor_id = null,
        actor_role = 'System',
        action = 'Unknown Action',
        module = 'system',
        details = '',
        context = '',
        result = 'success',
        category = 'system',
        tone = 'blue',
        hostel_id = null,
        floor_flat_id = null,
        room_id = null,
        student_id = null,
        session_id = null,
        ip_address = null,
        user_agent = null,
        metadata = {},
        time = null
      } = params;

      const { data, error } = await supabase
        .from('audit_logs')
        .insert({
          actor,
          actor_id,
          actor_role,
          action,
          module,
          details,
          context: context || action,
          result,
          category,
          tone,
          hostel_id,
          floor_flat_id,
          room_id,
          student_id,
          session_id,
          ip_address,
          user_agent,
          metadata,
          time: time || new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
          created_at: new Date().toISOString()
        })
        .select()
        .single();

      if (error) throw error;
      console.log(`📝 Audit Log: ${actor} (${actor_role}) - ${action} [${result}]`);
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
      if (filters.from_date) query = query.gte('created_at', new Date(filters.from_date).toISOString());
      if (filters.to_date) query = query.lte('created_at', new Date(filters.to_date).toISOString());
      if (filters.search) {
        query = query.or(
          `actor.ilike.%${filters.search}%,` +
          `action.ilike.%${filters.search}%,` +
          `details.ilike.%${filters.search}%,` +
          `context.ilike.%${filters.search}%`
        );
      }

      const limit = filters.limit || 50;
      const offset = filters.offset || 0;
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
      session_id: session?.id
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
      session_id: session?.id
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
      session_id: session?.id
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
      session_id: session?.id
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
      session_id: session?.id
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
      session_id: session?.id
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
      student_id: student?.id
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
      hostel_id: user?.hostel_id
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
      hostel_id: user?.hostel_id
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
      hostel_id: user?.hostel_id
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
      hostel_id: hostel?.id
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
      tone: 'gold'
    });
  },

  async faceEnrolled(student, result, req) {
    return auditService.log({
      actor: req?.headers['x-staff-name'] || 'Student',
      actor_id: student.id,
      actor_role: req?.headers['x-staff-role'] || 'Student',
      action: 'Face Enrolled',
      module: 'face',
      details: `${student.name} (${student.matric}) enrolled face successfully with ${result.confidence || 'N/A'} confidence`,
      context: `Embedding dimension: 512`,
      result: 'success',
      category: 'face',
      tone: 'green',
      hostel_id: student.hostel_id,
      room_id: student.room_id,
      student_id: student.id
    });
  },

  async faceVerified(student, result, req) {
    return auditService.log({
      actor: req?.headers['x-staff-name'] || 'RA',
      actor_id: getStaffId(req),
      actor_role: req?.headers['x-staff-role'] || 'RA',
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
      student_id: student.id
    });
  },

  async livenessVerified(req) {
    return auditService.log({
      actor: req?.headers['x-staff-name'] || 'Student',
      actor_id: getStaffId(req),
      actor_role: req?.headers['x-staff-role'] || 'Student',
      action: 'Liveness Verified',
      module: 'face',
      details: `Liveness verified successfully`,
      context: 'Liveness check passed',
      result: 'success',
      category: 'face',
      tone: 'green'
    });
  }
};

// =====================================================
// AUDIT ENDPOINTS
// =====================================================

app.get('/api/audit', async (req, res) => {
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
    
    const filters = {
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
      limit: parseInt(limit),
      offset: parseInt(offset)
    };
    
    const auditResult = await auditService.getLogs(filters);
    res.json(auditResult);
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/audit/stats', async (req, res) => {
  try {
    const { hostel_id, from_date, to_date } = req.query;
    const filters = { hostel_id, from_date, to_date };
    const statsResult = await auditService.getStats(filters);
    res.json(statsResult);
  } catch (error) {
    console.error('Error fetching audit stats:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/audit/recent', async (req, res) => {
  try {
    const { hostel_id, limit = 10 } = req.query;
    const activity = await auditService.getRecentActivity(
      hostel_id || null, 
      parseInt(limit)
    );
    res.json({ success: true, data: activity });
  } catch (error) {
    console.error('Error fetching recent activity:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/audit/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { data, error } = await supabase
      .from('audit_logs')
      .select('*')
      .eq('id', id)
      .single();
    
    if (error) throw error;
    if (!data) {
      return res.status(404).json({ 
        success: false, 
        message: 'Audit log not found' 
      });
    }
    
    res.json({ success: true, data });
  } catch (error) {
    console.error('Error fetching audit log:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/audit/hostel/:hostelId', async (req, res) => {
  try {
    const hostelId = parseInt(req.params.hostelId);
    const { limit = 50, offset = 0, from_date, to_date } = req.query;
    
    const auditResult = await auditService.getLogs({
      hostel_id: hostelId,
      limit: parseInt(limit),
      offset: parseInt(offset),
      from_date,
      to_date
    });
    
    res.json(auditResult);
  } catch (error) {
    console.error('Error fetching hostel audit logs:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/audit/module/:module', async (req, res) => {
  try {
    const { module } = req.params;
    const { limit = 50, offset = 0 } = req.query;
    
    const auditResult = await auditService.getLogs({
      module,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
    
    res.json(auditResult);
  } catch (error) {
    console.error('Error fetching module audit logs:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/audit/category/:category', async (req, res) => {
  try {
    const { category } = req.params;
    const { limit = 50, offset = 0 } = req.query;
    
    const auditResult = await auditService.getLogs({
      category,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
    
    res.json(auditResult);
  } catch (error) {
    console.error('Error fetching category audit logs:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/audit/actor/:actor', async (req, res) => {
  try {
    const { actor } = req.params;
    const { limit = 50, offset = 0 } = req.query;
    
    const auditResult = await auditService.getLogs({
      actor,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
    
    res.json(auditResult);
  } catch (error) {
    console.error('Error fetching actor audit logs:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/audit/result/:result', async (req, res) => {
  try {
    const { result } = req.params;
    const { limit = 50, offset = 0 } = req.query;
    
    const auditResult = await auditService.getLogs({
      result,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
    
    res.json(auditResult);
  } catch (error) {
    console.error('Error fetching result audit logs:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/audit/summary', async (req, res) => {
  try {
    const { hostel_id } = req.query;
    
    const statsResult = await auditService.getStats({ hostel_id });
    const recentActivity = await auditService.getRecentActivity(hostel_id || null, 5);
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayStr = today.toISOString();
    
    const logsResult = await auditService.getLogs({ 
      hostel_id,
      from_date: todayStr,
      limit: 1
    });
    
    res.json({ 
      success: true, 
      data: {
        stats: statsResult.data || statsResult,
        recentActivity,
        todayCount: logsResult.total || 0
      }
    });
  } catch (error) {
    console.error('Error fetching audit summary:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

// =====================================================
// AUTHENTICATION
// =====================================================

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ 
      success: false, 
      message: 'Username and password are required' 
    });
  }
  
  try {
    const { data, error } = await supabase
      .from('staff')
      .select('id, username, role, name, initials, scope, hostel_id, assigned_floor, assigned_room, is_admin, email, phone, department, staff_id, joined, status, submission_status, level, password')
      .eq('username', username);
    
    if (error) {
      await auditEvents.loginFailed(username, req);
      console.error('Login error:', error);
      return res.status(500).json({ 
        success: false, 
        message: 'Database error: ' + error.message 
      });
    }
    
    if (data && data.length > 0) {
      const user = data[0];
      
      let validPassword = false;
      
      if (user.password && user.password.startsWith('$2b$')) {
        try {
          validPassword = await bcrypt.compare(password, user.password);
        } catch (e) {
          console.error('Bcrypt compare error:', e);
          validPassword = false;
        }
      } else {
        validPassword = password === user.password;
        
        if (validPassword && user.password && !user.password.startsWith('$2b$')) {
          console.log(`🔄 Upgrading password for ${user.username} to bcrypt hash`);
          try {
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
            await supabase
              .from('staff')
              .update({ password: hashedPassword })
              .eq('id', user.id);
            console.log(`✅ Password upgraded for ${user.username}`);
          } catch (e) {
            console.error(`❌ Failed to upgrade password for ${user.username}:`, e);
          }
        }
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
      
      await supabase
        .from('staff')
        .update({ last_login: new Date().toISOString() })
        .eq('id', user.id);
      
      await auditEvents.loginSuccess(user, req);
      
      const { password: _, ...userWithoutPassword } = user;
      
      res.json({ 
        success: true, 
        user: userWithoutPassword,
        role: user.role
      });
    } else {
      await auditEvents.loginFailed(username, req);
      res.status(401).json({ 
        success: false, 
        message: 'Invalid username or password' 
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error: ' + error.message 
    });
  }
});

app.get('/api/me', async (req, res) => {
  const staffId = req.headers['x-staff-id'] || req.query.staff_id;
  
  if (!staffId) {
    return res.status(401).json({ 
      success: false, 
      message: 'Authentication required. Please login.' 
    });
  }
  
  try {
    const { data, error } = await supabase
      .from('staff')
      .select('id, username, role, name, initials, scope, hostel_id, assigned_floor, assigned_room, is_admin, email, phone, department, status, submission_status, level')
      .eq('id', parseInt(staffId))
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
      message: 'Database error: ' + error.message
    });
  }
});

// =====================================================
// CHANGE PASSWORD
// =====================================================

app.put('/api/staff/:id/change-password', async (req, res) => {
  try {
    const staffId = parseInt(req.params.id);
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters'
      });
    }

    const { data: staff, error: staffError } = await supabase
      .from('staff')
      .select('id, password, name')
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
      validPassword = currentPassword === staff.password;
    }

    if (!validPassword) {
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
      actor: req.headers['x-staff-name'] || staff?.name || 'Staff',
      actor_id: staffId,
      actor_role: req.headers['x-staff-role'] || 'HRA',
      action: 'Password Changed',
      module: 'security',
      details: 'Account password updated successfully',
      result: 'success',
      category: 'security',
      tone: 'blue',
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
      message: 'Server error: ' + error.message
    });
  }
});

// =====================================================
// INSIGHTFACE ENDPOINTS
// =====================================================

// Health check for Face API
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

// Detect face from image
app.post('/api/face/detect', async (req, res) => {
    try {
        const { image, student_id } = req.body;
        
        if (!image) {
            return res.status(400).json({
                success: false,
                message: 'Image is required'
            });
        }

        const result = await faceService.detectFace(image);
        
        if (result.success) {
            if (student_id) {
                await supabase
                    .from('students')
                    .update({ 
                        face_enrolled: true,
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', student_id);
            }
            
            res.json(result);
        } else {
            res.status(400).json(result);
        }
    } catch (error) {
        console.error('Face detection error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// Enroll face (single image)
app.post('/api/face/enroll', async (req, res) => {
    try {
        const { 
            image,
            student_id,
            name,
            matric,
            hostel_id,
            room_id,
            bed_space_id
        } = req.body;

        if (!student_id && !matric) {
            return res.status(400).json({
                success: false,
                message: 'student_id or matric is required'
            });
        }

        if (!image) {
            return res.status(400).json({
                success: false,
                message: 'Face image is required'
            });
        }

        // Get student details
        let studentQuery = supabase.from('students').select('*');
        if (student_id) {
            studentQuery = studentQuery.eq('id', student_id);
        } else if (matric) {
            studentQuery = studentQuery.eq('matric', matric);
        }
        
        const { data: student, error: studentError } = await studentQuery.single();
        
        if (studentError || !student) {
            return res.status(404).json({
                success: false,
                message: 'Student not found'
            });
        }

        // Enroll face
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

        // Update student record
        const { data: updatedStudent, error: updateError } = await supabase
            .from('students')
            .update({
                face_enrolled: true,
                face_embedding: result.embedding,
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

        // Log audit
        await auditEvents.faceEnrolled(student, result, req);

        res.json({
            success: true,
            data: {
                student: updatedStudent,
                embedding: result.embedding,
                confidence: result.confidence,
                quality: result.quality,
                message: result.message
            }
        });

    } catch (error) {
        console.error('Face enrollment error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// Enroll face with multiple frames
app.post('/api/face/enroll-bulk', async (req, res) => {
    try {
        const { 
            frames,
            student_id,
            name,
            matric,
            hostel_id,
            room_id
        } = req.body;

        if (!student_id && !matric) {
            return res.status(400).json({
                success: false,
                message: 'student_id or matric is required'
            });
        }

        if (!frames || !Array.isArray(frames) || frames.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'At least one frame is required'
            });
        }

        // Get student details
        let studentQuery = supabase.from('students').select('*');
        if (student_id) {
            studentQuery = studentQuery.eq('id', student_id);
        } else if (matric) {
            studentQuery = studentQuery.eq('matric', matric);
        }
        
        const { data: student, error: studentError } = await studentQuery.single();
        
        if (studentError || !student) {
            return res.status(404).json({
                success: false,
                message: 'Student not found'
            });
        }

        // Bulk enroll
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

        // Update student record
        const { data: updatedStudent, error: updateError } = await supabase
            .from('students')
            .update({
                face_enrolled: true,
                face_embedding: result.embedding,
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

        // Log audit
        await auditEvents.faceEnrolled(student, result, req);

        res.json({
            success: true,
            data: {
                student: updatedStudent,
                embedding: result.embedding,
                confidence: result.confidence,
                quality: result.quality,
                frames_used: result.frames_used,
                message: result.message
            }
        });

    } catch (error) {
        console.error('Bulk enrollment error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// Verify face against a single student
app.post('/api/face/verify', async (req, res) => {
    try {
        const { 
            image,
            student_id,
            matric,
            threshold = 0.55
        } = req.body;

        if (!image) {
            return res.status(400).json({
                success: false,
                message: 'Face image is required'
            });
        }

        // Get student and their embedding
        let studentQuery = supabase.from('students').select('id, name, matric, face_embedding, hostel_id, room_id');
        if (student_id) {
            studentQuery = studentQuery.eq('id', student_id);
        } else if (matric) {
            studentQuery = studentQuery.eq('matric', matric);
        } else {
            return res.status(400).json({
                success: false,
                message: 'student_id or matric is required'
            });
        }
        
        const { data: student, error: studentError } = await studentQuery.single();
        
        if (studentError || !student) {
            return res.status(404).json({
                success: false,
                message: 'Student not found'
            });
        }

        if (!student.face_embedding) {
            return res.status(400).json({
                success: false,
                message: 'Student has no face enrolled'
            });
        }

        // Verify face
        const result = await faceService.verifyFace(
            image,
            student.face_embedding,
            threshold
        );

        // Log audit
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
                message: result.message
            }
        });

    } catch (error) {
        console.error('Face verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// Verify face against multiple students (for RA BedCheck)
app.post('/api/face/verify-room', async (req, res) => {
    try {
        const { 
            image,
            room_id,
            hostel_id,
            threshold = 0.55
        } = req.body;

        if (!image) {
            return res.status(400).json({
                success: false,
                message: 'Face image is required'
            });
        }

        // Get students in the room
        let query = supabase.from('students')
            .select('id, name, matric, face_embedding, hostel_id, room_id, room_code')
            .eq('face_enrolled', true);
        
        if (room_id) {
            query = query.eq('room_id', room_id);
        } else if (hostel_id) {
            query = query.eq('hostel_id', hostel_id);
        } else {
            return res.status(400).json({
                success: false,
                message: 'room_id or hostel_id is required'
            });
        }
        
        const { data: students, error: studentsError } = await query;
        
        if (studentsError) {
            console.error('Fetch students error:', studentsError);
            return res.status(500).json({
                success: false,
                message: 'Database error: ' + studentsError.message
            });
        }

        if (!students || students.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'No students found with face enrolled in this room'
            });
        }

        // Prepare data for verification
        const embeddings = students.map(s => s.face_embedding);
        const studentIds = students.map(s => s.id);

        // Verify against all students
        const result = await faceService.verifyMultiple(
            image,
            embeddings,
            studentIds,
            threshold
        );

        let matchedStudent = null;
        if (result.success && result.student_id) {
            matchedStudent = students.find(s => s.id === result.student_id);
        }

        // Log audit
        await auditService.log({
            actor: req.headers['x-staff-name'] || 'RA',
            actor_id: getStaffId(req),
            actor_role: req.headers['x-staff-role'] || 'RA',
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
            student_id: matchedStudent?.id || null
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
            }
        });

    } catch (error) {
        console.error('Room verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// Liveness detection
app.post('/api/face/liveness', async (req, res) => {
    try {
        const { image } = req.body;
        
        if (!image) {
            return res.status(400).json({
                success: false,
                message: 'Image is required'
            });
        }

        const result = await faceService.checkLiveness(image);
        
        // Log if liveness is verified
        if (result.is_live) {
            await auditEvents.livenessVerified(req);
        }

        res.json(result);
    } catch (error) {
        console.error('Liveness check error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// Reset liveness detector
app.post('/api/face/liveness/reset', async (req, res) => {
    try {
        const result = await faceService.resetLiveness();
        res.json(result);
    } catch (error) {
        console.error('Reset liveness error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// Get face status for a student
app.get('/api/face/status/:studentId', async (req, res) => {
    try {
        const studentId = parseInt(req.params.studentId);
        
        const { data: student, error } = await supabase
            .from('students')
            .select('id, name, matric, face_enrolled, face_embedding, updated_at')
            .eq('id', studentId)
            .single();
        
        if (error || !student) {
            return res.status(404).json({
                success: false,
                message: 'Student not found'
            });
        }

        res.json({
            success: true,
            data: {
                student: {
                    id: student.id,
                    name: student.name,
                    matric: student.matric
                },
                face_enrolled: student.face_enrolled,
                has_embedding: !!student.face_embedding,
                embedding_dimension: student.face_embedding ? student.face_embedding.length : 0,
                updated_at: student.updated_at
            }
        });
    } catch (error) {
        console.error('Get face status error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// Compare two embeddings
app.post('/api/face/compare', async (req, res) => {
    try {
        const { embedding1, embedding2 } = req.body;
        
        if (!embedding1 || !embedding2) {
            return res.status(400).json({
                success: false,
                message: 'Both embeddings are required'
            });
        }

        const result = await faceService.compareEmbeddings(embedding1, embedding2);
        res.json(result);
    } catch (error) {
        console.error('Compare embeddings error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// Extract embedding from image
app.post('/api/face/extract', async (req, res) => {
    try {
        const { image } = req.body;
        
        if (!image) {
            return res.status(400).json({
                success: false,
                message: 'Image is required'
            });
        }

        const result = await faceService.extractEmbedding(image);
        res.json(result);
    } catch (error) {
        console.error('Extract embedding error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// =====================================================
// STUDENT FACE ENDPOINTS (Integrated)
// =====================================================

// Get students with face enrollment status
app.get('/api/students/face-status', async (req, res) => {
    try {
        const { hostel_id, room_id } = req.query;
        
        let query = supabase.from('students')
            .select('id, name, matric, hostel_id, room_id, room_code, face_enrolled, face_embedding');
        
        if (hostel_id) query = query.eq('hostel_id', parseInt(hostel_id));
        if (room_id) query = query.eq('room_id', parseInt(room_id));
        
        const { data, error } = await query;
        
        if (error) throw error;
        
        const stats = {
            total: data.length,
            enrolled: data.filter(s => s.face_enrolled).length,
            not_enrolled: data.filter(s => !s.face_enrolled).length
        };
        
        res.json({
            success: true,
            data: data,
            stats: stats
        });
    } catch (error) {
        console.error('Get face status error:', error);
        res.status(500).json({
            success: false,
            message: 'Database error: ' + error.message
        });
    }
});

// =====================================================
// STUDENT FACE ENROLLMENT (Legacy compatible)
// =====================================================

app.post('/api/students/enroll-face', async (req, res) => {
    try {
        const { 
            student_id,
            image,
            name,
            matric,
            hostel_id,
            room_id,
            bed_space_id
        } = req.body;

        if (!student_id && !matric) {
            return res.status(400).json({
                success: false,
                message: 'student_id or matric is required'
            });
        }

        if (!image) {
            return res.status(400).json({
                success: false,
                message: 'Face image is required'
            });
        }

        // Forward to the new enrollment endpoint
        req.body.prefer_insightface = true;
        return app._router.handle({
            ...req,
            url: '/api/face/enroll',
            method: 'POST'
        }, res);
    } catch (error) {
        console.error('Face enrollment error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// =====================================================
// STUDENT FACE VERIFICATION (Legacy compatible)
// =====================================================

app.post('/api/students/verify-face', async (req, res) => {
    try {
        const { 
            student_id,
            image,
            room_id,
            hostel_id,
            threshold = 80
        } = req.body;

        if (!image) {
            return res.status(400).json({
                success: false,
                message: 'Face image is required'
            });
        }

        // Convert threshold from percentage to decimal
        const decimalThreshold = threshold / 100;
        
        // Forward to the new verification endpoint
        return app._router.handle({
            ...req,
            url: '/api/face/verify-room',
            method: 'POST',
            body: {
                ...req.body,
                threshold: decimalThreshold
            }
        }, res);
    } catch (error) {
        console.error('Face verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// =====================================================
// GET STUDENT FACE STATUS (Legacy compatible)
// =====================================================

app.get('/api/students/:studentId/face-status', async (req, res) => {
    try {
        const studentId = parseInt(req.params.studentId);
        
        const { data: student, error } = await supabase
            .from('students')
            .select('id, name, matric, face_enrolled, face_embedding, updated_at')
            .eq('id', studentId)
            .single();
        
        if (error || !student) {
            return res.status(404).json({
                success: false,
                message: 'Student not found'
            });
        }

        res.json({
            success: true,
            data: {
                student: {
                    id: student.id,
                    name: student.name,
                    matric: student.matric
                },
                face_enrolled: student.face_enrolled,
                has_embedding: !!student.face_embedding,
                embedding_dimension: student.face_embedding ? student.face_embedding.length : 0
            }
        });
    } catch (error) {
        console.error('Get face status error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// =====================================================
// BEDCHECK SCANS WITH FACE VERIFICATION
// =====================================================

app.post('/api/bedcheck/scan-with-face', async (req, res) => {
    try {
        const { 
            session_id,
            image,
            room_id,
            threshold = 0.55,
            scanner_id
        } = req.body;

        if (!image) {
            return res.status(400).json({
                success: false,
                message: 'Face image is required'
            });
        }

        // Get students in the room
        let query = supabase.from('students')
            .select('id, name, matric, face_embedding, hostel_id, room_id, room_code')
            .eq('face_enrolled', true);
        
        if (room_id) {
            query = query.eq('room_id', room_id);
        } else {
            return res.status(400).json({
                success: false,
                message: 'room_id is required'
            });
        }
        
        const { data: students, error: studentsError } = await query;
        
        if (studentsError) {
            console.error('Fetch students error:', studentsError);
            return res.status(500).json({
                success: false,
                message: 'Database error: ' + studentsError.message
            });
        }

        if (!students || students.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'No students found with face enrolled in this room'
            });
        }

        // Prepare data for verification
        const embeddings = students.map(s => s.face_embedding);
        const studentIds = students.map(s => s.id);

        // Verify against all students
        const result = await faceService.verifyMultiple(
            image,
            embeddings,
            studentIds,
            threshold
        );

        let matchedStudent = null;
        if (result.success && result.student_id) {
            matchedStudent = students.find(s => s.id === result.student_id);
        }

        // Create scan record
        let scanResult = null;
        if (matchedStudent) {
            const newScan = {
                session_id: session_id || null,
                student_id: matchedStudent.id,
                room: matchedStudent.room_code || null,
                bed_number: null,
                status: 'Verified',
                scanner_id: scanner_id || 'Face-001',
                created_at: new Date().toISOString()
            };
            
            const { data: scanData, error: scanError } = await supabase
                .from('bedcheck_scans')
                .insert(newScan)
                .select()
                .single();
            
            if (!scanError) {
                scanResult = scanData;
                
                // Update student status
                await supabase
                    .from('students')
                    .update({ 
                        status: 'Present',
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', matchedStudent.id);
            }
        }

        // Log audit
        await auditService.log({
            actor: req.headers['x-staff-name'] || 'RA',
            actor_id: getStaffId(req),
            actor_role: req.headers['x-staff-role'] || 'RA',
            action: matchedStudent ? 'Face Scan Verified' : 'Face Scan Failed',
            module: 'bedcheck',
            details: matchedStudent 
                ? `${matchedStudent.name} (${matchedStudent.matric}) verified via face scan`
                : `Face verification failed in room ${room_id}`,
            context: `Session: ${session_id || 'N/A'}`,
            result: matchedStudent ? 'success' : 'failed',
            category: 'bedcheck',
            tone: matchedStudent ? 'green' : 'red',
            hostel_id: matchedStudent?.hostel_id,
            room_id: room_id,
            student_id: matchedStudent?.id || null,
            session_id: session_id || null
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
            }
        });

    } catch (error) {
        console.error('Face scan error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});

// =====================================================
// REGISTRATION MANAGEMENT - RASD ENDPOINTS
// =====================================================

app.get('/api/registration/stats', async (req, res) => {
  try {
    const { data: students, error: studentsError } = await supabase
      .from('students')
      .select('id, room_id, name, matric, hostel_id, hostel_name, room_code, status, created_at, face_enrolled');
    
    if (studentsError) throw studentsError;

    const { data: bedSpaces, error: bedError } = await supabase
      .from('bed_spaces')
      .select('id, room_id, status');
    
    if (bedError) throw bedError;

    const { data: hostels, error: hostelsError } = await supabase
      .from('hostels')
      .select('id, name, type, total_floors, rooms_per_floor, total_flats, rooms_per_flat');
    
    if (hostelsError) throw hostelsError;

    const totalRegistered = students.length || 0;
    const hostelAssigned = students.filter(s => s.room_id !== null && s.room_id > 0).length || 0;
    const completed = students.filter(s => s.status === 'Completed' || s.status === 'Registration Complete').length || 0;
    const faceEnrolled = students.filter(s => s.face_enrolled === true).length || 0;
    const issues = students.filter(s => !s.name || !s.matric || (s.room_id === null || s.room_id === 0)).length || 0;
    const totalBedSpaces = bedSpaces.length || 0;
    const availableBeds = bedSpaces.filter(b => b.status === 'available').length || 0;

    const pipeline = [
      { label: 'Online Registration', count: totalRegistered, icon: 'fa-globe', color: 'blue', students: students },
      { label: 'Hostel Assignment', count: hostelAssigned, icon: 'fa-building', color: 'purple', students: students.filter(s => s.room_id !== null && s.room_id > 0) },
      { label: 'Face Enrolled', count: faceEnrolled, icon: 'fa-user-check', color: 'gold', students: students.filter(s => s.face_enrolled === true) },
      { label: 'Registration Completed', count: completed, icon: 'fa-check-circle', color: 'green', students: students.filter(s => s.status === 'Completed' || s.status === 'Registration Complete') },
      { label: 'Registration Issues', count: issues, icon: 'fa-exclamation-triangle', color: 'red', students: students.filter(s => !s.name || !s.matric || (s.room_id === null || s.room_id === 0)) }
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

    res.json({ success: true, data: { overview: { totalRegistered, hostelAssigned, completed, faceEnrolled, issues, totalBedSpaces, availableBeds }, pipeline, hostelProgress, issueTypes } });
  } catch (error) {
    console.error('Error fetching registration stats:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// HRA DASHBOARD ENDPOINTS
// =====================================================

app.get('/api/hra/hostel', async (req, res) => {
  const staffId = getStaffId(req);
  
  if (!staffId) {
    return res.status(400).json({ success: false, message: 'staff_id is required. Please provide it in headers (X-Staff-ID) or query parameters.' });
  }
  
  try {
    const { data: staffData, error: staffError } = await supabase
      .from('staff')
      .select('hostel_id, role, name, username, email, phone, assigned_floor, assigned_room')
      .eq('id', staffId)
      .single();
    
    if (staffError || !staffData) {
      return res.status(404).json({ success: false, message: 'Staff member not found' });
    }
    
    if (staffData.role !== 'HRA') {
      return res.status(403).json({ success: false, message: 'User is not an HRA' });
    }
    
    if (!staffData.hostel_id) {
      return res.status(404).json({ success: false, message: 'HRA not assigned to a hostel' });
    }
    
    const { data: hostelData, error: hostelError } = await supabase
      .from('hostels')
      .select('*')
      .eq('id', staffData.hostel_id)
      .single();
    
    if (hostelError || !hostelData) {
      return res.status(404).json({ success: false, message: 'Hostel not found' });
    }
    
    const { data: hostelStaff, error: staffListError } = await supabase
      .from('staff')
      .select('id, name, role, username, email, phone, status, assigned_floor, assigned_room, submission_status, level')
      .eq('hostel_id', hostelData.id)
      .eq('status', 'Active');
    
    if (staffListError) throw staffListError;
    
    const hraStaff = hostelStaff?.find(s => s.role === 'HRA');
    const raStaff = hostelStaff?.filter(s => s.role === 'RA') || [];
    
    const { count: totalStudents, error: countError } = await supabase
      .from('students')
      .select('*', { count: 'exact', head: true })
      .eq('hostel_id', hostelData.id);
    
    if (countError) throw countError;
    
    const { data: studentStatuses, error: statusError } = await supabase
      .from('students')
      .select('status, face_enrolled')
      .eq('hostel_id', hostelData.id);
    
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
      }
    });
  } catch (error) {
    console.error('Error fetching HRA hostel:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// STAFF - Unified CRUD
// =====================================================

app.get('/api/staff', async (req, res) => {
  try {
    const { data, error } = await supabase.from('staff').select('id, name, username, role, hostel_id, assigned_floor, assigned_room, status, email, phone, department, initials, submission_status, level, joined').order('name', { ascending: true });
    if (error) throw error;
    const enrichedData = data.map(item => ({ ...item, staff_id: item.id }));
    res.json({ success: true, data: enrichedData });
  } catch (error) {
    console.error('Error fetching staff:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.get('/api/staff/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { data, error } = await supabase.from('staff').select('id, name, username, role, hostel_id, assigned_floor, assigned_room, status, email, phone, department, initials, submission_status, level, joined, last_login').eq('id', id).single();
    if (error || !data) return res.status(404).json({ success: false, message: 'Staff not found' });
    if (!data.last_login) data.last_login = new Date().toLocaleString();
    res.json({ success: true, data: { ...data, staff_id: data.id } });
  } catch (error) {
    console.error('Error fetching staff:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.post('/api/staff', async (req, res) => {
  const { name, username, password, role, hostel_id, email, phone, department, assigned_floor, assigned_room, level } = req.body;
  try {
    const { data: existingStaff, error: checkError } = await supabase.from('staff').select('id').eq('username', username).single();
    if (checkError && checkError.code !== 'PGRST116') throw checkError;
    if (existingStaff) return res.status(400).json({ success: false, message: 'Username already exists' });
    
    const initials = name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase();
    const hashedPassword = password ? await bcrypt.hash(password, SALT_ROUNDS) : await bcrypt.hash('password1', SALT_ROUNDS);
    
    const newStaff = { 
      name, 
      username, 
      password: hashedPassword, 
      role, 
      hostel_id: hostel_id || null, 
      assigned_floor: assigned_floor || null, 
      assigned_room: assigned_room || null, 
      status: 'Active', 
      initials, 
      email: email || null, 
      phone: phone || null, 
      department: department || null, 
      submission_status: 'Not Started', 
      level: level || null, 
      joined: new Date().toISOString().split('T')[0] 
    };
    const { data, error } = await supabase.from('staff').insert(newStaff).select().single();
    if (error) throw error;
    await auditEvents.userCreated(data, { name: 'System', role: 'System' });
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error creating staff:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/staff/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { name, username, role, hostel_id, status, email, phone, department, assigned_floor, assigned_room, submission_status, level } = req.body;
  try {
    const { data: currentUser } = await supabase.from('staff').select('name, role').eq('id', id).single();
    const updateData = {};
    const changes = [];
    if (name !== undefined) { updateData.name = name; changes.push('name'); }
    if (username !== undefined) { updateData.username = username; changes.push('username'); }
    if (role !== undefined) { updateData.role = role; changes.push('role'); if (currentUser && currentUser.role !== role) { await auditEvents.userRoleChanged({ id, name: currentUser.name }, currentUser.role, role, { name: req.headers['x-staff-name'] || 'Admin', role: 'Admin' }); } }
    if (hostel_id !== undefined) { updateData.hostel_id = hostel_id || null; changes.push('hostel_id'); }
    if (assigned_floor !== undefined) { updateData.assigned_floor = assigned_floor || null; changes.push('assigned_floor'); }
    if (assigned_room !== undefined) { updateData.assigned_room = assigned_room || null; changes.push('assigned_room'); }
    if (status !== undefined) { updateData.status = status; changes.push('status'); }
    if (email !== undefined) { updateData.email = email; changes.push('email'); }
    if (phone !== undefined) { updateData.phone = phone; changes.push('phone'); }
    if (department !== undefined) { updateData.department = department; changes.push('department'); }
    if (submission_status !== undefined) { updateData.submission_status = submission_status; changes.push('submission_status'); }
    if (level !== undefined) { updateData.level = level; changes.push('level'); }
    updateData.updated_at = new Date().toISOString();
    if (Object.keys(updateData).length === 0) return res.status(400).json({ success: false, message: 'No fields to update' });
    const { data, error } = await supabase.from('staff').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    await auditService.log({ actor: req.headers['x-staff-name'] || 'Admin', actor_id: parseInt(req.headers['x-staff-id']) || null, actor_role: req.headers['x-staff-role'] || 'Admin', action: 'User Updated', module: 'staff', details: `Updated ${data?.name}: ${changes.join(', ')}`, context: `User ID: ${id}`, result: 'success', category: 'staff', tone: 'blue', hostel_id: data?.hostel_id });
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error updating staff:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/staff/:id/password', async (req, res) => {
  const id = parseInt(req.params.id);
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ success: false, message: 'Password must be at least 8 characters' });
  try {
    const { data: user } = await supabase.from('staff').select('name').eq('id', id).single();
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const { error } = await supabase.from('staff').update({ password: hashedPassword }).eq('id', id);
    if (error) throw error;
    await auditEvents.passwordChanged({ id, name: user?.name || 'User' }, { name: req.headers['x-staff-name'] || 'User', role: 'User' });
    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.delete('/api/staff/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { data: user } = await supabase.from('staff').select('name, role').eq('id', id).single();
    const { error } = await supabase.from('staff').delete().eq('id', id);
    if (error) throw error;
    await auditService.log({ actor: req.headers['x-staff-name'] || 'Admin', actor_id: parseInt(req.headers['x-staff-id']) || null, actor_role: req.headers['x-staff-role'] || 'Admin', action: 'User Deleted', module: 'staff', details: `Deleted ${user?.name} (${user?.role})`, context: `User ID: ${id}`, result: 'success', category: 'staff', tone: 'red' });
    res.json({ success: true, message: 'Staff deleted successfully' });
  } catch (error) {
    console.error('Error deleting staff:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// STUDENTS - Full CRUD (UPDATED - REMOVED notes)
// =====================================================

app.get('/api/students', async (req, res) => {
  const { hostel, search, status, room_id } = req.query;
  try {
    let query = supabase.from('students').select('*');
    if (hostel && hostel !== 'all') query = query.eq('hostel', hostel);
    if (room_id) query = query.eq('room_id', parseInt(room_id));
    if (search) query = query.or(`name.ilike.%${search}%,matric.ilike.%${search}%`);
    if (status && status !== 'all') query = query.eq('status', status);
    const { data, error } = await query.order('id', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching students:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.post('/api/students', async (req, res) => {
  const { 
    name, matric, faculty, department, level, session, 
    hostel_id, hostel_name, floor_flat_id, floor_name, 
    room_id, room_code, bed_space_id, bed_code, 
    status, gender, phone, email, 
    emergency_name, emergency_relation, emergency_phone,
    face_enrolled, face_embedding, photo, registration_date
  } = req.body;
  
  try {
    const newStudent = {
      name, 
      matric, 
      gender: gender || 'Male', 
      phone: phone || null, 
      email: email || null,
      faculty: faculty || 'Engineering', 
      department: department || 'General', 
      level: level || '300',
      session: session || '2025/2026', 
      hostel_id: hostel_id || null, 
      hostel_name: hostel_name || null,
      floor_flat_id: floor_flat_id || null, 
      floor_name: floor_name || null,
      room_id: room_id || null, 
      room_code: room_code || null,
      bed_space_id: bed_space_id || null, 
      bed_code: bed_code || null,
      status: status || 'Present',
      emergency_name: emergency_name || null, 
      emergency_relation: emergency_relation || null,
      emergency_phone: emergency_phone || null,
      photo: photo || null,
      registration_date: registration_date || new Date().toISOString(),
      face_enrolled: face_enrolled || false,
      face_embedding: face_embedding || null,
      created_at: new Date().toISOString(), 
      updated_at: new Date().toISOString()
    };
    
    Object.keys(newStudent).forEach(key => { 
      if (newStudent[key] === undefined) delete newStudent[key]; 
    });
    
    const { data, error } = await supabase.from('students').insert(newStudent).select().single();
    if (error) throw error;
    
    if (bed_space_id) {
      await supabase
        .from('bed_spaces')
        .update({ status: 'occupied', student_id: data.id, updated_at: new Date().toISOString() })
        .eq('id', parseInt(bed_space_id));
    }
    
    const hostel = { id: hostel_id, name: hostel_name };
    await auditEvents.studentRegistered(data, hostel, { name: 'Student Registration', role: 'System' });
    
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error creating student:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/students/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const updateData = {};
  const allowedFields = [
    'name', 'matric', 'gender', 'phone', 'email', 'faculty', 'department', 
    'level', 'session', 'hostel_id', 'hostel_name', 'floor_flat_id', 'floor_name',
    'room_id', 'room_code', 'bed_space_id', 'bed_code', 'status', 'photo',
    'emergency_name', 'emergency_relation', 'emergency_phone', 'face_enrolled',
    'face_embedding', 'registration_date', 'updated_at'
  ];
  
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
      .select()
      .single();
    
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error updating student:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/students/:id/status', async (req, res) => {
  const id = parseInt(req.params.id);
  const { status } = req.body;
  if (!status) return res.status(400).json({ success: false, message: 'Status is required' });
  try {
    const { data, error } = await supabase.from('students').update({ status: status, updated_at: new Date().toISOString() }).eq('id', id).select().single();
    if (error) throw error;
    await auditService.log({ actor: req.headers['x-staff-name'] || 'System', actor_id: parseInt(req.headers['x-staff-id']) || null, actor_role: req.headers['x-staff-role'] || 'System', action: 'Student Status Updated', module: 'students', details: `Updated ${data?.name} (${data?.matric}) status to ${status}`, context: `Student ID: ${id}`, result: 'success', category: 'student', tone: status === 'Present' ? 'green' : status === 'Absent' ? 'red' : 'gold', hostel_id: data?.hostel_id, room_id: data?.room_id, student_id: data?.id });
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error updating student status:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.delete('/api/students/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { data: student } = await supabase.from('students').select('name, matric, bed_space_id, hostel_id, room_id').eq('id', id).single();
    
    if (student && student.bed_space_id) {
      await supabase.from('bed_spaces').update({ status: 'available', student_id: null, updated_at: new Date().toISOString() }).eq('id', student.bed_space_id);
    }
    
    const { error } = await supabase.from('students').delete().eq('id', id);
    if (error) throw error;
    
    await auditService.log({ actor: req.headers['x-staff-name'] || 'System', actor_id: parseInt(req.headers['x-staff-id']) || null, actor_role: req.headers['x-staff-role'] || 'System', action: 'Student Deleted', module: 'students', details: `Deleted ${student?.name} (${student?.matric})`, context: `Student ID: ${id}`, result: 'success', category: 'student', tone: 'red', hostel_id: student?.hostel_id, room_id: student?.room_id, student_id: id });
    res.json({ success: true, message: 'Student deleted successfully' });
  } catch (error) {
    console.error('Error deleting student:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// FLOORS_FLATS, ROOMS, BED_SPACES, HOSTELS
// =====================================================

// Floors/Flats
app.get('/api/floors-flats', async (req, res) => {
  const { hostel_id } = req.query;
  try {
    let query = supabase.from('floors_flats').select('*');
    if (hostel_id) query = query.eq('hostel_id', parseInt(hostel_id));
    const { data, error } = await query.order('name', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching floors/flats:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.get('/api/floors-flats/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { data, error } = await supabase.from('floors_flats').select('*').eq('id', id).single();
    if (error || !data) return res.status(404).json({ success: false, message: 'Floor/Flat not found' });
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching floor/flat:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.post('/api/floors-flats', async (req, res) => {
  const { hostel_id, name, type } = req.body;
  if (!hostel_id || !name) return res.status(400).json({ success: false, message: 'hostel_id and name are required' });
  try {
    const newFloor = { hostel_id: parseInt(hostel_id), name, type: type || 'floor' };
    const { data, error } = await supabase.from('floors_flats').insert(newFloor).select().single();
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error creating floor/flat:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/floors-flats/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { hostel_id, name, type } = req.body;
  try {
    const updateData = {};
    if (hostel_id !== undefined) updateData.hostel_id = parseInt(hostel_id);
    if (name !== undefined) updateData.name = name;
    if (type !== undefined) updateData.type = type;
    if (Object.keys(updateData).length === 0) return res.status(400).json({ success: false, message: 'No fields to update' });
    const { data, error } = await supabase.from('floors_flats').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error updating floor/flat:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.delete('/api/floors-flats/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { error } = await supabase.from('floors_flats').delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true, message: 'Floor/Flat deleted successfully' });
  } catch (error) {
    console.error('Error deleting floor/flat:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// ROOMS
// =====================================================

app.get('/api/rooms', async (req, res) => {
  const { floor_flat_id, hostel_id } = req.query;
  try {
    let query = supabase.from('rooms').select('*');
    
    if (floor_flat_id) {
      query = query.eq('floor_flat_id', parseInt(floor_flat_id));
    }
    
    if (hostel_id) {
      const { data: hostelFloors, error: floorsError } = await supabase
        .from('floors_flats')
        .select('id')
        .eq('hostel_id', parseInt(hostel_id));
      
      if (floorsError) {
        console.error('Error fetching hostel floors:', floorsError);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error: ' + floorsError.message 
        });
      }
      
      if (hostelFloors && hostelFloors.length > 0) {
        const floorIds = hostelFloors.map(f => f.id);
        query = query.in('floor_flat_id', floorIds);
      } else {
        return res.json({ success: true, data: [] });
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
    
    res.json({ success: true, data: enrichedData });
  } catch (error) {
    console.error('Error fetching rooms:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.get('/api/rooms/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { data, error } = await supabase.from('rooms').select('*').eq('id', id).single();
    if (error || !data) return res.status(404).json({ success: false, message: 'Room not found' });
    
    const { data: floorData } = await supabase
      .from('floors_flats')
      .select('name, hostel_id')
      .eq('id', data.floor_flat_id)
      .maybeSingle();
    
    const { data: bedData } = await supabase
      .from('bed_spaces')
      .select('id, status')
      .eq('room_id', id);
    
    const capacity = bedData?.length || 4;
    const occupiedCount = bedData?.filter(b => b.status === 'occupied').length || 0;
    
    res.json({ 
      success: true, 
      data: {
        ...data,
        floor_label: floorData?.name || null,
        hostel_id: floorData?.hostel_id || null,
        capacity: capacity,
        occupied: occupiedCount,
        available: capacity - occupiedCount
      }
    });
  } catch (error) {
    console.error('Error fetching room:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.post('/api/rooms', async (req, res) => {
  const { floor_flat_id, room_code } = req.body;
  if (!floor_flat_id || !room_code) return res.status(400).json({ success: false, message: 'floor_flat_id and room_code are required' });
  try {
    const newRoom = { floor_flat_id: parseInt(floor_flat_id), room_code };
    const { data, error } = await supabase.from('rooms').insert(newRoom).select().single();
    if (error) throw error;
    
    const { data: floorData } = await supabase
      .from('floors_flats')
      .select('name, hostel_id')
      .eq('id', data.floor_flat_id)
      .maybeSingle();
    
    res.json({ 
      success: true, 
      data: {
        ...data,
        floor_label: floorData?.name || null,
        hostel_id: floorData?.hostel_id || null,
        capacity: 4,
        occupied: 0,
        available: 4
      }
    });
  } catch (error) {
    console.error('Error creating room:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/rooms/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { floor_flat_id, room_code } = req.body;
  try {
    const updateData = {};
    if (floor_flat_id !== undefined) updateData.floor_flat_id = parseInt(floor_flat_id);
    if (room_code !== undefined) updateData.room_code = room_code;
    if (Object.keys(updateData).length === 0) return res.status(400).json({ success: false, message: 'No fields to update' });
    const { data, error } = await supabase.from('rooms').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    
    const { data: floorData } = await supabase
      .from('floors_flats')
      .select('name, hostel_id')
      .eq('id', data.floor_flat_id)
      .maybeSingle();
    
    res.json({ 
      success: true, 
      data: {
        ...data,
        floor_label: floorData?.name || null,
        hostel_id: floorData?.hostel_id || null
      }
    });
  } catch (error) {
    console.error('Error updating room:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.delete('/api/rooms/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { error } = await supabase.from('rooms').delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true, message: 'Room deleted successfully' });
  } catch (error) {
    console.error('Error deleting room:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// BED SPACES - Filter By Hostel_id
// =====================================================

app.get('/api/bed-spaces', async (req, res) => {
  const { room_id, hostel_id } = req.query;
  try {
    let query = supabase.from('bed_spaces').select('*');
    
    if (room_id) {
      query = query.eq('room_id', parseInt(room_id));
    }
    
    if (hostel_id) {
      const { data: hostelFloors, error: floorsError } = await supabase
        .from('floors_flats')
        .select('id')
        .eq('hostel_id', parseInt(hostel_id));
      
      if (floorsError) {
        console.error('Error fetching hostel floors:', floorsError);
        return res.status(500).json({ 
          success: false, 
          message: 'Database error: ' + floorsError.message 
        });
      }
      
      if (hostelFloors && hostelFloors.length > 0) {
        const floorIds = hostelFloors.map(f => f.id);
        
        const { data: hostelRooms, error: roomsError } = await supabase
          .from('rooms')
          .select('id')
          .in('floor_flat_id', floorIds);
        
        if (roomsError) {
          console.error('Error fetching hostel rooms:', roomsError);
          return res.status(500).json({ 
            success: false, 
            message: 'Database error: ' + roomsError.message 
          });
        }
        
        if (hostelRooms && hostelRooms.length > 0) {
          const roomIds = hostelRooms.map(r => r.id);
          query = query.in('room_id', roomIds);
        } else {
          return res.json({ success: true, data: [] });
        }
      } else {
        return res.json({ success: true, data: [] });
      }
    }
    
    const { data, error } = await query.order('bed_code', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching bed spaces:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.get('/api/bed-spaces/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { data, error } = await supabase.from('bed_spaces').select('*').eq('id', id).single();
    if (error || !data) return res.status(404).json({ success: false, message: 'Bed space not found' });
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching bed space:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.post('/api/bed-spaces', async (req, res) => {
  const { room_id, bed_code, full_bed_code, status } = req.body;
  if (!room_id || !bed_code) return res.status(400).json({ success: false, message: 'room_id and bed_code are required' });
  try {
    const newBed = { room_id: parseInt(room_id), bed_code, full_bed_code: full_bed_code || null, status: status || 'available', student_id: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    const { data, error } = await supabase.from('bed_spaces').insert(newBed).select().single();
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error creating bed space:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/bed-spaces/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { room_id, bed_code, full_bed_code, status, student_id } = req.body;
  try {
    const updateData = {};
    if (room_id !== undefined) updateData.room_id = parseInt(room_id);
    if (bed_code !== undefined) updateData.bed_code = bed_code;
    if (full_bed_code !== undefined) updateData.full_bed_code = full_bed_code;
    if (status !== undefined) updateData.status = status;
    if (student_id !== undefined) updateData.student_id = student_id;
    updateData.updated_at = new Date().toISOString();
    if (Object.keys(updateData).length === 0) return res.status(400).json({ success: false, message: 'No fields to update' });
    const { data, error } = await supabase.from('bed_spaces').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error updating bed space:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.patch('/api/bed-spaces/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { status, student_id } = req.body;
  try {
    const updateData = {};
    if (status !== undefined) updateData.status = status;
    if (student_id !== undefined) updateData.student_id = student_id;
    updateData.updated_at = new Date().toISOString();
    if (Object.keys(updateData).length === 0) return res.status(400).json({ success: false, message: 'No fields to update' });
    const { data, error } = await supabase.from('bed_spaces').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error patching bed space:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.delete('/api/bed-spaces/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { error } = await supabase.from('bed_spaces').delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true, message: 'Bed space deleted successfully' });
  } catch (error) {
    console.error('Error deleting bed space:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// HOSTELS
// =====================================================

app.get('/api/hostels', async (req, res) => {
  try {
    const { data: hostelsData, error: hostelsError } = await supabase.from('hostels').select('*').order('name', { ascending: true });
    if (hostelsError) throw hostelsError;
    if (!hostelsData || hostelsData.length === 0) return res.json({ success: true, data: [] });
    
    const { data: floorsData, error: floorsError } = await supabase
      .from('floors_flats')
      .select('id, hostel_id, name, type');
    if (floorsError) throw floorsError;
    
    const { data: roomsData, error: roomsError } = await supabase
      .from('rooms')
      .select('id, floor_flat_id');
    if (roomsError) throw roomsError;
    
    const { data: bedSpacesData, error: bedError } = await supabase
      .from('bed_spaces')
      .select('id, room_id, status');
    if (bedError) throw bedError;
    
    const { data: staffData, error: staffError } = await supabase
      .from('staff')
      .select('id, name, role, hostel_id, assigned_floor, assigned_room, status, username, email, phone, submission_status, level')
      .eq('status', 'Active');
    if (staffError) throw staffError;
    
    const enrichedHostels = hostelsData.map(hostel => {
      const hostelFloors = floorsData?.filter(f => f.hostel_id === hostel.id) || [];
      const totalFloors = hostelFloors.length;
      
      let totalRooms = 0;
      const floorIds = hostelFloors.map(f => f.id);
      if (floorIds.length > 0) {
        const hostelRooms = roomsData?.filter(r => floorIds.includes(r.floor_flat_id)) || [];
        totalRooms = hostelRooms.length;
      }
      
      let totalBeds = 0;
      let occupiedBeds = 0;
      if (totalRooms > 0) {
        const roomIds = roomsData?.filter(r => floorIds.includes(r.floor_flat_id)).map(r => r.id) || [];
        if (roomIds.length > 0) {
          const hostelBeds = bedSpacesData?.filter(b => roomIds.includes(b.room_id)) || [];
          totalBeds = hostelBeds.length;
          occupiedBeds = hostelBeds.filter(b => b.status === 'occupied').length;
        }
      }
      
      const hostelStaff = staffData.filter(s => s.hostel_id === hostel.id);
      const hraStaff = hostelStaff.find(s => s.role === 'HRA');
      const raStaff = hostelStaff.filter(s => s.role === 'RA');
      
      const bedsPerRoom = hostel.beds_per_room || (hostel.gender === 'female' ? 6 : 4);
      
      return {
        ...hostel,
        floors: totalFloors || hostel.total_floors || 0,
        total_floors: totalFloors || hostel.total_floors || 0,
        room_count: totalRooms,
        total_rooms: totalRooms,
        total_beds: totalBeds,
        beds_per_room: bedsPerRoom,
        occupied_beds: occupiedBeds,
        available_beds: totalBeds - occupiedBeds,
        rooms_per_floor: hostel.rooms_per_floor || (hostel.gender === 'female' ? 24 : 18),
        rooms_per_flat: hostel.rooms_per_flat || 4,
        hra_name: hraStaff ? hraStaff.name : null,
        hra_id: hraStaff ? hraStaff.id : null,
        hra: hraStaff ? hraStaff.name : hostel.hra || null,
        ra_names: raStaff.map(s => s.name).join(', '),
        ra_list: raStaff.map(s => ({
          id: s.id,
          name: s.name,
          username: s.username,
          email: s.email,
          phone: s.phone,
          assigned_floor: s.assigned_floor || null,
          assigned_room: s.assigned_room || null,
          submission_status: s.submission_status || 'Not Started',
          level: s.level || null
        })),
        ra_count: raStaff.length,
        staff: hostelStaff.map(s => ({
          id: s.id,
          name: s.name,
          role: s.role,
          username: s.username,
          assigned_floor: s.assigned_floor || null,
          assigned_room: s.assigned_room || null,
          submission_status: s.submission_status || 'Not Started'
        }))
      };
    });
    
    res.json({ success: true, data: enrichedHostels });
  } catch (error) {
    console.error('Error fetching hostels:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.get('/api/hostels/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const { data: hostelData, error: hostelError } = await supabase.from('hostels').select('*').eq('id', id).single();
    if (hostelError || !hostelData) return res.status(404).json({ success: false, message: 'Hostel not found' });
    
    const { data: floorsData, error: floorsError } = await supabase
      .from('floors_flats')
      .select('*')
      .eq('hostel_id', id);
    if (floorsError) throw floorsError;
    
    const floorIds = floorsData?.map(f => f.id) || [];
    let roomsData = [];
    if (floorIds.length > 0) {
      const { data: rooms, error: roomsError } = await supabase
        .from('rooms')
        .select('*')
        .in('floor_flat_id', floorIds);
      if (roomsError) throw roomsError;
      roomsData = rooms || [];
    }
    
    const roomIds = roomsData.map(r => r.id);
    let bedSpacesData = [];
    if (roomIds.length > 0) {
      const { data: beds, error: bedError } = await supabase
        .from('bed_spaces')
        .select('*')
        .in('room_id', roomIds);
      if (bedError) throw bedError;
      bedSpacesData = beds || [];
    }
    
    const { data: staffData, error: staffError } = await supabase
      .from('staff')
      .select('id, name, role, hostel_id, assigned_floor, assigned_room, status, username, email, phone, submission_status, level')
      .eq('hostel_id', id)
      .eq('status', 'Active');
    if (staffError) throw staffError;
    
    const hraStaff = staffData.find(s => s.role === 'HRA');
    const raStaff = staffData.filter(s => s.role === 'RA');
    
    const bedsPerRoom = hostelData.beds_per_room || (hostelData.gender === 'female' ? 6 : 4);
    const totalRooms = roomsData.length;
    const totalBeds = bedSpacesData.length;
    const occupiedBeds = bedSpacesData.filter(b => b.status === 'occupied').length;
    
    const enrichedHostel = {
      ...hostelData,
      floors: floorsData?.length || hostelData.total_floors || 0,
      total_floors: floorsData?.length || hostelData.total_floors || 0,
      room_count: totalRooms,
      total_rooms: totalRooms,
      total_beds: totalBeds,
      beds_per_room: bedsPerRoom,
      occupied_beds: occupiedBeds,
      available_beds: totalBeds - occupiedBeds,
      rooms_per_floor: hostelData.rooms_per_floor || (hostelData.gender === 'female' ? 24 : 18),
      rooms_per_flat: hostelData.rooms_per_flat || 4,
      hra_name: hraStaff ? hraStaff.name : null,
      hra_id: hraStaff ? hraStaff.id : null,
      hra: hraStaff ? hraStaff.name : hostelData.hra || null,
      ra_names: raStaff.map(s => s.name).join(', '),
      ra_list: raStaff.map(s => ({
        id: s.id,
        name: s.name,
        username: s.username,
        email: s.email,
        phone: s.phone,
        assigned_floor: s.assigned_floor || null,
        assigned_room: s.assigned_room || null,
        submission_status: s.submission_status || 'Not Started',
        level: s.level || null
      })),
      ra_count: raStaff.length,
      staff: staffData,
      floors_list: floorsData || [],
      rooms_list: roomsData || [],
      bed_spaces: bedSpacesData || []
    };
    
    res.json({ success: true, data: enrichedHostel });
  } catch (error) {
    console.error('Error fetching hostel:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/hostels/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { name, gender, type, total_floors, rooms_per_floor, total_flats, rooms_per_flat, beds_per_room, progress, state, ra, hra } = req.body;
  try {
    const { data: currentHostel } = await supabase.from('hostels').select('*').eq('id', id).single();
    const updateData = {};
    const changes = [];
    if (name !== undefined) { updateData.name = name; changes.push('name'); }
    if (gender !== undefined) { updateData.gender = gender; changes.push('gender'); }
    if (type !== undefined) { updateData.type = type; changes.push('type'); }
    if (total_floors !== undefined && total_floors !== null) { updateData.total_floors = total_floors; changes.push('total_floors'); }
    if (rooms_per_floor !== undefined && rooms_per_floor !== null) { updateData.rooms_per_floor = rooms_per_floor; changes.push('rooms_per_floor'); }
    if (total_flats !== undefined && total_flats !== null) { updateData.total_flats = total_flats; changes.push('total_flats'); }
    if (rooms_per_flat !== undefined && rooms_per_flat !== null) { updateData.rooms_per_flat = rooms_per_flat; changes.push('rooms_per_flat'); }
    if (beds_per_room !== undefined) { updateData.beds_per_room = beds_per_room; changes.push('beds_per_room'); }
    if (progress !== undefined) { updateData.progress = progress; changes.push('progress'); }
    if (state !== undefined) { updateData.state = state; changes.push('state'); }
    if (ra !== undefined) { updateData.ra = ra; changes.push('ra'); }
    if (hra !== undefined) { updateData.hra = hra; changes.push('hra'); }
    updateData.updated_at = new Date().toISOString();
    if (Object.keys(updateData).length === 0) return res.status(400).json({ success: false, message: 'No fields to update' });
    const { data, error } = await supabase.from('hostels').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    if (changes.length > 0) { await auditEvents.hostelUpdated({ id, name: data?.name }, changes, { name: req.headers['x-staff-name'] || 'Admin', role: 'Admin' }); }
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error updating hostel:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// HOSTEL ALERTS & EXTRA ENDPOINTS
// =====================================================

app.get('/api/hostels/:id/alerts', async (req, res) => {
  const id = parseInt(req.params.id);
  
  try {
    const { data: hostel, error: hostelError } = await supabase
      .from('hostels')
      .select('id, name')
      .eq('id', id)
      .single();
    
    if (hostelError || !hostel) {
      return res.status(404).json({ 
        success: false, 
        message: 'Hostel not found' 
      });
    }
    
    const alerts = [];
    
    const { data: absentStudents, error: absentError } = await supabase
      .from('students')
      .select('id, name, matric, status, room_code')
      .eq('hostel_id', id)
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
            studentCount: students.length,
            students: students.map(s => ({ name: s.name, matric: s.matric }))
          });
        }
      });
      
      if (absentStudents.length > 10) {
        alerts.push({
          type: 'warning',
          severity: 'high',
          title: `${absentStudents.length} students marked absent`,
          description: `High number of absent students in this hostel.`,
          studentCount: absentStudents.length
        });
      }
    }
    
    const { data: pendingRA, error: raError } = await supabase
      .from('staff')
      .select('id, name, submission_status')
      .eq('hostel_id', id)
      .eq('role', 'RA')
      .eq('submission_status', 'Not Started');
    
    if (!raError && pendingRA && pendingRA.length > 0) {
      alerts.push({
        type: 'warning',
        severity: 'medium',
        title: `${pendingRA.length} RA submission${pendingRA.length > 1 ? 's' : ''} pending`,
        description: `${pendingRA.map(s => s.name).join(', ')} have not started submission.`,
        staff: pendingRA.map(s => ({ name: s.name, status: s.submission_status }))
      });
    }
    
    const { data: bedSpaces, error: bedError } = await supabase
      .from('bed_spaces')
      .select('id, status')
      .eq('hostel_id', id);
    
    if (!bedError && bedSpaces && bedSpaces.length > 0) {
      const total = bedSpaces.length;
      const available = bedSpaces.filter(b => b.status === 'available').length;
      const occupancyRate = total > 0 ? Math.round(((total - available) / total) * 100) : 0;
      
      if (occupancyRate > 90) {
        alerts.push({
          type: 'info',
          severity: 'medium',
          title: `High occupancy rate: ${occupancyRate}%`,
          description: `${total - available} of ${total} beds occupied. Only ${available} beds available.`,
          occupancyRate: occupancyRate,
          availableBeds: available,
          totalBeds: total
        });
      }
    }
    
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    
    const { data: recentSessions, error: sessionError } = await supabase
      .from('bedcheck_sessions')
      .select('id, status, created_at')
      .eq('hostel_id', id)
      .gte('created_at', yesterday.toISOString())
      .order('created_at', { ascending: false })
      .limit(1);
    
    if (!sessionError && (!recentSessions || recentSessions.length === 0)) {
      alerts.push({
        type: 'warning',
        severity: 'low',
        title: 'No recent BedCheck session',
        description: 'No BedCheck session has been started in the last 24 hours.'
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
      hostel: hostel.name
    });
    
  } catch (error) {
    console.error('Error fetching hostel alerts:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/hostels/:id/occupancy', async (req, res) => {
  const id = parseInt(req.params.id);
  
  try {
    const { data: hostel, error: hostelError } = await supabase
      .from('hostels')
      .select('id, name, total_floors, rooms_per_floor, total_flats, rooms_per_flat, type')
      .eq('id', id)
      .single();
    
    if (hostelError || !hostel) {
      return res.status(404).json({ 
        success: false, 
        message: 'Hostel not found' 
      });
    }
    
    const { data: bedSpaces, error: bedError } = await supabase
      .from('bed_spaces')
      .select('id, status, room_id')
      .eq('hostel_id', id);
    
    if (bedError) throw bedError;
    
    const total = bedSpaces?.length || 0;
    const available = bedSpaces?.filter(b => b.status === 'available').length || 0;
    const occupied = bedSpaces?.filter(b => b.status === 'occupied').length || 0;
    const maintenance = bedSpaces?.filter(b => b.status === 'maintenance').length || 0;
    const occupancyRate = total > 0 ? Math.round((occupied / total) * 100) : 0;
    
    const { count: studentCount, error: studentError } = await supabase
      .from('students')
      .select('*', { count: 'exact', head: true })
      .eq('hostel_id', id);
    
    if (studentError) throw studentError;
    
    const { data: rooms, error: roomsError } = await supabase
      .from('rooms')
      .select('id, room_code, floor_flat_id')
      .eq('hostel_id', id);
    
    if (roomsError) throw roomsError;
    
    res.json({
      success: true,
      data: {
        hostel: hostel.name,
        totalBeds: total,
        availableBeds: available,
        occupiedBeds: occupied,
        maintenanceBeds: maintenance,
        occupancyRate: occupancyRate,
        totalRooms: rooms?.length || 0,
        totalStudents: studentCount || 0
      }
    });
    
  } catch (error) {
    console.error('Error fetching hostel occupancy:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/hostels/:id/summary', async (req, res) => {
  const id = parseInt(req.params.id);
  
  try {
    const { data: hostel, error: hostelError } = await supabase
      .from('hostels')
      .select('*')
      .eq('id', id)
      .single();
    
    if (hostelError || !hostel) {
      return res.status(404).json({ 
        success: false, 
        message: 'Hostel not found' 
      });
    }
    
    const { data: students, error: studentError } = await supabase
      .from('students')
      .select('status, room_id, face_enrolled')
      .eq('hostel_id', id);
    
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
      .eq('hostel_id', id);
    
    if (bedError) throw bedError;
    
    const totalBeds = bedSpaces?.length || 0;
    const availableBeds = bedSpaces?.filter(b => b.status === 'available').length || 0;
    const occupiedBeds = bedSpaces?.filter(b => b.status === 'occupied').length || 0;
    
    const { count: staffCount, error: staffError } = await supabase
      .from('staff')
      .select('*', { count: 'exact', head: true })
      .eq('hostel_id', id)
      .eq('status', 'Active');
    
    if (staffError) throw staffError;
    
    res.json({
      success: true,
      data: {
        hostel: {
          id: hostel.id,
          name: hostel.name,
          gender: hostel.gender,
          type: hostel.type
        },
        students: {
          total: totalStudents,
          present: present,
          absent: absent,
          late: late,
          assigned: assigned,
          faceEnrolled: faceEnrolled
        },
        beds: {
          total: totalBeds,
          available: availableBeds,
          occupied: occupiedBeds,
          occupancyRate: totalBeds > 0 ? Math.round((occupiedBeds / totalBeds) * 100) : 0
        },
        staff: staffCount || 0
      }
    });
    
  } catch (error) {
    console.error('Error fetching hostel summary:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

// =====================================================
// BEDCHECK SESSIONS (per-hostel sessions)
// =====================================================

app.get('/api/bedcheck/sessions', async (req, res) => {
  const { hostel_id, date } = req.query;
  try {
    let query = supabase.from('bedcheck_sessions').select('*');
    if (hostel_id) query = query.eq('hostel_id', parseInt(hostel_id));
    if (date) query = query.eq('date', date);
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching bedcheck sessions:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.post('/api/bedcheck/sessions', async (req, res) => {
  const { hostel_id, date, start_time, end_time, status, scanner_id, battery } = req.body;
  try {
    const newSession = { hostel_id: hostel_id || null, date: date || new Date().toISOString().split('T')[0], start_time: start_time || '10:00 PM', end_time: end_time || '12:00 AM', status: status || 'Active', scanner_id: scanner_id || 'FP-027', battery: battery || 94, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    const { data, error } = await supabase.from('bedcheck_sessions').insert(newSession).select().single();
    if (error) throw error;
    const { data: hostel } = await supabase.from('hostels').select('name').eq('id', hostel_id).single();
    await auditEvents.sessionCreated(data, { id: hostel_id, name: hostel?.name || 'Unknown' }, { name: req.headers['x-staff-name'] || 'System', role: req.headers['x-staff-role'] || 'System' });
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error creating bedcheck session:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/bedcheck/sessions/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { status, scanner_id, battery, completed_at } = req.body;
  try {
    const updateData = {};
    if (status !== undefined) updateData.status = status;
    if (scanner_id !== undefined) updateData.scanner_id = scanner_id;
    if (battery !== undefined) updateData.battery = battery;
    if (completed_at !== undefined) updateData.completed_at = completed_at;
    updateData.updated_at = new Date().toISOString();
    const { data, error } = await supabase.from('bedcheck_sessions').update(updateData).eq('id', id).select().single();
    if (error) throw error;
    if (status === 'Active') { await auditEvents.sessionStarted(data, { id: data.hostel_id }, { name: req.headers['x-staff-name'] || 'RA', role: req.headers['x-staff-role'] || 'RA' }); }
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error updating bedcheck session:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// BEDCHECK SCANS (REMOVED notes field)
// =====================================================

app.get('/api/bedcheck/scans', async (req, res) => {
  const { session_id, room, student_id } = req.query;
  try {
    let query = supabase.from('bedcheck_scans').select('*, students(name, matric)');
    if (session_id) query = query.eq('session_id', parseInt(session_id));
    if (room) query = query.eq('room', room);
    if (student_id) query = query.eq('student_id', parseInt(student_id));
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching bedcheck scans:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.post('/api/bedcheck/scans', async (req, res) => {
  const { session_id, student_id, room, bed_number, status, scanner_id } = req.body;
  try {
    const newScan = {
      session_id: session_id || null,
      student_id: student_id || null,
      room: room || null,
      bed_number: bed_number || null,
      status: status || 'Verified',
      scanner_id: scanner_id || 'FP-027',
      created_at: new Date().toISOString()
    };
    const { data, error } = await supabase.from('bedcheck_scans').insert(newScan).select().single();
    if (error) throw error;
    if (student_id) {
      const { data: student } = await supabase.from('students').select('name, matric, hostel_id, room_id').eq('id', student_id).single();
      await supabase.from('students').update({ status: status === 'Verified' ? 'Present' : status, updated_at: new Date().toISOString() }).eq('id', student_id);
      await auditService.log({
        actor: req.headers['x-staff-name'] || 'RA',
        actor_id: parseInt(req.headers['x-staff-id']) || null,
        actor_role: req.headers['x-staff-role'] || 'RA',
        action: status === 'Verified' ? 'QR Verification' : 'Verification Failed',
        module: 'verification',
        details: `${student?.name} (${student?.matric}) ${status === 'Verified' ? 'verified' : 'failed verification'} in ${room || 'Unknown Room'}`,
        context: `Student ID: ${student?.id}`,
        result: status === 'Verified' ? 'success' : 'failed',
        category: 'verification',
        tone: status === 'Verified' ? 'green' : 'red',
        hostel_id: student?.hostel_id,
        room_id: student?.room_id,
        student_id: student?.id
      });
    }
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error creating bedcheck scan:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// RA - ROOM HISTORY
// =====================================================

app.get('/api/room-history', async (req, res) => {
  const { hostel_id, room, student_id, date_from, date_to } = req.query;
  try {
    let query = supabase.from('bedcheck_scans').select('*, students(name, matric)');
    if (hostel_id) {
      const { data: studentsInHostel, error: studentError } = await supabase.from('students').select('id').eq('hostel_id', parseInt(hostel_id));
      if (studentError) throw studentError;
      if (studentsInHostel && studentsInHostel.length > 0) {
        const studentIds = studentsInHostel.map(s => s.id);
        query = query.in('student_id', studentIds);
      } else { return res.json({ success: true, data: [] }); }
    }
    if (room) query = query.eq('room', room);
    if (student_id) query = query.eq('student_id', parseInt(student_id));
    if (date_from) query = query.gte('created_at', new Date(date_from).toISOString());
    if (date_to) query = query.lte('created_at', new Date(date_to).toISOString());
    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching room history:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// RA - SUBMIT BEDCHECK
// =====================================================

app.post('/api/bedcheck/submit', async (req, res) => {
  const { session_id, hostel_id, notes, actor } = req.body;
  try {
    const { data: sessionData, error: sessionError } = await supabase.from('bedcheck_sessions').update({ status: 'Submitted', completed_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq('id', session_id).select().single();
    if (sessionError) throw sessionError;
    const { data: hostelData } = await supabase.from('hostels').select('name').eq('id', hostel_id).single();
    await auditEvents.sessionSubmitted(sessionData, { id: hostel_id, name: hostelData?.name || 'Unknown' }, { name: actor || req.headers['x-staff-name'] || 'RA', role: 'RA' }, null);
    res.json({ success: true, data: sessionData });
  } catch (error) {
    console.error('Error submitting bedcheck:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// SESSIONS
// =====================================================

app.get('/api/sessions', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('sessions')
      .select('*')
      .order('date', { ascending: false });
    
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching sessions:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.get('/api/sessions/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { data, error } = await supabase
      .from('sessions')
      .select('*')
      .eq('id', id)
      .single();
    
    if (error) throw error;
    if (!data) {
      return res.status(404).json({ success: false, message: 'Session not found' });
    }
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching session:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.post('/api/sessions', async (req, res) => {
  try {
    const { 
      name,
      date, 
      start_time, 
      end_time, 
      status, 
      hostels_completed, 
      total_hostels, 
      completion,
      academic_session,
      grace_period,
      created_by
    } = req.body;

    let creatorName = null;
    if (created_by) {
      const { data: staff } = await supabase
        .from('staff')
        .select('name')
        .eq('id', parseInt(created_by))
        .maybeSingle();
      if (staff) creatorName = staff.name;
    }

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
      created_by: created_by || null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    const { data, error } = await supabase
      .from('sessions')
      .insert(newSession)
      .select()
      .single();

    if (error) {
      console.error('Session insert error:', error);
      throw error;
    }

    await auditService.log({
      actor: creatorName || req.headers['x-staff-name'] || 'System',
      actor_id: created_by || parseInt(req.headers['x-staff-id']) || null,
      actor_role: req.headers['x-staff-role'] || 'Admin',
      action: 'Created BedCheck Session',
      module: 'sessions',
      details: `Created session: ${data.name} for ${data.date}`,
      context: `Session ID: ${data.id}`,
      result: 'success',
      category: 'bedcheck',
      tone: 'blue',
      session_id: data.id
    });

    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error creating session:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.put('/api/sessions/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { 
      name,
      date, 
      start_time, 
      end_time, 
      status, 
      hostels_completed, 
      total_hostels, 
      completion,
      academic_session,
      grace_period
    } = req.body;

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
      .select()
      .single();

    if (error) {
      console.error('Session update error:', error);
      throw error;
    }

    await auditService.log({
      actor: req.headers['x-staff-name'] || 'System',
      actor_id: parseInt(req.headers['x-staff-id']) || null,
      actor_role: req.headers['x-staff-role'] || 'Admin',
      action: 'Updated BedCheck Session',
      module: 'sessions',
      details: `Updated session #${id}: ${changes.join(', ')}`,
      context: `Session ID: ${id}`,
      result: 'success',
      category: 'bedcheck',
      tone: 'gold',
      session_id: id
    });

    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error updating session:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.delete('/api/sessions/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    
    const { data: session, error: fetchError } = await supabase
      .from('sessions')
      .select('name, date, status')
      .eq('id', id)
      .single();
    
    if (fetchError) {
      console.error('Session fetch error:', fetchError);
      return res.status(404).json({ 
        success: false, 
        message: 'Session not found' 
      });
    }

    if (!session) {
      return res.status(404).json({ 
        success: false, 
        message: 'Session not found' 
      });
    }

    if (session.status?.toLowerCase() === 'active') {
      console.log(`⚠️ Deleting active session: ${session.name} (ID: ${id})`);
    }

    const { error: deleteError } = await supabase
      .from('sessions')
      .delete()
      .eq('id', id);

    if (deleteError) {
      console.error('Session delete error:', deleteError);
      return res.status(500).json({ 
        success: false, 
        message: 'Database error: ' + deleteError.message 
      });
    }

    await auditService.log({
      actor: req.headers['x-staff-name'] || 'System',
      actor_id: parseInt(req.headers['x-staff-id']) || null,
      actor_role: req.headers['x-staff-role'] || 'Admin',
      action: 'Deleted BedCheck Session',
      module: 'sessions',
      details: `Deleted session: ${session.name} (${session.date}) - Status: ${session.status}`,
      context: `Session ID: ${id}`,
      result: 'success',
      category: 'bedcheck',
      tone: 'red',
      session_id: id
    });

    console.log(`✅ Session ${id} deleted successfully`);

    res.json({ 
      success: true, 
      message: 'Session deleted successfully',
      data: { id, name: session.name, date: session.date }
    });
  } catch (error) {
    console.error('❌ Error deleting session:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error: ' + error.message 
    });
  }
});

app.get('/api/sessions/active', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('sessions')
      .select('*')
      .eq('status', 'active')
      .order('date', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching active session:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/sessions/latest', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('sessions')
      .select('*')
      .order('date', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching latest session:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

app.get('/api/sessions/stats', async (req, res) => {
  try {
    const { data: sessions, error } = await supabase
      .from('sessions')
      .select('status, hostels_completed, total_hostels, completion');

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

    res.json({ success: true, data: stats });
  } catch (error) {
    console.error('Error fetching session stats:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Database error: ' + error.message 
    });
  }
});

// =====================================================
// SUBMISSION STATE
// =====================================================

app.get('/api/submission', async (req, res) => {
  try {
    const { data, error } = await supabase.from('submission_state').select('state, notice').order('id', { ascending: false }).limit(1);
    if (error) throw error;
    if (data && data.length > 0) { res.json({ success: true, data: data[0] }); } else {
      const { data: insertData, error: insertError } = await supabase.from('submission_state').insert({ state: 'Open', notice: 'Tonight\'s BedCheck is active · 9:30 PM — 11:00 PM' }).select().single();
      if (insertError) throw insertError;
      res.json({ success: true, data: insertData });
    }
  } catch (error) {
    console.error('Error fetching submission state:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.put('/api/submission', async (req, res) => {
  const { state, notice } = req.body;
  try {
    const { data: existingData, error: fetchError } = await supabase.from('submission_state').select('id').order('id', { ascending: false }).limit(1);
    if (fetchError) throw fetchError;
    let result;
    if (existingData && existingData.length > 0) {
      const { data, error } = await supabase.from('submission_state').update({ state, notice, updated_at: new Date().toISOString() }).eq('id', existingData[0].id).select().single();
      if (error) throw error;
      result = data;
    } else {
      const { data, error } = await supabase.from('submission_state').insert({ state, notice }).select().single();
      if (error) throw error;
      result = data;
    }
    await auditEvents.systemSettingsUpdated('submission_state', existingData?.[0]?.state || 'Open', state, { name: req.headers['x-staff-name'] || 'Admin', role: 'Admin' });
    res.json({ success: true, data: result });
  } catch (error) {
    console.error('Error updating submission state:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// DASHBOARD STATISTICS
// =====================================================

app.get('/api/dashboard/stats', async (req, res) => {
  try {
    const stats = {};
    const { count: studentsCount, error: studentsError } = await supabase.from('students').select('*', { count: 'exact', head: true });
    stats.totalStudents = studentsCount || 0;
    const { count: hostelsCount, error: hostelsError } = await supabase.from('hostels').select('*', { count: 'exact', head: true });
    stats.totalHostels = hostelsCount || 0;
    const { data: statusData, error: statusError } = await supabase.from('students').select('status, face_enrolled');
    if (!statusError && statusData) {
      stats.present = statusData.filter(s => s.status === 'Present').length;
      stats.absent = statusData.filter(s => s.status === 'Absent').length;
      stats.late = statusData.filter(s => s.status === 'Late').length;
      stats.faceEnrolled = statusData.filter(s => s.face_enrolled === true).length;
    } else { stats.present = 0; stats.absent = 0; stats.late = 0; stats.faceEnrolled = 0; }
    res.json({ success: true, data: stats });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.get('/api/dashboard/activity', async (req, res) => {
  const { hostel_id, limit } = req.query;
  try {
    const activity = await auditService.getRecentActivity(hostel_id || null, limit || 10);
    res.json({ success: true, data: activity });
  } catch (error) {
    console.error('Error fetching recent activity:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// RASD - Live BedCheck Monitor
// =====================================================

app.get('/api/monitor/hostels', async (req, res) => {
  try {
    const { data, error } = await supabase.from('hostels').select('*').order('name', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching monitor hostels:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

app.get('/api/monitor/students', async (req, res) => {
  const { hostel, status } = req.query;
  try {
    let query = supabase.from('students').select('*');
    if (hostel && hostel !== 'all') query = query.eq('hostel', hostel);
    if (status && status !== 'all') query = query.eq('status', status);
    const { data, error } = await query.order('name', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data });
  } catch (error) {
    console.error('Error fetching monitor students:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// REPORTS
// =====================================================

app.get('/api/reports/attendance', async (req, res) => {
  const { type } = req.query;
  try {
    const { data, error } = await supabase.from('students').select('*');
    if (error) throw error;
    const total = data.length;
    const present = data.filter(s => s.status === 'Present').length;
    const absent = data.filter(s => s.status === 'Absent').length;
    const late = data.filter(s => s.status === 'Late').length;
    const faceEnrolled = data.filter(s => s.face_enrolled === true).length;
    res.json({ success: true, data: { total, present, absent, late, faceEnrolled, attendanceRate: total > 0 ? Math.round((present / total) * 100) : 0, students: data } });
  } catch (error) {
    console.error('Error fetching attendance report:', error);
    res.status(500).json({ success: false, message: 'Database error: ' + error.message });
  }
});

// =====================================================
// FACE TEMPLATE ENDPOINTS
// =====================================================

app.get('/api/face-templates/student/:studentId', async (req, res) => {
    try {
        const studentId = parseInt(req.params.studentId);
        
        const { data: student, error } = await supabase
            .from('students')
            .select('face_embedding, face_enrolled')
            .eq('id', studentId)
            .single();
        
        if (error || !student) {
            return res.json({ 
                success: true, 
                data: null, 
                message: 'Student not found' 
            });
        }
        
        if (!student.face_embedding) {
            return res.json({ 
                success: true, 
                data: null, 
                message: 'No face template found for this student' 
            });
        }
        
        res.json({
            success: true,
            data: {
                face_enrolled: student.face_enrolled,
                embedding_dimension: student.face_embedding.length
            }
        });
    } catch (error) {
        console.error('Error fetching face template:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Database error: ' + error.message 
        });
    }
});

// =====================================================
// CATCH-ALL FOR 404
// =====================================================

app.use((req, res) => {
  console.log(`❌ Route not found: ${req.method} ${req.path}`);
  res.status(404).json({ success: false, message: `Route not found: ${req.method} ${req.path}` });
});

// =====================================================
// ERROR HANDLING
// =====================================================

app.use((err, req, res, next) => {
  console.error('❌ Server error:', err.stack);
  res.status(500).json({ success: false, message: 'Something went wrong!', error: process.env.NODE_ENV === 'development' ? err.message : undefined });
});

// =====================================================
// START SERVER
// =====================================================

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`🚀 BIU BedCheck API Server running on port ${PORT}`);
  console.log(`📋 API Endpoint: http://localhost:${PORT}/api`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔐 Face Provider: InsightFace`);
  
  // Check Face API health
  try {
    const health = await faceService.checkHealth();
    if (health.status === 'healthy') {
      console.log(`✅ InsightFace API is healthy`);
    } else {
      console.log(`⚠️ InsightFace API is running but health check returned: ${health.status}`);
    }
  } catch (error) {
    console.log(`⚠️ InsightFace API is not running or unreachable: ${error.message}`);
    console.log(`   Please start the Python server: cd python && uvicorn app:app --reload`);
  }
  
  console.log(`${'='.repeat(60)}\n`);
});