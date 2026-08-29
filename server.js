// server.js - BIU BedCheck with Face Recognition
// SECURE PRODUCTION VERSION v4.7.0
// ============================================================

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
const compression = require('compression');
require('dotenv').config();

// =====================================================
// DASHBOARD ROUTES - Role to Page Mapping (Server Side)
// =====================================================

const DASHBOARD_ROUTES = {
    'Administrator': '/admin/index.html',
    'Admin': '/admin/index.html',
    'Administration': '/admin/index.html',
    'RASD': '/RASD/rasd-index.html',
    'HRA': '/HRA/hra-index.html',
    'RA': '/RA/ra-index.html',
    'Developer': '/app/dev-index.html',
    'Student': '/student/hub.html'
};

// =====================================================
// CONFIGURATION & VALIDATION
// =====================================================

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS) || 12;

app.set('trust proxy', 1);

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

const SUPPORTED_CAMPUSES = ['Legacy', 'Heritage'];

const getCampusContext = (req) => {
    const headerCampus = req.headers['x-campus'];
    if (headerCampus && SUPPORTED_CAMPUSES.includes(headerCampus)) {
        return headerCampus;
    }
    if (req.user && req.user.campus && SUPPORTED_CAMPUSES.includes(req.user.campus)) {
        return req.user.campus;
    }
    return process.env.DEFAULT_CAMPUS || 'Legacy';
};

// =====================================================
// FACE RECOGNITION CONFIGURATION
// =====================================================

const FACE_API_URL = process.env.FACE_API_URL || 'http://localhost:8000';
const FACE_API_TIMEOUT = parseInt(process.env.FACE_API_TIMEOUT) || 30000;
const FACE_VERIFICATION_THRESHOLD = parseFloat(process.env.FACE_VERIFICATION_THRESHOLD) || 0.55;

console.log('🔐 Environment:', process.env.NODE_ENV || 'production');
console.log('🔐 Face API URL:', FACE_API_URL);

// =====================================================
// FACE RECOGNITION SERVICE
// =====================================================

class InsightFaceService {
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
        this.failureCount = 0;
        this.circuitOpen = false;
        this.lastFailureTime = null;
        this.circuitTimeout = 60000;
        this.maxFailures = 5;
        this.maxImageSize = parseInt(process.env.MAX_IMAGE_SIZE) || 10 * 1024 * 1024;
    }

    // Circuit breaker methods
    _checkCircuit() {
        if (this.circuitOpen) {
            const now = Date.now();
            if (now - this.lastFailureTime > this.circuitTimeout) {
                console.log('🔌 Circuit breaker resetting');
                this.circuitOpen = false;
                this.failureCount = 0;
                return true;
            }
            return false;
        }
        return true;
    }

    _recordFailure() {
        this.failureCount++;
        if (this.failureCount >= this.maxFailures) {
            this.circuitOpen = true;
            this.lastFailureTime = Date.now();
            console.warn('🔌 Circuit breaker opened - Face API is down');
        }
    }

    _recordSuccess() {
        this.failureCount = 0;
        this.circuitOpen = false;
    }

    isValidBase64(str) {
        if (!str || typeof str !== 'string') return false;
        const base64Str = str.replace(/^data:image\/\w+;base64,/, '');
        try {
            const buffer = Buffer.from(base64Str, 'base64');
            if (buffer.length === 0) return false;
            if (buffer.length > this.maxImageSize) return false;
            // Do NOT require buffer.toString('base64') === base64Str (padding differs)
            return true;
        } catch {
            return false;
        }
    }

    // Main request method (SINGLE version - remove the duplicate)
    async _makeRequest(endpoint, data, options = {}) {
        // Check circuit breaker
        if (!this._checkCircuit()) {
            return { 
                success: false, 
                error: 'Face API service temporarily unavailable (circuit open)',
                fallback: 'Manual verification required'
            };
        }

        // Validate image data if present
        if (data.image && !this.isValidBase64(data.image)) {
            return {
                success: false,
                error: 'Invalid base64 image data',
                fallback: 'Manual verification required'
            };
        }

        // Validate frames if present (for bulk enrollment)
        if (data.frames && Array.isArray(data.frames)) {
            for (const frame of data.frames) {
                if (!this.isValidBase64(frame)) {
                    return {
                        success: false,
                        error: 'Invalid base64 frame data detected',
                        fallback: 'Manual verification required'
                    };
                }
            }
        }

        try {
            const response = await axios({
                method: 'post',
                url: `${this.apiUrl}${endpoint}`,
                data: data,
                timeout: options.timeout || FACE_API_TIMEOUT,
                headers: { 
                    'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key',
                    'Content-Type': 'application/json'
                }
            });
            this._recordSuccess();
            return response.data;
        } catch (error) {
            this._recordFailure();
            console.error(`Face API error (${endpoint}):`, error.response?.data || error.message);
            return { 
                success: false, 
                error: error.response?.data?.detail || error.message,
                fallback: 'Manual verification required',
                circuit_open: this.circuitOpen
            };
        }
    }

    async checkHealth() {
        try {
            const response = await axios.get(`${this.apiUrl}/health`, {
                timeout: 5000,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            this._recordSuccess();
            return response.data;
        } catch (error) {
            this._recordFailure();
            console.error('Face API health check error:', error.message);
            return { status: 'unhealthy', error: error.message };
        }
    }

    async detectFace(imageBase64) {
        // Validate image first
        if (!this.isValidBase64(imageBase64)) {
            return {
                success: false,
                error: 'Invalid base64 image data',
                fallback: 'Manual verification required'
            };
        }
        const imageData = this._sanitizeImage(imageBase64);
        return this._makeRequest('/detect-face', { image: imageData });
    }

    async enrollFace(imageBase64, studentId, hostel, room, name) {
        // Validate image first
        if (!this.isValidBase64(imageBase64)) {
            return {
                success: false,
                error: 'Invalid base64 image data',
                fallback: 'Manual verification required'
            };
        }
        const imageData = this._sanitizeImage(imageBase64);
        return this._makeRequest('/enroll-face', {
            image: imageData,
            student_id: studentId,
            hostel: hostel,
            room: room,
            name: name
        });
    }

    async enrollBulk(frames, studentId, hostel, room, name) {
        // Validate all frames first
        for (const frame of frames) {
            if (!this.isValidBase64(frame)) {
                return {
                    success: false,
                    error: 'Invalid base64 frame data detected',
                    fallback: 'Manual verification required'
                };
            }
        }
        const imageDataList = frames.map(frame => this._sanitizeImage(frame));
        return this._makeRequest('/enroll-bulk', {
            frames: imageDataList,
            student_id: studentId,
            hostel: hostel,
            room: room,
            name: name
        }, { timeout: FACE_API_TIMEOUT * 2 });
    }

    async verifyFace(imageBase64, storedEmbedding, threshold = FACE_VERIFICATION_THRESHOLD) {
        // Validate image first
        if (!this.isValidBase64(imageBase64)) {
            return {
                success: false,
                error: 'Invalid base64 image data',
                fallback: 'Manual verification required'
            };
        }
        
        // First extract embedding from the captured image
        const extracted = await this.extractEmbedding(imageBase64);
        
        if (!extracted.success || !extracted.embedding) {
            return {
                success: false,
                error: extracted.error || 'Failed to extract face from image',
                fallback: 'Manual verification required'
            };
        }

        // Then compare with stored embedding
        const comparison = await this.compareEmbeddings(
            extracted.embedding,
            storedEmbedding
        );

        if (!comparison.success) {
            return {
                success: false,
                error: comparison.error || 'Failed to compare faces',
                fallback: 'Manual verification required'
            };
        }

        const isMatch = comparison.similarity >= threshold;

        return {
            success: true,
            verified: isMatch,
            similarity: comparison.similarity,
            threshold: threshold,
            confidence: comparison.similarity,
            message: isMatch ? 'Face verified successfully' : 'Face verification failed'
        };
    }

    async verifyMultiple(imageBase64, embeddings, studentIds, threshold = FACE_VERIFICATION_THRESHOLD) {
        // Validate image first
        if (!this.isValidBase64(imageBase64)) {
            return {
                success: false,
                error: 'Invalid base64 image data',
                fallback: 'Manual verification required'
            };
        }

        // Extract embedding from captured image
        const extracted = await this.extractEmbedding(imageBase64);
        
        if (!extracted.success || !extracted.embedding) {
            return {
                success: false,
                error: extracted.error || 'Failed to extract face from image',
                fallback: 'Manual verification required'
            };
        }

        // Compare against all embeddings
        let bestMatch = null;
        let bestSimilarity = 0;

        for (let i = 0; i < embeddings.length; i++) {
            const comparison = await this.compareEmbeddings(
                extracted.embedding,
                embeddings[i]
            );

            if (comparison.success && comparison.similarity > bestSimilarity) {
                bestSimilarity = comparison.similarity;
                bestMatch = {
                    student_id: studentIds[i],
                    similarity: comparison.similarity
                };
            }
        }

        const isMatch = bestMatch && bestSimilarity >= threshold;

        return {
            success: true,
            verified: isMatch,
            student_id: isMatch ? bestMatch.student_id : null,
            similarity: bestSimilarity,
            threshold: threshold,
            confidence: bestSimilarity,
            message: isMatch ? 'Match found' : 'No match found'
        };
    }

    async checkLiveness(imageBase64) {
        // Validate image first
        if (!this.isValidBase64(imageBase64)) {
            return {
                success: false,
                error: 'Invalid base64 image data',
                fallback: 'Manual verification required'
            };
        }
        const imageData = this._sanitizeImage(imageBase64);
        const result = await this._makeRequest('/check-liveness', { image: imageData });
        return result.is_live !== undefined ? result : { is_live: false, error: result.error };
    }

    async resetLiveness() {
        return this._makeRequest('/reset-liveness', {});
    }

    async compareEmbeddings(embedding1, embedding2) {
            // Validate inputs
            if (!embedding1 || !embedding2) {
                return {
                    success: false,
                    error: 'Both embeddings are required for comparison',
                    similarity: 0
                };
            }

            if (!Array.isArray(embedding1) || !Array.isArray(embedding2)) {
                return {
                    success: false,
                    error: 'Embeddings must be arrays',
                    similarity: 0
                };
            }

            if (embedding1.length !== 512 || embedding2.length !== 512) {
                return {
                    success: false,
                    error: `Invalid embedding dimensions. Expected 512, got ${embedding1.length} and ${embedding2.length}`,
                    similarity: 0
                };
            }

            const result = await this._makeRequest('/compare-embeddings', {
                embedding1: embedding1,
                embedding2: embedding2
            });

            // Ensure consistent response format
            if (result.success) {
                return {
                    success: true,
                    similarity: result.similarity || 0,
                    distance: result.distance || null,
                    is_match: (result.similarity || 0) >= FACE_VERIFICATION_THRESHOLD
                };
            }

            return {
                success: false,
                error: result.error || 'Failed to compare embeddings',
                similarity: 0
            };
        }

    async extractEmbedding(imageBase64) {
        // Validate image first
        if (!this.isValidBase64(imageBase64)) {
            return {
                success: false,
                error: 'Invalid base64 image data',
                fallback: 'Manual verification required'
            };
        }
        const imageData = this._sanitizeImage(imageBase64);
        const result = await this._makeRequest('/extract-embedding', { image: imageData });
        
        // Ensure consistent response format
        if (result.success && result.embedding) {
            return {
                success: true,
                embedding: result.embedding,
                confidence: result.confidence || 0.95,
                quality: result.quality || 0.8,
                face_count: result.face_count || 1
            };
        }
        
        return result;
    }

    _sanitizeImage(imageBase64) {
        if (!imageBase64) return '';
        return imageBase64.replace(/^data:image\/\w+;base64,/, '');
    }

    validateImage(imageBase64) {
        if (!imageBase64) {
            return { valid: false, error: 'No image provided' };
        }

        const base64Pattern = /^data:image\/(png|jpeg|jpg|gif|webp);base64,/;
        if (!base64Pattern.test(imageBase64)) {
            return { 
                valid: false, 
                error: 'Invalid image format. Only PNG, JPEG, GIF, and WebP are allowed.' 
            };
        }

        const base64String = imageBase64.replace(base64Pattern, '');
        const sizeInBytes = Buffer.from(base64String, 'base64').length;
        const maxSize = parseInt(process.env.MAX_IMAGE_SIZE) || 10 * 1024 * 1024;
        
        if (sizeInBytes > maxSize) {
            return { 
                valid: false, 
                error: `Image size exceeds ${maxSize / 1024 / 1024}MB limit` 
            };
        }

        return { valid: true };
    }
}

const faceService = new InsightFaceService(FACE_API_URL);

// =====================================================
// SESSION MANAGEMENT FUNCTIONS
// =====================================================

async function getOrCreateTodaySession(hostelId, campus = 'Legacy') {
    const today = new Date().toISOString().split('T')[0];
    
    const { data: existingSession, error: checkError } = await supabase
        .from('sessions')
        .select('*')
        .eq('hostel_id', hostelId)
        .eq('date', today)
        .eq('campus', campus)
        .maybeSingle();
    
    if (checkError) {
        console.error('Error checking session:', checkError);
        return null;
    }
    
    if (existingSession) {
        return existingSession;
    }
    
    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const dayName = dayNames[new Date().getDay()] || 'Night';
    
    const newSession = {
        hostel_id: hostelId,
        date: today,
        name: `${dayName} Night BedCheck`,
        status: 'draft',
        start_time: '22:00:00',
        end_time: '23:30:00',
        campus: campus,
        campus_code: campus === 'Legacy' ? 'LEG' : 'HER',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
    };
    
    const { data: session, error: insertError } = await supabase
        .from('sessions')
        .insert(newSession)
        .select()
        .single();
    
    if (insertError) {
        console.error('Error creating session:', insertError);
        return null;
    }
    
    console.log(`📋 Created new session for ${hostelId} on ${today}`);
    return session;
}

// =====================================================
// HELPER: Create University-Wide Bedcheck Sessions
// =====================================================

async function createUniversityWideBedcheckSessions(sessionId) {
    try {
        // Fetch all required data in parallel
        const [{ data: hostels }, { data: ras }] = await Promise.all([
            supabase.from('hostels').select('id, campus').eq('status', 'Active'),
            supabase.from('staff')
                .select('id, hostel_id, campus')
                .eq('role', 'RA')
                .eq('status', 'Active')
        ]);

        if (!hostels?.length) {
            console.warn('No active hostels found for bedcheck creation');
            return;
        }

        const raMap = Object.fromEntries(
            (ras || [])
                .filter(ra => ra.hostel_id)
                .map(ra => [ra.hostel_id, ra.id])
        );

        const now = new Date().toISOString();
        
        const hostelPromises = hostels.map(async (hostel) => {
            const { data: existing } = await supabase
                .from('bedcheck_sessions')
                .select('id')
                .eq('global_session_id', sessionId)
                .eq('hostel_id', hostel.id)
                .eq('campus', hostel.campus)
                .maybeSingle();

            if (existing) {
                console.log(`📋 Bedcheck session already exists for hostel ${hostel.id}`);
                return null;
            }

            const { count: studentCount, error: countError } = await supabase
                .from('students')
                .select('*', { count: 'exact', head: true })
                .eq('hostel_id', hostel.id)
                .eq('campus', hostel.campus)
                .eq('status', 'Active');

            if (countError) {
                console.error(`Error counting students for hostel ${hostel.id}:`, countError);
                return null;
            }

            return {
                global_session_id: sessionId,
                hostel_id: hostel.id,
                ra_id: raMap[hostel.id] || null,
                campus: hostel.campus,
                campus_code: hostel.campus === 'Legacy' ? 'LEG' : 'HER',
                status: 'pending',
                total_students: studentCount || 0,
                present_students: 0,
                completion: 0,
                created_by: 'system',
                created_at: now,
                updated_at: now
            };
        });

        const bedcheckInserts = (await Promise.all(hostelPromises))
            .filter(insert => insert !== null);

        if (bedcheckInserts.length === 0) {
            console.log('No new bedcheck sessions to create');
            return;
        }

        const { error: insertError } = await supabase
            .from('bedcheck_sessions')
            .upsert(bedcheckInserts, { 
                onConflict: 'global_session_id,hostel_id',
                ignoreDuplicates: false
            });

        if (insertError) {
            console.error('Error creating bedcheck sessions:', insertError);
            throw insertError;
        }

        console.log(`✅ Created ${bedcheckInserts.length} bedcheck sessions for session ${sessionId}`);

        await supabase
            .from('sessions')
            .update({ total_hostels: hostels.length })
            .eq('id', sessionId);

    } catch (error) {
        console.error('Error in createUniversityWideBedcheckSessions:', error);
        throw error;
    }
}

// =====================================================
// HELPER: Mark Unverified as Absent (University-Wide)
// =====================================================

async function markUnverifiedAsAbsentUniversityWide(sessionId) {
    try {
        // ✅ Get ALL students from ALL campuses
        const { data: allStudents, error: studentsError } = await supabase
            .from('students')
            .select('id, name, matric, hostel_id, room_code, campus')
            .eq('status', 'Active');

        if (studentsError || !allStudents) {
            console.error('Error fetching students:', studentsError);
            return;
        }

        // ✅ Get verified students from ALL campuses
        const { data: verified, error: verifiedError } = await supabase
            .from('bedcheck_attendance')
            .select('student_id, campus')
            .eq('global_session_id', sessionId)
            .eq('status', 'present');

        if (verifiedError) {
            console.error('Error fetching verified students:', verifiedError);
            return;
        }

        const verifiedIds = verified?.map(v => v.student_id) || [];
        const unverified = allStudents.filter(s => !verifiedIds.includes(s.id));

        if (unverified.length === 0) {
            console.log(`✅ All students verified for session ${sessionId}`);
            return;
        }

        console.log(`📝 Marking ${unverified.length} students as absent across all campuses`);

        // ✅ Mark unverified students as absent
        const absentInserts = [];
        const now = new Date().toISOString();

        for (const student of unverified) {
            // Check if already marked
            const { data: existing } = await supabase
                .from('bedcheck_attendance')
                .select('id')
                .eq('global_session_id', sessionId)
                .eq('student_id', student.id)
                .eq('campus', student.campus)
                .maybeSingle();

            if (existing) continue;

            absentInserts.push({
                global_session_id: sessionId,
                student_id: student.id,
                hostel_id: student.hostel_id,
                room_id: null,
                bed_space_id: null,
                status: 'absent',
                signed_at: now,
                verified_by: null,
                verification_method: 'auto',
                campus: student.campus,
                created_at: now
            });
        }

        if (absentInserts.length > 0) {
            const { error: insertError } = await supabase
                .from('bedcheck_attendance')
                .insert(absentInserts);

            if (insertError) {
                console.error('Error marking absent students:', insertError);
            } else {
                console.log(`✅ Marked ${absentInserts.length} students as absent`);
            }
        }

        // ✅ Update student statuses
        for (const student of unverified) {
            await supabase
                .from('students')
                .update({ 
                    status: 'Absent',
                    updated_at: now
                })
                .eq('id', student.id);

            // Create absent scan
            await supabase
                .from('bedcheck_scans')
                .insert({
                    session_id: sessionId,
                    student_id: student.id,
                    room: student.room_code || 'Unknown',
                    status: 'Absent',
                    scanner_id: 'System-Auto',
                    campus: student.campus,
                    created_at: now,
                    metadata: { method: 'auto-absent' }
                });
        }

        // ✅ Update session progress
        await updateSessionProgressUniversityWide(sessionId);

    } catch (error) {
        console.error('Error marking unverified as absent:', error);
    }
}

// =====================================================
// HELPER: Update Session Progress (University-Wide)
// =====================================================

async function updateSessionProgressUniversityWide(sessionId) {
    try {
        // ✅ Get all bedcheck sessions for this global session
        const { data: bedcheckSessions, error: bedcheckError } = await supabase
            .from('bedcheck_sessions')
            .select('status, campus')
            .eq('global_session_id', sessionId);

        if (bedcheckError) {
            console.error('Error fetching bedcheck sessions:', bedcheckError);
            return;
        }

        const total = bedcheckSessions?.length || 0;
        const completed = bedcheckSessions?.filter(b => b.status === 'completed').length || 0;
        const completion = total > 0 ? Math.round((completed / total) * 100) : 0;

        // ✅ Update session
        await supabase
            .from('sessions')
            .update({
                hostels_completed: completed,
                completion: completion,
                updated_at: new Date().toISOString()
            })
            .eq('id', sessionId);

        // ✅ Update hostel_progress for each campus
        const campuses = ['Legacy', 'Heritage'];
        for (const campus of campuses) {
            const campusBedchecks = bedcheckSessions?.filter(b => b.campus === campus) || [];
            const campusTotal = campusBedchecks.length;
            const campusCompleted = campusBedchecks.filter(b => b.status === 'completed').length;
            const campusCompletion = campusTotal > 0 ? Math.round((campusCompleted / campusTotal) * 100) : 0;

            // Get or create hostel_progress record for this campus
            const { data: existing } = await supabase
                .from('hostel_progress')
                .select('id')
                .eq('session_id', sessionId)
                .eq('campus', campus)
                .maybeSingle();

            if (existing) {
                await supabase
                    .from('hostel_progress')
                    .update({
                        total_students: 0,
                        verified_students: 0,
                        absent_students: 0,
                        completion: campusCompletion,
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', existing.id);
            } else {
                await supabase
                    .from('hostel_progress')
                    .insert({
                        session_id: sessionId,
                        hostel_id: null,  // Campus-level progress
                        total_students: 0,
                        verified_students: 0,
                        absent_students: 0,
                        completion: campusCompletion,
                        campus: campus,
                        created_at: new Date().toISOString(),
                        updated_at: new Date().toISOString()
                    });
            }
        }

        console.log(`✅ Updated session progress: ${completed}/${total} hostels completed (${completion}%)`);

    } catch (error) {
        console.error('Error updating session progress:', error);
    }
}

// =====================================================
// 🔥 ADVANCED FIREWALL SYSTEM
// =====================================================

class RateLimiterFirewall {
    constructor() {
        this.failedAttempts = new Map();
        this.blockedIPs = new Map();
        this.requestHistory = new Map();
        this.cleanupInterval = setInterval(() => this.cleanup(), 3600000);
    }

    cleanup() {
        const now = Date.now();
        for (const [key, data] of this.blockedIPs) {
            if (data.expiry < now) this.blockedIPs.delete(key);
        }
        for (const [key, data] of this.failedAttempts) {
            if (data.timestamp < now - 3600000) this.failedAttempts.delete(key);
        }
        for (const [key, data] of this.requestHistory) {
            if (data.timestamp < now - 60000) this.requestHistory.delete(key);
        }
    }

    isBlocked(ip) {
        if (this.blockedIPs.has(ip)) {
            const data = this.blockedIPs.get(ip);
            if (data.expiry > Date.now()) return true;
            this.blockedIPs.delete(ip);
        }
        return false;
    }

    recordFailedAttempt(ip) {
        const key = ip;
        if (!this.failedAttempts.has(key)) {
            this.failedAttempts.set(key, { count: 0, timestamp: Date.now() });
        }
        const data = this.failedAttempts.get(key);
        data.count += 1;
        data.timestamp = Date.now();

        const threshold = parseInt(process.env.SECURITY_ALERT_THRESHOLD) || 10;
        if (data.count >= threshold) {
            this.blockIP(ip, 30);
            return true;
        }
        return false;
    }

    blockIP(ip, minutes = 30) {
        this.blockedIPs.set(ip, {
            expiry: Date.now() + minutes * 60 * 1000,
            reason: 'Too many failed attempts'
        });
        console.log(`🛡️ IP ${ip} blocked for ${minutes} minutes`);
    }

    getThreatLevel(ip) {
        if (this.blockedIPs.has(ip)) return 'blocked';
        if (this.failedAttempts.has(ip)) {
            const data = this.failedAttempts.get(ip);
            if (data.count >= 5) return 'high';
            if (data.count >= 3) return 'medium';
        }
        return 'low';
    }

    throttleRequests() {
        return (req, res, next) => {
            const ip = req.ip || req.connection.remoteAddress;
            
            if (this.isBlocked(ip)) {
                return res.status(403).json({
                    success: false,
                    message: 'IP blocked due to suspicious activity. Please try again later.',
                    code: 'IP_BLOCKED'
                });
            }

            const key = `${ip}:${req.method}:${req.path}`;
            if (!this.requestHistory.has(key)) {
                this.requestHistory.set(key, { count: 0, timestamp: Date.now() });
            }
            const history = this.requestHistory.get(key);
            history.count += 1;
            history.timestamp = Date.now();

            const maxRequests = parseInt(process.env.MAX_CONNECTIONS_PER_MINUTE) || 200;
            if (history.count > maxRequests) {
                this.blockIP(ip, 15);
                return res.status(429).json({
                    success: false,
                    message: 'Request throttled due to suspicious activity.',
                    code: 'RATE_LIMIT_EXCEEDED'
                });
            }

            next();
        };
    }
}

class IPBlacklist {
    constructor() {
        this.blacklist = new Set();
        this.whitelist = new Set();
        this.manualBlacklist = new Set();
        this.loadBlacklist();
    }

    loadBlacklist() {
        const blacklistEnv = process.env.IP_BLACKLIST;
        if (blacklistEnv) {
            blacklistEnv.split(',').forEach(ip => {
                ip = ip.trim();
                if (ip) this.manualBlacklist.add(ip);
            });
        }

        const whitelistEnv = process.env.IP_WHITELIST;
        if (whitelistEnv) {
            whitelistEnv.split(',').forEach(ip => {
                ip = ip.trim();
                if (ip) this.whitelist.add(ip);
            });
        }
    }

    isBlacklisted(ip) {
        if (this.whitelist.has(ip)) return false;
        if (this.blacklist.has(ip) || this.manualBlacklist.has(ip)) return true;
        
        for (const blocked of this.blacklist) {
            if (blocked.includes('/')) {
                if (this.isIPInCIDR(ip, blocked)) return true;
            }
        }
        return false;
    }

    isIPInCIDR(ip, cidr) {
        const [range, bits] = cidr.split('/');
        const ipParts = ip.split('.').map(Number);
        const rangeParts = range.split('.').map(Number);
        const mask = ~(0xFFFFFFFF >>> parseInt(bits));
        const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
        const rangeInt = (rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3];
        return (ipInt & mask) === (rangeInt & mask);
    }

    addToBlacklist(ip, reason = 'Manual block') {
        this.manualBlacklist.add(ip);
        console.log(`🛡️ IP ${ip} added to blacklist: ${reason}`);
    }

    removeFromBlacklist(ip) {
        this.manualBlacklist.delete(ip);
        this.blacklist.delete(ip);
        console.log(`✅ IP ${ip} removed from blacklist`);
    }

    middleware() {
        return (req, res, next) => {
            const ip = req.ip || req.connection.remoteAddress;
            if (this.isBlacklisted(ip)) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied.',
                    code: 'IP_BLOCKED'
                });
            }
            next();
        };
    }
}

class RequestValidationFirewall {
    constructor() {
        this.maxBodySize = (parseInt(process.env.MAX_REQUEST_BODY_SIZE) || 5) * 1024 * 1024;
        this.allowedContentTypes = ['application/json', 'application/x-www-form-urlencoded'];
        this.blockedUserAgents = [
            /curl/i, /wget/i, /python-requests/i, /postman/i,
            /insomnia/i, /nmap/i, /nikto/i, /sqlmap/i,
            /dirbuster/i, /gobuster/i, /ffuf/i
        ];
    }

    validateSize() {
        return (req, res, next) => {
            const contentLength = parseInt(req.headers['content-length'] || '0');
            if (contentLength > this.maxBodySize) {
                return res.status(413).json({
                    success: false,
                    message: 'Request entity too large',
                    maxSize: this.maxBodySize,
                    code: 'PAYLOAD_TOO_LARGE'
                });
            }
            next();
        };
    }

    validateContentType() {
        return (req, res, next) => {
            const contentType = req.headers['content-type'] || '';
            if (req.method !== 'GET' && req.method !== 'DELETE') {
                const isValid = this.allowedContentTypes.some(type => 
                    contentType.toLowerCase().includes(type.toLowerCase())
                );
                if (!isValid && contentType) {
                    return res.status(415).json({
                        success: false,
                        message: 'Unsupported content type',
                        allowed: this.allowedContentTypes,
                        code: 'UNSUPPORTED_CONTENT_TYPE'
                    });
                }
            }
            next();
        };
    }

    validateUserAgent() {
        return (req, res, next) => {
            const userAgent = req.headers['user-agent'] || '';
            for (const pattern of this.blockedUserAgents) {
                if (pattern.test(userAgent)) {
                    console.log(`🛡️ Blocked suspicious user-agent: ${userAgent}`);
                    return res.status(403).json({
                        success: false,
                        message: 'Access denied.',
                        code: 'USER_AGENT_BLOCKED'
                    });
                }
            }
            next();
        };
    }

    sanitizeInput() {
        return (req, res, next) => {
            if (req.body && typeof req.body === 'object') {
                req.body = this.sanitizeObject(req.body);
            }
            if (req.query && typeof req.query === 'object') {
                req.query = this.sanitizeObject(req.query);
            }
            next();
        };
    }

    sanitizeObject(obj) {
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string') {
                sanitized[key] = this.sanitizeString(value);
            } else if (typeof value === 'object' && value !== null) {
                sanitized[key] = this.sanitizeObject(value);
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    }

    sanitizeString(str) {
        return str
            .replace(/[<>]/g, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+=/gi, '')
            .replace(/&/g, '&amp;')
            .trim()
            .slice(0, 1000);
    }

    protectSQLInjection() {
        return (req, res, next) => {
            const dangerousPatterns = [
                /DROP\s+TABLE/i,
                /DROP\s+DATABASE/i,
                /TRUNCATE\s+TABLE/i,
                /ALTER\s+TABLE/i
            ];
            
            const checkValue = (value) => {
                if (typeof value === 'string') {
                    for (const pattern of dangerousPatterns) {
                        if (pattern.test(value)) return true;
                    }
                }
                return false;
            };
            
            const checkObject = (obj) => {
                for (const [key, value] of Object.entries(obj)) {
                    if (typeof value === 'string' && checkValue(value)) return true;
                    if (typeof value === 'object' && value !== null) {
                        if (checkObject(value)) return true;
                    }
                }
                return false;
            };
            
            const inputs = [req.body, req.query, req.params];
            for (const input of inputs) {
                if (input && typeof input === 'object') {
                    if (checkObject(input)) {
                        return res.status(400).json({
                            success: false,
                            message: 'Invalid input detected',
                            code: 'SQL_INJECTION_BLOCKED'
                        });
                    }
                }
            }
            next();
        };
    }

    validateImage() {
        return (req, res, next) => {
            const image = req.body?.image || req.body?.photo;            
            if (image) {
                const validation = faceService.validateImage(image);
                if (!validation.valid) {
                    return res.status(400).json({
                        success: false,
                        message: validation.error,
                        code: 'INVALID_IMAGE'
                    });
                }
            }
            next();
        };
    }
}

class AuthenticationFirewall {
    constructor() {
        this.tokenBlacklist = new Set();
        this.failedAttempts = new Map();
        this.maxAttempts = parseInt(process.env.AUTH_RATE_LIMIT_MAX_ATTEMPTS) || 5;
        this.blockDuration = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000;
    }

    blacklistToken(token) {
        if (token) {
            this.tokenBlacklist.add(token);
            const cleanupMs = parseInt(process.env.TOKEN_BLACKLIST_CLEANUP_MS) || 86400000;
            setTimeout(() => this.tokenBlacklist.delete(token), cleanupMs);
        }
    }

    isTokenBlacklisted(token) {
        return this.tokenBlacklist.has(token);
    }

    recordFailedAttempt(identifier) {
        const key = identifier;
        if (!this.failedAttempts.has(key)) {
            this.failedAttempts.set(key, { attempts: 0, firstAttempt: Date.now() });
        }
        const data = this.failedAttempts.get(key);
        data.attempts += 1;

        if (data.attempts >= this.maxAttempts) {
            data.blockedUntil = Date.now() + this.blockDuration;
            return true;
        }
        return false;
    }

    isAuthenticationBlocked(identifier) {
        const key = identifier;
        if (this.failedAttempts.has(key)) {
            const data = this.failedAttempts.get(key);
            if (data.blockedUntil && data.blockedUntil > Date.now()) {
                return true;
            }
            if (data.blockedUntil && data.blockedUntil <= Date.now()) {
                this.failedAttempts.delete(key);
            }
        }
        return false;
    }

    resetFailedAttempts(identifier) {
        this.failedAttempts.delete(identifier);
    }

    checkAuthStatus() {
        return (req, res, next) => {
            const identifier = req.ip || req.connection.remoteAddress;
            
            if (this.isAuthenticationBlocked(identifier)) {
                return res.status(429).json({
                    success: false,
                    message: 'Too many failed login attempts. Please try again later.',
                    code: 'AUTH_BLOCKED'
                });
            }

            const token = req.headers.authorization?.split(' ')[1];
            if (token && this.isTokenBlacklisted(token)) {
                return res.status(401).json({
                    success: false,
                    message: 'Session expired. Please login again.',
                    code: 'TOKEN_BLACKLISTED'
                });
            }

            next();
        };
    }
}

class DoSProtection {
    constructor() {
        this.connectionLimit = parseInt(process.env.MAX_CONCURRENT_CONNECTIONS) || 100;
        this.activeConnections = new Map();
        this.connectionHistory = new Map();
    }

    protect() {
        return (req, res, next) => {
            const ip = req.ip || req.connection.remoteAddress;
            const now = Date.now();

            if (!this.activeConnections.has(ip)) {
                this.activeConnections.set(ip, 0);
            }
            this.activeConnections.set(ip, this.activeConnections.get(ip) + 1);

            if (this.activeConnections.get(ip) > this.connectionLimit) {
                this.activeConnections.set(ip, 0);
                return res.status(429).json({
                    success: false,
                    message: 'Too many concurrent connections',
                    code: 'CONCURRENT_LIMIT_EXCEEDED'
                });
            }

            if (!this.connectionHistory.has(ip)) {
                this.connectionHistory.set(ip, []);
            }
            const history = this.connectionHistory.get(ip);
            history.push(now);

            while (history.length > 0 && history[0] < now - 60000) {
                history.shift();
            }

            const maxConnections = parseInt(process.env.MAX_CONNECTIONS_PER_MINUTE) || 200;
            if (history.length > maxConnections) {
                this.activeConnections.set(ip, 0);
                return res.status(429).json({
                    success: false,
                    message: 'Connection rate limit exceeded',
                    code: 'RATE_LIMIT_EXCEEDED'
                });
            }

            res.on('finish', () => {
                if (this.activeConnections.has(ip)) {
                    this.activeConnections.set(ip, Math.max(0, this.activeConnections.get(ip) - 1));
                }
            });

            next();
        };
    }
}

// Initialize Firewalls
const rateLimiterFirewall = new RateLimiterFirewall();
const ipBlacklist = new IPBlacklist();
const validationFirewall = new RequestValidationFirewall();
const authFirewall = new AuthenticationFirewall();
const dosProtection = new DoSProtection();

// =====================================================
// APPLY FIREWALL MIDDLEWARE
// =====================================================

app.use(compression());
app.use(ipBlacklist.middleware());
app.use(dosProtection.protect());
app.use(validationFirewall.validateSize());
app.use(validationFirewall.validateContentType());
app.use(validationFirewall.validateUserAgent());
app.use(validationFirewall.protectSQLInjection());
app.use(validationFirewall.sanitizeInput());
app.use(validationFirewall.validateImage());
app.use(rateLimiterFirewall.throttleRequests());

console.log('✅ Firewall applied successfully');

// =====================================================
// SECURITY HEADERS
// =====================================================

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "blob:"],
            connectSrc: ["'self'", "https://*.supabase.co"],
            fontSrc: ["'self'", "https:", "data:"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'", "data:", "blob:"],
            frameSrc: ["'none'"],
            workerSrc: ["'self'", "blob:"],
            childSrc: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: "same-origin" },
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
    xssFilter: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' }
}));

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
    next();
});

// =====================================================
// CORS
// =====================================================

const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(o => o.length > 0)
    : [];

const defaultOrigins = [
    'https://bed-check-biu.vercel.app',
    'https://bed-check-biu-*.vercel.app'
];

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
                const pattern = allowed
                    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
                    .replace(/\\\*/g, '.*');
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

// Rate limiting
const globalLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: { success: false, message: 'Too many requests, please try again later.', code: 'GLOBAL_RATE_LIMIT' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) {
            return forwarded.split(',')[0].trim();  // Take first IP
        }
        return req.ip || req.connection.remoteAddress || 'unknown';
    },
    validate: { xForwardedForHeader: false },
    skip: (req) => {
        const forwarded = req.headers['x-forwarded-for'];
        let ip;
        if (forwarded) {
            ip = forwarded.split(',')[0].trim();
        } else {
            ip = req.ip || req.connection.remoteAddress;
        }
        return ipBlacklist.whitelist.has(ip);
    }
});

app.use('/api', globalLimiter);

const authLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: parseInt(process.env.AUTH_RATE_LIMIT_MAX_ATTEMPTS) || 5,
    message: { success: false, message: 'Too many login attempts. Please try again after 15 minutes.', code: 'AUTH_RATE_LIMIT' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => {
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) {
            return forwarded.split(',')[0].trim();
        }
        return req.ip || req.connection.remoteAddress || 'unknown';
    },
    validate: { xForwardedForHeader: false },
    skip: (req) => {
        const forwarded = req.headers['x-forwarded-for'];
        let ip;
        if (forwarded) {
            ip = forwarded.split(',')[0].trim();
        } else {
            ip = req.ip || req.connection.remoteAddress;
        }
        return ipBlacklist.whitelist.has(ip);
    }
});

const faceLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: parseInt(process.env.FACE_RATE_LIMIT_MAX_ATTEMPTS) || 10,
    message: { success: false, message: 'Too many verification attempts. Please wait.', code: 'FACE_RATE_LIMIT' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) {
            return forwarded.split(',')[0].trim();
        }
        return req.ip || req.connection.remoteAddress || 'unknown';
    },
    validate: { xForwardedForHeader: false },
    skip: (req) => {
        const forwarded = req.headers['x-forwarded-for'];
        let ip;
        if (forwarded) {
            ip = forwarded.split(',')[0].trim();
        } else {
            ip = req.ip || req.connection.remoteAddress;
        }
        return ipBlacklist.whitelist.has(ip);
    }
});

app.use(express.json({ 
    limit: `${parseInt(process.env.MAX_REQUEST_BODY_SIZE) || 5}mb`,
    verify: (req, res, buf) => {
        try {
            JSON.parse(buf);
        } catch (e) {
            res.status(400).json({ success: false, message: 'Invalid JSON payload', code: 'INVALID_JSON' });
            throw new Error('Invalid JSON');
        }
    }
}));
app.use(express.urlencoded({ extended: true, limit: `${parseInt(process.env.MAX_REQUEST_BODY_SIZE) || 5}mb` }));

// Request logging
app.use((req, res, next) => {
    const forwarded = req.headers['x-forwarded-for'];
    req.clientIp = forwarded ? forwarded.split(',')[0].trim() : req.ip || req.connection.remoteAddress || 'unknown';
    req.userAgent = req.headers['user-agent'] || 'unknown';
    
    authFirewall.checkAuthStatus()(req, res, (err) => {
        if (err) return next(err);
        
        if (process.env.NODE_ENV === 'development') {
            const sanitizedPath = req.path.replace(/\d+/g, '[id]');
            console.log(`📨 ${req.method} ${sanitizedPath} from ${req.clientIp}`);
        }
        next();
    });
});

// =====================================================
// ROLE MANAGEMENT & AUTHORIZATION
// =====================================================

// Role hierarchy and aliases
const roleMap = {
    'Administrator': ['Admin', 'Administrator', 'Administration'],
    'Admin': ['Admin', 'Administrator', 'Administration'],
    'Administration': ['Admin', 'Administrator', 'Administration'],
    'RASD': ['RASD'],
    'HRA': ['HRA'],
    'RA': ['RA'],
    'Developer': ['Developer']
};

// Role hierarchy levels (higher = more access)
const roleHierarchy = {
    'RA': 1,
    'HRA': 2,
    'RASD': 3,
    'Administrator': 4,
    'Admin': 4,
    'Administration': 4,
    'Developer': 5
};

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
            campus: user.campus,
            tokenVersion: Date.now()
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
    const publicPaths = ['/api/auth/login', '/api/face/health', '/health', '/', '/api/security/status'];
    if (publicPaths.includes(req.path)) {
        return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
            success: false, 
            message: 'Authentication required. Please provide a valid token.',
            code: 'AUTH_REQUIRED'
        });
    }

    const token = authHeader.split(' ')[1];
    
    if (authFirewall.isTokenBlacklisted(token)) {
        return res.status(401).json({ 
            success: false, 
            message: 'Session expired. Please login again.',
            code: 'TOKEN_BLACKLISTED'
        });
    }
    
    const decoded = verifyToken(token);
    
    if (!decoded) {
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid or expired token. Please login again.',
            code: 'TOKEN_INVALID'
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
            message: 'User account not found or inactive.',
            code: 'USER_INACTIVE'
        });
    }

    req.user = { ...decoded, ...user };
    req.campus = user.campus || process.env.DEFAULT_CAMPUS || 'Legacy';
    next();
};

// =====================================================
// AUTHORIZATION MIDDLEWARE - UPDATED WITH ROLE MAP & HIERARCHY
// =====================================================

const requireRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Authentication required', 
                code: 'AUTH_REQUIRED' 
            });
        }
        
        const userRole = req.user.role;
        const userLevel = roleHierarchy[userRole] || 0;
        
        // Check if user has the required role OR higher level access
        const isAuthorized = roles.some(requiredRole => {
            // 1. Check direct role match (with aliases)
            const allowedRoles = roleMap[requiredRole] || [requiredRole];
            if (allowedRoles.includes(userRole)) {
                return true;
            }
            
            // 2. Check hierarchy - users with higher level can access lower level endpoints
            const requiredLevel = roleHierarchy[requiredRole] || 0;
            
            // Developer has access to everything
            if (userRole === 'Developer') {
                return true;
            }
            
            // Admin/Administrator has access to Admin, RASD, HRA, RA
            if (['Administrator', 'Admin', 'Administration'].includes(userRole) && 
                ['RASD', 'HRA', 'RA'].includes(requiredRole)) {
                return true;
            }
            
            // RASD has access to HRA and RA
            if (userRole === 'RASD' && ['HRA', 'RA'].includes(requiredRole)) {
                return true;
            }
            
            // HRA has access to RA
            if (userRole === 'HRA' && requiredRole === 'RA') {
                return true;
            }
            
            // Check by level (if both have levels defined)
            if (requiredLevel > 0 && userLevel >= requiredLevel) {
                return true;
            }
            
            return false;
        });
        
        if (!isAuthorized) {
            // Log the unauthorized access attempt
            auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Unauthorized Access Attempt',
                module: 'security',
                details: `User ${req.user.username} (${req.user.role}) attempted to access ${req.method} ${req.path}`,
                context: `Required roles: ${roles.join(', ')}`,
                result: 'failed',
                category: 'security',
                tone: 'red',
                campus: req.campus || 'Legacy',
                ip_address: req.clientIp || req.ip,
                user_agent: req.userAgent || req.headers['user-agent']
            }).catch(() => {});
            
            return res.status(403).json({ 
                success: false, 
                message: `Access denied. Required role: ${roles.join(' or ')}`,
                code: 'ROLE_REQUIRED',
                user_role: userRole,
                required_roles: roles
            });
        }
        next();
    };
};

// =====================================================
// CAMPUS ISOLATION MIDDLEWARE - UPDATED
// Admins, Developers, and Administrators can see ALL campuses
// =====================================================

const campusIsolation = (req, res, next) => {
    // Admin, Developer, and Administration can see ALL campuses
    const adminRoles = ['Admin', 'Developer', 'Administrator', 'Administration'];
    
    if (adminRoles.includes(req.user?.role)) {
        // Admins get the campus from header or default, but can see all
        req.campus = req.headers['x-campus'] || req.user?.campus || process.env.DEFAULT_CAMPUS || 'Legacy';
        req.viewAllCampuses = true;  // Flag to bypass campus filters
        return next();
    }
    
    // For non-admin users, enforce campus isolation
    const campus = req.headers['x-campus'] || req.user?.campus || process.env.DEFAULT_CAMPUS || 'Legacy';
    
    if (!campus || !SUPPORTED_CAMPUSES.includes(campus)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid campus context',
            code: 'INVALID_CAMPUS'
        });
    }
    
    req.campus = campus;
    req.viewAllCampuses = false;
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
            code: 'VALIDATION_ERROR',
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
        body('name').trim().notEmpty().withMessage('Name is required')
            .isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters'),
        body('username').trim().notEmpty().withMessage('Username is required')
            .isLength({ min: 3, max: 50 }).withMessage('Username must be between 3 and 50 characters')
            .matches(/^[a-zA-Z0-9._-]+$/).withMessage('Username can only contain letters, numbers, dots, underscores, and hyphens'),
        body('role').isIn(['RA', 'HRA', 'Admin', 'Administrator', 'RASD', 'Developer']).withMessage('Invalid role'),
        body('email').optional().isEmail().withMessage('Invalid email address')
            .normalizeEmail(),
        body('phone').optional().isString().withMessage('Invalid phone number'),
        body('campus').optional().isIn(['Legacy', 'Heritage']).withMessage('Invalid campus'),
        body('hostel_id').optional().custom((value) => {
            if (value === null || value === undefined || value === '') return true;
            const id = parseInt(value);
            return !isNaN(id) && id > 0;
        }).withMessage('Invalid hostel ID'),
        body('assigned_floor').optional().isString().withMessage('Invalid floor'),
        body('assigned_room').optional().isString().withMessage('Invalid room'),
        body('department').optional().isString().withMessage('Invalid department')
    ],
    updateStaff: [
        body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
        body('username').optional().trim().notEmpty().withMessage('Username cannot be empty')
            .isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
        body('role').optional().isIn(['RA', 'HRA', 'Admin', 'Administrator', 'RASD', 'Developer']).withMessage('Invalid role'),
        body('email').optional().isEmail().withMessage('Invalid email address'),
        body('campus').optional().isIn(['Legacy', 'Heritage']).withMessage('Invalid campus'),
        body('status').optional().isIn(['Active', 'Suspended', 'Inactive', 'Offline']).withMessage('Invalid status'),
        body('hostel_id').optional().custom((value) => {
            if (value === null || value === undefined || value === '') return true;
            return !isNaN(parseInt(value));
        }).withMessage('Invalid hostel ID'),
        body('assigned_floor').optional().isString().withMessage('Invalid floor'),
        body('assigned_room').optional().isString().withMessage('Invalid room'),
        body('phone').optional().isString().withMessage('Invalid phone'),
        body('department').optional().isString().withMessage('Invalid department')
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
        body('campus').optional().isIn(SUPPORTED_CAMPUSES).withMessage('Invalid campus')
    ],
    updateStudent: [
        body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
        body('matric').optional().trim().notEmpty().withMessage('Matric number cannot be empty'),
        body('gender').optional().isIn(['Male', 'Female']).withMessage('Invalid gender'),
        body('phone').optional().isMobilePhone().withMessage('Invalid phone number'),
        body('email').optional().isEmail().withMessage('Invalid email address'),
        body('status').optional().isIn(['Present', 'Absent', 'Verified']).withMessage('Invalid status'),
        body('campus').optional().isIn(SUPPORTED_CAMPUSES).withMessage('Invalid campus')
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
    hostelId: [param('id').isInt().withMessage('Invalid hostel ID')],
    studentId: [param('id').isInt().withMessage('Invalid student ID')],
    staffId: [param('id').isInt().withMessage('Invalid staff ID')],
    floorFlatId: [param('id').isInt().withMessage('Invalid floor/flat ID')],
    roomId: [param('id').isInt().withMessage('Invalid room ID')],
    bedSpaceId: [param('id').isInt().withMessage('Invalid bed space ID')],
    sessionId: [param('id').isInt().withMessage('Invalid session ID')],
    pagination: [
        query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
        query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be 0 or greater')
    ],
    hostelCreate: [
        body('name').trim().notEmpty().withMessage('Hostel name is required'),
        body('gender').optional().isIn(['Male', 'Female', 'Mixed']).withMessage('Invalid gender'),
        body('type').optional().isIn(['floor', 'flat']).withMessage('Invalid type'),
        body('campus').optional().isIn(SUPPORTED_CAMPUSES).withMessage('Invalid campus')
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
        body('name').optional().isString().withMessage('Session name must be a string'),
        body('date').optional().isISO8601().withMessage('Invalid date format'),
        body('start_time').optional().isString().withMessage('Start time must be a string'),
        body('end_time').optional().isString().withMessage('End time must be a string'),
        body('status').optional().isIn(['scheduled', 'active', 'completed', 'archived']).withMessage('Invalid status'),
        body('total_hostels').optional().isInt({ min: 1 }).withMessage('Total hostels must be at least 1'),
        body('hostels_completed').optional().isInt({ min: 0 }).withMessage('Hostels completed must be 0 or greater'),
        body('completion').optional().isInt({ min: 0, max: 100 }).withMessage('Completion must be between 0 and 100'),
        body('academic_session').optional().isString().withMessage('Academic session must be a string'),
        body('grace_period').optional().isInt({ min: 0, max: 60 }).withMessage('Grace period must be between 0 and 60'),
        body('campus').optional().isIn(SUPPORTED_CAMPUSES).withMessage('Invalid campus')
    ],
    submissionState: [
        body('state').isIn(['Open', 'Closed']).withMessage('Invalid state'),
        body('notice').optional().isString().withMessage('Invalid notice')
    ],
    campus: [query('campus').optional().isIn(SUPPORTED_CAMPUSES).withMessage('Invalid campus')],
    raRoomAssignment: [
        body('ra_id').isInt().withMessage('Invalid RA ID'),
        body('room_ids').isArray({ min: 1 }).withMessage('At least one room is required')
    ],
    bedcheckStart: [body('session_id').isInt().withMessage('session_id is required')],
    suspiciousResolve: [
        body('resolution').isIn(['cleared', 'warning', 'escalated']).withMessage('Invalid resolution status'),
        body('notes').optional().isString().withMessage('notes must be a string')
    ],
    attendanceVerify: [
        body('student_id').isInt().withMessage('Student ID is required'),
        body('image').notEmpty().withMessage('Face image is required'),
        body('session_id').optional().isInt().withMessage('Invalid session ID')
    ],
    // =============================================
    // DEVELOPER VALIDATORS
    // =============================================
    executeQuery: [
        body('query').isString().notEmpty().withMessage('Query is required'),
        body('params').optional().isObject().withMessage('Params must be an object')
    ],
    developerAction: [
        body('action').isString().notEmpty().withMessage('Action is required'),
        body('target').optional().isString().withMessage('Target must be a string'),
        body('data').optional().isObject().withMessage('Data must be an object')
    ],
    developerSettings: [
        body('value').notEmpty().withMessage('Value is required'),
        body('category').optional().isString().withMessage('Category must be a string'),
        body('description').optional().isString().withMessage('Description must be a string')
    ],
    developerRoleChange: [
        body('role').isIn(['RA', 'HRA', 'Admin', 'Administrator', 'RASD', 'Developer']).withMessage('Invalid role'),
        body('reason').optional().isString().withMessage('Reason must be a string')
    ],
    developerMaintenance: [
        body('enabled').isBoolean().withMessage('Enabled must be a boolean'),
        body('message').optional().isString().withMessage('Message must be a string')
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
    },

    async attendanceVerified(student, session, scan, req) {
        return auditService.log({
            actor: req.user.name || req.user.username,
            actor_id: req.user.id,
            actor_role: req.user.role,
            action: 'Face Verification',
            module: 'attendance',
            details: `${student.name} (${student.matric}) verified via face recognition`,
            context: `Session: ${session.name}, Confidence: ${scan.metadata?.confidence || 'N/A'}%`,
            result: 'success',
            category: 'attendance',
            tone: 'green',
            hostel_id: student.hostel_id,
            room_id: student.room_id,
            student_id: student.id,
            session_id: session.id,
            campus: req.campus,
            ip_address: req.clientIp,
            user_agent: req.userAgent
        });
    }
};

// =====================================================
// 🔓 PUBLIC ENDPOINTS - FIXED
// =====================================================

app.get('/health', async (req, res) => {
    try {
        const { data: dbCheck, error: dbError } = await supabase
            .from('hostels')
            .select('id')
            .limit(1)
            .maybeSingle();
        
        let faceApiHealth = { status: 'unknown' };
        try {
            const response = await axios.get(`${FACE_API_URL}/health`, {
                timeout: 3000,
                headers: { 'X-Internal-Key': process.env.INTERNAL_API_KEY || 'secure-key' }
            });
            if (response.status === 200) {
                faceApiHealth = response.data;
            } else {
                faceApiHealth = { status: 'unhealthy' };
            }
        } catch (error) {
            console.error('Face API health check error:', error.message);
            faceApiHealth = { status: 'unhealthy', error: error.message };
        }
        
        const isHealthy = !dbError && faceApiHealth.status !== 'unhealthy';
        
        res.status(isHealthy ? 200 : 503).json({
            status: isHealthy ? 'healthy' : 'degraded',
            uptime: process.uptime(),
            timestamp: new Date().toISOString(),
            services: {
                database: dbError ? 'unhealthy' : 'healthy',
                face_api: faceApiHealth.status || 'healthy'
            },
            environment: process.env.NODE_ENV || 'production',
            circuit_breaker: faceService.circuitOpen ? 'open' : 'closed'
        });
    } catch (error) {
        console.error('Health check error:', error);
        res.status(503).json({
            status: 'unhealthy',
            error: 'Health check failed',
            timestamp: new Date().toISOString()
        });
    }
});

app.get('/', (req, res) => {
    res.json({
        name: 'BIU BedCheck API',
        version: '4.7.0',
        status: 'running',
        environment: process.env.NODE_ENV || 'production',
        security: {
            firewall: 'active',
            rate_limiting: 'active',
            dos_protection: 'active',
            ip_blacklist: 'active',
            authentication_firewall: 'active',
            circuit_breaker: faceService.circuitOpen ? 'open' : 'closed'
        }
    });
});

app.get('/api/security/status', (req, res) => {
    res.json({
        success: true,
        data: {
            firewall: 'active',
            rate_limiting: 'active',
            dos_protection: 'active',
            ip_blacklist: 'active',
            authentication_firewall: 'active',
            circuit_breaker: faceService.circuitOpen ? 'open' : 'closed',
            face_api_failures: faceService.failureCount,
            max_failures: faceService.maxFailures
        }
    });
});

// =============================================
// PUBLIC STUDENT SEARCH - NO AUTH REQUIRED
// =============================================

app.get('/api/public/students/search', async (req, res) => {
    try {
        const { query } = req.query;
        
        if (!query || query.length < 1) {
            return res.json({ 
                success: true, 
                data: [],
                message: 'Please enter at least 1 character'
            });
        }

        const cleanQuery = query.trim();
        const searchTerm = `%${cleanQuery}%`;
        const lowerQuery = cleanQuery.toLowerCase();

        console.log('🔍 Searching for:', cleanQuery);

        let { data, error } = await supabase
            .from('students')
            .select(`
                id, 
                name, 
                matric, 
                faculty, 
                department, 
                level, 
                session, 
                hostel_id, 
                hostel_name, 
                room_id, 
                room_code, 
                bed_space_id, 
                bed_code, 
                phone, 
                gender, 
                email, 
                emergency_name, 
                emergency_relation, 
                emergency_phone, 
                status, 
                face_enrolled, 
                campus,
                registration_date
            `)
            .or(`name.ilike.${searchTerm},matric.ilike.${searchTerm}`)
            .in('status', ['Active', 'Present'])
            .order('name', { ascending: true })
            .limit(20);

        if (error) {
            console.error('Search DB error:', error);
            return res.status(500).json({
                success: false,
                message: 'Database error: ' + error.message,
                code: 'DB_ERROR'
            });
        }

        let results = data || [];

        if (results.length === 0) {
            console.log('🔄 No ILIKE results, trying flexible search...');
            
            const { data: allStudents, error: allError } = await supabase
                .from('students')
                .select(`
                    id, 
                    name, 
                    matric, 
                    faculty, 
                    department, 
                    level, 
                    session, 
                    hostel_id, 
                    hostel_name, 
                    room_id, 
                    room_code, 
                    bed_space_id, 
                    bed_code, 
                    phone, 
                    gender, 
                    email, 
                    emergency_name, 
                    emergency_relation, 
                    emergency_phone, 
                    status, 
                    face_enrolled, 
                    campus,
                    registration_date
                `)
                .in('status', ['Active', 'Present'])
                .limit(100);

            if (!allError && allStudents) {
                const queryWords = cleanQuery.toLowerCase().split(/\s+/).filter(w => w.length >= 1);
                
                results = allStudents.filter(s => {
                    const name = (s.name || '').toLowerCase();
                    const matric = (s.matric || '').toLowerCase();
                    
                    return queryWords.some(word => {
                        if (name.includes(word)) return true;
                        if (matric.includes(word)) return true;
                        if (name.split(' ').some(part => part.startsWith(word))) return true;
                        const initials = name.split(' ').map(p => p[0]).join('');
                        if (initials.includes(word)) return true;
                        return false;
                    });
                });
                
                console.log(`🔍 Flexible search found ${results.length} results`);
            }
        }

        results.sort((a, b) => {
            const aName = (a.name || '').toLowerCase();
            const bName = (b.name || '').toLowerCase();
            const aMatric = (a.matric || '').toLowerCase();
            const bMatric = (b.matric || '').toLowerCase();
            const lq = lowerQuery;
            
            const aExact = aName === lq;
            const bExact = bName === lq;
            if (aExact && !bExact) return -1;
            if (!aExact && bExact) return 1;
            
            const aStarts = aName.startsWith(lq);
            const bStarts = bName.startsWith(lq);
            if (aStarts && !bStarts) return -1;
            if (!aStarts && bStarts) return 1;
            
            const aMatricMatch = aMatric.includes(lq);
            const bMatricMatch = bMatric.includes(lq);
            if (aMatricMatch && !bMatricMatch) return -1;
            if (!aMatricMatch && bMatricMatch) return 1;
            
            const aContains = aName.includes(lq);
            const bContains = bName.includes(lq);
            if (aContains && !bContains) return -1;
            if (!aContains && bContains) return 1;
            
            return aName.localeCompare(bName);
        });

        console.log(`✅ Search results: ${results.length} students found for "${cleanQuery}"`);

        res.json({
            success: true,
            data: results.slice(0, 10),
            count: results.length,
            query: cleanQuery
        });

    } catch (error) {
        console.error('❌ Public search error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR',
            error: error.message
        });
    }
});

// =============================================
// PUBLIC REGISTRATION ENDPOINTS - NO AUTH REQUIRED
// FIXED: Case-insensitive status matching
// =============================================

// Public - Get all hostels (filtered by campus) - FIXED
app.get('/api/public/hostels', async (req, res) => {
    try {
        const { campus } = req.query;
        
        let query = supabase
            .from('hostels')
            .select('*')
            .order('name', { ascending: true });
        
        if (campus) {
            query = query.eq('campus', campus);
        }
        
        const { data, error } = await query;
        
        if (error) {
            console.error('Public hostels error:', error);
            return res.status(500).json({
                success: false,
                message: 'Database error',
                code: 'DB_ERROR'
            });
        }
        
        const activeHostels = (data || []).filter(h => 
            h.status && h.status.toLowerCase() === 'active'
        );
        
        res.json({
            success: true,
            data: activeHostels,
            count: activeHostels.length
        });
    } catch (error) {
        console.error('Public hostels error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
        });
    }
});

// Public - Get all floors/flats for a hostel - FIXED
app.get('/api/public/floors-flats', async (req, res) => {
    try {
        const { hostel_id } = req.query;
        
        if (!hostel_id) {
            return res.json({
                success: true,
                data: [],
                message: 'hostel_id is required'
            });
        }
        
        const { data, error } = await supabase
            .from('floors_flats')
            .select('*')
            .eq('hostel_id', parseInt(hostel_id))
            .order('name', { ascending: true });
        
        if (error) {
            console.error('Public floors error:', error);
            return res.status(500).json({
                success: false,
                message: 'Database error',
                code: 'DB_ERROR'
            });
        }
        
        const activeFloors = (data || []).filter(f => 
            f.status && f.status.toLowerCase() === 'active'
        );
        
        res.json({
            success: true,
            data: activeFloors,
            count: activeFloors.length
        });
    } catch (error) {
        console.error('Public floors error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
        });
    }
});

// Public - Get all rooms for a floor/flat - FIXED
app.get('/api/public/rooms', async (req, res) => {
    try {
        const { floor_flat_id } = req.query;
        
        if (!floor_flat_id) {
            return res.json({
                success: true,
                data: [],
                message: 'floor_flat_id is required'
            });
        }
        
        const { data, error } = await supabase
            .from('rooms')
            .select('*')
            .eq('floor_flat_id', parseInt(floor_flat_id))
            .order('room_code', { ascending: true });
        
        if (error) {
            console.error('Public rooms error:', error);
            return res.status(500).json({
                success: false,
                message: 'Database error',
                code: 'DB_ERROR'
            });
        }
        
        const activeRooms = (data || []).filter(r => 
            r.status && (r.status.toLowerCase() === 'active' || r.status.toLowerCase() === 'available')
        );
        
        res.json({
            success: true,
            data: activeRooms,
            count: activeRooms.length
        });
    } catch (error) {
        console.error('Public rooms error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
        });
    }
});

// Public - Get all bed spaces for a room - FIXED
app.get('/api/public/bed-spaces', async (req, res) => {
    try {
        const { room_id } = req.query;
        
        if (!room_id) {
            return res.json({
                success: true,
                data: [],
                message: 'room_id is required'
            });
        }
        
        const { data, error } = await supabase
            .from('bed_spaces')
            .select('*')
            .eq('room_id', parseInt(room_id))
            .order('bed_code', { ascending: true });
        
        if (error) {
            console.error('Public bed spaces error:', error);
            return res.status(500).json({
                success: false,
                message: 'Database error',
                code: 'DB_ERROR'
            });
        }
        
        const availableBeds = (data || []).filter(b => 
            b.status && (b.status.toLowerCase() === 'available')
        );
        
        res.json({
            success: true,
            data: availableBeds,
            count: availableBeds.length
        });
    } catch (error) {
        console.error('Public bed spaces error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
        });
    }
});

// Public - Check if student exists (by matric)
app.get('/api/public/students/check', async (req, res) => {
    try {
        const { matric } = req.query;
        
        if (!matric) {
            return res.json({
                success: true,
                exists: false,
                message: 'matric is required'
            });
        }
        
        const { data, error } = await supabase
            .from('students')
            .select('id, name, matric, status, face_enrolled')
            .eq('matric', matric.toUpperCase())
            .maybeSingle();
        
        if (error) {
            console.error('Public student check error:', error);
            return res.status(500).json({
                success: false,
                message: 'Database error',
                code: 'DB_ERROR'
            });
        }
        
        res.json({
            success: true,
            exists: !!data,
            data: data || null
        });
    } catch (error) {
        console.error('Public student check error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
        });
    }
});

// Public - Create/Update student (registration)
app.post('/api/public/students/register', async (req, res) => {
    try {
        const studentData = req.body;
        
        const required = ['name', 'matric', 'gender', 'phone', 'faculty', 'department', 'level', 'session', 'campus'];
        for (const field of required) {
            if (!studentData[field]) {
                return res.status(400).json({
                    success: false,
                    message: `Missing required field: ${field}`,
                    code: 'MISSING_FIELD'
                });
            }
        }
        
        const { data: existing, error: checkError } = await supabase
            .from('students')
            .select('id')
            .eq('matric', studentData.matric.toUpperCase())
            .maybeSingle();
        
        if (checkError) {
            console.error('Check existing error:', checkError);
            return res.status(500).json({
                success: false,
                message: 'Database error',
                code: 'DB_ERROR'
            });
        }
        
        let result;
        let isUpdate = false;
        
        if (existing) {
            isUpdate = true;
            const { data, error } = await supabase
                .from('students')
                .update({
                    ...studentData,
                    updated_at: new Date().toISOString()
                })
                .eq('id', existing.id)
                .select()
                .single();
            
            if (error) {
                console.error('Update student error:', error);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to update student',
                    code: 'UPDATE_ERROR'
                });
            }
            result = data;
        } else {
            const { data, error } = await supabase
                .from('students')
                .insert({
                    ...studentData,
                    status: 'Present',
                    face_enrolled: false,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                })
                .select()
                .single();
            
            if (error) {
                console.error('Create student error:', error);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to create student',
                    code: 'CREATE_ERROR'
                });
            }
            result = data;
        }
        
        if (studentData.bed_space_id) {
            await supabase
                .from('bed_spaces')
                .update({
                    status: 'occupied',
                    student_id: result.id,
                    updated_at: new Date().toISOString()
                })
                .eq('id', parseInt(studentData.bed_space_id));
        }
        
        res.json({
            success: true,
            data: result,
            is_update: isUpdate,
            message: isUpdate ? 'Student updated successfully' : 'Student registered successfully'
        });
        
    } catch (error) {
        console.error('Public registration error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
        });
    }
});

// =============================================
// ✅ PUBLIC FACE ENROLLMENT - NO AUTH REQUIRED
// =============================================

app.post('/api/public/students/:id/face/enroll', async (req, res) => {
    try {
        const studentId = parseInt(req.params.id, 10);
        const { image } = req.body;

        if (!studentId || Number.isNaN(studentId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid student ID',
                code: 'INVALID_STUDENT_ID'
            });
        }

        let imageData = image;
        if (!imageData || typeof imageData !== 'string') {
            return res.status(400).json({
                success: false,
                message: 'No image provided',
                code: 'INVALID_IMAGE'
            });
        }
        if (!imageData.startsWith('data:image')) {
            imageData = `data:image/jpeg;base64,${imageData}`;
        }

        const validation = faceService.validateImage(imageData);
        if (!validation.valid) {
            return res.status(400).json({
                success: false,
                message: validation.error,
                code: 'INVALID_IMAGE'
            });
        }

        const { data: student, error: studentError } = await supabase
            .from('students')
            .select('id, name, matric, hostel_id, room_id, campus')
            .eq('id', studentId)
            .maybeSingle();

        if (studentError || !student) {
            return res.status(404).json({
                success: false,
                message: 'Student not found',
                code: 'STUDENT_NOT_FOUND'
            });
        }

        const embeddingResult = await faceService.extractEmbedding(imageData);
        if (!embeddingResult.success || !embeddingResult.embedding) {
            return res.status(400).json({
                success: false,
                message: embeddingResult.error ||
                    'Failed to generate face embedding. No face detected or image quality too low.',
                code: 'EMBEDDING_GENERATION_FAILED',
                fallback: 'Manual verification required'
            });
        }
        if (!Array.isArray(embeddingResult.embedding) || embeddingResult.embedding.length !== 512) {
            return res.status(400).json({
                success: false,
                message: `Invalid embedding. Expected 512 dimensions, got ${embeddingResult.embedding?.length || 0}`,
                code: 'INVALID_EMBEDDING'
            });
        }

        const now = new Date().toISOString();
        const campus = student.campus || 'Legacy';
        const campusCode = campus === 'Legacy' ? 'LEG' : 'HER';

        const facePayload = {
            student_id: student.id,
            campus,
            campus_code: campusCode,
            face_embedding: embeddingResult.embedding,
            face_image_url: null,
            face_image_path: null,
            enrollment_status: 'enrolled',
            enrollment_date: now,
            last_verified: null,
            verification_count: 0,
            confidence_score: embeddingResult.confidence ?? 0.95,
            is_active: true,
            notes: null,
            updated_at: now,
            enrolled_by: null,
            enrolled_by_student: true,
            enrollment_ip: req.ip || req.headers['x-forwarded-for'] || null,
            enrollment_device: (req.headers['user-agent'] || '').slice(0, 500)
        };

        const { data: existingFace } = await supabase
            .from('student_face')
            .select('id')
            .eq('student_id', student.id)
            .eq('campus', campus)
            .maybeSingle();

        let faceData, faceError;
        if (existingFace?.id) {
            const result = await supabase
                .from('student_face')
                .update(facePayload)
                .eq('id', existingFace.id)
                .select('id, enrollment_status, enrollment_date, confidence_score')
                .single();
            faceData = result.data;
            faceError = result.error;
        } else {
            facePayload.created_at = now;
            const result = await supabase
                .from('student_face')
                .insert(facePayload)
                .select('id, enrollment_status, enrollment_date, confidence_score')
                .single();
            faceData = result.data;
            faceError = result.error;
        }

        if (faceError) {
            console.error('Save face error:', faceError);
            return res.status(500).json({
                success: false,
                message: 'Failed to save face data to database',
                code: 'DATABASE_ERROR',
                error: faceError.message,
                details: faceError.details,
                hint: faceError.hint
            });
        }

        await supabase
            .from('students')
            .update({ face_enrolled: true, updated_at: now })
            .eq('id', student.id);

        return res.json({
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
                    confidence: faceData.confidence_score
                },
                message: 'Face enrolled successfully'
            },
            campus
        });
    } catch (error) {
        console.error('Public face enrollment error:', error);
        return res.status(500).json({
            success: false,
            message: 'An error occurred during face enrollment.',
            code: 'SERVER_ERROR'
        });
    }
});

// =====================================================
// AUTHENTICATION ENDPOINTS
// =====================================================

app.post('/api/auth/login', authLimiter, validate(validators.login), async (req, res) => {
    const { username, password } = req.body;
    const identifier = req.ip || req.connection.remoteAddress;
    
    try {
        if (authFirewall.isAuthenticationBlocked(identifier)) {
            return res.status(429).json({
                success: false,
                message: 'Too many login attempts. Please try again later.',
                code: 'AUTH_BLOCKED'
            });
        }

        const { data, error } = await supabase
            .from('staff')
            .select(`
                id, 
                username, 
                role, 
                name, 
                initials, 
                scope, 
                hostel_id,
                assigned_floor, 
                assigned_room, 
                is_admin, 
                email, 
                phone, 
                department, 
                staff_id, 
                joined, 
                status, 
                password, 
                campus, 
                campus_code,
                hostels!hostel_id (
                    id,
                    name,
                    type
                )
            `)
            .eq('username', username)
            .maybeSingle();
        
        if (error) {
            console.error('Login error:', error);
            authFirewall.recordFailedAttempt(identifier);
            await auditEvents.loginFailed(username, req);
            return res.status(500).json({ 
                success: false, 
                message: 'An error occurred during login. Please try again.',
                code: 'LOGIN_ERROR'
            });
        }
        
        if (!data) {
            authFirewall.recordFailedAttempt(identifier);
            await auditEvents.loginFailed(username, req);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password',
                code: 'INVALID_CREDENTIALS'
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
            authFirewall.recordFailedAttempt(identifier);
            await auditEvents.loginFailed(username, req);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password',
                code: 'INVALID_CREDENTIALS'
            });
        }

        if (user.status !== 'Active') {
            authFirewall.recordFailedAttempt(identifier);
            await auditEvents.loginFailed(username, req);
            return res.status(401).json({ 
                success: false, 
                message: 'Account is inactive. Please contact administrator.',
                code: 'ACCOUNT_INACTIVE'
            });
        }

        authFirewall.resetFailedAttempts(identifier);

        req.campus = user.campus || process.env.DEFAULT_CAMPUS || 'Legacy';

        await supabase
            .from('staff')
            .update({ last_login: new Date().toISOString() })
            .eq('id', user.id);

        const token = generateToken(user);

        await auditEvents.loginSuccess(user, req);

        const { password: _, ...userWithoutPassword } = user;

        const formattedUser = {
            ...userWithoutPassword,
            hostel: user.hostels?.name || null,
            hostel_name: user.hostels?.name || null,
            hostel_type: user.hostels?.type || null,
            assigned_floor: user.assigned_floor,
            assigned_room: user.assigned_room,
            hostels: undefined
        };

        const redirectUrl = DASHBOARD_ROUTES[user.role] || '/index.html';

        res.json({ 
            success: true, 
            data: {
                user: formattedUser,
                token: token,
                expiresIn: process.env.JWT_EXPIRY || '8h',
                campus: user.campus || process.env.DEFAULT_CAMPUS || 'Legacy',
                redirect: redirectUrl
            },
            role: user.role
        });
    } catch (error) {
        console.error('Login error:', error);
        authFirewall.recordFailedAttempt(identifier);
        res.status(500).json({ 
            success: false, 
            message: 'An unexpected error occurred. Please try again.',
            code: 'SERVER_ERROR'
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
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
        authFirewall.blacklistToken(token);
    }

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
                message: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }
        
        res.json({ success: true, data: data });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
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

            if (req.user.id !== staffId && req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator') {
                return res.status(403).json({
                    success: false,
                    message: 'You can only change your own password',
                    code: 'PERMISSION_DENIED'
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
                    message: 'Staff not found',
                    code: 'STAFF_NOT_FOUND'
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
                    message: 'Current password is incorrect',
                    code: 'INCORRECT_PASSWORD'
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

            const token = req.headers.authorization?.split(' ')[1];
            if (token) {
                authFirewall.blacklistToken(token);
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
                message: 'Password changed successfully. Please login again.'
            });

        } catch (error) {
            console.error('Change password error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            campus: req.campus || process.env.DEFAULT_CAMPUS || 'Legacy',
            user_campus: req.user?.campus || process.env.DEFAULT_CAMPUS || 'Legacy',
            supported_campuses: SUPPORTED_CAMPUSES
        }
    });
});

app.post('/api/campus/switch', requireRole('Admin', 'Developer'), validate([
    body('campus').isIn(SUPPORTED_CAMPUSES).withMessage('Invalid campus')
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
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
        });
    }
});

app.get('/api/campus/stats', requireRole('Admin', 'HRA', 'Developer'), async (req, res) => {
    try {
        const campus = req.query.campus || req.campus || process.env.DEFAULT_CAMPUS || 'Legacy';
        
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
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
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
            api_url: FACE_API_URL,
            circuit_breaker: faceService.circuitOpen ? 'open' : 'closed'
        });
    } catch (error) {
        console.error('Face API health check error:', error);
        res.status(500).json({
            success: false,
            message: 'Face API is unreachable',
            error: error.message,
            code: 'FACE_API_ERROR'
        });
    }
});

app.post('/api/face/detect', 
    campusIsolation,
    faceLimiter,
    validate(validators.faceImage),
    async (req, res) => {
        try {
            if (!req.body || !req.body.image) {
                return res.status(400).json({ success: false, message: 'Image is required', code: 'MISSING_IMAGE' });
            }
            const { image, student_id } = req.body;
            
            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }
            
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
                res.status(400).json({ 
                    ...result, 
                    code: 'FACE_DETECTION_FAILED',
                    fallback: 'Manual verification required'
                });
            }
        } catch (error) {
            console.error('Face detection error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// FACE RECOGNITION ENDPOINTS - COMPLETE FIX
// =====================================================

/**
 * ENROLL FACE - Single Image
 * Generates embedding and stores it in the database
 */
app.post('/api/face/enroll', 
    campusIsolation,
    faceLimiter,
    validate([...validators.faceImage, ...validators.faceVerify]),
    async (req, res) => {
        try {
            const { image, student_id, matric } = req.body;

            // 1. VALIDATE IMAGE
            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }

            // 2. FIND STUDENT
            if (!student_id && !matric) {
                return res.status(400).json({
                    success: false,
                    message: 'student_id or matric is required',
                    code: 'MISSING_IDENTIFIER'
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
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            // 3. CHECK PERMISSIONS
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && 
                req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only enroll students in your hostel.',
                    code: 'PERMISSION_DENIED'
                });
            }

            // 4. GENERATE EMBEDDING (CRITICAL STEP - FIXED)
            console.log(`📸 Generating embedding for ${student.name} (ID: ${student.id})`);
            
            // Use the Face API to extract embedding
            const embeddingResult = await faceService.extractEmbedding(image);
            
            if (!embeddingResult.success || !embeddingResult.embedding) {
                return res.status(400).json({
                    success: false,
                    message: embeddingResult.error || 'Failed to generate face embedding. No face detected or image quality too low.',
                    code: 'EMBEDDING_GENERATION_FAILED',
                    fallback: 'Manual verification required'
                });
            }

            // Validate embedding dimension
            if (!Array.isArray(embeddingResult.embedding) || embeddingResult.embedding.length !== 512) {
                return res.status(400).json({
                    success: false,
                    message: `Invalid embedding. Expected 512 dimensions, got ${embeddingResult.embedding?.length || 0}`,
                    code: 'INVALID_EMBEDDING'
                });
            }

            console.log(`✅ Embedding generated: ${embeddingResult.embedding.length} dimensions, quality: ${embeddingResult.quality || 'N/A'}`);

            // 5. SAVE TO student_face TABLE
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .upsert({
                    student_id: student.id,
                    campus: student.campus || req.campus,
                    campus_code: student.campus === 'Legacy' ? 'LEG' : 'HER',
                    face_embedding: embeddingResult.embedding,
                    face_image_url: embeddingResult.image_url || null,
                    enrollment_status: 'enrolled',
                    enrollment_date: new Date().toISOString(),
                    is_active: true,
                    enrolled_by: req.user.id,
                    confidence_score: embeddingResult.confidence || 0.95,
                    embedding_quality: embeddingResult.quality || 0.8,
                    embedding_version: 1,
                    last_verified: null,
                    verification_count: 0,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }, {
                    onConflict: 'student_id,campus'
                })
                .select()
                .single();

            if (faceError) {
                console.error('Save face error:', faceError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to save face data to database',
                    code: 'DATABASE_ERROR',
                    error: faceError.message
                });
            }

            // 6. UPDATE students table
            const { data: updatedStudent, error: updateError } = await supabase
                .from('students')
                .update({
                    face_enrolled: true,
                    embedding_quality: embeddingResult.quality || 0.8,
                    updated_at: new Date().toISOString()
                })
                .eq('id', student.id)
                .select()
                .single();

            if (updateError) {
                console.error('Update student error:', updateError);
                // Non-critical, continue
            }

            // 7. AUDIT LOG
            await auditEvents.faceEnrolled(student, {
                success: true,
                confidence: embeddingResult.confidence,
                quality: embeddingResult.quality
            }, req);

            // 8. RESPONSE
            res.json({
                success: true,
                data: {
                    student: {
                        id: updatedStudent?.id || student.id,
                        name: updatedStudent?.name || student.name,
                        matric: updatedStudent?.matric || student.matric
                    },
                    face: {
                        id: faceData.id,
                        enrollment_status: faceData.enrollment_status,
                        enrollment_date: faceData.enrollment_date,
                        confidence: embeddingResult.confidence || 0.95,
                        quality: embeddingResult.quality || 0.8,
                        embedding_dimension: embeddingResult.embedding.length
                    },
                    message: 'Face enrolled successfully with embedding'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Face enrollment error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred during face enrollment. Please try again.',
                code: 'SERVER_ERROR',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }
);

/**
 * ENROLL FACE - Bulk (Multiple Frames)
 * Generates average embedding from multiple frames for better accuracy
 */
app.post('/api/face/enroll-bulk', 
    campusIsolation,
    faceLimiter,
    validate([
        body('frames').isArray({ min: 1 }).withMessage('At least one frame is required'),
        body('student_id').optional().isInt(),
        body('matric').optional().isString()
    ]),
    async (req, res) => {
        try {
            const { frames, student_id, matric } = req.body;

            // 1. VALIDATE FRAMES
            for (const frame of frames) {
                const validation = faceService.validateImage(frame);
                if (!validation.valid) {
                    return res.status(400).json({
                        success: false,
                        message: `Invalid frame: ${validation.error}`,
                        code: 'INVALID_IMAGE'
                    });
                }
            }

            // 2. FIND STUDENT
            if (!student_id && !matric) {
                return res.status(400).json({
                    success: false,
                    message: 'student_id or matric is required',
                    code: 'MISSING_IDENTIFIER'
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
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            // 3. CHECK PERMISSIONS
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && 
                req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only enroll students in your hostel.',
                    code: 'PERMISSION_DENIED'
                });
            }

            // 4. GENERATE EMBEDDINGS FROM ALL FRAMES
            console.log(`📸 Generating embedding from ${frames.length} frames for ${student.name}`);
            
            const embeddings = [];
            let qualities = [];
            let successfulFrames = 0;

            for (let i = 0; i < frames.length; i++) {
                try {
                    const result = await faceService.extractEmbedding(frames[i]);
                    if (result.success && result.embedding) {
                        embeddings.push(result.embedding);
                        qualities.push(result.quality || 0.7);
                        successfulFrames++;
                    }
                } catch (err) {
                    console.warn(`Frame ${i + 1} failed:`, err.message);
                }
            }

            if (embeddings.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'No valid face detected in any frame. Please try again with better lighting.',
                    code: 'NO_VALID_FRAMES'
                });
            }

            // 5. AVERAGE EMBEDDINGS FOR BETTER ACCURACY
            const avgEmbedding = embeddings.reduce((acc, emb) => {
                return acc.map((val, idx) => val + emb[idx]);
            }, new Array(embeddings[0].length).fill(0))
            .map(val => val / embeddings.length);

            const avgQuality = qualities.reduce((a, b) => a + b, 0) / qualities.length;

            console.log(`✅ Averaged ${embeddings.length} embeddings, quality: ${avgQuality}`);

            // 6. SAVE TO DATABASE
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .upsert({
                    student_id: student.id,
                    campus: student.campus || req.campus,
                    campus_code: student.campus === 'Legacy' ? 'LEG' : 'HER',
                    face_embedding: avgEmbedding,
                    face_image_url: null,
                    enrollment_status: 'enrolled',
                    enrollment_date: new Date().toISOString(),
                    is_active: true,
                    enrolled_by: req.user.id,
                    confidence_score: 0.95,
                    embedding_quality: avgQuality,
                    embedding_version: 1,
                    frames_used: embeddings.length,
                    last_verified: null,
                    verification_count: 0,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }, {
                    onConflict: 'student_id,campus'
                })
                .select()
                .single();

            if (faceError) {
                console.error('Save face error:', faceError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to save face data',
                    code: 'DATABASE_ERROR'
                });
            }

            // 7. UPDATE STUDENT
            const { data: updatedStudent, error: updateError } = await supabase
                .from('students')
                .update({
                    face_enrolled: true,
                    embedding_quality: avgQuality,
                    updated_at: new Date().toISOString()
                })
                .eq('id', student.id)
                .select()
                .single();

            if (updateError) {
                console.error('Update student error:', updateError);
            }

            // 8. AUDIT LOG
            await auditEvents.faceEnrolled(student, {
                success: true,
                confidence: 0.95,
                quality: avgQuality,
                frames_used: embeddings.length
            }, req);

            // 9. RESPONSE
            res.json({
                success: true,
                data: {
                    student: {
                        id: updatedStudent?.id || student.id,
                        name: updatedStudent?.name || student.name,
                        matric: updatedStudent?.matric || student.matric
                    },
                    face: {
                        id: faceData.id,
                        enrollment_status: faceData.enrollment_status,
                        enrollment_date: faceData.enrollment_date,
                        quality: avgQuality,
                        frames_used: embeddings.length,
                        embedding_dimension: avgEmbedding.length
                    },
                    message: `Face enrolled successfully using ${embeddings.length} frames`
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Bulk enrollment error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred during bulk enrollment. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * VERIFY FACE - Single Student
 * Compares captured face with stored embedding
 */
app.post('/api/face/verify', 
    campusIsolation,
    faceLimiter,
    validate(validators.faceVerify),
    async (req, res) => {
        try {
            const { image, student_id, matric, threshold = FACE_VERIFICATION_THRESHOLD } = req.body;

            // 1. VALIDATE IMAGE
            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }

            // 2. FIND STUDENT
            if (!student_id && !matric) {
                return res.status(400).json({
                    success: false,
                    message: 'student_id or matric is required',
                    code: 'MISSING_IDENTIFIER'
                });
            }

            let studentQuery = supabase
                .from('students')
                .select('id, name, matric, face_enrolled, hostel_id, room_id, room_code, campus')
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
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            // 3. CHECK PERMISSIONS
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && 
                req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied.',
                    code: 'PERMISSION_DENIED'
                });
            }

            // 4. GET STORED EMBEDDING
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('face_embedding, enrollment_status, verification_count, confidence_score')
                .eq('student_id', student.id)
                .eq('campus', req.campus)
                .eq('is_active', true)
                .maybeSingle();

            if (faceError || !faceData || !faceData.face_embedding) {
                return res.status(404).json({
                    success: false,
                    message: 'No face enrollment found for this student',
                    code: 'NO_FACE_ENROLLMENT'
                });
            }

            // 5. EXTRACT EMBEDDING FROM CAPTURED IMAGE
            console.log(`📸 Verifying face for ${student.name}`);
            
            const capturedEmbedding = await faceService.extractEmbedding(image);
            
            if (!capturedEmbedding.success || !capturedEmbedding.embedding) {
                return res.status(400).json({
                    success: false,
                    message: capturedEmbedding.error || 'Failed to extract face from captured image. Please try again.',
                    code: 'EXTRACTION_FAILED'
                });
            }

            // 6. COMPARE EMBEDDINGS (CRITICAL STEP)
            const comparison = await faceService.compareEmbeddings(
                capturedEmbedding.embedding,
                faceData.face_embedding
            );

            if (!comparison.success) {
                return res.status(400).json({
                    success: false,
                    message: comparison.error || 'Failed to compare face embeddings',
                    code: 'COMPARISON_FAILED'
                });
            }

            const isMatch = comparison.similarity >= threshold;

            // 7. UPDATE STATS IF MATCH
            if (isMatch) {
                const newVerificationCount = (faceData.verification_count || 0) + 1;
                await supabase
                    .from('student_face')
                    .update({
                        last_verified: new Date().toISOString(),
                        verification_count: newVerificationCount,
                        confidence_score: comparison.similarity,
                        updated_at: new Date().toISOString()
                    })
                    .eq('student_id', student.id);

                // Update student status
                await supabase
                    .from('students')
                    .update({
                        status: 'Verified',
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', student.id);
            }

            // 8. AUDIT LOG
            await auditEvents.faceVerified(student, {
                success: isMatch,
                confidence: comparison.similarity,
                threshold: threshold
            }, req);

            // 9. RESPONSE
            res.json({
                success: true,
                data: {
                    student: {
                        id: student.id,
                        name: student.name,
                        matric: student.matric,
                        room_code: student.room_code
                    },
                    verified: isMatch,
                    similarity: comparison.similarity,
                    threshold: threshold,
                    message: isMatch ? 'Face verified successfully' : 'Face verification failed - similarity below threshold',
                    stats: {
                        verification_count: (faceData.verification_count || 0) + (isMatch ? 1 : 0),
                        previous_confidence: faceData.confidence_score
                    }
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Face verification error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred during face verification. Please try again.',
                code: 'SERVER_ERROR',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }
);

/**
 * VERIFY FACE - Room/Group
 * Compares captured face against all students in a room
 */
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
            const { image, room_id, hostel_id, threshold = FACE_VERIFICATION_THRESHOLD } = req.body;

            // 1. VALIDATE IMAGE
            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }

            // 2. CHECK PARAMETERS
            if (!room_id && !hostel_id) {
                return res.status(400).json({
                    success: false,
                    message: 'room_id or hostel_id is required',
                    code: 'MISSING_IDENTIFIER'
                });
            }

            // 3. GET STUDENTS IN ROOM/HOSTEL
            let query = supabase.from('students')
                .select('id, name, matric, face_enrolled, hostel_id, room_id, room_code, campus')
                .eq('campus', req.campus)
                .eq('face_enrolled', true);
            
            if (room_id) {
                query = query.eq('room_id', room_id);
            } else if (hostel_id) {
                query = query.eq('hostel_id', hostel_id);
            }
            
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && 
                req.user.role !== 'Administrator' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            const { data: students, error: studentsError } = await query;
            
            if (studentsError) {
                console.error('Fetch students error:', studentsError);
                return res.status(500).json({
                    success: false,
                    message: 'An error occurred while fetching students.',
                    code: 'SERVER_ERROR'
                });
            }

            if (!students || students.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No students found with face enrolled in this room/hostel',
                    code: 'NO_STUDENTS_FOUND'
                });
            }

            // 4. GET ALL EMBEDDINGS
            const studentIds = students.map(s => s.id);
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('student_id, face_embedding, verification_count, confidence_score')
                .in('student_id', studentIds)
                .eq('campus', req.campus)
                .eq('is_active', true);

            if (faceError || !faceData || faceData.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No face embeddings found for students in this room',
                    code: 'NO_FACE_EMBEDDINGS'
                });
            }

            // 5. EXTRACT CAPTURED EMBEDDING
            console.log(`📸 Verifying face against ${faceData.length} students`);
            
            const capturedEmbedding = await faceService.extractEmbedding(image);
            
            if (!capturedEmbedding.success || !capturedEmbedding.embedding) {
                return res.status(400).json({
                    success: false,
                    message: capturedEmbedding.error || 'Failed to extract face from captured image',
                    code: 'EXTRACTION_FAILED'
                });
            }

            // 6. COMPARE AGAINST ALL STUDENTS
            let bestMatch = null;
            let bestSimilarity = 0;

            for (const face of faceData) {
                const comparison = await faceService.compareEmbeddings(
                    capturedEmbedding.embedding,
                    face.face_embedding
                );

                if (comparison.success && comparison.similarity > bestSimilarity) {
                    bestSimilarity = comparison.similarity;
                    bestMatch = {
                        ...face,
                        similarity: comparison.similarity
                    };
                }
            }

            const isMatch = bestMatch && bestSimilarity >= threshold;
            let matchedStudent = null;

            if (isMatch && bestMatch) {
                matchedStudent = students.find(s => s.id === bestMatch.student_id);
                
                if (matchedStudent) {
                    // Update verification stats
                    const newVerificationCount = (bestMatch.verification_count || 0) + 1;
                    await supabase
                        .from('student_face')
                        .update({
                            last_verified: new Date().toISOString(),
                            verification_count: newVerificationCount,
                            confidence_score: bestSimilarity,
                            updated_at: new Date().toISOString()
                        })
                        .eq('student_id', matchedStudent.id);

                    await supabase
                        .from('students')
                        .update({
                            status: 'Verified',
                            updated_at: new Date().toISOString()
                        })
                        .eq('id', matchedStudent.id);
                }
            }

            // 7. AUDIT LOG
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: matchedStudent ? 'Room Face Verified' : 'Room Face Verification Failed',
                module: 'face',
                details: matchedStudent 
                    ? `${matchedStudent.name} (${matchedStudent.matric}) verified in room ${matchedStudent.room_code || 'N/A'} with ${(bestSimilarity * 100).toFixed(1)}% confidence`
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

            // 8. RESPONSE
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
                    similarity: bestSimilarity,
                    threshold: threshold,
                    students_checked: students.length,
                    message: matchedStudent ? 'Match found' : 'No match found'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Room verification error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred during room verification. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * CHECK LIVENESS
 */
app.post('/api/face/liveness', 
    campusIsolation,
    faceLimiter,
    validate(validators.faceImage),
    async (req, res) => {
        try {
            const { image } = req.body;
            
            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }
            
            const result = await faceService.checkLiveness(image);
            if (result.is_live) {
                await auditEvents.livenessVerified(req);
            }
            res.json({ 
                ...result, 
                campus: req.campus,
                message: result.is_live ? 'Liveness check passed' : 'Liveness check failed'
            });
        } catch (error) {
            console.error('Liveness check error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred during liveness check.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/face/liveness/reset', 
    campusIsolation,
    requireRole('Admin', 'Developer'),
    async (req, res) => {
        try {
            const result = await faceService.resetLiveness();
            res.json({ ...result, campus: req.campus });
        } catch (error) {
            console.error('Reset liveness error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * GET FACE STATUS
 */
app.get('/api/face/status/:studentId',
    campusIsolation,
    validate(validators.studentId),
    async (req, res) => {
        try {
            const studentId = parseInt(req.params.id);
            
            // Get student
            const { data: student, error } = await supabase
                .from('students')
                .select('id, name, matric, face_enrolled, updated_at, hostel_id, campus, embedding_quality')
                .eq('id', studentId)
                .eq('campus', req.campus)
                .single();
            
            if (error || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            // Check permissions
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && 
                req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
                });
            }

            // Get face data
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('id, enrollment_status, face_embedding, face_image_url, last_verified, verification_count, confidence_score, embedding_quality, embedding_version, frames_used')
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
                    embedding_quality: faceData?.embedding_quality || student.embedding_quality || null,
                    embedding_version: faceData?.embedding_version || 1,
                    frames_used: faceData?.frames_used || 1,
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
                message: 'An error occurred while fetching face status.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * COMPARE TWO EMBEDDINGS
 */
app.post('/api/face/compare', 
    campusIsolation,
    validate([
        body('embedding1').isArray().withMessage('Embedding 1 must be an array'),
        body('embedding2').isArray().withMessage('Embedding 2 must be an array')
    ]),
    async (req, res) => {
        try {
            const { embedding1, embedding2 } = req.body;
            
            // Validate embedding dimensions
            if (embedding1.length !== 512 || embedding2.length !== 512) {
                return res.status(400).json({
                    success: false,
                    message: `Invalid embedding dimensions. Expected 512, got ${embedding1.length} and ${embedding2.length}`,
                    code: 'INVALID_DIMENSIONS'
                });
            }
            
            const result = await faceService.compareEmbeddings(embedding1, embedding2);
            
            res.json({ 
                success: true,
                data: {
                    similarity: result.similarity || 0,
                    is_match: (result.similarity || 0) >= FACE_VERIFICATION_THRESHOLD,
                    threshold: FACE_VERIFICATION_THRESHOLD
                },
                campus: req.campus 
            });
        } catch (error) {
            console.error('Compare embeddings error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred while comparing embeddings.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * EXTRACT EMBEDDING FROM IMAGE
 */
app.post('/api/face/extract', 
    campusIsolation,
    faceLimiter,
    validate(validators.faceImage),
    async (req, res) => {
        try {
            const { image } = req.body;
            
            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }
            
            const result = await faceService.extractEmbedding(image);
            
            if (!result.success) {
                return res.status(400).json({
                    success: false,
                    message: result.error || 'Failed to extract face embedding',
                    code: 'EXTRACTION_FAILED'
                });
            }
            
            res.json({ 
                success: true,
                data: {
                    embedding: result.embedding,
                    dimension: result.embedding?.length || 0,
                    quality: result.quality || null,
                    face_count: result.face_count || 0
                },
                campus: req.campus 
            });
        } catch (error) {
            console.error('Extract embedding error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred while extracting embedding.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =============================================
// GET FACE STATUS
// =============================================
app.get('/api/students/:id/face-status',
    campusIsolation,
    validate(validators.studentId),
    async (req, res) => {
        try {
            const studentId = parseInt(req.params.id);
            
            // =============================================
            // STEP 1: GET STUDENT FROM students TABLE
            // =============================================
            const { data: student, error: studentError } = await supabase
                .from('students')
                .select('id, name, matric, hostel_id, campus, face_enrolled')
                .eq('id', studentId)
                .eq('campus', req.campus)
                .single();
            
            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            // Check permissions
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && 
                req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
                });
            }

            const isFaceEnrolledInStudents = student.face_enrolled === true || student.face_enrolled === 1;
            
            console.log(`📊 Step 1 - Student ${studentId} (${student.name}):`, {
                face_enrolled: student.face_enrolled,
                isFaceEnrolled: isFaceEnrolledInStudents
            });

            // =============================================
            // STEP 2: GET FACE DATA FROM student_face TABLE
            // =============================================
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('id, enrollment_status, face_embedding, face_image_url, last_verified, verification_count, confidence_score, embedding_quality, embedding_version, frames_used')
                .eq('student_id', studentId)
                .eq('campus', req.campus)
                .eq('is_active', true)
                .maybeSingle();

            if (faceError) {
                console.error('Face table error:', faceError);
            }

            const hasFaceRecord = faceData !== null;
            const isEnrolledInFaceTable = hasFaceRecord && faceData.enrollment_status === 'enrolled';
            const hasEmbedding = hasFaceRecord && 
                                 faceData.face_embedding !== null && 
                                 Array.isArray(faceData.face_embedding) && 
                                 faceData.face_embedding.length > 0;
            
            console.log(`📊 Step 2 - Student ${studentId} face data:`, {
                hasFaceRecord,
                isEnrolledInFaceTable,
                hasEmbedding,
                enrollmentStatus: faceData?.enrollment_status || 'no record',
                embeddingLength: hasEmbedding ? faceData.face_embedding.length : 0,
                verificationCount: faceData?.verification_count || 0
            });

            // =============================================
            // STEP 3: COMBINE THE RESULTS
            // =============================================
            const isFullyEnrolled = isFaceEnrolledInStudents && hasEmbedding;
            
            const canVerify = isFaceEnrolledInStudents && hasEmbedding;

            console.log(`📊 Step 3 - Final status for ${student.name}:`, {
                isFaceEnrolledInStudents,
                hasEmbedding,
                isFullyEnrolled,
                canVerify,
                status: isFullyEnrolled ? '✅ FULLY ENROLLED' : 
                        isFaceEnrolledInStudents ? '⚠️ PARTIAL (no embedding)' : 
                        '❌ NOT ENROLLED'
            });

            // =============================================
            // STEP 4: RESPONSE
            // =============================================
            res.json({
                success: true,
                data: {
                    student: {
                        id: student.id,
                        name: student.name,
                        matric: student.matric
                    },
                    
                    // Primary status - combination of both tables
                    face_enrolled: isFullyEnrolled,
                    enrollment_status: isFullyEnrolled ? 'enrolled' : 
                                      (isFaceEnrolledInStudents ? 'partial' : 'pending'),
                    has_embedding: hasEmbedding,
                    can_verify: canVerify,
                    
                    // Details from student_face table
                    face_image_url: faceData?.face_image_url || null,
                    last_verified: faceData?.last_verified || null,
                    verification_count: faceData?.verification_count || 0,
                    confidence_score: faceData?.confidence_score || null,
                    embedding_quality: faceData?.embedding_quality || null,
                    embedding_version: faceData?.embedding_version || 1,
                    
                    // Embedding info
                    embedding_dimension: hasEmbedding ? faceData.face_embedding.length : 0,
                    
                    // Source tracking
                    _source: {
                        students_table: {
                            face_enrolled: isFaceEnrolledInStudents
                        },
                        student_face_table: {
                            has_record: hasFaceRecord,
                            enrollment_status: faceData?.enrollment_status || null,
                            has_embedding: hasEmbedding,
                            embedding_length: hasEmbedding ? faceData.face_embedding.length : 0
                        }
                    }
                },
                campus: req.campus
            });
        } catch (error) {
            console.error('Get face status error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred while fetching face status.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * FIXED: STUDENT FACE ENROLL
 */
app.post('/api/students/:id/face/enroll',
    campusIsolation,
    faceLimiter,
    validate([validators.studentId, ...validators.faceImage]),
    async (req, res) => {
        try {
            const studentId = parseInt(req.params.id);
            const { image } = req.body;

            // 1. VALIDATE IMAGE
            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }

            // 2. GET STUDENT
            const { data: student, error: studentError } = await supabase
                .from('students')
                .select('id, name, matric, hostel_id, room_id, campus')
                .eq('id', studentId)
                .eq('campus', req.campus)
                .single();

            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            // 3. CHECK PERMISSIONS
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
                });
            }

            // 4. GENERATE EMBEDDING
            console.log(`📸 Generating embedding for ${student.name} (ID: ${student.id})`);

            const embeddingResult = await faceService.extractEmbedding(image);

            if (!embeddingResult.success || !embeddingResult.embedding) {
                return res.status(400).json({
                    success: false,
                    message: embeddingResult.error || 'Failed to generate face embedding. No face detected or image quality too low.',
                    code: 'EMBEDDING_GENERATION_FAILED',
                    fallback: 'Manual verification required'
                });
            }

            // Validate embedding dimension
            if (!Array.isArray(embeddingResult.embedding) || embeddingResult.embedding.length !== 512) {
                return res.status(400).json({
                    success: false,
                    message: `Invalid embedding. Expected 512 dimensions, got ${embeddingResult.embedding?.length || 0}`,
                    code: 'INVALID_EMBEDDING'
                });
            }

            console.log(`✅ Embedding generated: ${embeddingResult.embedding.length} dimensions, quality: ${embeddingResult.quality || 'N/A'}`);

            // 5. SAVE TO student_face TABLE (SINGLE UPSERT - NO DUPLICATE)
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .upsert({
                    student_id: student.id,
                    campus: student.campus || req.campus,
                    campus_code: student.campus === 'Legacy' ? 'LEG' : 'HER',
                    face_embedding: embeddingResult.embedding,
                    face_image_url: embeddingResult.image_url || null,
                    enrollment_status: 'enrolled',
                    enrollment_date: new Date().toISOString(),
                    is_active: true,
                    enrolled_by: req.user.id,
                    confidence_score: embeddingResult.confidence || 0.95,
                    embedding_quality: embeddingResult.quality || 0.8,
                    embedding_version: 1,
                    frames_used: 1,
                    last_verified: null,
                    verification_count: 0,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }, {
                    onConflict: 'student_id,campus'
                })
                .select()
                .single();

            if (faceError) {
                console.error('Save face error:', faceError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to save face data to database',
                    code: 'DATABASE_ERROR',
                    error: faceError.message
                });
            }

            // 6. UPDATE students table
            const { data: updatedStudent, error: updateError } = await supabase
                .from('students')
                .update({
                    face_enrolled: true,
                    embedding_quality: embeddingResult.quality || 0.8,
                    updated_at: new Date().toISOString()
                })
                .eq('id', student.id)
                .select()
                .single();

            if (updateError) {
                console.error('Update student error:', updateError);
                // Non-critical, continue
            }

            // 7. AUDIT LOG
            await auditEvents.faceEnrolled(student, {
                success: true,
                confidence: embeddingResult.confidence,
                quality: embeddingResult.quality
            }, req);

            // 8. RESPONSE
            res.json({
                success: true,
                data: {
                    student: {
                        id: updatedStudent?.id || student.id,
                        name: updatedStudent?.name || student.name,
                        matric: updatedStudent?.matric || student.matric
                    },
                    face: {
                        id: faceData.id,
                        enrollment_status: faceData.enrollment_status,
                        enrollment_date: faceData.enrollment_date,
                        confidence: embeddingResult.confidence || 0.95,
                        quality: embeddingResult.quality || 0.8,
                        embedding_dimension: embeddingResult.embedding.length
                    },
                    message: 'Face enrolled successfully with embedding'
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Face enrollment error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * FIXED: STUDENT FACE VERIFY - PROPERLY STRUCTURED
 */
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
            const { image, threshold = FACE_VERIFICATION_THRESHOLD } = req.body;

            // 1. VALIDATE IMAGE
            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }

            // 2. GET STUDENT
            const { data: student, error: studentError } = await supabase
                .from('students')
                .select('id, name, matric, hostel_id, room_id, campus')
                .eq('id', studentId)
                .eq('campus', req.campus)
                .single();

            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            // 3. CHECK PERMISSIONS
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
                });
            }

            // 4. GET STORED EMBEDDING
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('face_embedding, enrollment_status, verification_count, confidence_score')
                .eq('student_id', studentId)
                .eq('campus', req.campus)
                .eq('is_active', true)
                .maybeSingle();

            if (faceError || !faceData || !faceData.face_embedding) {
                return res.status(404).json({
                    success: false,
                    message: 'No face enrollment found for this student',
                    code: 'NO_FACE_ENROLLMENT'
                });
            }

            // 5. EXTRACT EMBEDDING FROM CAPTURED IMAGE
            console.log(`📸 Verifying face for ${student.name}`);

            const capturedEmbedding = await faceService.extractEmbedding(image);

            if (!capturedEmbedding.success || !capturedEmbedding.embedding) {
                return res.status(400).json({
                    success: false,
                    message: capturedEmbedding.error || 'Failed to extract face from captured image. Please try again.',
                    code: 'EXTRACTION_FAILED'
                });
            }

            // 6. COMPARE EMBEDDINGS
            const comparison = await faceService.compareEmbeddings(
                capturedEmbedding.embedding,
                faceData.face_embedding
            );

            if (!comparison.success) {
                return res.status(400).json({
                    success: false,
                    message: comparison.error || 'Failed to compare face embeddings',
                    code: 'COMPARISON_FAILED'
                });
            }

            const isMatch = comparison.similarity >= threshold;

            // 7. UPDATE STATS IF MATCH
            if (isMatch) {
                const newVerificationCount = (faceData.verification_count || 0) + 1;
                await supabase
                    .from('student_face')
                    .update({
                        last_verified: new Date().toISOString(),
                        verification_count: newVerificationCount,
                        confidence_score: comparison.similarity,
                        updated_at: new Date().toISOString()
                    })
                    .eq('student_id', student.id);

                // Update student status
                await supabase
                    .from('students')
                    .update({
                        status: 'Verified',
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', student.id);
            }

            // 8. AUDIT LOG
            await auditEvents.faceVerified(student, {
                success: isMatch,
                confidence: comparison.similarity,
                threshold: threshold
            }, req);

            // 9. RESPONSE
            res.json({
                success: true,
                data: {
                    student: {
                        id: student.id,
                        name: student.name,
                        matric: student.matric,
                        room_code: student.room_code
                    },
                    verified: isMatch,
                    similarity: comparison.similarity,
                    threshold: threshold,
                    message: isMatch ? 'Face verified successfully' : 'Face verification failed - similarity below threshold',
                    stats: {
                        verification_count: (faceData.verification_count || 0) + (isMatch ? 1 : 0),
                        previous_confidence: faceData.confidence_score
                    }
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Face verification error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

/**
 * FIXED: GET ALL FACE STATUS - PROPERLY STRUCTURED
 */
app.get('/api/students/face-status/all',
    campusIsolation,
    async (req, res) => {
        try {
            const { hostel_id, room_id } = req.query;
            
            let query = supabase
                .from('students')
                .select('id, name, matric, hostel_id, room_id, room_code, face_enrolled, campus')
                .eq('campus', req.campus);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
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
                    .select('student_id, enrollment_status, last_verified, verification_count, confidence_score, embedding_quality')
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
                    verification_count: face?.verification_count || 0,
                    confidence_score: face?.confidence_score || null,
                    embedding_quality: face?.embedding_quality || null
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            const studentCampus = campus || req.campus || process.env.DEFAULT_CAMPUS || 'Legacy';
            
            const { data: existingStudent } = await supabase
                .from('students')
                .select('id')
                .eq('matric', matric)
                .eq('campus', studentCampus)
                .maybeSingle();

            if (existingStudent) {
                return res.status(400).json({
                    success: false,
                    message: 'Student with this matric number already exists in this campus',
                    code: 'DUPLICATE_STUDENT'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only add students to your hostel.',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== data.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
                });
            }

            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching student:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                message: 'Student not found in this campus',
                code: 'STUDENT_NOT_FOUND'
            });
        }
        
        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== existingStudent.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                message: 'Invalid student ID',
                code: 'INVALID_ID'
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
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== existingStudent.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                    message: 'No fields to update',
                    code: 'NO_FIELDS_TO_UPDATE'
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
                    message: 'An error occurred. Please try again.',
                    code: 'SERVER_ERROR'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.put('/api/students/:id/status', 
    campusIsolation,
    validate([
        body('status').isIn(['Present', 'Absent', 'Verified']).withMessage('Invalid status')
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
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// STAFF CRUD - SINGLE STAFF ENDPOINT
// =====================================================

app.get('/api/staff/:id', 
    campusIsolation,
    validate(validators.staffId),
    async (req, res) => {
        const id = parseInt(req.params.id);
        try {
            const { data, error } = await supabase
                .from('staff')
                .select(`
                    id, 
                    name, 
                    username, 
                    role, 
                    hostel_id,
                    assigned_floor, 
                    assigned_room, 
                    status, 
                    email, 
                    phone, 
                    department, 
                    initials, 
                    joined, 
                    last_login, 
                    campus, 
                    campus_code,
                    hostels!hostel_id (
                        id,
                        name,
                        type,
                        gender
                    )
                `)
                .eq('id', id)
                .eq('campus', req.campus)
                .maybeSingle();

            if (error || !data) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Staff not found in this campus',
                    code: 'STAFF_NOT_FOUND'
                });
            }

            if (data.role === 'Developer' && req.user.role !== 'Developer') {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Staff not found in this campus',
                    code: 'STAFF_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== data.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
                });
            }

            const formattedData = {
                ...data,
                hostel_id: data.hostel_id,
                hostel: data.hostels?.name || null,
                hostel_name: data.hostels?.name || null,
                hostel_type: data.hostels?.type || null,
                hostel_gender: data.hostels?.gender || null,
                assigned_floor: data.assigned_floor,
                assigned_room: data.assigned_room,
                hostels: undefined
            };

            res.json({ 
                success: true, 
                data: { ...formattedData, staff_id: formattedData.id },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching staff:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// STAFF LIST ENDPOINT
// =====================================================

app.get('/api/staff', 
    campusIsolation,
    validate(validators.pagination),
    async (req, res) => {
        try {
            const limit = Math.min(parseInt(req.query.limit) || 50, 100);
            const offset = parseInt(req.query.offset) || 0;
            
            const adminRoles = ['Admin', 'Developer', 'Administrator', 'Administration'];
            
            let query = supabase
                .from('staff')
                .select('id, name, username, role, hostel_id, assigned_floor, assigned_room, status, email, phone, department, initials, joined, last_login, campus, campus_code')
                .order('name', { ascending: true })
                .range(offset, offset + limit - 1);

            // ✅ Only filter by campus if NOT admin
            if (!adminRoles.includes(req.user.role)) {
                query = query.eq('campus', req.campus);
                if (req.user.hostel_id) {
                    query = query.eq('hostel_id', req.user.hostel_id);
                }
            }
            // ✅ Admins see ALL campuses

            // ✅ Never show Developer accounts to non-Developers
            if (req.user.role !== 'Developer') {
                query = query.neq('role', 'Developer');
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// STAFF CREATE
// =====================================================

app.post('/api/staff', 
    campusIsolation,
    requireRole('Admin', 'Developer'),
    validate(validators.createStaff),
    async (req, res) => {
        const { name, username, role, hostel_id, email, phone, department, assigned_floor, assigned_room, campus } = req.body;
        
        try {
            // Validate required fields
            if (!name || !username || !role) {
                return res.status(400).json({
                    success: false,
                    message: 'Name, username, and role are required',
                    code: 'MISSING_REQUIRED_FIELDS'
                });
            }

            // Validate role
            const validRoles = ['RA', 'HRA', 'Admin', 'Administrator', 'RASD', 'Developer'];
            if (!validRoles.includes(role)) {
                return res.status(400).json({
                    success: false,
                    message: `Invalid role. Must be one of: ${validRoles.join(', ')}`,
                    code: 'INVALID_ROLE'
                });
            }

            // Check if user is trying to create a Developer account
            if (role === 'Developer' && req.user.role !== 'Developer') {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. Only Developers can create Developer accounts.',
                    code: 'PERMISSION_DENIED'
                });
            }

            const staffCampus = campus || req.campus || process.env.DEFAULT_CAMPUS || 'Legacy';

            // Check for existing username (case-insensitive)
            const { data: existingStaff, error: checkError } = await supabase
                .from('staff')
                .select('id, name')
                .ilike('username', username) // Case-insensitive check
                .eq('campus', staffCampus)
                .maybeSingle();

            if (checkError) {
                console.error('Error checking existing staff:', checkError);
                // Continue despite error, let the insert handle it
            }

            if (existingStaff) {
                return res.status(409).json({ 
                    success: false, 
                    message: `Username "${username}" is already taken by ${existingStaff.name}. Please choose a different username.`,
                    code: 'DUPLICATE_USERNAME',
                    existing_user: existingStaff
                });
            }

            // Validate RA/HRA must have hostel
            if ((role === 'RA' || role === 'HRA') && !hostel_id) {
                return res.status(400).json({
                    success: false,
                    message: `${role} must be assigned to a hostel`,
                    code: 'HOSTEL_REQUIRED'
                });
            }

            // If hostel_id is provided, verify it exists
            if (hostel_id) {
                const { data: hostel, error: hostelError } = await supabase
                    .from('hostels')
                    .select('id, name')
                    .eq('id', parseInt(hostel_id))
                    .eq('campus', staffCampus)
                    .maybeSingle();

                if (hostelError || !hostel) {
                    return res.status(404).json({
                        success: false,
                        message: 'Hostel not found in this campus',
                        code: 'HOSTEL_NOT_FOUND'
                    });
                }
            }

            // Generate initials
            const initials = name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase();

            // Generate temporary password
            const tempPassword = crypto.randomBytes(12).toString('base64').slice(0, 16);
            const hashedPassword = await bcrypt.hash(tempPassword, SALT_ROUNDS);

            // Prepare staff data
            const newStaff = { 
                name: name.trim(),
                username: username.trim().toLowerCase(), // Store username in lowercase
                password: hashedPassword,
                role: role,
                hostel_id: hostel_id ? parseInt(hostel_id) : null,
                assigned_floor: assigned_floor || null,
                assigned_room: assigned_room || null,
                status: 'Active',
                initials: initials,
                email: email || null,
                phone: phone || null,
                department: department || null,
                joined: new Date().toISOString().split('T')[0],
                campus: staffCampus,
                campus_code: staffCampus === 'Legacy' ? 'LEG' : 'HER',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };

            // Insert staff
            const { data, error: insertError } = await supabase
                .from('staff')
                .insert(newStaff)
                .select()
                .single();

            if (insertError) {
                console.error('Supabase insert error:', insertError);

                // Check for duplicate key error (just in case)
                if (insertError.code === '23505' || insertError.message?.includes('duplicate key value violates unique constraint')) {
                    return res.status(409).json({
                        success: false,
                        message: `Username "${username}" is already taken. Please choose a different username.`,
                        code: 'DUPLICATE_USERNAME',
                        details: insertError.details
                    });
                }

                return res.status(500).json({
                    success: false,
                    message: 'Database error: ' + insertError.message,
                    code: 'DATABASE_ERROR',
                    details: process.env.NODE_ENV === 'development' ? insertError : undefined
                });
            }

            // Log the creation
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Staff Created',
                module: 'staff',
                details: `Created ${role} account for ${data.name} (${data.username}) in ${staffCampus} campus`,
                result: 'success',
                category: 'staff',
                hostel_id: data.hostel_id,
                campus: staffCampus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            // Remove password from response
            const { password: _, ...staffWithoutPassword } = data;

            // Send response with temporary password
            res.status(201).json({ 
                success: true, 
                data: staffWithoutPassword,
                campus: staffCampus,
                temporary_password: tempPassword,
                message: `Staff created successfully. Temporary password: ${tempPassword} (Please change on first login)`
            });

        } catch (error) {
            console.error('Error creating staff:', error);
            
            // Handle bcrypt errors
            if (error.message && error.message.includes('bcrypt')) {
                return res.status(500).json({
                    success: false,
                    message: 'Error securing password. Please try again.',
                    code: 'PASSWORD_ENCRYPTION_ERROR'
                });
            }

            res.status(500).json({ 
                success: false, 
                message: 'An error occurred while creating staff. Please try again.',
                code: 'SERVER_ERROR',
                details: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }
);

// =====================================================
// STAFF UPDATE
// =====================================================

app.put('/api/staff/:id', 
    campusIsolation,
    requireRole('Admin', 'Developer'),
    validate(validators.updateStaff),
    async (req, res) => {
        const id = parseInt(req.params.id);
        
        if (isNaN(id)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid staff ID',
                code: 'INVALID_ID'
            });
        }
        
        try {
            // Get existing staff
            const { data: existing, error: fetchError } = await supabase
                .from('staff')
                .select('*')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (fetchError || !existing) {
                return res.status(404).json({
                    success: false,
                    message: 'Staff not found in this campus',
                    code: 'STAFF_NOT_FOUND'
                });
            }

            // Check Developer permissions
            if (existing.role === 'Developer' && req.user.role !== 'Developer') {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. Only Developers can modify Developer accounts.',
                    code: 'PERMISSION_DENIED'
                });
            }

            // Build update data
            const updateData = {};
            const changes = [];
            
            const fieldMap = {
                'name': 'name',
                'username': 'username', 
                'role': 'role',
                'hostel_id': 'hostel_id',
                'assigned_floor': 'assigned_floor',
                'assigned_room': 'assigned_room',
                'status': 'status',
                'email': 'email',
                'phone': 'phone',
                'department': 'department',
                'campus': 'campus'
            };
            
            for (const [reqField, dbField] of Object.entries(fieldMap)) {
                if (req.body[reqField] !== undefined && req.body[reqField] !== null) {
                    // Special handling for username - check for duplicates
                    if (reqField === 'username') {
                        const newUsername = req.body[reqField];
                        
                        // Check if username already exists for another staff member
                        const { data: duplicateCheck, error: checkError } = await supabase
                            .from('staff')
                            .select('id, name')
                            .eq('username', newUsername)
                            .neq('id', id)
                            .eq('campus', req.campus)
                            .maybeSingle();
                        
                        if (!checkError && duplicateCheck) {
                            return res.status(409).json({
                                success: false,
                                message: `Username "${newUsername}" is already taken by ${duplicateCheck.name}`,
                                code: 'DUPLICATE_USERNAME',
                                existing_user: duplicateCheck
                            });
                        }
                        
                        updateData.username = newUsername;
                        changes.push('username');
                    } else if (reqField === 'role') {
                        const newRole = req.body[reqField];
                        if (newRole === 'Developer' && req.user.role !== 'Developer') {
                            return res.status(403).json({
                                success: false,
                                message: 'Access denied. Only Developers can create Developer accounts.',
                                code: 'PERMISSION_DENIED'
                            });
                        }
                        if (existing.role === 'Developer' && newRole !== 'Developer' && req.user.role !== 'Developer') {
                            return res.status(403).json({
                                success: false,
                                message: 'Cannot change Developer role.',
                                code: 'PERMISSION_DENIED'
                            });
                        }
                        updateData.role = newRole;
                        changes.push('role');
                    } else if (reqField === 'campus') {
                        const newCampus = req.body[reqField];
                        updateData.campus = newCampus;
                        updateData.campus_code = newCampus === 'Legacy' ? 'LEG' : 'HER';
                        changes.push('campus');
                    } else if (reqField === 'hostel_id') {
                        const hostelId = req.body[reqField];
                        updateData.hostel_id = hostelId ? parseInt(hostelId) : null;
                        changes.push('hostel_id');
                    } else {
                        updateData[dbField] = req.body[reqField];
                        changes.push(reqField);
                    }
                }
            }

            // Check if anything to update
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'No valid fields to update',
                    code: 'NO_FIELDS_TO_UPDATE'
                });
            }

            // Add updated_at
            updateData.updated_at = new Date().toISOString();

            console.log('Updating staff:', { id, updateData, changes });

            // Perform update
            const { data: updatedStaff, error: updateError } = await supabase
                .from('staff')
                .update(updateData)
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();

            if (updateError) {
                console.error('Supabase update error:', updateError);
                
                // Check for duplicate key error
                if (updateError.code === '23505' || updateError.message.includes('duplicate key value violates unique constraint')) {
                    return res.status(409).json({
                        success: false,
                        message: 'Username already exists. Please choose a different username.',
                        code: 'DUPLICATE_USERNAME',
                        details: updateError.details
                    });
                }
                
                return res.status(500).json({
                    success: false,
                    message: 'Database error: ' + updateError.message,
                    code: 'DATABASE_ERROR',
                    details: process.env.NODE_ENV === 'development' ? updateError : undefined
                });
            }

            // Log update
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'Staff Updated',
                module: 'staff',
                details: `Updated ${updatedStaff?.name}: ${changes.join(', ')}`,
                result: 'success',
                category: 'staff',
                hostel_id: updatedStaff?.hostel_id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            const { password: _, ...staffWithoutPassword } = updatedStaff;

            res.json({ 
                success: true, 
                data: staffWithoutPassword, 
                campus: req.campus,
                message: 'Staff updated successfully'
            });

        } catch (error) {
            console.error('Error updating staff:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred while updating staff: ' + error.message,
                code: 'SERVER_ERROR',
                details: process.env.NODE_ENV === 'development' ? error.stack : undefined
            });
        }
    }
);

// =====================================================
// STAFF DELETE
// =====================================================

app.delete('/api/staff/:id', 
    campusIsolation,
    requireRole('Admin', 'Developer'),
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
                    message: 'Staff not found in this campus',
                    code: 'STAFF_NOT_FOUND'
                });
            }

            if (user.role === 'Developer' && req.user.role !== 'Developer') {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. Only Developers can delete Developer accounts.',
                    code: 'PERMISSION_DENIED'
                });
            }

            if (id === req.user.id) {
                return res.status(403).json({
                    success: false,
                    message: 'You cannot delete your own account.',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// DEVELOPER STAFF MANAGEMENT
// =====================================================

app.get('/api/developer/staff',
    campusIsolation,
    requireRole('Developer'),
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
            console.error('Error fetching staff for Developer:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/developer/staff',
    campusIsolation,
    requireRole('Developer'),
    validate(validators.createStaff),
    async (req, res) => {
        const { name, username, role, hostel_id, email, phone, department, assigned_floor, assigned_room, campus } = req.body;
        
        if (role !== 'Developer') {
            return res.status(403).json({
                success: false,
                message: 'This endpoint can only create Developer accounts.',
                code: 'PERMISSION_DENIED'
            });
        }
        
        try {
            const staffCampus = campus || req.campus || process.env.DEFAULT_CAMPUS || 'Legacy';
            
            const { data: existingStaff } = await supabase
                .from('staff')
                .select('id')
                .eq('username', username)
                .eq('campus', staffCampus)
                .maybeSingle();

            if (existingStaff) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Username already exists in this campus',
                    code: 'DUPLICATE_USERNAME'
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
                action: 'Developer Created',
                module: 'staff',
                details: `Created Developer account for ${name} (${username})`,
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
                message: `Developer created successfully. Temporary password: ${tempPassword} (Please change on first login)`
            });
        } catch (error) {
            console.error('Error creating Developer:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.put('/api/developer/staff/:id',
    campusIsolation,
    requireRole('Developer'),
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
                    message: 'Staff not found in this campus',
                    code: 'STAFF_NOT_FOUND'
                });
            }

            if (existing.role === 'Developer' && req.user.role !== 'Developer') {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. Only Developers can update Developer accounts.',
                    code: 'PERMISSION_DENIED'
                });
            }

            const updateData = {};
            const changes = [];

            if (name !== undefined) { updateData.name = name; changes.push('name'); }
            if (username !== undefined) { updateData.username = username; changes.push('username'); }
            if (role !== undefined) { 
                if (existing.role === 'Developer' && role !== 'Developer') {
                    return res.status(403).json({
                        success: false,
                        message: 'Cannot change Developer role.',
                        code: 'PERMISSION_DENIED'
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
                    message: 'No fields to update',
                    code: 'NO_FIELDS_TO_UPDATE'
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
                action: 'Developer Updated',
                module: 'staff',
                details: `Updated Developer ${data?.name}: ${changes.join(', ')}`,
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
            console.error('Error updating Developer:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.delete('/api/developer/staff/:id',
    campusIsolation,
    requireRole('Developer'),
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
                    message: 'Staff not found in this campus',
                    code: 'STAFF_NOT_FOUND'
                });
            }

            if (user.role === 'Developer' && req.user.role !== 'Developer') {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. Only Developers can delete Developer accounts.',
                    code: 'PERMISSION_DENIED'
                });
            }

            if (id === req.user.id) {
                return res.status(403).json({
                    success: false,
                    message: 'You cannot delete your own account.',
                    code: 'PERMISSION_DENIED'
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
                action: 'Developer Deleted',
                module: 'staff',
                details: `Deleted Developer: ${user?.name}`,
                result: 'success',
                category: 'staff',
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                message: 'Developer deleted successfully',
                campus: req.campus
            });
        } catch (error) {
            console.error('Error deleting Developer:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// ATTENDANCE ENDPOINTS - FACE ONLY
// =====================================================

// Verify a student with face recognition
app.post('/api/attendance/verify',
    campusIsolation,
    requireRole('RA', 'HRA'),
    validate(validators.attendanceVerify),
    async (req, res) => {
        try {
            const { student_id, image, session_id } = req.body;
            const campus = req.campus;
            
            // Validate image
            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }
            
            // Get student
            const { data: student, error: studentError } = await supabase
                .from('students')
                .select('id, name, matric, room_id, room_code, hostel_id, campus, face_enrolled')
                .eq('id', student_id)
                .eq('campus', campus)
                .single();
            
            if (studentError || !student) {
                return res.status(404).json({
                    success: false,
                    message: 'Student not found',
                    code: 'STUDENT_NOT_FOUND'
                });
            }
            
            // Check if student has face enrolled
            if (!student.face_enrolled) {
                return res.status(400).json({
                    success: false,
                    message: `${student.name} has not enrolled their face yet`,
                    code: 'FACE_NOT_ENROLLED',
                    data: { student_id: student.id }
                });
            }
            
            // Check if RA has access to this student
            if (req.user.role === 'RA') {
                const { data: assignment, error: assignError } = await supabase
                    .from('ra_room_assignments')
                    .select('room_id')
                    .eq('ra_id', req.user.id)
                    .eq('room_id', student.room_id)
                    .eq('status', 'active')
                    .eq('campus', campus)
                    .maybeSingle();
                
                if (assignError || !assignment) {
                    return res.status(403).json({
                        success: false,
                        message: 'Student not in your assigned rooms',
                        code: 'NOT_ASSIGNED_TO_RA'
                    });
                }
            }
            
            // Get or create today's session
            let session = null;
            if (session_id) {
                const { data: existingSession } = await supabase
                    .from('sessions')
                    .select('*')
                    .eq('id', session_id)
                    .eq('campus', campus)
                    .single();
                session = existingSession;
            } else {
                session = await getOrCreateTodaySession(req.user.hostel_id || student.hostel_id, campus);
            }
            
            if (!session) {
                return res.status(404).json({
                    success: false,
                    message: 'No active session found',
                    code: 'SESSION_NOT_FOUND'
                });
            }
            
            // Check if session is active
            if (session.status !== 'active') {
                return res.status(403).json({
                    success: false,
                    message: `Session is not active (status: ${session.status})`,
                    code: 'SESSION_NOT_ACTIVE'
                });
            }
            
            // Check if already verified
            const { data: existingScan, error: scanError } = await supabase
                .from('bedcheck_scans')
                .select('id, status, created_at')
                .eq('session_id', session.id)
                .eq('student_id', student.id)
                .maybeSingle();
            
            if (scanError) {
                console.error('Error checking scan:', scanError);
            }
            
            if (existingScan && existingScan.status === 'Verified') {
                return res.status(400).json({
                    success: false,
                    message: `${student.name} is already verified`,
                    code: 'ALREADY_VERIFIED',
                    data: {
                        student: student,
                        verified_at: existingScan.created_at
                    }
                });
            }
            
            // Get student's face embedding
            const { data: faceData, error: faceError } = await supabase
                .from('student_face')
                .select('face_embedding')
                .eq('student_id', student.id)
                .eq('campus', campus)
                .eq('is_active', true)
                .maybeSingle();
            
            if (faceError || !faceData || !faceData.face_embedding) {
                return res.status(404).json({
                    success: false,
                    message: 'No face embedding found for this student',
                    code: 'NO_FACE_EMBEDDING'
                });
            }
            
            // Verify face with InsightFace API
            const verificationResult = await faceService.verifyFace(
                image,
                faceData.face_embedding,
                FACE_VERIFICATION_THRESHOLD
            );
            
            if (!verificationResult.success) {
                return res.status(400).json({
                    success: false,
                    message: verificationResult.error || 'Face verification failed',
                    code: 'FACE_VERIFICATION_FAILED',
                    data: {
                        confidence: verificationResult.confidence || 0,
                        threshold: FACE_VERIFICATION_THRESHOLD
                    }
                });
            }
            
            // Create verification record
            const scanData = {
                session_id: session.id,
                student_id: student.id,
                room: student.room_code,
                status: 'Verified',
                scanner_id: 'Face-001',
                campus: campus,
                created_at: new Date().toISOString(),
                metadata: {
                    method: 'face',
                    ra_id: req.user.id,
                    ra_name: req.user.name,
                    confidence: verificationResult.confidence || 0,
                    threshold: FACE_VERIFICATION_THRESHOLD
                }
            };
            
            const { data: scan, error: insertError } = await supabase
                .from('bedcheck_scans')
                .insert(scanData)
                .select()
                .single();
            
            if (insertError) {
                console.error('Error creating scan:', insertError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to record verification',
                    code: 'SCAN_ERROR'
                });
            }
            
            // Update student status
            await supabase
                .from('students')
                .update({ 
                    status: 'Verified',
                    updated_at: new Date().toISOString()
                })
                .eq('id', student.id);
            
            // Update face verification count
            await supabase
                .from('student_face')
                .update({
                    last_verified: new Date().toISOString(),
                    verification_count: (faceData.verification_count || 0) + 1,
                    confidence_score: verificationResult.confidence || null,
                    updated_at: new Date().toISOString()
                })
                .eq('student_id', student.id);
            
            // Log audit
            await auditEvents.attendanceVerified(student, session, scan, req);
            
            res.json({
                success: true,
                data: {
                    student: {
                        id: student.id,
                        name: student.name,
                        matric: student.matric,
                        room: student.room_code
                    },
                    scan: scan,
                    confidence: verificationResult.confidence || 0,
                    threshold: FACE_VERIFICATION_THRESHOLD,
                    session: {
                        id: session.id,
                        name: session.name,
                        status: session.status
                    },
                    message: `${student.name} verified successfully`
                },
                campus: campus
            });
            
        } catch (error) {
            console.error('Verification error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// Get attendance for today (face-only)
app.get('/api/attendance/today',
    campusIsolation,
    requireRole('RA', 'HRA', 'Admin'),
    async (req, res) => {
        try {
            const campus = req.campus;
            const hostelId = req.user.hostel_id;
            
            if (!hostelId && req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator') {
                return res.status(400).json({
                    success: false,
                    message: 'No hostel assigned',
                    code: 'NO_HOSTEL_ASSIGNED'
                });
            }
            
            const today = new Date().toISOString().split('T')[0];
            
            // Get or create today's session
            const session = await getOrCreateTodaySession(hostelId, campus);
            
            if (!session) {
                return res.status(500).json({
                    success: false,
                    message: 'Failed to get/create session',
                    code: 'SESSION_ERROR'
                });
            }
            
            // Get scans for today
            const { data: scans, error: scansError } = await supabase
                .from('bedcheck_scans')
                .select(`
                    *,
                    students!student_id (
                        id, name, matric, room_code
                    )
                `)
                .eq('session_id', session.id)
                .eq('campus', campus)
                .order('created_at', { ascending: false });
            
            if (scansError) {
                console.error('Error fetching scans:', scansError);
            }
            
            // Get RA's assigned rooms
            let assignedRoomIds = [];
            if (req.user.role === 'RA') {
                const { data: assignments, error: assignError } = await supabase
                    .from('ra_room_assignments')
                    .select('room_id')
                    .eq('ra_id', req.user.id)
                    .eq('status', 'active')
                    .eq('campus', campus);
                
                if (!assignError && assignments) {
                    assignedRoomIds = assignments.map(a => a.room_id);
                }
            }
            
            // Get students in assigned rooms
            let studentQuery = supabase
                .from('students')
                .select('id, name, matric, room_code, room_id, status, face_enrolled')
                .eq('hostel_id', hostelId)
                .eq('campus', campus);
            
            if (assignedRoomIds.length > 0) {
                studentQuery = studentQuery.in('room_id', assignedRoomIds);
            }
            
            const { data: students, error: studentError } = await studentQuery;
            
            if (studentError) {
                console.error('Error fetching students:', studentError);
            }
            
            // Build response
            const verifiedStudents = scans?.filter(s => s.status === 'Verified').map(s => ({
                id: s.student_id,
                name: s.students?.name || 'Unknown',
                matric: s.students?.matric || 'Unknown',
                room: s.room,
                verified_at: s.created_at,
                confidence: s.metadata?.confidence || null
            })) || [];
            
            const allStudents = students || [];
            const verifiedIds = verifiedStudents.map(v => v.id);
            const pendingStudents = allStudents.filter(s => !verifiedIds.includes(s.id));
            const notEnrolled = allStudents.filter(s => !s.face_enrolled);
            
            res.json({
                success: true,
                data: {
                    session: {
                        id: session.id,
                        name: session.name,
                        status: session.status,
                        is_active: session.status === 'active'
                    },
                    stats: {
                        total_students: allStudents.length,
                        verified: verifiedStudents.length,
                        pending: pendingStudents.length,
                        not_enrolled: notEnrolled.length,
                        completion_rate: allStudents.length > 0 
                            ? Math.round((verifiedStudents.length / allStudents.length) * 100) 
                            : 0
                    },
                    verified_students: verifiedStudents,
                    pending_students: pendingStudents.map(s => ({
                        id: s.id,
                        name: s.name,
                        matric: s.matric,
                        room: s.room_code,
                        face_enrolled: s.face_enrolled
                    })),
                    not_enrolled: notEnrolled.map(s => ({
                        id: s.id,
                        name: s.name,
                        matric: s.matric,
                        room: s.room_code
                    }))
                },
                campus: campus
            });
            
        } catch (error) {
            console.error('Error fetching today\'s attendance:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// Get attendance for a specific session
app.get('/api/attendance/session/:sessionId',
    campusIsolation,
    requireRole('RA', 'HRA', 'Admin', 'RASD', 'Developer'),
    validate([
        param('sessionId').isInt().withMessage('Invalid session ID')
    ]),
    async (req, res) => {
        try {
            const sessionId = parseInt(req.params.sessionId);
            const campus = req.campus;
            
            // Get session
            const { data: session, error: sessionError } = await supabase
                .from('sessions')
                .select('*, hostels!hostel_id (id, name, type)')
                .eq('id', sessionId)
                .eq('campus', campus)
                .single();
            
            if (sessionError || !session) {
                return res.status(404).json({
                    success: false,
                    message: 'Session not found',
                    code: 'SESSION_NOT_FOUND'
                });
            }
            
            // Check access
            if (req.user.role === 'RA' && req.user.hostel_id !== session.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'ACCESS_DENIED'
                });
            }
            
            // Get all scans for this session
            const { data: scans, error: scansError } = await supabase
                .from('bedcheck_scans')
                .select(`
                    *,
                    students!student_id (
                        id, name, matric, room_code, hostel_id
                    )
                `)
                .eq('session_id', sessionId)
                .eq('campus', campus)
                .order('created_at', { ascending: false });
            
            if (scansError) {
                console.error('Error fetching scans:', scansError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to fetch attendance',
                    code: 'SCAN_FETCH_ERROR'
                });
            }
            
            // Get all students in the hostel
            const { data: allStudents, error: studentError } = await supabase
                .from('students')
                .select('id, name, matric, room_code, hostel_id, status, face_enrolled')
                .eq('hostel_id', session.hostel_id)
                .eq('campus', campus);
            
            if (studentError) {
                console.error('Error fetching students:', studentError);
            }
            
            // Calculate stats
            const totalStudents = allStudents?.length || 0;
            const verifiedScans = scans?.filter(s => s.status === 'Verified') || [];
            const absentScans = scans?.filter(s => s.status === 'Absent') || [];
            const pendingStudents = allStudents?.filter(s => 
                !scans?.some(sc => sc.student_id === s.id && sc.status === 'Verified')
            ) || [];
            
            res.json({
                success: true,
                data: {
                    session: {
                        id: session.id,
                        name: session.name,
                        date: session.date,
                        status: session.status,
                        start_time: session.start_time,
                        end_time: session.end_time,
                        hostel: session.hostels?.name || 'Unknown'
                    },
                    stats: {
                        total_students: totalStudents,
                        verified: verifiedScans.length,
                        absent: absentScans.length,
                        pending: pendingStudents.length,
                        completion_rate: totalStudents > 0 
                            ? Math.round((verifiedScans.length / totalStudents) * 100) 
                            : 0
                    },
                    scans: scans || [],
                    pending_students: pendingStudents.map(s => ({
                        id: s.id,
                        name: s.name,
                        matric: s.matric,
                        room: s.room_code,
                        face_enrolled: s.face_enrolled
                    }))
                },
                campus: campus
            });
            
        } catch (error) {
            console.error('Error fetching attendance:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// SESSIONS (Global BedCheck Sessions) - UNIFIED
// =====================================================

// ==========================================
// 1. GET ACTIVE SESSION - MUST COME FIRST
// ==========================================
app.get('/api/sessions/active',
    campusIsolation,
    async (req, res) => {
        try {
            const campusContext = req.campus || 'Legacy';
            const adminRoles = ['Admin', 'Developer', 'Administrator', 'Administration'];
            const isAdmin = adminRoles.includes(req.user?.role);

            // ✅ Get the active session (university-wide - no campus filter)
            const { data: session, error } = await supabase
                .from('sessions')
                .select('*')
                .eq('status', 'active')
                .order('date', { ascending: false })
                .limit(1)
                .maybeSingle();

            if (error) {
                console.error('Error fetching active session:', error);
                return res.status(500).json({ 
                    success: false, 
                    message: 'An error occurred. Please try again.',
                    code: 'SERVER_ERROR'
                });
            }

            if (!session) {
                return res.json({ 
                    success: true, 
                    data: null,
                    campus: campusContext,
                    is_active: false
                });
            }

            // ✅ For non-admins, filter stats by their campus
            let campusFilter = isAdmin ? null : campusContext;
            
            // Get hostel IDs for the campus
            let hostelQuery = supabase.from('hostels').select('id');
            if (campusFilter) {
                hostelQuery = hostelQuery.eq('campus', campusFilter);
            }
            const { data: campusHostels } = await hostelQuery;
            const hostelIds = campusHostels?.map(h => h.id) || [];

            // Get bedcheck sessions for this campus
            let bedcheckQuery = supabase
                .from('bedcheck_sessions')
                .select('*')
                .eq('global_session_id', session.id);
            
            if (campusFilter && hostelIds.length > 0) {
                bedcheckQuery = bedcheckQuery.in('hostel_id', hostelIds);
            }
            
            const { data: bedcheckSessions, error: bedcheckError } = await bedcheckQuery;

            if (bedcheckError) {
                console.error('Error fetching bedcheck sessions:', bedcheckError);
            }

            // Get attendance for this campus
            let attendanceQuery = supabase
                .from('bedcheck_attendance')
                .select('*', { count: 'exact', head: true })
                .eq('global_session_id', session.id);
            
            if (campusFilter) {
                attendanceQuery = attendanceQuery.eq('campus', campusFilter);
            }
            const { count: totalStudents } = await attendanceQuery;

            let presentQuery = supabase
                .from('bedcheck_attendance')
                .select('*', { count: 'exact', head: true })
                .eq('global_session_id', session.id)
                .eq('status', 'present');
            
            if (campusFilter) {
                presentQuery = presentQuery.eq('campus', campusFilter);
            }
            const { count: presentStudents } = await presentQuery;

            let scansQuery = supabase
                .from('bedcheck_scans')
                .select('*', { count: 'exact', head: true })
                .eq('session_id', session.id);
            
            if (campusFilter) {
                scansQuery = scansQuery.eq('campus', campusFilter);
            }
            const { count: scansCount } = await scansQuery;

            // Calculate hostel stats
            const totalHostels = bedcheckSessions?.length || 0;
            const completedHostels = bedcheckSessions?.filter(b => b.status === 'completed').length || 0;
            const inProgressHostels = bedcheckSessions?.filter(b => b.status === 'in_progress' || b.status === 'started').length || 0;
            const pendingHostels = bedcheckSessions?.filter(b => b.status === 'pending').length || 0;

            const stats = {
                campus: campusFilter || 'All Campuses',
                total_students: totalStudents || 0,
                present_students: presentStudents || 0,
                scans_count: scansCount || 0,
                total_hostels: totalHostels,
                hostels_completed: completedHostels,
                hostels_in_progress: inProgressHostels,
                hostels_pending: pendingHostels,
                hostel_completion: totalHostels > 0 ? Math.round((completedHostels / totalHostels) * 100) : 0,
                attendance_completion: totalStudents > 0 ? Math.round((presentStudents / totalStudents) * 100) : 0,
                bedcheck_sessions: bedcheckSessions || []
            };

            res.json({ 
                success: true, 
                data: { ...session, stats },
                campus: campusFilter || 'All',
                is_active: true,
                view_all: isAdmin
            });
        } catch (error) {
            console.error('Error fetching active session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 2. GET LATEST SESSION - MUST COME BEFORE /:id
// ==========================================
app.get('/api/sessions/latest',
    campusIsolation,
    async (req, res) => {
        try {
            // ✅ NO CAMPUS FILTER
            const { data: session, error } = await supabase
                .from('sessions')
                .select('*')
                .order('date', { ascending: false })
                .order('created_at', { ascending: false })
                .limit(1)
                .maybeSingle();

            if (error) throw error;
            
            res.json({ 
                success: true, 
                data: session, 
                campus: req.campus || 'Legacy' 
            });
        } catch (error) {
            console.error('Error fetching latest session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 3. GET SESSION STATS - MUST COME BEFORE /:id
// ==========================================
app.get('/api/sessions/stats',
    campusIsolation,
    async (req, res) => {
        try {
            const campusContext = req.campus || 'Legacy';

            // ✅ NO CAMPUS FILTER
            const { data: sessions, error } = await supabase
                .from('sessions')
                .select('status, date')
                .order('date', { ascending: false });

            if (error) throw error;

            const today = new Date().toISOString().split('T')[0];

            const stats = {
                total: sessions?.length || 0,
                scheduled: sessions?.filter(s => s.status === 'scheduled').length || 0,
                active: sessions?.filter(s => s.status === 'active').length || 0,
                completed: sessions?.filter(s => s.status === 'completed').length || 0,
                archived: sessions?.filter(s => s.status === 'archived').length || 0,
                today_sessions: sessions?.filter(s => s.date === today).length || 0,
                today_active: sessions?.filter(s => s.date === today && s.status === 'active').length || 0,
                campus: campusContext
            };

            res.json({ success: true, data: stats });
        } catch (error) {
            console.error('Error fetching session stats:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 4. GET SESSIONS FOR A SPECIFIC HOSTEL - MUST COME BEFORE /:id
// ==========================================
app.get('/api/sessions/hostel/:hostelId',
    campusIsolation,
    validate(validators.hostelId),
    async (req, res) => {
        try {
            const hostelId = parseInt(req.params.hostelId);
            const campusContext = req.campus || 'Legacy';

            // ✅ Verify hostel belongs to this campus
            const { data: hostel } = await supabase
                .from('hostels')
                .select('id, campus')
                .eq('id', hostelId)
                .eq('campus', campusContext)
                .single();

            if (!hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Hostel not found in this campus',
                    code: 'HOSTEL_NOT_FOUND'
                });
            }

            // ✅ NO CAMPUS FILTER on sessions
            const { data: sessions, error: sessionsError } = await supabase
                .from('sessions')
                .select('*')
                .order('date', { ascending: false });

            if (sessionsError) throw sessionsError;

            // ✅ Get bedcheck sessions for this hostel
            const sessionsWithHostelData = await Promise.all((sessions || []).map(async (session) => {
                const { data: bedcheckData } = await supabase
                    .from('bedcheck_sessions')
                    .select('*')
                    .eq('global_session_id', session.id)
                    .eq('hostel_id', hostelId)
                    .eq('campus', campusContext)
                    .maybeSingle();

                // Get attendance for this hostel
                const { data: attendanceData } = await supabase
                    .from('bedcheck_attendance')
                    .select('status')
                    .eq('global_session_id', session.id)
                    .eq('hostel_id', hostelId)
                    .eq('campus', campusContext);

                const total = attendanceData?.length || 0;
                const present = attendanceData?.filter(a => a.status === 'present').length || 0;

                return {
                    ...session,
                    hostel_session: bedcheckData || null,
                    hostel_attendance: {
                        total: total,
                        present: present,
                        absent: total - present,
                        completion: total > 0 ? Math.round((present / total) * 100) : 0
                    }
                };
            }));

            res.json({ 
                success: true, 
                data: sessionsWithHostelData,
                campus: campusContext
            });
        } catch (error) {
            console.error('Error fetching hostel sessions:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 5. GET SESSIONS FOR A SPECIFIC RA - MUST COME BEFORE /:id
// ==========================================
app.get('/api/sessions/ra/:raId',
    campusIsolation,
    validate(validators.staffId),
    async (req, res) => {
        try {
            const raId = parseInt(req.params.raId);
            const campusContext = req.campus || 'Legacy';

            // ✅ Verify RA belongs to this campus
            const { data: ra } = await supabase
                .from('staff')
                .select('id, campus')
                .eq('id', raId)
                .eq('campus', campusContext)
                .single();

            if (!ra) {
                return res.status(404).json({
                    success: false,
                    message: 'RA not found in this campus',
                    code: 'RA_NOT_FOUND'
                });
            }

            // ✅ Get all bedcheck sessions for this RA
            const { data: raSessions, error: raError } = await supabase
                .from('bedcheck_sessions')
                .select(`
                    *,
                    sessions!global_session_id (*),
                    hostels!hostel_id (id, name, type, gender)
                `)
                .eq('ra_id', raId)
                .eq('campus', campusContext)
                .order('created_at', { ascending: false });

            if (raError) throw raError;

            // Get attendance for each session
            const sessionsWithAttendance = await Promise.all((raSessions || []).map(async (raSession) => {
                const { data: attendanceData } = await supabase
                    .from('bedcheck_attendance')
                    .select('status')
                    .eq('global_session_id', raSession.global_session_id)
                    .eq('campus', campusContext);

                const total = attendanceData?.length || 0;
                const present = attendanceData?.filter(a => a.status === 'present').length || 0;

                return {
                    ...raSession,
                    attendance: {
                        total: total,
                        present: present,
                        absent: total - present,
                        completion: total > 0 ? Math.round((present / total) * 100) : 0
                    }
                };
            }));

            res.json({ 
                success: true, 
                data: sessionsWithAttendance,
                campus: campusContext
            });
        } catch (error) {
            console.error('Error fetching RA sessions:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 6. GET ALL SESSIONS (LIST) - NO CAMPUS FILTER
// ==========================================
app.get('/api/sessions',
    campusIsolation,
    validate(validators.pagination),
    async (req, res) => {
        try {
            const limit = Math.min(parseInt(req.query.limit) || 50, 100);
            const offset = parseInt(req.query.offset) || 0;
            const campusContext = req.campus || 'Legacy';
            
            // ✅ NO CAMPUS FILTER on sessions
            const { data: sessions, error, count } = await supabase
                .from('sessions')
                .select('*', { count: 'exact' })
                .order('date', { ascending: false })
                .range(offset, offset + limit - 1);
            
            if (error) {
                console.error('Error fetching sessions:', error);
                return res.status(500).json({ 
                    success: false, 
                    message: 'An error occurred. Please try again.',
                    code: 'SERVER_ERROR'
                });
            }
            
            // Get stats for each session with campus context
            const sessionsWithStats = await Promise.all((sessions || []).map(async (session) => {
                // Get hostel sessions count for this campus
                const { count: hostelSessionsCount } = await supabase
                    .from('bedcheck_sessions')
                    .select('*', { count: 'exact', head: true })
                    .eq('global_session_id', session.id)
                    .eq('campus', campusContext);
                
                // Get attendance count for this campus
                const { count: totalAttendance } = await supabase
                    .from('bedcheck_attendance')
                    .select('*', { count: 'exact', head: true })
                    .eq('global_session_id', session.id)
                    .eq('campus', campusContext);
                
                const { count: presentCount } = await supabase
                    .from('bedcheck_attendance')
                    .select('*', { count: 'exact', head: true })
                    .eq('global_session_id', session.id)
                    .eq('status', 'present')
                    .eq('campus', campusContext);
                
                const { count: scansCount } = await supabase
                    .from('bedcheck_scans')
                    .select('*', { count: 'exact', head: true })
                    .eq('session_id', session.id)
                    .eq('campus', campusContext);
                
                // Get bedcheck session count by status for this campus
                const { data: bedcheckStatuses } = await supabase
                    .from('bedcheck_sessions')
                    .select('status')
                    .eq('global_session_id', session.id)
                    .eq('campus', campusContext);
                
                const completedHostels = bedcheckStatuses?.filter(b => b.status === 'completed').length || 0;
                const totalHostels = bedcheckStatuses?.length || 0;
                const inProgressHostels = bedcheckStatuses?.filter(b => b.status === 'in_progress' || b.status === 'started').length || 0;
                const pendingHostels = bedcheckStatuses?.filter(b => b.status === 'pending').length || 0;
                
                return {
                    ...session,
                    campus_context: campusContext,
                    total_hostels: totalHostels,
                    hostels_completed: completedHostels,
                    hostels_in_progress: inProgressHostels,
                    hostels_pending: pendingHostels,
                    total_students: totalAttendance || 0,
                    present_students: presentCount || 0,
                    scans_count: scansCount || 0,
                    completion: totalAttendance > 0 ? Math.round((presentCount / totalAttendance) * 100) : 0,
                    hostel_completion: totalHostels > 0 ? Math.round((completedHostels / totalHostels) * 100) : 0
                };
            }));
            
            res.json({ 
                success: true, 
                data: sessionsWithStats,
                pagination: { limit, offset, total: count || sessions?.length || 0 },
                campus: campusContext
            });
        } catch (error) {
            console.error('Error fetching sessions:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 7. GET SINGLE SESSION BY ID
// THIS MUST COME AFTER ALL NAMED ROUTES
// ==========================================
app.get('/api/sessions/:id',
    campusIsolation,
    validate(validators.sessionId),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const campusContext = req.campus || 'Legacy';
            
            // ✅ NO CAMPUS FILTER - get session by ID only
            const { data: session, error: sessionError } = await supabase
                .from('sessions')
                .select('*')
                .eq('id', id)
                .single();
            
            if (sessionError || !session) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Session not found',
                    code: 'SESSION_NOT_FOUND'
                });
            }
            
            // ✅ Get hostel IDs for this campus
            const { data: campusHostels } = await supabase
                .from('hostels')
                .select('id')
                .eq('campus', campusContext)
                .eq('status', 'Active');
            
            const hostelIds = campusHostels?.map(h => h.id) || [];

            // ✅ Get bedcheck sessions for this campus
            const { data: bedcheckSessions, error: bedcheckError } = await supabase
                .from('bedcheck_sessions')
                .select(`
                    *,
                    staff!ra_id (id, name, username, email, phone),
                    hostels!hostel_id (id, name, type, gender, campus)
                `)
                .eq('global_session_id', id)
                .in('hostel_id', hostelIds)
                .eq('campus', campusContext);
            
            if (bedcheckError) {
                console.error('Error fetching bedcheck sessions:', bedcheckError);
            }
            
            // ✅ Get attendance for this campus
            const { data: attendance, error: attendanceError } = await supabase
                .from('bedcheck_attendance')
                .select(`
                    *,
                    students!student_id (
                        id, 
                        name, 
                        matric, 
                        room_code, 
                        hostel_id,
                        hostel_name,
                        gender,
                        level,
                        faculty,
                        department,
                        phone,
                        email
                    ),
                    rooms!room_id (
                        id,
                        room_code,
                        capacity
                    ),
                    bed_spaces!bed_space_id (
                        id,
                        bed_code
                    )
                `)
                .eq('global_session_id', id)
                .eq('campus', campusContext);
            
            if (attendanceError) {
                console.error('Error fetching attendance:', attendanceError);
            }
            
            // ✅ Get scans for this campus
            const { data: scans, error: scansError } = await supabase
                .from('bedcheck_scans')
                .select(`
                    *,
                    students!student_id (
                        id, 
                        name, 
                        matric, 
                        room_code,
                        hostel_id,
                        hostel_name
                    )
                `)
                .eq('session_id', id)
                .eq('campus', campusContext);
            
            if (scansError) {
                console.error('Error fetching scans:', scansError);
            }
            
            // Calculate stats for this campus
            const totalAttendance = attendance?.length || 0;
            const presentCount = attendance?.filter(a => a.status === 'present').length || 0;
            const absentCount = attendance?.filter(a => a.status === 'absent').length || 0;
            const verifiedScans = scans?.filter(s => s.status === 'Verified').length || 0;
            const absentScans = scans?.filter(s => s.status === 'Absent').length || 0;
            
            // Group attendance by hostel
            const hostelAttendance = {};
            attendance?.forEach(a => {
                const hostelId = a.hostel_id || a.students?.hostel_id;
                if (hostelId) {
                    if (!hostelAttendance[hostelId]) {
                        hostelAttendance[hostelId] = {
                            total: 0,
                            present: 0,
                            absent: 0,
                            students: []
                        };
                    }
                    hostelAttendance[hostelId].total++;
                    if (a.status === 'present') hostelAttendance[hostelId].present++;
                    if (a.status === 'absent') hostelAttendance[hostelId].absent++;
                    hostelAttendance[hostelId].students.push(a);
                }
            });
            
            // Build hostel breakdown for this campus
            const hostelBreakdown = (bedcheckSessions || []).map(b => {
                const hostelStats = hostelAttendance[b.hostel_id] || { total: 0, present: 0, absent: 0 };
                return {
                    hostel_id: b.hostel_id,
                    hostel: b.hostels || { name: 'Unknown', type: '—', gender: '—' },
                    ra: b.staff || { name: 'Not assigned', id: null },
                    total_students: hostelStats.total || 0,
                    present_students: hostelStats.present || 0,
                    absent_students: hostelStats.absent || 0,
                    completion: hostelStats.total > 0 ? Math.round((hostelStats.present / hostelStats.total) * 100) : 0,
                    status: b.status || 'pending',
                    started_at: b.started_at,
                    completed_at: b.completed_at,
                    students: hostelStats.students || []
                };
            });
            
            // Get total students for this campus
            const { count: totalStudents } = await supabase
                .from('students')
                .select('*', { count: 'exact', head: true })
                .eq('campus', campusContext);
            
            const response = {
                ...session,
                campus_context: campusContext,
                total_students: totalStudents || 0,
                attendance_count: totalAttendance,
                present_students: presentCount,
                absent_students: absentCount,
                verified_scans: verifiedScans,
                absent_scans: absentScans,
                attendance_rate: totalAttendance > 0 ? Math.round((presentCount / totalAttendance) * 100) : 0,
                completion: totalStudents > 0 ? Math.round((presentCount / totalStudents) * 100) : 0,
                hostels: hostelBreakdown,
                bedcheck_sessions: bedcheckSessions || [],
                attendance: attendance || [],
                scans: scans || [],
                attendance_by_hostel: hostelAttendance
            };
            
            res.json({ success: true, data: response, campus: campusContext });
        } catch (error) {
            console.error('Error fetching session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 8. CREATE SESSION (Admin creates the master session)
// ==========================================
app.post('/api/sessions',
    campusIsolation,
    requireRole('Admin', 'Developer', 'RASD'),
    validate(validators.sessionCreate),
    async (req, res) => {
        try {
            const { 
                name, 
                date, 
                start_time, 
                end_time, 
                status, 
                academic_session,
                grace_period
            } = req.body;
            
            // Validate required fields
            if (!name || !date || !start_time || !end_time) {
                return res.status(400).json({
                    success: false,
                    message: 'Name, date, start time, and end time are required',
                    code: 'MISSING_REQUIRED_FIELDS'
                });
            }
            
            // ✅ Check if session already exists for this date (university-wide)
            const { data: existing, error: checkError } = await supabase
                .from('sessions')
                .select('id, status')
                .eq('date', date)
                .maybeSingle();
            
            if (checkError) {
                console.error('Error checking existing session:', checkError);
            }
            
            if (existing) {
                return res.status(400).json({
                    success: false,
                    message: `A session already exists for ${date}`,
                    code: 'SESSION_EXISTS'
                });
            }
            
            // ✅ Create UNIVERSITY-WIDE session (campus = NULL)
            const newSession = {
                name: name,
                date: date,
                start_time: start_time,
                end_time: end_time,
                status: status || 'scheduled',
                academic_session: academic_session || '2026/2027',
                grace_period: grace_period || 15,
                campus: null,  // ✅ NULL = ALL CAMPUSES
                campus_code: null,  // ✅ NULL = ALL CAMPUSES
                total_hostels: 0,
                hostels_completed: 0,
                completion: 0,
                created_by: req.user.id,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };
            
            const { data: session, error: insertError } = await supabase
                .from('sessions')
                .insert(newSession)
                .select()
                .single();
            
            if (insertError) {
                console.error('Error creating session:', insertError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to create session',
                    code: 'DATABASE_ERROR'
                });
            }
            
            // ✅ If session is active, create bedcheck_sessions for ALL campuses
            if (session.status === 'active') {
                await createUniversityWideBedcheckSessions(session.id);
            }
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'University-Wide Session Created',
                module: 'sessions',
                details: `Created university-wide session: ${session.name} for ${session.date}`,
                result: 'success',
                category: 'sessions',
                tone: 'blue',
                session_id: session.id,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                data: session,
                message: 'University-wide session created successfully'
            });
        } catch (error) {
            console.error('Error creating session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 9. UPDATE SESSION (Admin activates the general session)
// ==========================================
app.put('/api/sessions/:id',
    campusIsolation,
    requireRole('Admin', 'RASD', 'Developer'),
    validate(validators.sessionId),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const { 
                name, 
                date, 
                start_time, 
                end_time, 
                status,
                academic_session,
                grace_period
            } = req.body;
            
            // ✅ Get the session (it's university-wide, so no campus filter)
            const { data: existing, error: existingError } = await supabase
                .from('sessions')
                .select('*')
                .eq('id', id)
                .maybeSingle();
            
            if (existingError || !existing) {
                return res.status(404).json({
                    success: false,
                    message: 'Session not found',
                    code: 'SESSION_NOT_FOUND'
                });
            }
            
            const updateData = {};
            const changes = [];
            
            if (name !== undefined) { updateData.name = name; changes.push('name'); }
            if (date !== undefined) { updateData.date = date; changes.push('date'); }
            if (start_time !== undefined) { updateData.start_time = start_time; changes.push('start_time'); }
            if (end_time !== undefined) { updateData.end_time = end_time; changes.push('end_time'); }
            if (grace_period !== undefined) { updateData.grace_period = grace_period; changes.push('grace_period'); }
            if (academic_session !== undefined) { updateData.academic_session = academic_session; changes.push('academic_session'); }
            
            if (status !== undefined) { 
                updateData.status = status; 
                changes.push('status'); 
                
                if (status === 'active' && existing.status !== 'active') {
                    updateData.started_at = new Date().toISOString();
                    // ✅ Create bedcheck sessions for ALL hostels when activating
                    await createUniversityWideBedcheckSessions(id);
                }
                
                if (status === 'completed' && existing.status !== 'completed') {
                    updateData.completed_at = new Date().toISOString();
                    // ✅ Mark unverified as absent for ALL campuses
                    await markUnverifiedAsAbsentUniversityWide(id);
                }
            }
            
            updateData.updated_at = new Date().toISOString();
            
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update',
                    code: 'NO_FIELDS_TO_UPDATE'
                });
            }
            
            const { data: updated, error: updateError } = await supabase
                .from('sessions')
                .update(updateData)
                .eq('id', id)
                .select()
                .single();
            
            if (updateError) {
                console.error('Error updating session:', updateError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to update session',
                    code: 'DATABASE_ERROR'
                });
            }
            
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: `University-Wide Session ${status === 'active' ? 'Activated' : status === 'completed' ? 'Completed' : 'Updated'}`,
                module: 'sessions',
                details: `Session: ${updated.name} - Status: ${updated.status}`,
                result: 'success',
                category: 'sessions',
                tone: status === 'active' ? 'green' : status === 'completed' ? 'blue' : 'gold',
                session_id: id,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({ 
                success: true, 
                data: updated,
                message: `Session ${status === 'active' ? 'activated' : status === 'completed' ? 'completed' : 'updated'} successfully`
            });
        } catch (error) {
            console.error('Error updating session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 10. DELETE SESSION
// ==========================================
app.delete('/api/sessions/:id',
    campusIsolation,
    requireRole('Admin', 'RASD', 'Developer'),
    validate(validators.sessionId),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            
            // ✅ Get session without campus filter
            const { data: session, error: fetchError } = await supabase
                .from('sessions')
                .select('name, date, status')
                .eq('id', id)
                .single();

            if (fetchError || !session) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'Session not found',
                    code: 'SESSION_NOT_FOUND'
                });
            }

            // ✅ Delete related records for ALL campuses
            await supabase
                .from('bedcheck_scans')
                .delete()
                .eq('session_id', id);

            await supabase
                .from('bedcheck_attendance')
                .delete()
                .eq('global_session_id', id);

            await supabase
                .from('bedcheck_sessions')
                .delete()
                .eq('global_session_id', id);

            await supabase
                .from('hostel_progress')
                .delete()
                .eq('session_id', id);

            await supabase
                .from('room_verifications')
                .delete()
                .eq('session_id', id);

            // Delete the session
            const { error: deleteError } = await supabase
                .from('sessions')
                .delete()
                .eq('id', id);

            if (deleteError) {
                console.error('Error deleting session:', deleteError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to delete session',
                    code: 'DATABASE_ERROR'
                });
            }

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'University-Wide Session Deleted',
                module: 'sessions',
                details: `Deleted session: ${session.name} (${session.date})`,
                result: 'success',
                category: 'sessions',
                tone: 'red',
                session_id: id,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({ 
                success: true, 
                message: 'Session deleted successfully'
            });
        } catch (error) {
            console.error('Error deleting session:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// ==========================================
// 11. SESSION MANAGEMENT (RASD/Admin Only)
// ==========================================
app.post('/api/sessions/manage',
    campusIsolation,
    requireRole('Admin', 'RASD', 'Developer'),
    validate([
        body('action').isIn(['create', 'activate', 'complete', 'archive']).withMessage('Invalid action'),
        body('session_id').optional().isInt().withMessage('Invalid session ID'),
        body('date').optional().isISO8601().withMessage('Invalid date'),
        body('start_time').optional().isString().withMessage('Invalid start time'),
        body('end_time').optional().isString().withMessage('Invalid end time'),
        body('total_hostels').optional().isInt({ min: 1 }).withMessage('Total hostels must be at least 1')
    ]),
    async (req, res) => {
        try {
            const { action, session_id, date, start_time, end_time, total_hostels } = req.body;
            const campusContext = req.campus || 'Legacy';
            let result = null;
            
            switch (action) {
                case 'create':
                    const sessionDate = date || new Date().toISOString().split('T')[0];
                    
                    // ✅ Check if session already exists for this date (university-wide)
                    const { data: existing } = await supabase
                        .from('sessions')
                        .select('id')
                        .eq('date', sessionDate)
                        .maybeSingle();
                    
                    if (existing) {
                        return res.status(400).json({
                            success: false,
                            message: 'Session already exists for this date',
                            code: 'SESSION_EXISTS'
                        });
                    }
                    
                    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
                    const dayName = dayNames[new Date(sessionDate).getDay()] || 'Night';
                    
                    // ✅ Create university-wide session
                    const { data: newSession, error: createError } = await supabase
                        .from('sessions')
                        .insert({
                            date: sessionDate,
                            name: `${dayName} Night BedCheck`,
                            status: 'scheduled',
                            start_time: start_time || '22:00:00',
                            end_time: end_time || '23:30:00',
                            total_hostels: total_hostels || 0,
                            hostels_completed: 0,
                            completion: 0,
                            academic_session: '2026/2027',
                            grace_period: 15,
                            created_by: req.user.id,
                            campus: null,  // ✅ University-wide
                            campus_code: null,  // ✅ University-wide
                            created_at: new Date().toISOString(),
                            updated_at: new Date().toISOString()
                        })
                        .select()
                        .single();
                    
                    if (createError) throw createError;
                    result = newSession;
                    break;
                    
                case 'activate':
                    if (!session_id) {
                        return res.status(400).json({
                            success: false,
                            message: 'Session ID required',
                            code: 'SESSION_ID_REQUIRED'
                        });
                    }
                    
                    // ✅ Activate without campus filter
                    const { data: activated, error: activateError } = await supabase
                        .from('sessions')
                        .update({ 
                            status: 'active', 
                            started_at: new Date().toISOString(),
                            updated_at: new Date().toISOString()
                        })
                        .eq('id', session_id)
                        .select()
                        .single();
                    
                    if (activateError) throw activateError;
                    
                    // ✅ Create bedcheck sessions for ALL hostels
                    await createUniversityWideBedcheckSessions(session_id);
                    
                    result = activated;
                    break;
                    
                case 'complete':
                    if (!session_id) {
                        return res.status(400).json({
                            success: false,
                            message: 'Session ID required',
                            code: 'SESSION_ID_REQUIRED'
                        });
                    }
                    
                    // ✅ Complete without campus filter
                    const { data: completed, error: completeError } = await supabase
                        .from('sessions')
                        .update({ 
                            status: 'completed', 
                            completed_at: new Date().toISOString(),
                            updated_at: new Date().toISOString()
                        })
                        .eq('id', session_id)
                        .select()
                        .single();
                    
                    if (completeError) throw completeError;
                    
                    // ✅ Mark unverified as absent for ALL campuses
                    await markUnverifiedAsAbsentUniversityWide(session_id);
                    
                    result = completed;
                    break;
                    
                case 'archive':
                    if (!session_id) {
                        return res.status(400).json({
                            success: false,
                            message: 'Session ID required',
                            code: 'SESSION_ID_REQUIRED'
                        });
                    }
                    
                    // ✅ Archive without campus filter
                    const { data: archived, error: archiveError } = await supabase
                        .from('sessions')
                        .update({ 
                            status: 'archived', 
                            archived_at: new Date().toISOString(),
                            updated_at: new Date().toISOString()
                        })
                        .eq('id', session_id)
                        .select()
                        .single();
                    
                    if (archiveError) throw archiveError;
                    result = archived;
                    break;
                    
                default:
                    return res.status(400).json({
                        success: false,
                        message: 'Invalid action',
                        code: 'INVALID_ACTION'
                    });
            }
            
            // Log audit
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: `University-Wide Session ${action}`,
                module: 'sessions',
                details: `Session ${action}ed: ${result?.name || 'N/A'} (${result?.date || 'N/A'})`,
                context: `Session ID: ${result?.id || 'N/A'}`,
                result: 'success',
                category: 'sessions',
                tone: 'blue',
                session_id: result?.id,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });
            
            res.json({
                success: true,
                data: result,
                message: `Session ${action}ed successfully`
            });
            
        } catch (error) {
            console.error(`Session management error:`, error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// EMERGENCY SECURITY ENDPOINTS
// =====================================================

app.post('/api/admin/block-ip', 
    campusIsolation,
    requireRole('Developer'),
    validate([
        body('ip').isIP().withMessage('Invalid IP address'),
        body('reason').optional().isString().withMessage('Reason must be a string')
    ]),
    async (req, res) => {
        const { ip, reason } = req.body;
        ipBlacklist.addToBlacklist(ip, reason || 'Admin block');
        
        await auditService.log({
            actor: req.user.name || req.user.username,
            actor_id: req.user.id,
            actor_role: req.user.role,
            action: 'IP Blocked',
            module: 'security',
            details: `IP ${ip} blocked: ${reason || 'Admin action'}`,
            result: 'success',
            category: 'security',
            campus: req.campus,
            ip_address: req.clientIp,
            user_agent: req.userAgent
        });
        
        res.json({ 
            success: true, 
            message: `IP ${ip} blocked successfully`,
            campus: req.campus
        });
    }
);

app.post('/api/admin/unblock-ip',
    campusIsolation,
    requireRole('Developer'),
    validate([
        body('ip').isIP().withMessage('Invalid IP address')
    ]),
    async (req, res) => {
        const { ip } = req.body;
        ipBlacklist.removeFromBlacklist(ip);
        
        await auditService.log({
            actor: req.user.name || req.user.username,
            actor_id: req.user.id,
            actor_role: req.user.role,
            action: 'IP Unblocked',
            module: 'security',
            details: `IP ${ip} unblocked`,
            result: 'success',
            category: 'security',
            campus: req.campus,
            ip_address: req.clientIp,
            user_agent: req.userAgent
        });
        
        res.json({ 
            success: true, 
            message: `IP ${ip} unblocked successfully`,
            campus: req.campus
        });
    }
);

app.post('/api/admin/lockdown',
    campusIsolation,
    requireRole('Developer'),
    validate([
        body('duration').optional().isInt({ min: 1, max: 1440 }).withMessage('Duration must be between 1 and 1440 minutes')
    ]),
    async (req, res) => {
        const duration = req.body.duration || 30;
        const activeIPs = Array.from(rateLimiterFirewall.requestHistory.keys())
            .map(key => key.split(':')[0])
            .filter(ip => !ipBlacklist.whitelist.has(ip));
        
        const uniqueIPs = [...new Set(activeIPs)];
        uniqueIPs.forEach(ip => {
            ipBlacklist.addToBlacklist(ip, `Emergency lockdown for ${duration} minutes`);
        });
        
        setTimeout(() => {
            uniqueIPs.forEach(ip => {
                ipBlacklist.removeFromBlacklist(ip);
            });
            console.log(`🔓 Emergency lockdown lifted after ${duration} minutes`);
        }, duration * 60 * 1000);
        
        await auditService.log({
            actor: req.user.name || req.user.username,
            actor_id: req.user.id,
            actor_role: req.user.role,
            action: 'System Lockdown',
            module: 'security',
            details: `Emergency lockdown activated for ${duration} minutes. ${uniqueIPs.length} IPs blocked.`,
            result: 'success',
            category: 'security',
            campus: req.campus,
            ip_address: req.clientIp,
            user_agent: req.userAgent
        });
        
        res.json({ 
            success: true, 
            message: `Emergency lockdown activated for ${duration} minutes. ${uniqueIPs.length} IPs blocked.`,
            blocked_ips: uniqueIPs.length,
            duration: duration,
            campus: req.campus
        });
    }
);

app.get('/api/admin/security-status',
    campusIsolation,
    requireRole('Admin', 'Developer'),
    async (req, res) => {
        try {
            const now = Date.now();
            const activeBlocks = Array.from(rateLimiterFirewall.blockedIPs.entries())
                .filter(([_, data]) => data.expiry > now)
                .map(([ip, data]) => ({
                    ip,
                    expiry: new Date(data.expiry).toISOString(),
                    reason: data.reason
                }));
            
            const failedAttempts = Array.from(rateLimiterFirewall.failedAttempts.entries())
                .filter(([_, data]) => data.timestamp > now - 3600000)
                .map(([ip, data]) => ({
                    ip,
                    count: data.count,
                    last_attempt: new Date(data.timestamp).toISOString()
                }));
            
            const requestStats = Array.from(rateLimiterFirewall.requestHistory.entries())
                .filter(([_, data]) => data.timestamp > now - 60000)
                .map(([key, data]) => ({
                    key,
                    count: data.count,
                    last_request: new Date(data.timestamp).toISOString()
                }));
            
            res.json({
                success: true,
                data: {
                    active_blocks: activeBlocks,
                    total_blocked: activeBlocks.length,
                    failed_attempts: failedAttempts,
                    total_failed_attempts: failedAttempts.length,
                    request_stats: requestStats,
                    total_requests: requestStats.length,
                    blacklist_ips: Array.from(ipBlacklist.manualBlacklist),
                    whitelist_ips: Array.from(ipBlacklist.whitelist),
                    threat_levels: {
                        high: Array.from(rateLimiterFirewall.failedAttempts.entries())
                            .filter(([_, data]) => data.count >= 5)
                            .length,
                        medium: Array.from(rateLimiterFirewall.failedAttempts.entries())
                            .filter(([_, data]) => data.count >= 3 && data.count < 5)
                            .length,
                        low: Array.from(rateLimiterFirewall.failedAttempts.entries())
                            .filter(([_, data]) => data.count < 3)
                            .length
                    },
                    timestamp: new Date().toISOString(),
                    circuit_breaker: {
                        open: faceService.circuitOpen,
                        failures: faceService.failureCount,
                        max_failures: faceService.maxFailures
                    }
                },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching security status:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR',
                campus: req.campus
            });
        }
    }
);

// =====================================================
// RA ROOM ASSIGNMENTS (HRA Only)
// =====================================================

app.get('/api/hra/ras',
    campusIsolation,
    requireRole('HRA', 'Admin', 'Developer'),
    async (req, res) => {
        try {
            let hostelId = req.user.hostel_id;
            
            if ((req.user.role === 'Admin' || req.user.role === 'Developer' || req.user.role === 'Administrator') && req.query.hostel_id) {
                hostelId = parseInt(req.query.hostel_id);
            }

            if (!hostelId) {
                return res.status(400).json({
                    success: false,
                    message: 'No hostel assigned to this HRA',
                    code: 'NO_HOSTEL_ASSIGNED'
                });
            }

            const { data: hostel, error: hostelError } = await supabase
                .from('hostels')
                .select('id, name, assignment_type')
                .eq('id', hostelId)
                .eq('campus', req.campus)
                .single();

            if (hostelError || !hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Hostel not found in this campus',
                    code: 'HOSTEL_NOT_FOUND'
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
                    .select(`
                        ra_id, 
                        room_id,
                        rooms!inner (room_code, id)
                    `)
                    .in('ra_id', raIds)
                    .eq('status', 'active')
                    .eq('campus', req.campus);
                assignments = assignData || [];
            }

            const { data: rooms, error: roomsError } = await supabase
                .from('rooms')
                .select(`
                    id, 
                    room_code, 
                    capacity, 
                    occupied, 
                    status, 
                    floor_flat_id,
                    floors_flats!inner (name)
                `)
                .eq('floors_flats.hostel_id', hostelId)
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

            const assignedRoomIds = new Set(assignments.map(a => a.room_id));
            const totalRooms = rooms?.length || 0;
            const assignedRoomsCount = assignedRoomIds.size;
            const unassignedRoomsCount = totalRooms - assignedRoomsCount;

            res.json({
                success: true,
                data: {
                    hostel: { 
                        id: hostel.id, 
                        name: hostel.name, 
                        assignment_type: hostel.assignment_type || 'room_range' 
                    },
                    ras: enrichedRas,
                    rooms: rooms || [],
                    total_ras: ras.length,
                    total_rooms: totalRooms,
                    assigned_rooms_count: assignedRoomsCount,
                    unassigned_rooms_count: unassignedRoomsCount
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Error fetching RAs:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/hra/assign-rooms',
    campusIsolation,
    requireRole('HRA', 'Admin', 'Developer'),
    validate(validators.raRoomAssignment),
    async (req, res) => {
        try {
            const { ra_id, room_ids } = req.body;
            const hraId = req.user.id;

            if (!req.user.hostel_id && req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator') {
                return res.status(400).json({
                    success: false,
                    message: 'You are not assigned to a hostel.',
                    code: 'NO_HOSTEL_ASSIGNED'
                });
            }

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
                    message: 'RA not found in this campus',
                    code: 'RA_NOT_FOUND'
                });
            }

            if (req.user.role === 'HRA' && req.user.hostel_id !== ra.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only assign rooms in your hostel.',
                    code: 'PERMISSION_DENIED'
                });
            }

            // ✅ FIX: Accept multiple room statuses (active, available, Active, Available)
            const { data: rooms, error: roomsError } = await supabase
                .from('rooms')
                .select(`
                    id, 
                    room_code, 
                    floor_flat_id,
                    floors_flats!inner (hostel_id)
                `)
                .in('id', room_ids)
                .eq('floors_flats.hostel_id', ra.hostel_id)
                .in('status', ['active', 'available', 'Active', 'Available']);  // ← FIXED HERE

            if (roomsError) throw roomsError;

            if (!rooms || rooms.length !== room_ids.length) {
                // Log the mismatch for debugging
                console.warn('ROOM_NOT_FOUND', {
                    requested: room_ids,
                    found: rooms?.map(r => r.id) || [],
                    ra_hostel: ra.hostel_id,
                    campus: req.campus
                });
                return res.status(400).json({
                    success: false,
                    message: 'One or more rooms not found or not in this hostel',
                    code: 'ROOM_NOT_FOUND'
                });
            }

            // Delete existing assignments for this RA
            await supabase
                .from('ra_room_assignments')
                .delete()
                .eq('ra_id', ra_id)
                .eq('campus', req.campus);

            // Create new assignments
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
                .select(`
                    *,
                    rooms!inner (room_code)
                `);

            if (assignError) throw assignError;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'RA Room Assignment',
                module: 'ra_assignments',
                details: `Assigned ${rooms.length} rooms to RA ${ra.name}`,
                context: `Rooms: ${rooms.map(r => r.room_code).join(', ')}`,
                result: 'success',
                category: 'staff',
                tone: 'blue',
                hostel_id: ra.hostel_id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.delete('/api/hra/remove-rooms/:ra_id',
    campusIsolation,
    requireRole('HRA', 'Admin', 'Developer'),
    validate([
        param('ra_id').isInt().withMessage('Invalid RA ID'),
        body('room_ids').isArray().withMessage('room_ids must be an array')
    ]),
    async (req, res) => {
        try {
            const raId = parseInt(req.params.ra_id);
            const { room_ids } = req.body;

            const { data: ra, error: raError } = await supabase
                .from('staff')
                .select('id, name, hostel_id, campus')
                .eq('id', raId)
                .eq('role', 'RA')
                .eq('status', 'Active')
                .eq('campus', req.campus)
                .single();

            if (raError || !ra) {
                return res.status(404).json({
                    success: false,
                    message: 'RA not found in this campus',
                    code: 'RA_NOT_FOUND'
                });
            }

            if (req.user.role === 'HRA' && req.user.hostel_id !== ra.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only manage RAs in your hostel.',
                    code: 'PERMISSION_DENIED'
                });
            }

            const { data, error } = await supabase
                .from('ra_room_assignments')
                .delete()
                .eq('ra_id', raId)
                .in('room_id', room_ids)
                .eq('campus', req.campus)
                .select();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: req.user.role,
                action: 'RA Rooms Removed',
                module: 'ra_assignments',
                details: `Removed ${room_ids.length} rooms from RA ${ra.name}`,
                context: `Room IDs: ${room_ids.join(', ')}`,
                result: 'success',
                category: 'staff',
                tone: 'gold',
                hostel_id: ra.hostel_id,
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                message: `Removed ${room_ids.length} rooms from ${ra.name}`,
                data: { removed_count: room_ids.length },
                campus: req.campus
            });

        } catch (error) {
            console.error('Error removing rooms:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.get('/api/hra/hostel-overview',
    campusIsolation,
    requireRole('HRA', 'Admin', 'Developer'),
    async (req, res) => {
        try {
            let hostelId = req.user.hostel_id;
            
            if ((req.user.role === 'Admin' || req.user.role === 'Developer' || req.user.role === 'Administrator') && req.query.hostel_id) {
                hostelId = parseInt(req.query.hostel_id);
            }

            if (!hostelId) {
                return res.status(400).json({
                    success: false,
                    message: 'No hostel assigned',
                    code: 'NO_HOSTEL_ASSIGNED'
                });
            }

            const { data: hostel, error: hostelError } = await supabase
                .from('hostels')
                .select('*')
                .eq('id', hostelId)
                .eq('campus', req.campus)
                .single();

            if (hostelError || !hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Hostel not found',
                    code: 'HOSTEL_NOT_FOUND'
                });
            }

            const { data: ras, error: rasError } = await supabase
                .from('staff')
                .select('id, name, username, email, phone, status')
                .eq('hostel_id', hostelId)
                .eq('role', 'RA')
                .eq('status', 'Active')
                .eq('campus', req.campus);

            if (rasError) throw rasError;

            const raIds = ras.map(r => r.id);
            let assignments = [];
            if (raIds.length > 0) {
                const { data: assignData } = await supabase
                    .from('ra_room_assignments')
                    .select('ra_id, room_id, rooms(room_code)')
                    .in('ra_id', raIds)
                    .eq('status', 'active')
                    .eq('campus', req.campus);
                assignments = assignData || [];
            }

            const enrichedRas = ras.map(ra => {
                const raAssignments = assignments.filter(a => a.ra_id === ra.id);
                return {
                    ...ra,
                    assigned_rooms: raAssignments.length,
                    assigned_room_codes: raAssignments.map(a => a.rooms?.room_code).filter(Boolean).sort()
                };
            });

            const { data: students, error: studentsError } = await supabase
                .from('students')
                .select('status, face_enrolled')
                .eq('hostel_id', hostelId)
                .eq('campus', req.campus);

            if (studentsError) throw studentsError;

            const totalStudents = students?.length || 0;
            const present = students?.filter(s => s.status === 'Present').length || 0;
            const absent = students?.filter(s => s.status === 'Absent').length || 0;
            const faceEnrolled = students?.filter(s => s.face_enrolled === true).length || 0;

            const { data: bedSpaces, error: bedError } = await supabase
                .from('bed_spaces')
                .select('status')
                .eq('campus', req.campus)
                .in('room_id', (await supabase
                    .from('rooms')
                    .select('id')
                    .eq('campus', req.campus)
                    .in('floor_flat_id', (await supabase
                        .from('floors_flats')
                        .select('id')
                        .eq('hostel_id', hostelId)
                        .eq('campus', req.campus))
                        .data?.map(f => f.id) || [])
                ).data?.map(r => r.id) || []);

            const totalBeds = bedSpaces?.length || 0;
            const occupiedBeds = bedSpaces?.filter(b => b.status === 'occupied').length || 0;

            res.json({
                success: true,
                data: {
                    hostel: {
                        id: hostel.id,
                        name: hostel.name,
                        type: hostel.type,
                        gender: hostel.gender,
                        total_rooms: hostel.total_rooms,
                        total_beds: hostel.total_beds
                    },
                    ras: enrichedRas,
                    total_ras: ras.length,
                    students: {
                        total: totalStudents,
                        present,
                        absent,
                        face_enrolled
                    },
                    beds: {
                        total: totalBeds,
                        occupied: occupiedBeds,
                        available: totalBeds - occupiedBeds,
                        occupancy_rate: totalBeds > 0 ? Math.round((occupiedBeds / totalBeds) * 100) : 0
                    }
                },
                campus: req.campus
            });

        } catch (error) {
            console.error('Error fetching hostel overview:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// RA DASHBOARD - WITH ROOM ASSIGNMENTS
// =====================================================

app.get('/api/ra/dashboard',
    campusIsolation,
    requireRole('RA'),
    async (req, res) => {
        try {
            const raId = req.user.id;

            const { data: assignments, error: roomsError } = await supabase
                .from('ra_room_assignments')
                .select(`
                    room_id,
                    rooms!inner (
                        id, room_code, capacity, occupied, status,
                        floor_flat_id,
                        floors_flats!inner (
                            name, hostel_id,
                            hostels!inner (id, name, campus)
                        )
                    )
                `)
                .eq('ra_id', raId)
                .eq('status', 'active')
                .eq('campus', req.campus);

            if (roomsError) {
                console.error('Fetch RA rooms error:', roomsError);
                return res.status(500).json({
                    success: false,
                    message: 'An error occurred. Please try again.',
                    code: 'SERVER_ERROR'
                });
            }

            const assignedRooms = assignments
                .map(a => a.rooms)
                .filter(Boolean)
                .map(room => ({
                    id: room.id,
                    room_code: room.room_code,
                    capacity: room.capacity || 4,
                    occupied: room.occupied || 0,
                    floor: room.floors_flats?.name || 'Unknown',
                    hostel: room.floors_flats?.hostels?.name || 'Unknown',
                    hostel_id: room.floors_flats?.hostel_id || null
                }));

            if (assignedRooms.length === 0) {
                return res.json({
                    success: true,
                    data: {
                        assigned_rooms: [],
                        room_count: 0,
                        room_codes: [],
                        active_session: null,
                        has_active_session: false,
                        has_completed_today: false,
                        is_suspicious: false,
                        can_start_new: false,
                        message: 'No rooms assigned. Please contact your HRA.'
                    },
                    campus: req.campus
                });
            }

            const hostelId = assignedRooms[0]?.hostel_id || req.user.hostel_id;

            const { data: activeSession } = await supabase
                .from('ra_bedcheck_sessions')
                .select('*')
                .eq('ra_id', raId)
                .eq('campus', req.campus)
                .eq('status', 'started')
                .maybeSingle();

            const today = new Date().toISOString().split('T')[0];
            const { data: completedToday } = await supabase
                .from('ra_bedcheck_sessions')
                .select('id')
                .eq('ra_id', raId)
                .eq('campus', req.campus)
                .eq('status', 'completed')
                .gte('completed_at', `${today}T00:00:00`)
                .lt('completed_at', `${today}T23:59:59`)
                .maybeSingle();

            const { data: suspiciousData } = await supabase
                .from('ra_bedcheck_sessions')
                .select('id, is_suspicious, suspicious_reason')
                .eq('ra_id', raId)
                .eq('campus', req.campus)
                .eq('is_suspicious', true)
                .maybeSingle();

            res.json({
                success: true,
                data: {
                    assigned_rooms: assignedRooms,
                    room_count: assignedRooms.length,
                    room_codes: assignedRooms.map(r => r.room_code).sort(),
                    hostel_id: hostelId,
                    active_session: activeSession || null,
                    has_active_session: !!activeSession,
                    has_completed_today: !!completedToday,
                    is_suspicious: !!suspiciousData,
                    suspicious_reason: suspiciousData?.suspicious_reason || null,
                    can_start_new: !activeSession && !completedToday && !suspiciousData,
                    message: !activeSession && !completedToday && !suspiciousData 
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                .select(`
                    room_id,
                    rooms!inner (
                        id, room_code, capacity, occupied, status,
                        floor_flat_id,
                        floors_flats!inner (
                            name, hostel_id,
                            hostels!inner (id, name, campus)
                        )
                    )
                `)
                .eq('ra_id', raId)
                .eq('status', 'active')
                .eq('campus', req.campus);

            if (error) {
                console.error('Fetch RA rooms error:', error);
                return res.status(500).json({
                    success: false,
                    message: 'An error occurred. Please try again.',
                    code: 'SERVER_ERROR'
                });
            }

            const rooms = assignments
                .map(a => a.rooms)
                .filter(Boolean)
                .map(room => ({
                    id: room.id,
                    room_code: room.room_code,
                    capacity: room.capacity || 4,
                    occupied: room.occupied || 0,
                    available: (room.capacity || 4) - (room.occupied || 0),
                    floor: room.floors_flats?.name || 'Unknown',
                    hostel: room.floors_flats?.hostels?.name || 'Unknown',
                    hostel_id: room.floors_flats?.hostel_id || null
                }));

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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// RA BEDCHECK START - CHECKS GLOBAL SESSION
// =====================================================
app.post('/api/ra/bedcheck/start',
    campusIsolation,
    requireRole('RA'),
    validate(validators.bedcheckStart),
    async (req, res) => {
        try {
            const { session_id } = req.body;
            const raId = req.user.id;
            const campusContext = req.campus || 'Legacy';
            const hostelId = req.user.hostel_id;

            // ✅ Find active global session WITHOUT campus filter
            let globalSessionId = session_id;
            
            if (!globalSessionId) {
                const { data: globalSessions, error: globalError } = await supabase
                    .from('sessions')
                    .select('id')
                    .eq('status', 'active')
                    // REMOVED: .eq('campus', campusContext)
                    .order('created_at', { ascending: false })
                    .limit(1);
                
                if (!globalError && globalSessions && globalSessions.length > 0) {
                    globalSessionId = globalSessions[0].id;
                    console.log(`📋 Using global session ${globalSessionId} for RA ${raId} (${campusContext})`);
                } else {
                    return res.status(400).json({
                        success: false,
                        message: 'No active BedCheck session available. Please wait for the session to start.',
                        code: 'NO_ACTIVE_SESSION'
                    });
                }
            }

            // ✅ Verify RA has assigned rooms
            const { data: assignedRooms, error: roomsError } = await supabase
                .from('ra_room_assignments')
                .select('room_id, rooms(room_code, id, floor_flat_id)')
                .eq('ra_id', raId)
                .eq('status', 'active')
                .eq('campus', campusContext);

            if (roomsError) throw roomsError;

            if (!assignedRooms || assignedRooms.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'No rooms assigned to you. Please contact your HRA.',
                    code: 'NO_ROOMS_ASSIGNED'
                });
            }

            // ✅ Check if RA already has a bedcheck session for this global session
            const { data: existing, error: checkError } = await supabase
                .from('bedcheck_sessions')
                .select('id, status, started_at, completed_at')
                .eq('ra_id', raId)
                .eq('global_session_id', globalSessionId)
                .eq('hostel_id', hostelId)
                .eq('campus', campusContext)
                .maybeSingle();

            if (checkError) throw checkError;

            if (existing) {
                if (existing.status === 'completed') {
                    return res.status(403).json({
                        success: false,
                        message: 'You have already completed today\'s BedCheck.',
                        code: 'SESSION_ALREADY_COMPLETED',
                        data: {
                            completed_at: existing.completed_at
                        }
                    });
                }

                if (existing.status === 'started' || existing.status === 'in_progress') {
                    return res.json({
                        success: true,
                        data: {
                            session_id: globalSessionId,
                            bedcheck_session: existing,
                            status: existing.status,
                            started_at: existing.started_at,
                            message: 'BedCheck already started',
                            is_new_session: false
                        },
                        campus: campusContext
                    });
                }
            }

            // ✅ Get total students for this hostel
            const { data: students, error: studentsError } = await supabase
                .from('students')
                .select('id')
                .eq('hostel_id', hostelId)
                .eq('campus', campusContext)
                .eq('status', 'Active');

            if (studentsError) throw studentsError;

            const totalStudents = students?.length || 0;

            // ✅ Create bedcheck session (using bedcheck_sessions table)
            const { data: bedcheckSession, error: sessionError } = await supabase
                .from('bedcheck_sessions')
                .insert({
                    ra_id: raId,
                    global_session_id: globalSessionId,
                    hostel_id: hostelId,
                    status: 'started',
                    total_students: totalStudents,
                    present_students: 0,
                    completion: 0,
                    started_at: new Date().toISOString(),
                    campus: campusContext,
                    campus_code: campusContext === 'Legacy' ? 'LEG' : 'HER',
                    created_by: req.user.id,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                })
                .select()
                .single();

            if (sessionError) throw sessionError;

            // ✅ Audit log
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: 'RA',
                action: 'Started BedCheck',
                module: 'bedcheck',
                details: `RA ${req.user.name} started BedCheck for hostel ${req.user.hostel_id}`,
                context: `Global Session: ${globalSessionId}`,
                result: 'success',
                category: 'bedcheck',
                tone: 'green',
                hostel_id: hostelId,
                session_id: globalSessionId,
                campus: campusContext,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: {
                    bedcheck_session: bedcheckSession,
                    assigned_rooms: assignedRooms.map(a => a.rooms).filter(Boolean),
                    room_count: assignedRooms.length,
                    total_students: totalStudents,
                    is_new_session: true,
                    message: 'BedCheck session started successfully'
                },
                campus: campusContext
            });

        } catch (error) {
            console.error('Start RA BedCheck error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            const campusContext = req.campus || 'Legacy';
            const hostelId = req.user.hostel_id;

            // ✅ Find the bedcheck session
            const { data: bedcheckSession, error: sessionError } = await supabase
                .from('bedcheck_sessions')
                .select('*')
                .eq('ra_id', raId)
                .eq('global_session_id', session_id)
                .eq('hostel_id', hostelId)
                .eq('campus', campusContext)
                .single();

            if (sessionError || !bedcheckSession) {
                return res.status(404).json({
                    success: false,
                    message: 'BedCheck session not found',
                    code: 'SESSION_NOT_FOUND'
                });
            }

            if (bedcheckSession.status === 'completed') {
                return res.status(400).json({
                    success: false,
                    message: 'This session is already completed',
                    code: 'SESSION_ALREADY_COMPLETED'
                });
            }

            // ✅ Get attendance for this hostel
            const { data: attendance, error: attendanceError } = await supabase
                .from('bedcheck_attendance')
                .select('status')
                .eq('global_session_id', session_id)
                .eq('hostel_id', hostelId)
                .eq('campus', campusContext);

            if (attendanceError) throw attendanceError;

            const totalStudents = bedcheckSession.total_students || 0;
            const presentStudents = attendance?.filter(a => a.status === 'present').length || 0;
            const completion = totalStudents > 0 ? Math.round((presentStudents / totalStudents) * 100) : 0;

            // ✅ Update bedcheck session
            const { data: updated, error: updateError } = await supabase
                .from('bedcheck_sessions')
                .update({
                    status: 'completed',
                    present_students: presentStudents,
                    completion: completion,
                    completed_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                })
                .eq('id', bedcheckSession.id)
                .select()
                .single();

            if (updateError) throw updateError;

            // ✅ Update session progress for this campus
            await updateSessionProgressUniversityWide(session_id);

            // ✅ Audit log
            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: 'RA',
                action: 'Completed BedCheck',
                module: 'bedcheck',
                details: `RA ${req.user.name} completed BedCheck for hostel ${req.user.hostel_id}`,
                context: `Global Session: ${session_id}, Completion: ${completion}%`,
                result: 'success',
                category: 'bedcheck',
                tone: 'green',
                hostel_id: hostelId,
                session_id: session_id,
                campus: campusContext,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: {
                    bedcheck_session: updated,
                    total_students: totalStudents,
                    present_students: presentStudents,
                    completion: completion,
                    message: 'BedCheck completed successfully'
                },
                campus: campusContext
            });

        } catch (error) {
            console.error('Complete RA BedCheck error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// RA BEDCHECK STATUS
// =====================================================
app.get('/api/ra/bedcheck/status',
    campusIsolation,
    requireRole('RA'),
    async (req, res) => {
        try {
            const raId = req.user.id;
            const { session_id } = req.query;
            const campusContext = req.campus || 'Legacy';
            const hostelId = req.user.hostel_id;

            // =============================================
            // 1. FIND ACTIVE GLOBAL SESSION (NO CAMPUS FILTER)
            // =============================================
            let globalSession = null;
            let globalSessionActive = false;
            
            try {
                const { data: globalSessions, error: globalError } = await supabase
                    .from('sessions')
                    .select('*')
                    .eq('status', 'active')
                    // REMOVED: .eq('campus', campusContext)
                    .order('created_at', { ascending: false })
                    .limit(1);
                
                if (!globalError && globalSessions && globalSessions.length > 0) {
                    globalSession = globalSessions[0];
                    globalSessionActive = true;
                    console.log(`📋 Global session ACTIVE for RA ${raId}:`, globalSession.id);
                } else {
                    console.log(`📋 No global active session found`);
                }
            } catch (e) {
                console.warn('Error checking global session:', e.message);
            }

            // =============================================
            // 2. GET RA'S BEDCHECK SESSIONS
            // =============================================
            let query = supabase
                .from('bedcheck_sessions')
                .select(`
                    *,
                    staff!ra_id (id, name, username),
                    hostels!hostel_id (id, name, type, gender)
                `)
                .eq('ra_id', raId)
                .eq('hostel_id', hostelId)
                .eq('campus', campusContext);

            if (session_id) {
                query = query.eq('global_session_id', parseInt(session_id));
            }

            const { data: raSessions, error: raError } = await query
                .order('created_at', { ascending: false })
                .limit(10);

            if (raError) {
                console.error('Error fetching RA sessions:', raError);
                return res.status(500).json({
                    success: false,
                    message: 'An error occurred. Please try again.',
                    code: 'SERVER_ERROR'
                });
            }

            // =============================================
            // 3. ANALYZE RA SESSION STATUS
            // =============================================
            let activeRASession = null;
            let hasCompletedToday = false;
            let raSessionExists = false;

            if (raSessions && raSessions.length > 0) {
                raSessionExists = true;
                
                // Check for active RA session
                const active = raSessions.find(s => s.status === 'started' || s.status === 'in_progress');
                if (active) {
                    activeRASession = active;
                    console.log(`📋 RA has active session:`, active.id);
                }

                // Check if RA completed today
                const today = new Date().toISOString().split('T')[0];
                const completed = raSessions.find(s => 
                    s.status === 'completed' && 
                    s.completed_at && 
                    s.completed_at.startsWith(today)
                );
                if (completed) {
                    hasCompletedToday = true;
                    console.log(`📋 RA completed today's session`);
                }
            }

            // =============================================
            // 4. DETERMINE EFFECTIVE STATUS
            // =============================================
            let effectiveStatus = 'draft';
            let effectiveSession = null;
            let isSessionActive = false;

            if (activeRASession) {
                // RA already has an active session - PRIORITY 1
                effectiveStatus = activeRASession.status;
                effectiveSession = activeRASession;
                isSessionActive = true;
                console.log('📋 Effective status: started (RA session active)');
            } else if (hasCompletedToday) {
                // RA completed today - PRIORITY 2
                effectiveStatus = 'completed';
                effectiveSession = raSessions.find(s => s.status === 'completed');
                isSessionActive = false;
                console.log('📋 Effective status: completed (RA completed today)');
            } else if (globalSessionActive) {
                // Global session is active, RA can start - PRIORITY 3
                effectiveStatus = 'ready';
                effectiveSession = globalSession;
                isSessionActive = true;
                console.log('📋 Effective status: ready (Global session active, RA can start)');
            } else {
                // No session at all - PRIORITY 4
                effectiveStatus = 'draft';
                effectiveSession = null;
                isSessionActive = false;
                console.log('📋 Effective status: draft (No session)');
            }

            // =============================================
            // 5. GET ASSIGNED ROOMS COUNT
            // =============================================
            const { data: roomsData, error: roomsError } = await supabase
                .from('ra_room_assignments')
                .select('room_id', { count: 'exact' })
                .eq('ra_id', raId)
                .eq('status', 'active')
                .eq('campus', campusContext);

            if (roomsError) {
                console.error('Error fetching rooms:', roomsError);
            }

            // =============================================
            // 6. GET STUDENT STATS FOR THIS HOSTEL
            // =============================================
            const { data: hostelStudents } = await supabase
                .from('students')
                .select('status, face_enrolled')
                .eq('hostel_id', hostelId)
                .eq('campus', campusContext);

            const totalStudents = hostelStudents?.length || 0;
            const presentStudents = hostelStudents?.filter(s => s.status === 'Present' || s.status === 'Verified').length || 0;
            const absentStudents = hostelStudents?.filter(s => s.status === 'Absent').length || 0;
            const faceEnrolled = hostelStudents?.filter(s => s.face_enrolled === true).length || 0;

            // =============================================
            // 7. BUILD ACTIVE SESSION DATA
            // =============================================
            let activeSessionData = null;
            if (effectiveSession) {
                activeSessionData = {
                    id: effectiveSession.id,
                    status: effectiveStatus,
                    session_id: effectiveSession.global_session_id || effectiveSession.id,
                    hostel_id: effectiveSession.hostel_id || hostelId,
                    started_at: effectiveSession.started_at || effectiveSession.created_at,
                    completed_at: effectiveSession.completed_at || null,
                    total_students: effectiveSession.total_students || totalStudents,
                    present_students: effectiveSession.present_students || presentStudents,
                    completion: effectiveSession.completion || 0,
                    is_global: !effectiveSession.ra_id
                };
            }

            // =============================================
            // 8. FORMAT SESSIONS LIST
            // =============================================
            const formattedSessions = (raSessions || []).map(session => ({
                ...session,
                staff: session.staff || { name: 'Unknown' },
                hostel: session.hostels || { name: 'Unknown' },
                is_global: false
            }));

            // Add global session to the list if active and RA hasn't started
            if (globalSessionActive && !activeRASession && !hasCompletedToday) {
                formattedSessions.unshift({
                    id: globalSession.id,
                    global_session_id: globalSession.id,
                    status: 'ready',
                    started_at: globalSession.started_at || globalSession.created_at,
                    staff: { name: 'System (Global)' },
                    hostel: { name: 'All Hostels' },
                    is_global: true,
                    hostel_id: null,
                    created_at: globalSession.created_at,
                    message: '🟡 Global session active - Click "Start BedCheck" to begin'
                });
            }

            // =============================================
            // 9. DETERMINE STATUS MESSAGE
            // =============================================
            let statusMessage = '';
            if (effectiveStatus === 'started' || effectiveStatus === 'in_progress') {
                statusMessage = '🟢 Your BedCheck session is active - Recording enabled';
            } else if (effectiveStatus === 'ready') {
                statusMessage = '🟡 A BedCheck session is active - Click "Start BedCheck" to begin';
            } else if (effectiveStatus === 'completed') {
                statusMessage = '✅ You have completed today\'s BedCheck';
            } else {
                statusMessage = '⏳ No active session available - Please wait for the session to start';
            }

            // =============================================
            // 10. RESPONSE
            // =============================================
            res.json({
                success: true,
                data: {
                    sessions: formattedSessions,
                    assigned_rooms: roomsData?.length || 0,
                    active_session: activeSessionData,
                    has_active_session: isSessionActive,
                    has_completed_today: hasCompletedToday,
                    is_global_session: !activeRASession && globalSessionActive,
                    global_session_active: globalSessionActive,
                    ra_session_active: !!activeRASession,
                    ra_session_exists: raSessionExists,
                    effective_status: effectiveStatus,
                    message: statusMessage,
                    hostel_stats: {
                        total_students: totalStudents,
                        present_students: presentStudents,
                        absent_students: absentStudents,
                        face_enrolled: faceEnrolled,
                        completion: totalStudents > 0 ? Math.round((presentStudents / totalStudents) * 100) : 0
                    },
                    // Debug info
                    debug: {
                        global_session_found: !!globalSession,
                        ra_session_found: raSessionExists,
                        ra_session_active: !!activeRASession,
                        has_completed_today: hasCompletedToday
                    }
                },
                campus: campusContext
            });

        } catch (error) {
            console.error('Get RA BedCheck status error:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// SECURITY - SUSPICIOUS ACTIVITY
// =====================================================

app.get('/api/security/suspicious',
    campusIsolation,
    requireRole('Admin', 'HRA', 'RASD', 'Developer'),
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.put('/api/security/resolve/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'RASD', 'Developer'),
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
                    message: 'Session not found in this campus',
                    code: 'SESSION_NOT_FOUND'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// HOSTEL CRUD
// =====================================================

app.get('/api/hostels',
    campusIsolation,
    async (req, res) => {
        try {
            let query = supabase
                .from('hostels')
                .select('*')
                .order('name', { ascending: true });
            
            // ✅ If NOT admin, filter by campus AND hostel
            const adminRoles = ['Admin', 'Developer', 'Administrator', 'Administration'];
            if (!adminRoles.includes(req.user.role)) {
                query = query.eq('campus', req.campus);
                if (req.user.hostel_id) {
                    query = query.eq('id', req.user.hostel_id);
                }
            }
            // ✅ Admins see ALL campuses (no campus filter)

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

                // ✅ If NOT admin, filter staff by campus
                let staffQuery = supabase
                    .from('staff')
                    .select('id, name, role, hostel_id')
                    .in('hostel_id', hostelIds)
                    .eq('status', 'Active');
                
                if (!adminRoles.includes(req.user.role)) {
                    staffQuery = staffQuery.eq('campus', req.campus);
                }
                
                const { data: staff } = await staffQuery;
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                    message: 'Hostel not found in this campus',
                    code: 'HOSTEL_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/hostels',
    campusIsolation,
    requireRole('Admin', 'Developer'),
    validate(validators.hostelCreate),
    async (req, res) => {
        const { name, gender, type, total_floors, rooms_per_floor, total_flats, rooms_per_flat, beds_per_room, campus } = req.body;
        try {
            const hostelCampus = campus || req.campus || process.env.DEFAULT_CAMPUS || 'Legacy';
            
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.put('/api/hostels/:id',
    campusIsolation,
    requireRole('Admin', 'Developer'),
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
                    message: 'Hostel not found in this campus',
                    code: 'HOSTEL_NOT_FOUND'
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
                    message: 'No fields to update',
                    code: 'NO_FIELDS_TO_UPDATE'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.delete('/api/hostels/:id',
    campusIsolation,
    requireRole('Admin', 'Developer'),
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
                    message: 'Hostel not found in this campus',
                    code: 'HOSTEL_NOT_FOUND'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                message: 'Hostel not found in this campus',
                code: 'HOSTEL_NOT_FOUND'
            });
        }
        
        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                message: 'Hostel not found in this campus',
                code: 'HOSTEL_NOT_FOUND'
            });
        }
        
        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                message: 'Hostel not found in this campus',
                code: 'HOSTEL_NOT_FOUND'
            });
        }
        
        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                .select('id');

            // Only filter by campus if NOT viewing all campuses
            if (!req.viewAllCampuses) {
                hostelQuery = hostelQuery.eq('campus', req.campus);
            }

            if (hostel_id) {
                hostelQuery = hostelQuery.eq('id', parseInt(hostel_id));
            }

            if (!req.viewAllCampuses && req.user.hostel_id) {
                hostelQuery = hostelQuery.eq('id', req.user.hostel_id);
            }

            const { data: hostels, error: hostelError } = await hostelQuery;
            if (hostelError) throw hostelError;

            const hostelIds = (hostels || []).map(h => h.id);

            if (hostelIds.length === 0) {
                return res.json({ success: true, data: [], campus: req.campus });
            }

            const { data, error } = await supabase
                .from('floors_flats')
                .select('*')
                .in('hostel_id', hostelIds)
                .order('name', { ascending: true });

            if (error) throw error;

            res.json({ success: true, data: data || [], campus: req.campus });
        } catch (error) {
            console.error('Error fetching floors/flats:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                    message: 'Floor/Flat not found',
                    code: 'FLOOR_FLAT_NOT_FOUND'
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
                    message: 'Floor/Flat not found in this campus',
                    code: 'FLOOR_FLAT_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== data.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
                });
            }
            
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching floor/flat:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/floors-flats',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                message: 'Hostel not found in this campus',
                code: 'HOSTEL_NOT_FOUND'
            });
        }

        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.put('/api/floors-flats/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                    message: 'Floor/Flat not found',
                    code: 'FLOOR_FLAT_NOT_FOUND'
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
                    message: 'Floor/Flat not found in this campus',
                    code: 'FLOOR_FLAT_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== existing.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                        message: 'Target hostel not found in this campus',
                        code: 'HOSTEL_NOT_FOUND'
                    });
                }
                updateData.hostel_id = parseInt(hostel_id);
            }
            if (name !== undefined) updateData.name = name;
            if (type !== undefined) updateData.type = type;
            
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update',
                    code: 'NO_FIELDS_TO_UPDATE'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.delete('/api/floors-flats/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                    message: 'Floor/Flat not found',
                    code: 'FLOOR_FLAT_NOT_FOUND'
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
                    message: 'Floor/Flat not found in this campus',
                    code: 'FLOOR_FLAT_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== existing.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// ROOMS CRUD
// =====================================================

app.get('/api/rooms',
    campusIsolation,
    async (req, res) => {
        const { floor_flat_id, hostel_id, type } = req.query;
        try {
            // Build hostel list
            let hostelQuery = supabase
                .from('hostels')
                .select('id, type');

            // Only filter by campus if NOT an admin viewing all campuses
            if (!req.viewAllCampuses) {
                hostelQuery = hostelQuery.eq('campus', req.campus);
            }

            // Non-admins with a specific hostel are further restricted
            if (!req.viewAllCampuses && req.user.hostel_id) {
                hostelQuery = hostelQuery.eq('id', req.user.hostel_id);
            }

            const { data: hostels, error: hostelError } = await hostelQuery;
            if (hostelError) throw hostelError;

            const hostelIds = (hostels || []).map(h => h.id);

            if (hostelIds.length === 0) {
                return res.json({ success: true, data: [], campus: req.campus });
            }

            let query = supabase.from('rooms').select('*');

            // CASE 1: Specific floor_flat_id provided
            if (floor_flat_id) {
                query = query.eq('floor_flat_id', parseInt(floor_flat_id));
            } 
            // CASE 2: hostel_id provided - handle both floor and flat types
            else if (hostel_id) {
                const parsedHostelId = parseInt(hostel_id);
                
                // Get the hostel to check its type
                const { data: hostelInfo, error: hostelInfoError } = await supabase
                    .from('hostels')
                    .select('type, name')
                    .eq('id', parsedHostelId)
                    .eq('campus', req.campus)
                    .single();
                
                if (hostelInfoError || !hostelInfo) {
                    return res.status(404).json({
                        success: false,
                        message: 'Hostel not found',
                        code: 'HOSTEL_NOT_FOUND'
                    });
                }

                // Get all floors/flats for this hostel
                const { data: floors, error: floorsError } = await supabase
                    .from('floors_flats')
                    .select('id, name, type')
                    .eq('hostel_id', parsedHostelId);

                if (floorsError) {
                    console.error('Error fetching floors/flats:', floorsError);
                    return res.status(500).json({
                        success: false,
                        message: 'An error occurred. Please try again.',
                        code: 'SERVER_ERROR'
                    });
                }

                if (floors && floors.length > 0) {
                    const floorIds = floors.map(f => f.id);
                    query = query.in('floor_flat_id', floorIds);
                    
                    // Also return the floor/flat info for the response
                    req.floorsInfo = floors;
                    req.hostelInfo = hostelInfo;
                } else {
                    return res.json({ success: true, data: [], campus: req.campus });
                }
            } 
            // CASE 3: No specific filter - get all rooms for accessible hostels
            else {
                const { data: floors, error: floorsError } = await supabase
                    .from('floors_flats')
                    .select('id')
                    .in('hostel_id', hostelIds);

                if (floorsError) {
                    console.error('Error fetching floors:', floorsError);
                    return res.status(500).json({
                        success: false,
                        message: 'An error occurred. Please try again.',
                        code: 'SERVER_ERROR'
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

            // Enrich the data with floor/flat and bed information
            const enrichedData = await Promise.all((data || []).map(async (room) => {
                const { data: floorData } = await supabase
                    .from('floors_flats')
                    .select('name, type, hostel_id')
                    .eq('id', room.floor_flat_id)
                    .maybeSingle();

                const { data: bedData } = await supabase
                    .from('bed_spaces')
                    .select('id, status, student_id, bed_code, full_bed_code')
                    .eq('room_id', room.id);

                const capacity = bedData?.length || room.capacity || 4;
                const occupiedCount = bedData?.filter(b => b.status === 'occupied').length || 0;
                
                // Get student info for occupied beds
                const occupiedBeds = bedData?.filter(b => b.status === 'occupied') || [];
                let students = [];
                if (occupiedBeds.length > 0) {
                    const studentIds = occupiedBeds.map(b => b.student_id).filter(id => id);
                    if (studentIds.length > 0) {
                        const { data: studentData } = await supabase
                            .from('students')
                            .select('id, name, matric')
                            .in('id', studentIds);
                        students = studentData || [];
                    }
                }

                return {
                    ...room,
                    floor_label: floorData?.name || null,
                    floor_type: floorData?.type || null,
                    hostel_id: floorData?.hostel_id || null,
                    capacity,
                    occupied: occupiedCount,
                    available: capacity - occupiedCount,
                    beds: bedData || [],
                    occupied_beds: occupiedBeds,
                    students: students,
                    bed_count: bedData?.length || 0
                };
            }));

            // If hostel_id was provided, add structure info
            const responseData = {
                success: true,
                data: enrichedData,
                campus: req.campus
            };

            // Add floors/flats info if available
            if (req.floorsInfo) {
                responseData.structure = {
                    hostel: req.hostelInfo,
                    floors: req.floorsInfo,
                    type: req.hostelInfo?.type || 'unknown',
                    total_floors: req.floorsInfo.length,
                    total_rooms: enrichedData.length
                };
            }

            res.json(responseData);
        } catch (error) {
            console.error('Error fetching rooms:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                    message: 'Room not found',
                    code: 'ROOM_NOT_FOUND'
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
                    message: 'Room not found in this campus',
                    code: 'ROOM_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== floorData?.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/rooms',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                    message: 'Floor/Flat not found in this campus',
                    code: 'FLOOR_FLAT_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== floorData?.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.put('/api/rooms/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                    message: 'Room not found in this campus',
                    code: 'ROOM_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== floorData?.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                        message: 'Target floor not found in this campus',
                        code: 'FLOOR_FLAT_NOT_FOUND'
                    });
                }
                updateData.floor_flat_id = parseInt(floor_flat_id);
            }
            if (room_code !== undefined) updateData.room_code = room_code;
            
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'No fields to update',
                    code: 'NO_FIELDS_TO_UPDATE'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.delete('/api/rooms/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                    message: 'Room not found in this campus',
                    code: 'ROOM_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== floorData?.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            // Build hostel list
            let hostelQuery = supabase
                .from('hostels')
                .select('id');

            // Only filter by campus if NOT an admin viewing all campuses
            if (!req.viewAllCampuses) {
                hostelQuery = hostelQuery.eq('campus', req.campus);
            }

            // Non-admins with a specific hostel are further restricted
            if (!req.viewAllCampuses && req.user.hostel_id) {
                hostelQuery = hostelQuery.eq('id', req.user.hostel_id);
            }

            const { data: hostels, error: hostelError } = await hostelQuery;
            if (hostelError) throw hostelError;

            const hostelIds = (hostels || []).map(h => h.id);

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
                        message: 'An error occurred. Please try again.',
                        code: 'SERVER_ERROR'
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
                            message: 'An error occurred. Please try again.',
                            code: 'SERVER_ERROR'
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
                        message: 'An error occurred. Please try again.',
                        code: 'SERVER_ERROR'
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
                            message: 'An error occurred. Please try again.',
                            code: 'SERVER_ERROR'
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

            res.json({ success: true, data: data || [], campus: req.campus });
        } catch (error) {
            console.error('Error fetching bed spaces:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                    message: 'Bed space not found in this campus',
                    code: 'BED_SPACE_NOT_FOUND'
                });
            }
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching bed space:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/bed-spaces',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                message: 'Room not found in this campus',
                code: 'ROOM_NOT_FOUND'
            });
        }

        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== floorData?.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.put('/api/bed-spaces/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                message: 'Bed space not found in this campus',
                code: 'BED_SPACE_NOT_FOUND'
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

        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== floorData?.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                    message: 'No fields to update',
                    code: 'NO_FIELDS_TO_UPDATE'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.patch('/api/bed-spaces/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                message: 'Bed space not found in this campus',
                code: 'BED_SPACE_NOT_FOUND'
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

        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== floorData?.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                    message: 'No fields to update',
                    code: 'NO_FIELDS_TO_UPDATE'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.delete('/api/bed-spaces/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                message: 'Bed space not found in this campus',
                code: 'BED_SPACE_NOT_FOUND'
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

        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== floorData?.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            const { data, error } = await query.order('created_at', { ascending: false });
            if (error) throw error;
            res.json({ success: true, data: data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching bedcheck sessions:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/bedcheck/sessions',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                message: 'Hostel not found in this campus',
                code: 'HOSTEL_NOT_FOUND'
            });
        }

        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                message: 'Session not found in this campus',
                code: 'SESSION_NOT_FOUND'
            });
        }

        if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== session.hostel_id) {
            return res.status(403).json({
                success: false,
                message: 'Access denied',
                code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
                    message: 'Student not found in this campus',
                    code: 'STUDENT_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== student.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/bedcheck/scan-with-face',
    campusIsolation,
    faceLimiter,
    validate([
        ...validators.faceImage,
        body('room_id').isInt().withMessage('room_id is required'),
        body('session_id').optional().isInt()
    ]),
    async (req, res) => {
        try {
            const { session_id, image, room_id, threshold = FACE_VERIFICATION_THRESHOLD, scanner_id } = req.body;

            const validation = faceService.validateImage(image);
            if (!validation.valid) {
                return res.status(400).json({
                    success: false,
                    message: validation.error,
                    code: 'INVALID_IMAGE'
                });
            }

            let query = supabase.from('students')
                .select('id, name, matric, hostel_id, room_id, room_code, campus')
                .eq('campus', req.campus)
                .eq('face_enrolled', true)
                .eq('room_id', room_id);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            const { data: students, error: studentsError } = await query;
            
            if (studentsError) {
                console.error('Fetch students error:', studentsError);
                return res.status(500).json({
                    success: false,
                    message: 'An error occurred. Please try again.',
                    code: 'SERVER_ERROR'
                });
            }

            if (!students || students.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No students found with face enrolled in this room',
                    code: 'NO_STUDENTS_FOUND'
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
                    message: 'No face embeddings found for students in this room',
                    code: 'NO_FACE_EMBEDDINGS'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            message: 'An error occurred. Please try again.',
            code: 'SERVER_ERROR'
        });
    }
});

app.put('/api/submission',
    campusIsolation,
    requireRole('Admin', 'Developer'),
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            const adminRoles = ['Admin', 'Developer', 'Administrator', 'Administration'];
            const isAdmin = adminRoles.includes(req.user.role);
            
            // ✅ If admin, get ALL students (both campuses)
            let studentsQuery = supabase.from('students').select('*', { count: 'exact', head: true });
            if (!isAdmin) {
                studentsQuery = studentsQuery.eq('campus', req.campus);
                if (req.user.hostel_id) {
                    studentsQuery = studentsQuery.eq('hostel_id', req.user.hostel_id);
                }
            }
            const { count: studentsCount } = await studentsQuery;
            stats.totalStudents = studentsCount || 0;
            
            // ✅ If admin, get ALL hostels
            let hostelsQuery = supabase.from('hostels').select('*', { count: 'exact', head: true });
            if (!isAdmin) {
                hostelsQuery = hostelsQuery.eq('campus', req.campus);
                if (req.user.hostel_id) {
                    hostelsQuery = hostelsQuery.eq('id', req.user.hostel_id);
                }
            }
            const { count: hostelsCount } = await hostelsQuery;
            stats.totalHostels = hostelsCount || 0;
            
            // ✅ If admin, get ALL staff
            let staffQuery = supabase.from('staff').select('role', { count: 'exact' });
            if (!isAdmin) {
                staffQuery = staffQuery.eq('campus', req.campus);
            }
            if (req.user.role !== 'Developer') {
                staffQuery = staffQuery.neq('role', 'Developer');
            }
            const { count: totalStaff } = await staffQuery;
            stats.totalStaff = totalStaff || 0;
            
            // ✅ If admin, get ALL student statuses
            let statusQuery = supabase.from('students').select('status, face_enrolled');
            if (!isAdmin) {
                statusQuery = statusQuery.eq('campus', req.campus);
                if (req.user.hostel_id) {
                    statusQuery = statusQuery.eq('hostel_id', req.user.hostel_id);
                }
            }
            const { data: statusData } = await statusQuery;
            
            if (statusData) {
                stats.present = statusData.filter(s => s.status === 'Present').length;
                stats.absent = statusData.filter(s => s.status === 'Absent').length;
                stats.faceEnrolled = statusData.filter(s => s.face_enrolled === true).length;
            } else {
                stats.present = 0;
                stats.absent = 0;
                stats.faceEnrolled = 0;
            }
            
            // ✅ If admin, get ALL face data
            let faceQuery = supabase
                .from('student_face')
                .select('enrollment_status')
                .eq('is_active', true);
            if (!isAdmin) {
                faceQuery = faceQuery.eq('campus', req.campus);
            }
            const { data: faceData } = await faceQuery;
            
            if (faceData) {
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// REGISTRATION MANAGEMENT - RASD ENDPOINTS
// =====================================================

app.get('/api/registration/stats',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
    async (req, res) => {
        try {
            let query = supabase.from('students')
                .select('id, room_id, name, matric, hostel_id, hostel_name, room_code, status, created_at, face_enrolled, campus')
                .eq('campus', req.campus);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
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
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// HRA DASHBOARD ENDPOINTS
// =====================================================

app.get('/api/hra/hostel', 
    campusIsolation,
    requireRole('HRA', 'Admin', 'Developer'),
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
                    message: 'Staff member not found in this campus',
                    code: 'STAFF_NOT_FOUND'
                });
            }
            
            if (!staffData.hostel_id) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'HRA not assigned to a hostel',
                    code: 'NO_HOSTEL_ASSIGNED'
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
                    message: 'Hostel not found in this campus',
                    code: 'HOSTEL_NOT_FOUND'
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
            
            let presentCount = 0, absentCount = 0, faceEnrolledCount = 0;
            if (!statusError && studentStatuses) {
                presentCount = studentStatuses.filter(s => s.status === 'Present' || s.status === 'Verified').length;
                absentCount = studentStatuses.filter(s => s.status === 'Absent').length;
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
                    face_enrolled_count: faceEnrolledCount,
                    current_session: currentSession
                },
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching HRA hostel:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// AUDIT ENDPOINTS (Restricted)
// =====================================================

app.get('/api/audit',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
                if (hostel_id && parseInt(hostel_id) !== req.user.hostel_id) {
                    return res.status(403).json({
                        success: false,
                        message: 'Access denied. You can only view your hostel logs.',
                        code: 'PERMISSION_DENIED'
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.get('/api/audit/stats',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
    async (req, res) => {
        try {
            const { hostel_id, from_date, to_date } = req.query;
            
            let effectiveHostelId = hostel_id;
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
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
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
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
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.get('/api/audit/:id',
    campusIsolation,
    requireRole('Admin', 'HRA', 'Developer'),
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
                    message: 'Audit log not found in this campus',
                    code: 'AUDIT_LOG_NOT_FOUND'
                });
            }

            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== data.hostel_id) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
                });
            }
            
            res.json({ success: true, data, campus: req.campus });
        } catch (error) {
            console.error('Error fetching audit log:', error);
            res.status(500).json({ 
                success: false, 
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// ⚡ DEVELOPER POWER ENDPOINTS
// =====================================================

app.get('/api/developer/system/stats',
    campusIsolation,
    requireRole('Developer'),
    async (req, res) => {
        try {
            const [
                studentsCount,
                staffCount,
                hostelsCount,
                floorsCount,
                roomsCount,
                bedSpacesCount,
                sessionsCount,
                bedcheckSessionsCount,
                bedcheckScansCount,
                auditCount
            ] = await Promise.all([
                supabase.from('students').select('*', { count: 'exact', head: true }).eq('campus', req.campus),
                supabase.from('staff').select('*', { count: 'exact', head: true }).eq('campus', req.campus),
                supabase.from('hostels').select('*', { count: 'exact', head: true }).eq('campus', req.campus),
                supabase.from('floors_flats').select('*', { count: 'exact', head: true }).eq('campus', req.campus),
                supabase.from('rooms').select('*', { count: 'exact', head: true }).eq('campus', req.campus),
                supabase.from('bed_spaces').select('*', { count: 'exact', head: true }).eq('campus', req.campus),
                supabase.from('sessions').select('*', { count: 'exact', head: true }).eq('campus', req.campus),
                supabase.from('bedcheck_sessions').select('*', { count: 'exact', head: true }).eq('campus', req.campus),
                supabase.from('bedcheck_scans').select('*', { count: 'exact', head: true }).eq('campus', req.campus),
                supabase.from('audit_logs').select('*', { count: 'exact', head: true }).eq('campus', req.campus)
            ]);

            res.json({
                success: true,
                data: {
                    tables: {
                        students: studentsCount.count || 0,
                        staff: staffCount.count || 0,
                        hostels: hostelsCount.count || 0,
                        floors_flats: floorsCount.count || 0,
                        rooms: roomsCount.count || 0,
                        bed_spaces: bedSpacesCount.count || 0,
                        sessions: sessionsCount.count || 0,
                        bedcheck_sessions: bedcheckSessionsCount.count || 0,
                        bedcheck_scans: bedcheckScansCount.count || 0,
                        audit_logs: auditCount.count || 0
                    },
                    total_records: (studentsCount.count || 0) + (staffCount.count || 0) + 
                                  (hostelsCount.count || 0) + (floorsCount.count || 0) + 
                                  (roomsCount.count || 0) + (bedSpacesCount.count || 0) + 
                                  (sessionsCount.count || 0) + (bedcheckSessionsCount.count || 0) + 
                                  (bedcheckScansCount.count || 0) + (auditCount.count || 0),
                    campus: req.campus
                }
            });
        } catch (error) {
            console.error('Error fetching system stats:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.get('/api/developer/students/all',
    campusIsolation,
    requireRole('Developer'),
    async (req, res) => {
        try {
            const { data, error } = await supabase
                .from('students')
                .select('*')
                .eq('campus', req.campus)
                .order('id', { ascending: true });

            if (error) throw error;

            res.json({
                success: true,
                data: data,
                count: data.length,
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching all students:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.get('/api/developer/backup/full',
    campusIsolation,
    requireRole('Developer'),
    async (req, res) => {
        try {
            const [
                students,
                staff,
                hostels,
                floors,
                rooms,
                bedSpaces,
                sessions,
                bedcheckSessions,
                bedcheckScans,
                auditLogs,
                raSessions,
                raAssignments,
                studentFace,
                systemSettings,
                submissionState
            ] = await Promise.all([
                supabase.from('students').select('*').eq('campus', req.campus),
                supabase.from('staff').select('*').eq('campus', req.campus),
                supabase.from('hostels').select('*').eq('campus', req.campus),
                supabase.from('floors_flats').select('*').eq('campus', req.campus),
                supabase.from('rooms').select('*').eq('campus', req.campus),
                supabase.from('bed_spaces').select('*').eq('campus', req.campus),
                supabase.from('sessions').select('*').eq('campus', req.campus),
                supabase.from('bedcheck_sessions').select('*').eq('campus', req.campus),
                supabase.from('bedcheck_scans').select('*').eq('campus', req.campus),
                supabase.from('audit_logs').select('*').eq('campus', req.campus),
                supabase.from('ra_bedcheck_sessions').select('*').eq('campus', req.campus),
                supabase.from('ra_room_assignments').select('*').eq('campus', req.campus),
                supabase.from('student_face').select('*').eq('campus', req.campus),
                supabase.from('system_settings').select('*').eq('campus', req.campus),
                supabase.from('submission_state').select('*').eq('campus', req.campus)
            ]);

            const backup = {
                timestamp: new Date().toISOString(),
                campus: req.campus,
                tables: {
                    students: students.data || [],
                    staff: staff.data || [],
                    hostels: hostels.data || [],
                    floors_flats: floors.data || [],
                    rooms: rooms.data || [],
                    bed_spaces: bedSpaces.data || [],
                    sessions: sessions.data || [],
                    bedcheck_sessions: bedcheckSessions.data || [],
                    bedcheck_scans: bedcheckScans.data || [],
                    audit_logs: auditLogs.data || [],
                    ra_bedcheck_sessions: raSessions.data || [],
                    ra_room_assignments: raAssignments.data || [],
                    student_face: studentFace.data || [],
                    system_settings: systemSettings.data || [],
                    submission_state: submissionState.data || []
                },
                summary: {
                    total_tables: 15,
                    total_records: (students.data?.length || 0) + (staff.data?.length || 0) +
                                   (hostels.data?.length || 0) + (floors.data?.length || 0) +
                                   (rooms.data?.length || 0) + (bedSpaces.data?.length || 0) +
                                   (sessions.data?.length || 0) + (bedcheckSessions.data?.length || 0) +
                                   (bedcheckScans.data?.length || 0) + (auditLogs.data?.length || 0) +
                                   (raSessions.data?.length || 0) + (raAssignments.data?.length || 0) +
                                   (studentFace.data?.length || 0) + (systemSettings.data?.length || 0) +
                                   (submissionState.data?.length || 0)
                }
            };

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: 'Developer',
                action: 'Full Database Backup',
                module: 'system',
                details: `Developer ${req.user.name} created full database backup`,
                context: `${backup.summary.total_records} records backed up`,
                result: 'success',
                category: 'system',
                tone: 'blue',
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: backup,
                message: 'Full database backup created successfully'
            });
        } catch (error) {
            console.error('Error creating backup:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/developer/query',
    campusIsolation,
    requireRole('Developer'),
    validate(validators.executeQuery),
    async (req, res) => {
        try {
            const { query, params = {} } = req.body;

            const dangerousPatterns = [
                /DROP\s+TABLE/i,
                /DROP\s+DATABASE/i,
                /TRUNCATE\s+TABLE/i,
                /ALTER\s+TABLE/i,
                /CREATE\s+TABLE/i,
                /DELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1/i,
                /UPDATE\s+\w+\s+SET\s+\w+\s*=\s*\w+\s+WHERE\s+1\s*=\s*1/i
            ];

            for (const pattern of dangerousPatterns) {
                if (pattern.test(query)) {
                    await auditService.log({
                        actor: req.user.name || req.user.username,
                        actor_id: req.user.id,
                        actor_role: 'Developer',
                        action: 'Dangerous Query Blocked',
                        module: 'security',
                        details: `Attempted dangerous query: ${query.substring(0, 100)}`,
                        context: 'Query blocked by security filter',
                        result: 'failed',
                        category: 'security',
                        tone: 'red',
                        campus: req.campus,
                        ip_address: req.clientIp,
                        user_agent: req.userAgent
                    });

                    return res.status(403).json({
                        success: false,
                        message: 'Dangerous query blocked for security reasons',
                        code: 'QUERY_BLOCKED'
                    });
                }
            }

            const { data, error } = await supabase.rpc('execute_sql', {
                query_text: query,
                query_params: params
            });

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: 'Developer',
                action: 'Custom Query Executed',
                module: 'system',
                details: `Executed custom query: ${query.substring(0, 100)}`,
                context: `Query returned ${data?.length || 0} rows`,
                result: 'success',
                category: 'system',
                tone: 'blue',
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: data,
                count: data?.length || 0,
                message: 'Query executed successfully'
            });
        } catch (error) {
            console.error('Error executing query:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.get('/api/developer/health/full',
    campusIsolation,
    requireRole('Developer'),
    async (req, res) => {
        try {
            const dbStart = Date.now();
            const { data: dbTest, error: dbError } = await supabase
                .from('students')
                .select('id', { count: 'exact', head: true })
                .limit(1);
            const dbLatency = Date.now() - dbStart;

            const faceStart = Date.now();
            let faceStatus = 'unknown';
            let faceLatency = 0;
            try {
                const faceHealth = await faceService.checkHealth();
                faceStatus = faceHealth.status || 'healthy';
                faceLatency = Date.now() - faceStart;
            } catch (faceError) {
                faceStatus = 'unhealthy';
                faceLatency = Date.now() - faceStart;
            }

            const memoryUsage = process.memoryUsage();

            const health = {
                status: dbError ? 'unhealthy' : 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                database: {
                    status: dbError ? 'unhealthy' : 'healthy',
                    latency: `${dbLatency}ms`,
                    error: dbError?.message || null
                },
                face_api: {
                    status: faceStatus,
                    latency: `${faceLatency}ms`,
                    circuit_breaker: faceService.circuitOpen ? 'open' : 'closed',
                    failures: faceService.failureCount
                },
                memory: {
                    rss: `${Math.round(memoryUsage.rss / 1024 / 1024)} MB`,
                    heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)} MB`,
                    heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)} MB`,
                    external: `${Math.round(memoryUsage.external / 1024 / 1024)} MB`
                },
                system: {
                    platform: process.platform,
                    arch: process.arch,
                    node_version: process.version,
                    cpu_cores: require('os').cpus().length,
                    total_memory: `${Math.round(require('os').totalmem() / 1024 / 1024 / 1024)} GB`,
                    free_memory: `${Math.round(require('os').freemem() / 1024 / 1024 / 1024)} GB`
                },
                campus: req.campus
            };

            res.json({
                success: true,
                data: health
            });
        } catch (error) {
            console.error('Error checking system health:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.get('/api/developer/settings/all',
    campusIsolation,
    requireRole('Developer'),
    async (req, res) => {
        try {
            const { data, error } = await supabase
                .from('system_settings')
                .select('*')
                .eq('campus', req.campus)
                .order('category', { ascending: true })
                .order('key', { ascending: true });

            if (error) throw error;

            res.json({
                success: true,
                data: data,
                count: data.length,
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching settings:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.put('/api/developer/settings/:key',
    campusIsolation,
    requireRole('Developer'),
    validate(validators.developerSettings),
    async (req, res) => {
        try {
            const { key } = req.params;
            const { value, category, description } = req.body;

            const { data, error } = await supabase
                .from('system_settings')
                .upsert({
                    key: key,
                    value: value,
                    category: category || 'general',
                    description: description || null,
                    updated_at: new Date().toISOString(),
                    campus: req.campus
                }, {
                    onConflict: 'key'
                })
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: 'Developer',
                action: 'System Setting Updated',
                module: 'system',
                details: `Updated setting ${key} to ${value}`,
                context: `Category: ${category || 'general'}`,
                result: 'success',
                category: 'system',
                tone: 'gold',
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: data,
                message: `Setting ${key} updated successfully`
            });
        } catch (error) {
            console.error('Error updating setting:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.get('/api/developer/users/all',
    campusIsolation,
    requireRole('Developer'),
    async (req, res) => {
        try {
            const { data, error } = await supabase
                .from('staff')
                .select('*')
                .eq('campus', req.campus)
                .order('role', { ascending: true })
                .order('name', { ascending: true });

            if (error) throw error;

            res.json({
                success: true,
                data: data,
                count: data.length,
                campus: req.campus
            });
        } catch (error) {
            console.error('Error fetching all users:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.put('/api/developer/users/:id/role',
    campusIsolation,
    requireRole('Developer'),
    validate(validators.developerRoleChange),
    async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            const { role, reason } = req.body;

            if (id === req.user.id) {
                return res.status(403).json({
                    success: false,
                    message: 'You cannot change your own role',
                    code: 'PERMISSION_DENIED'
                });
            }

            const { data: user, error: fetchError } = await supabase
                .from('staff')
                .select('name, role')
                .eq('id', id)
                .eq('campus', req.campus)
                .single();

            if (fetchError || !user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found in this campus',
                    code: 'USER_NOT_FOUND'
                });
            }

            const oldRole = user.role;

            const { data, error } = await supabase
                .from('staff')
                .update({
                    role: role,
                    updated_at: new Date().toISOString()
                })
                .eq('id', id)
                .eq('campus', req.campus)
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: 'Developer',
                action: 'User Role Changed (Developer)',
                module: 'staff',
                details: `Changed ${user.name} role from ${oldRole} to ${role}`,
                context: `Reason: ${reason || 'No reason provided'}`,
                result: 'success',
                category: 'staff',
                tone: 'gold',
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: data,
                message: `Role changed from ${oldRole} to ${role} successfully`
            });
        } catch (error) {
            console.error('Error changing user role:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

app.post('/api/developer/maintenance',
    campusIsolation,
    requireRole('Developer'),
    validate(validators.developerMaintenance),
    async (req, res) => {
        try {
            const { enabled, message } = req.body;

            const { data, error } = await supabase
                .from('system_settings')
                .upsert({
                    key: 'maintenance_mode',
                    value: enabled ? 'true' : 'false',
                    category: 'system',
                    description: message || 'System maintenance in progress',
                    updated_at: new Date().toISOString(),
                    campus: req.campus
                }, {
                    onConflict: 'key'
                })
                .select()
                .single();

            if (error) throw error;

            await auditService.log({
                actor: req.user.name || req.user.username,
                actor_id: req.user.id,
                actor_role: 'Developer',
                action: enabled ? 'Maintenance Mode Enabled' : 'Maintenance Mode Disabled',
                module: 'system',
                details: `Developer ${req.user.name} ${enabled ? 'enabled' : 'disabled'} maintenance mode`,
                context: `Message: ${message || 'No message provided'}`,
                result: 'success',
                category: 'system',
                tone: enabled ? 'red' : 'green',
                campus: req.campus,
                ip_address: req.clientIp,
                user_agent: req.userAgent
            });

            res.json({
                success: true,
                data: data,
                message: `Maintenance mode ${enabled ? 'enabled' : 'disabled'} successfully`
            });
        } catch (error) {
            console.error('Error toggling maintenance mode:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred. Please try again.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// REPORTS ENDPOINTS
// =====================================================

// Get attendance report data
app.get('/api/reports/attendance',
    campusIsolation,
    async (req, res) => {
        try {
            const campus = req.campus;
            
            // Get all students for this campus
            let query = supabase
                .from('students')
                .select('id, name, matric, status, hostel_id, hostel_name, room_id, room_code, gender, level, faculty, department, campus')
                .eq('campus', campus);
            
            // If user is not admin/developer, filter by their hostel
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            const { data: students, error: studentsError } = await query;
            
            if (studentsError) {
                console.error('Error fetching students for report:', studentsError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to fetch student data',
                    code: 'STUDENT_FETCH_ERROR'
                });
            }
            
            // Calculate attendance statistics
            const total = students?.length || 0;
            const present = students?.filter(s => s.status === 'Present' || s.status === 'Verified').length || 0;
            const absent = students?.filter(s => s.status === 'Absent').length || 0;
            const attendanceRate = total > 0 ? Math.round((present / total) * 100) : 0;
            const absenceRate = total > 0 ? Math.round((absent / total) * 100) : 0;
            
            // Get hostel breakdown
            const hostelMap = {};
            students?.forEach(s => {
                const hostel = s.hostel_name || s.hostel || 'Unassigned';
                if (!hostelMap[hostel]) {
                    hostelMap[hostel] = { total: 0, present: 0, absent: 0 };
                }
                hostelMap[hostel].total++;
                if (s.status === 'Present' || s.status === 'Verified') hostelMap[hostel].present++;
                if (s.status === 'Absent') hostelMap[hostel].absent++;
            });
            
            const hostelBreakdown = Object.keys(hostelMap).map(hostel => {
                const data = hostelMap[hostel];
                return {
                    hostel: hostel,
                    total: data.total,
                    present: data.present,
                    absent: data.absent,
                    attendance_rate: data.total > 0 ? Math.round((data.present / data.total) * 100) : 0
                };
            }).sort((a, b) => b.attendance_rate - a.attendance_rate);
            
            // Get submission state
            const { data: submissionData, error: submissionError } = await supabase
                .from('submission_state')
                .select('state')
                .eq('campus', campus)
                .order('id', { ascending: false })
                .limit(1)
                .maybeSingle();
            
            const submissionState = submissionData?.state || 'In progress';
            
            res.json({
                success: true,
                data: {
                    total: total,
                    present: present,
                    absent: absent,
                    attendance_rate: attendanceRate,
                    absence_rate: absenceRate,
                    submission_state: submissionState,
                    hostel_breakdown: hostelBreakdown,
                    students: students?.map(s => ({
                        id: s.id,
                        name: s.name,
                        matric: s.matric,
                        status: s.status,
                        hostel: s.hostel_name || s.hostel || 'Unassigned',
                        room: s.room_code || s.room || 'N/A',
                        gender: s.gender || 'N/A',
                        level: s.level || 'N/A',
                        faculty: s.faculty || 'N/A',
                        department: s.department || 'N/A'
                    })) || []
                },
                campus: campus
            });
            
        } catch (error) {
            console.error('Error generating attendance report:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred while generating the report.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// Get hostel-specific report
app.get('/api/reports/hostel/:hostelId',
    campusIsolation,
    validate(validators.hostelId),
    async (req, res) => {
        try {
            const hostelId = parseInt(req.params.hostelId);
            const campus = req.campus;
            
            // Check access
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id !== hostelId) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied',
                    code: 'PERMISSION_DENIED'
                });
            }
            
            // Get hostel details
            const { data: hostel, error: hostelError } = await supabase
                .from('hostels')
                .select('id, name, type, gender')
                .eq('id', hostelId)
                .eq('campus', campus)
                .single();
            
            if (hostelError || !hostel) {
                return res.status(404).json({
                    success: false,
                    message: 'Hostel not found',
                    code: 'HOSTEL_NOT_FOUND'
                });
            }
            
            // Get students in this hostel
            const { data: students, error: studentsError } = await supabase
                .from('students')
                .select('id, name, matric, status, room_code, gender, level, faculty, department')
                .eq('hostel_id', hostelId)
                .eq('campus', campus);
            
            if (studentsError) {
                console.error('Error fetching hostel students:', studentsError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to fetch student data',
                    code: 'STUDENT_FETCH_ERROR'
                });
            }
            
            const total = students?.length || 0;
            const present = students?.filter(s => s.status === 'Present' || s.status === 'Verified').length || 0;
            const absent = students?.filter(s => s.status === 'Absent').length || 0;
            const attendanceRate = total > 0 ? Math.round((present / total) * 100) : 0;
            
            // Group by room
            const roomMap = {};
            students?.forEach(s => {
                const room = s.room_code || 'Unknown';
                if (!roomMap[room]) {
                    roomMap[room] = { total: 0, present: 0, absent: 0 };
                }
                roomMap[room].total++;
                if (s.status === 'Present' || s.status === 'Verified') roomMap[room].present++;
                if (s.status === 'Absent') roomMap[room].absent++;
            });
            
            const roomBreakdown = Object.keys(roomMap).map(room => {
                const data = roomMap[room];
                return {
                    room: room,
                    total: data.total,
                    present: data.present,
                    absent: data.absent,
                    attendance_rate: data.total > 0 ? Math.round((data.present / data.total) * 100) : 0
                };
            }).sort((a, b) => b.attendance_rate - a.attendance_rate);
            
            res.json({
                success: true,
                data: {
                    hostel: hostel,
                    summary: {
                        total: total,
                        present: present,
                        absent: absent,
                        attendance_rate: attendanceRate
                    },
                    room_breakdown: roomBreakdown,
                    students: students || []
                },
                campus: campus
            });
            
        } catch (error) {
            console.error('Error generating hostel report:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred while generating the report.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// Get report statistics (for dashboard cards)
app.get('/api/reports/stats',
    campusIsolation,
    async (req, res) => {
        try {
            const campus = req.campus;
            
            // Get all students
            let query = supabase
                .from('students')
                .select('status')
                .eq('campus', campus);
            
            if (req.user.role !== 'Admin' && req.user.role !== 'Developer' && req.user.role !== 'Administrator' && req.user.hostel_id) {
                query = query.eq('hostel_id', req.user.hostel_id);
            }
            
            const { data: students, error: studentsError } = await query;
            
            if (studentsError) {
                console.error('Error fetching stats:', studentsError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to fetch statistics',
                    code: 'STATS_FETCH_ERROR'
                });
            }
            
            const total = students?.length || 0;
            const present = students?.filter(s => s.status === 'Present' || s.status === 'Verified').length || 0;
            const absent = students?.filter(s => s.status === 'Absent').length || 0;
            
            // Get submission state
            const { data: submissionData } = await supabase
                .from('submission_state')
                .select('state')
                .eq('campus', campus)
                .order('id', { ascending: false })
                .limit(1)
                .maybeSingle();
            
            res.json({
                success: true,
                data: {
                    total: total,
                    present: present,
                    absent: absent,
                    attendance_rate: total > 0 ? Math.round((present / total) * 100) : 0,
                    submission_state: submissionData?.state || 'In progress'
                },
                campus: campus
            });
            
        } catch (error) {
            console.error('Error fetching report stats:', error);
            res.status(500).json({
                success: false,
                message: 'An error occurred while fetching statistics.',
                code: 'SERVER_ERROR'
            });
        }
    }
);

// =====================================================
// SCHEDULED TASKS - Auto Session Management
// =====================================================

// Check every 30 seconds for session activation/completion
setInterval(async () => {
    try {
        const now = new Date();
        const currentTime = now.toTimeString().slice(0, 8);
        const today = now.toISOString().split('T')[0];
        
        // 1. ACTIVATE SCHEDULED SESSIONS (University-Wide)
        const { data: scheduledSessions } = await supabase
            .from('sessions')
            .select('*')
            .eq('status', 'scheduled')
            // REMOVED: .eq('campus', campus)
            .lte('start_time', currentTime);
        
        if (scheduledSessions && scheduledSessions.length > 0) {
            for (const session of scheduledSessions) {
                if (session.date <= today) {
                    const { error: updateError } = await supabase
                        .from('sessions')
                        .update({ 
                            status: 'active', 
                            started_at: new Date().toISOString(),
                            updated_at: new Date().toISOString()
                        })
                        .eq('id', session.id);
                    
                    if (!updateError) {
                        console.log(`✅ Session ${session.id} (${session.name}) auto-activated at ${currentTime}`);
                        
                        // ✅ Create bedcheck sessions for ALL hostels
                        await createUniversityWideBedcheckSessions(session.id);
                        
                        // ✅ Notify ALL RAs
                        await supabase
                            .from('notifications')
                            .insert({
                                title: '🔔 BedCheck Session Started',
                                detail: `${session.name} has started`,
                                body: `The BedCheck session for ${session.date} is now active. RAs can begin verification.`,
                                type: 'system',
                                priority: 'high',
                                campus: null,  // University-wide
                                recipient_role: 'RA',
                                actor: 'System',
                                action: 'Session Auto-Started',
                                tone: 'green',
                                read: false,
                                created_at: new Date().toISOString()
                            }).catch(() => {});
                    }
                }
            }
        }
        
        // 2. COMPLETE ACTIVE SESSIONS (University-Wide)
        const { data: activeSessions } = await supabase
            .from('sessions')
            .select('*')
            .eq('status', 'active')
            // REMOVED: .eq('campus', campus)
            .lte('end_time', currentTime);
        
        if (activeSessions && activeSessions.length > 0) {
            for (const session of activeSessions) {
                if (session.date <= today) {
                    // ✅ Mark unverified as absent for ALL campuses
                    await markUnverifiedAsAbsentUniversityWide(session.id);
                    
                    const { error: updateError } = await supabase
                        .from('sessions')
                        .update({ 
                            status: 'completed', 
                            completed_at: new Date().toISOString(),
                            updated_at: new Date().toISOString()
                        })
                        .eq('id', session.id);
                    
                    if (!updateError) {
                        console.log(`✅ Session ${session.id} (${session.name}) auto-completed at ${currentTime}`);
                        
                        // ✅ Notify ALL HRAs
                        await supabase
                            .from('notifications')
                            .insert({
                                title: '✅ BedCheck Session Completed',
                                detail: `${session.name} has ended`,
                                body: `The BedCheck session for ${session.date} is now completed. All unverified students have been marked absent.`,
                                type: 'system',
                                priority: 'medium',
                                campus: null,  // University-wide
                                recipient_role: 'HRA',
                                actor: 'System',
                                action: 'Session Auto-Completed',
                                tone: 'blue',
                                read: false,
                                created_at: new Date().toISOString()
                            }).catch(() => {});
                    }
                }
            }
        }
        
        // 3. AUTO-CREATE NEXT DAY'S SESSION (University-Wide)
        if (currentTime === '00:00:00') {
            // Check how many scheduled sessions exist
            const { count, error: countError } = await supabase
                .from('sessions')
                .select('id', { count: 'exact', head: true })
                .eq('status', 'scheduled');
            
            if (!countError) {
                const scheduledCount = count || 0;
                
                if (scheduledCount < 5) {
                    // ✅ Get ALL active hostels (both campuses)
                    const { data: hostels, error: hostelsError } = await supabase
                        .from('hostels')
                        .select('id, campus')
                        .eq('status', 'Active');
                    
                    if (!hostelsError && hostels && hostels.length > 0) {
                        const nextDate = new Date();
                        nextDate.setDate(nextDate.getDate() + 1);
                        const dateStr = nextDate.toISOString().split('T')[0];
                        const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
                        const dayName = dayNames[nextDate.getDay()] || 'Night';
                        
                        // ✅ Check if session already exists for this date
                        const { data: existing, error: existingError } = await supabase
                            .from('sessions')
                            .select('id')
                            .eq('date', dateStr)
                            // REMOVED: .eq('campus', campus)
                            .maybeSingle();
                        
                        if (!existingError && !existing) {
                            // ✅ Create university-wide session
                            const newSession = {
                                name: `${dayName} Night BedCheck`,
                                date: dateStr,
                                start_time: '22:00:00',
                                end_time: '23:30:00',
                                status: 'scheduled',
                                hostels_completed: 0,
                                total_hostels: hostels.length || 0,
                                completion: 0,
                                academic_session: '2026/2027',
                                grace_period: 15,
                                created_by: 'system',
                                campus: null,  // ✅ University-wide
                                campus_code: null,  // ✅ University-wide
                                created_at: new Date().toISOString(),
                                updated_at: new Date().toISOString()
                            };
                            
                            const { error: insertError } = await supabase
                                .from('sessions')
                                .insert(newSession);
                            
                            if (!insertError) {
                                console.log(`📋 Auto-created university-wide session for ${dateStr} (${scheduledCount + 1}/5)`);
                                
                                // ✅ Notify RASDs
                                await supabase
                                    .from('notifications')
                                    .insert({
                                        title: '📋 New BedCheck Session Scheduled',
                                        detail: `${dayName} Night BedCheck for ${dateStr}`,
                                        body: `A new BedCheck session has been auto-scheduled for ${dateStr}. It will start at 10:00 PM.`,
                                        type: 'system',
                                        priority: 'low',
                                        campus: null,  // University-wide
                                        recipient_role: 'RASD',
                                        actor: 'System',
                                        action: 'Session Auto-Scheduled',
                                        tone: 'blue',
                                        read: false,
                                        created_at: new Date().toISOString()
                                    }).catch(() => {});
                            }
                        }
                    }
                } else {
                    console.log(`📋 Max scheduled sessions reached (${scheduledCount}/5). No new session created.`);
                }
            }
        }
        
    } catch (error) {
        console.error('❌ Scheduler error:', error);
    }
}, 30000); // Check every 30 seconds

// =====================================================
// CATCH-ALL 404 HANDLER
// =====================================================

app.use((req, res) => {
    console.log(`❌ Route not found: ${req.method} ${req.path}`);
    res.status(404).json({ 
        success: false, 
        message: 'Endpoint not found',
        path: req.path,
        method: req.method,
        code: 'NOT_FOUND'
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
        code: 'SERVER_ERROR',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// =====================================================
// START SERVER
// =====================================================

const server = app.listen(PORT, '0.0.0.0', async () => {
    console.log(`\n🚀 BIU BedCheck API v4.7.0 - Face-Only Verification`);
    console.log(`📍 Port: ${PORT}`);
    console.log(`🔐 Mode: ${process.env.NODE_ENV || 'production'}`);
    console.log(`🏢 RA Assignment System: ENABLED`);
    console.log(`📸 Verification Method: FACE ONLY`);
    console.log(`⏰ Auto-Session Management: ENABLED`);
    
    try {
        const health = await faceService.checkHealth();
        console.log(`📡 Face API: ${health.status === 'healthy' ? '✅ Connected' : '⚠️ Unavailable'}`);
    } catch {
        console.log(`📡 Face API: ⚠️ Unavailable (circuit breaker active)`);
    }
    
    console.log(`\n✅ Ready for requests\n`);
});

// Graceful shutdown
const shutdown = () => {
    console.log('\n🛑 Shutting down gracefully...');
    clearInterval(rateLimiterFirewall?.cleanupInterval);
    server.close(() => {
        console.log('✅ Server closed.');
        process.exit(0);
    });
    setTimeout(() => {
        console.error('⚠️ Force shutdown.');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Error handlers
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error.message);
    if (process.env.NODE_ENV !== 'production') {
        console.error(error.stack);
        process.exit(1);
    }
});

process.on('unhandledRejection', (reason) => {
    console.error('❌ Unhandled Rejection:', reason?.message || reason);
    if (process.env.NODE_ENV !== 'production') {
        console.error(reason?.stack);
        process.exit(1);
    }
});

module.exports = app;