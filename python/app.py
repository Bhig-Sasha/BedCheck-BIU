from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import insightface
import cv2
import numpy as np
import base64
import time
from typing import List, Optional, Dict, Any
import logging
import os
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

# Import our modules
from embeddings import (
    create_embedding,
    create_embedding_with_quality,
    smart_enrollment,
    prepare_embedding_for_db,
    validate_embedding,
    capture_frames_for_enrollment,
    average_embeddings
)
from verify import (
    get_face_embedding,
    cosine_similarity,
    verify_student,
    verify_against_multiple,
    verify_with_confidence_tracking,
    verify_multiple_with_tracking
)
from liveness import LivenessDetector

# ==========================
# Logging Configuration
# ==========================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==========================
# Supabase Configuration
# ==========================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

# ==========================
# FastAPI App
# ==========================
app = FastAPI(
    title="BIU BedCheck Face Engine",
    description="Face Recognition API for BIU BedCheck System",
    version="1.0.0"
)

# ==========================
# CORS Configuration
# ==========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# Request/Response Models
# ==========================
class ImageRequest(BaseModel):
    image: str
    student_id: Optional[str] = None
    threshold: Optional[float] = 0.55

class MultipleImageRequest(BaseModel):
    image: str
    embeddings: List[List[float]]
    student_ids: List[str]
    threshold: Optional[float] = 0.55

class EnrollmentRequest(BaseModel):
    image: str
    student_id: str
    hostel: str
    room: str
    name: Optional[str] = None

class BulkEnrollmentRequest(BaseModel):
    frames: List[str]
    student_id: str
    hostel: str
    room: str
    name: Optional[str] = None

class LivenessRequest(BaseModel):
    image: str

class VerifyRequest(BaseModel):
    image: str
    stored_embedding: List[float]
    threshold: Optional[float] = 0.55

class StudentEmbeddingRequest(BaseModel):
    student_id: int

# ==========================
# Global Variables
# ==========================
face_model = None
MODEL_LOADED = False

try:
    logger.info("Loading InsightFace model...")
    try:
        face_model = insightface.app.FaceAnalysis(
            name="antelopev2",
            root="./models",
            providers=["CPUExecutionProvider"],
            allowed_modules=['detection', 'recognition']
        )
        face_model.prepare(ctx_id=0, det_size=(640, 640))
        MODEL_LOADED = True
        logger.info("===================================")
        logger.info(" InsightFace (antelopev2) Loaded ")
        logger.info("===================================")
    except Exception as e:
        logger.warning(f"antelopev2 failed: {e}")
        
        logger.info("Trying buffalo_l model...")
        face_model = insightface.app.FaceAnalysis(
            name="buffalo_l",
            root="./models",
            providers=["CPUExecutionProvider"]
        )
        face_model.prepare(ctx_id=0, det_size=(320, 320))
        MODEL_LOADED = True
        logger.info("===================================")
        logger.info(" InsightFace (buffalo_l) Loaded ")
        logger.info("===================================")
        
except Exception as e:
    logger.error(f"Failed to load any model: {e}")
    logger.warning("Face recognition features will be unavailable")

# Initialize liveness detector
liveness_detector = LivenessDetector()

# ==========================
# Helper Functions
# ==========================
def decode_image(image_data: str) -> np.ndarray:
    try:
        if "base64," in image_data:
            image_data = image_data.split("base64,")[1]
        
        img_bytes = base64.b64decode(image_data)
        nparr = np.frombuffer(img_bytes, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if frame is None:
            raise ValueError("Failed to decode image")
        
        return frame
    except Exception as e:
        logger.error(f"Image decoding error: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid image data: {str(e)}")

# ==========================
# Health and Status Endpoints
# ==========================
@app.get("/")
def home():
    return {
        "status": "running",
        "engine": "InsightFace",
        "model": "antelopev2" if MODEL_LOADED else "not loaded",
        "version": "1.0.0",
        "message": "BIU BedCheck Face Engine is Online",
        "endpoints": {
            "health": "/health",
            "detect": "/detect-face",
            "enroll": "/enroll-face",
            "enroll-bulk": "/enroll-bulk",
            "verify": "/verify-face",
            "verify-multiple": "/verify-multiple",
            "liveness": "/check-liveness",
            "reset-liveness": "/reset-liveness",
            "compare": "/compare-embeddings",
            "student-embedding": "/api/student/{student_id}/embedding"
        }
    }

@app.get("/health")
def health():
    return {
        "status": "healthy" if MODEL_LOADED else "degraded",
        "model_loaded": MODEL_LOADED,
        "timestamp": time.time()
    }

@app.get("/model-info")
def model_info():
    return {
        "model": "antelopev2" if MODEL_LOADED else "not loaded",
        "embedding_size": 512,
        "detection_size": (640, 640),
        "loaded": MODEL_LOADED
    }

# ==========================
# STUDENT EMBEDDING ENDPOINT
# ==========================
@app.get("/api/student/{student_id}/embedding")
async def get_student_embedding(student_id: int):
    """Get a student's stored face embedding from Supabase"""
    try:
        if not supabase:
            raise HTTPException(status_code=503, detail="Supabase not configured")
        
        result = supabase.table("students").select("face_embedding").eq("id", student_id).execute()
        
        if not result.data:
            raise HTTPException(status_code=404, detail="Student not found")
        
        student = result.data[0]
        embedding = student.get("face_embedding")
        
        if embedding is None:
            raise HTTPException(status_code=404, detail="No face embedding found for this student")
        
        return {
            "success": True,
            "embedding": embedding,
            "student_id": student_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving embedding for student {student_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving embedding: {str(e)}")

# ==========================
# Face Detection Endpoint
# ==========================
@app.post("/detect-face")
async def detect_face(request: ImageRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        if frame is None:
            return {
                "success": False,
                "message": "Failed to decode image",
                "faces": []
            }
        
        try:
            faces = face_model.get(frame)
        except Exception as model_error:
            logger.error(f"Model inference error: {model_error}")
            return {
                "success": False,
                "message": f"Face detection error: {str(model_error)}",
                "faces": []
            }
        
        if len(faces) == 0:
            return {
                "success": False,
                "message": "No face detected",
                "faces": []
            }
        
        face_data = []
        for face in faces:
            try:
                bbox = face.bbox.tolist()
                face_data.append({
                    "bbox": bbox,
                    "confidence": float(face.det_score),
                    "width": bbox[2] - bbox[0],
                    "height": bbox[3] - bbox[1]
                })
            except Exception as face_error:
                logger.warning(f"Error processing face: {face_error}")
                continue
        
        return {
            "success": True,
            "detected": True,
            "message": f"Detected {len(face_data)} face(s)",
            "faces": face_data,
            "count": len(face_data)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Face detection error: {e}")
        return {
            "success": False,
            "detected": False,
            "message": f"Error: {str(e)}",
            "faces": [],
            "error": str(e)
        }

# ==========================
# Enrollment Endpoints
# ==========================
@app.post("/enroll-face")
async def enroll_face(request: EnrollmentRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        result = create_embedding_with_quality(
            face_model, 
            frame, 
            min_confidence=0.35,  
            min_face_size=60      
        )
        
        if not result["success"]:
            return {
                "success": False,
                "message": result["message"],
                "embedding": None,
                "confidence": 0.0,
                "quality": 0.0
            }
        
        embedding = prepare_embedding_for_db(result["embedding"])
        
        if not supabase:
            raise HTTPException(status_code=503, detail="Supabase not configured")

        student_id_int = int(request.student_id)

        # 1. Fetch student info for campus mapping
        student_res = supabase.table("students").select("campus, campus_code").eq("id", student_id_int).execute()
        
        if not student_res.data:
            raise HTTPException(status_code=404, detail=f"Student {request.student_id} not found.")
        
        student_info = student_res.data[0]

        # 2. Insert into `student_face`
        face_record = {
            "student_id": student_id_int,
            "campus": student_info.get("campus"),
            "campus_code": student_info.get("campus_code"),
            "face_embedding": embedding,
            "enrollment_status": "enrolled",
            "enrolled_by_student": True,
            "is_active": True,
            "confidence_score": result["confidence"]
        }
        supabase.table("student_face").insert(face_record).execute()

        # 3. Update `students` table flags
        supabase.table("students").update({
            "face_enrolled": True,
            "face_enrolled_at": "now()",
            "face_enrolled_by_student": True,
            "face_embedding": embedding
        }).eq("id", student_id_int).execute()
        
        return {
            "success": True,
            "embedding": embedding,
            "confidence": result["confidence"],
            "quality": result["quality_score"],
            "student_id": request.student_id,
            "message": "Face enrolled and saved to database successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enrollment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/enroll-bulk")
async def enroll_bulk(request: BulkEnrollmentRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frames = []
        for img_data in request.frames:
            frame = decode_image(img_data)
            frames.append(frame)
        
        if len(frames) == 0:
            return {
                "success": False,
                "message": "No frames provided",
                "embedding": None
            }
        
        embeddings = []
        confidence_scores = []
        quality_scores = []
        
        for frame in frames:
            result = create_embedding_with_quality(
                face_model, 
                frame, 
                min_confidence=0.35,  
                min_face_size=60      
            )
            if result["success"]:
                embeddings.append(result["embedding"])
                confidence_scores.append(result["confidence"])
                quality_scores.append(result["quality_score"])
        
        if len(embeddings) < 3:
            return {
                "success": False,
                "message": f"Only {len(embeddings)} good frames captured. Need at least 3.",
                "embedding": None,
                "frames_used": len(embeddings)
            }
        
        avg_embedding = average_embeddings(embeddings, weights=quality_scores)
        avg_confidence = float(np.mean(confidence_scores))
        avg_quality = float(np.mean(quality_scores))
        
        embedding = prepare_embedding_for_db(avg_embedding)

        if not supabase:
            raise HTTPException(status_code=503, detail="Supabase not configured")

        student_id_int = int(request.student_id)

        # 1. Fetch student campus info
        student_res = supabase.table("students").select("campus, campus_code").eq("id", student_id_int).execute()
        
        if not student_res.data:
            raise HTTPException(status_code=404, detail=f"Student {request.student_id} not found.")
            
        student_info = student_res.data[0]

        # 2. Insert into `student_face`
        face_record = {
            "student_id": student_id_int,
            "campus": student_info.get("campus"),
            "campus_code": student_info.get("campus_code"),
            "face_embedding": embedding,
            "enrollment_status": "enrolled",
            "enrolled_by_student": True,
            "is_active": True,
            "confidence_score": avg_confidence
        }
        supabase.table("student_face").insert(face_record).execute()

        # 3. Update `students` table status
        supabase.table("students").update({
            "face_enrolled": True,
            "face_enrolled_at": "now()",
            "face_enrolled_by_student": True,
            "face_embedding": embedding
        }).eq("id", student_id_int).execute()
        
        return {
            "success": True,
            "embedding": embedding,
            "confidence": avg_confidence,
            "quality": avg_quality,
            "frames_used": len(embeddings),
            "student_id": request.student_id,
            "message": f"Enrolled and saved using {len(embeddings)} frames"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk enrollment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/start-smart-enrollment")
async def start_smart_enrollment(request: ImageRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        return {
            "success": True,
            "message": "Smart enrollment ready. Please send multiple frames to /enroll-bulk",
            "frames_needed": 10,
            "min_frames_needed": 3
        }
        
    except Exception as e:
        logger.error(f"Smart enrollment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==========================
# Verification Endpoints
# ==========================
@app.post("/verify-face")
async def verify_face(request: VerifyRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        if frame is None:
            return {
                "success": False,
                "verified": False,
                "confidence": 0.0,
                "threshold": request.threshold,
                "reason": "Failed to decode image"
            }
        
        try:
            result = verify_student(
                face_model,
                frame,
                request.stored_embedding,
                threshold=request.threshold
            )
            return result
        except Exception as verify_error:
            logger.error(f"Verification error: {verify_error}")
            return {
                "success": False,
                "verified": False,
                "confidence": 0.0,
                "threshold": request.threshold,
                "reason": f"Verification error: {str(verify_error)}"
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return {
            "success": False,
            "verified": False,
            "confidence": 0.0,
            "threshold": request.threshold,
            "reason": f"Error: {str(e)}"
        }

@app.post("/verify-multiple")
async def verify_multiple(request: MultipleImageRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        result = verify_against_multiple(
            face_model,
            frame,
            request.embeddings,
            request.student_ids,
            threshold=request.threshold
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Multiple verification error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/compare-embeddings")
async def compare_embeddings(request: dict):
    try:
        embedding1 = request.get("embedding1")
        embedding2 = request.get("embedding2")
        
        if not embedding1 or not embedding2:
            raise HTTPException(status_code=400, detail="Both embeddings are required")
        
        similarity = cosine_similarity(embedding1, embedding2)
        
        return {
            "similarity": float(similarity),
            "match": similarity > 0.55,
            "threshold": 0.55
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Comparison error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==========================
# Liveness Detection Endpoints
# ==========================
@app.post("/check-liveness")
async def check_liveness(request: LivenessRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        faces = face_model.get(frame)
        is_live, message, progress = liveness_detector.check_liveness(frame, faces)
        
        return {
            "is_live": is_live,
            "message": message,
            "progress": int(progress),
            "face_detected": len(faces) > 0,
            "faces": len(faces)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Liveness check error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/reset-liveness")
async def reset_liveness():
    try:
        liveness_detector.reset()
        return {
            "success": True,
            "message": "Liveness detector reset",
            "phase": liveness_detector.phase
        }
    except Exception as e:
        logger.error(f"Reset liveness error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/liveness-status")
async def get_liveness_status():
    return {
        "phase": liveness_detector.phase,
        "blinks_completed": liveness_detector.blinks_completed,
        "head_movement_detected": liveness_detector.head_movement_detected,
        "face_positions": len(liveness_detector.face_positions)
    }

# ==========================
# Utility Endpoints
# ==========================
@app.post("/validate-embedding")
async def validate_embedding_endpoint(request: dict):
    try:
        embedding = request.get("embedding")
        is_valid = validate_embedding(embedding)
        
        return {
            "valid": is_valid,
            "dimension": len(embedding) if embedding else 0,
            "expected_dimension": 512
        }
        
    except Exception as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/extract-embedding")
async def extract_embedding(request: ImageRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        embedding = get_face_embedding(face_model, frame)
        
        if embedding is None:
            return {
                "success": False,
                "message": "No face detected",
                "embedding": None
            }
        
        return {
            "success": True,
            "embedding": embedding.tolist(),
            "dimension": len(embedding),
            "message": "Embedding extracted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Extract embedding error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==========================
# Error Handling
# ==========================
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return {
        "error": True,
        "status_code": exc.status_code,
        "detail": exc.detail
    }

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unexpected error: {exc}")
    return {
        "error": True,
        "status_code": 500,
        "detail": "An unexpected error occurred"
    }

# ==========================
# Main Entry Point
# ==========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True, log_level="info")