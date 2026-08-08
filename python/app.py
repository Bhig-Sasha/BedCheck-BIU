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
import requests
import zipfile
import shutil

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
    allow_origins=["*"],  # In production, restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# Request/Response Models
# ==========================
class ImageRequest(BaseModel):
    image: str  # Base64 encoded image
    student_id: Optional[str] = None
    threshold: Optional[float] = 0.55

class MultipleImageRequest(BaseModel):
    image: str  # Base64 encoded image
    embeddings: List[List[float]]  # List of stored embeddings
    student_ids: List[str]  # Corresponding student IDs
    threshold: Optional[float] = 0.55

class EnrollmentRequest(BaseModel):
    image: str  # Base64 encoded image
    student_id: str
    hostel: str
    room: str
    name: Optional[str] = None

class BulkEnrollmentRequest(BaseModel):
    frames: List[str]  # List of base64 encoded images
    student_id: str
    hostel: str
    room: str
    name: Optional[str] = None

class LivenessRequest(BaseModel):
    image: str  # Base64 encoded image

class VerifyRequest(BaseModel):
    image: str  # Base64 encoded image
    stored_embedding: List[float]
    threshold: Optional[float] = 0.55

# ==========================
# Helper Function to Download Model
# ==========================
def download_model_if_needed():
    """Download the InsightFace model if it's not already present"""
    model_dir = "./models"
    model_path = os.path.join(model_dir, "models", "antelopev2")
    
    os.makedirs(model_dir, exist_ok=True)
    
    # Check if model already exists
    if os.path.exists(model_path) and os.listdir(model_path):
        logger.info("Model already exists locally")
        return True
    
    logger.info("Model not found. Downloading...")
    
    try:
        model_url = "https://github.com/deepinsight/insightface/releases/download/v0.7/antelopev2.zip"
        zip_path = os.path.join(model_dir, "antelopev2.zip")
        
        # Download
        logger.info(f"Downloading from {model_url}")
        response = requests.get(model_url, stream=True, timeout=120)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        if progress % 10 < 2:
                            logger.info(f"Download progress: {progress:.1f}%")
        
        logger.info("Download complete. Extracting...")
        
        # Extract
        extract_path = os.path.join(model_dir, "models")
        os.makedirs(extract_path, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        
        # Clean up
        os.remove(zip_path)
        
        logger.info(f"Model extracted to {model_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to download model: {e}")
        return False

# ==========================
# Global Variables
# ==========================
# Load InsightFace model
face_model = None

try:
    # Ensure model is downloaded
    if not download_model_if_needed():
        logger.warning("Could not download model, attempting to load anyway...")
    
    # Try to load the model
    face_model = insightface.app.FaceAnalysis(
        name="antelopev2",
        root="./models",
        providers=["CPUExecutionProvider"],
        allowed_modules=['detection', 'recognition']
    )
    
    # Prepare the model
    face_model.prepare(
        ctx_id=0,
        det_size=(640, 640)
    )
    
    logger.info("===================================")
    logger.info(" InsightFace Loaded Successfully ")
    logger.info("===================================")
    
except Exception as e:
    logger.error(f"Failed to load InsightFace: {e}")
    
    # Try with buffalo_l as fallback
    try:
        logger.info("Attempting to load buffalo_l model as fallback...")
        face_model = insightface.app.FaceAnalysis(
            name="buffalo_l",
            root="./models",
            providers=["CPUExecutionProvider"],
            allowed_modules=['detection', 'recognition']
        )
        face_model.prepare(
            ctx_id=0,
            det_size=(640, 640)
        )
        logger.info("===================================")
        logger.info(" InsightFace (buffalo_l) Loaded Successfully ")
        logger.info("===================================")
    except Exception as e2:
        logger.error(f"Failed to load fallback model: {e2}")
        # Don't raise - let the app start but with face_model = None
        logger.warning("Face recognition features will be unavailable")

# Initialize liveness detector
liveness_detector = LivenessDetector()

# ==========================
# Helper Functions
# ==========================
def decode_image(image_data: str) -> np.ndarray:
    """
    Decode base64 image to OpenCV format
    """
    try:
        # Remove data URL prefix if present
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
        "model": "antelopev2" if face_model else "not loaded",
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
            "compare": "/compare-embeddings"
        }
    }

@app.get("/health")
def health():
    return {
        "status": "healthy" if face_model else "unhealthy",
        "model_loaded": face_model is not None,
        "timestamp": time.time()
    }

@app.get("/model-info")
def model_info():
    return {
        "model": "antelopev2",
        "embedding_size": 512,
        "detection_size": (640, 640),
        "providers": ["CPUExecutionProvider"],
        "loaded": face_model is not None
    }

# ==========================
# Face Detection Endpoint
# ==========================
@app.post("/detect-face")
async def detect_face(request: ImageRequest):
    """
    Detect a face in the image and return bounding box
    """
    if face_model is None:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        # Detect faces
        faces = face_model.get(frame)
        
        if len(faces) == 0:
            return {
                "success": False,
                "message": "No face detected",
                "faces": []
            }
        
        # Process all detected faces
        face_data = []
        for face in faces:
            bbox = face.bbox.tolist()
            face_data.append({
                "bbox": bbox,
                "confidence": float(face.det_score),
                "width": bbox[2] - bbox[0],
                "height": bbox[3] - bbox[1]
            })
        
        return {
            "success": True,
            "message": f"Detected {len(faces)} face(s)",
            "faces": face_data,
            "count": len(faces)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Face detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==========================
# Enrollment Endpoints
# ==========================
@app.post("/enroll-face")
async def enroll_face(request: EnrollmentRequest):
    """
    Enroll a face (single image) and generate embedding
    """
    if face_model is None:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        # Create embedding with quality check
        result = create_embedding_with_quality(face_model, frame, min_confidence=0.5)
        
        if not result["success"]:
            return {
                "success": False,
                "message": result["message"],
                "embedding": None,
                "confidence": 0.0,
                "quality": 0.0
            }
        
        # Prepare embedding for database
        embedding = prepare_embedding_for_db(result["embedding"])
        
        return {
            "success": True,
            "embedding": embedding,
            "confidence": result["confidence"],
            "quality": result["quality_score"],
            "student_id": request.student_id,
            "message": "Face enrolled successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enrollment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/enroll-bulk")
async def enroll_bulk(request: BulkEnrollmentRequest):
    """
    Enroll a face using multiple frames for better accuracy
    """
    if face_model is None:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        # Decode all frames
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
        
        # Process each frame
        embeddings = []
        confidence_scores = []
        quality_scores = []
        
        for frame in frames:
            result = create_embedding_with_quality(face_model, frame, min_confidence=0.5)
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
        
        # Average embeddings with quality weighting
        avg_embedding = average_embeddings(embeddings, weights=quality_scores)
        avg_confidence = np.mean(confidence_scores)
        avg_quality = np.mean(quality_scores)
        
        # Prepare for database
        embedding = prepare_embedding_for_db(avg_embedding)
        
        return {
            "success": True,
            "embedding": embedding,
            "confidence": float(avg_confidence),
            "quality": float(avg_quality),
            "frames_used": len(embeddings),
            "student_id": request.student_id,
            "message": f"Enrolled using {len(embeddings)} frames"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk enrollment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/start-smart-enrollment")
async def start_smart_enrollment(request: ImageRequest):
    """
    Start smart enrollment - captures multiple frames automatically
    """
    if face_model is None:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        # This endpoint would typically be used with a video stream
        # For now, we'll just return instructions
        return {
            "success": True,
            "message": "Smart enrollment ready. Please send multiple frames to /enroll-bulk",
            "frames_needed": 10,
            "min_frames_needed": 5
        }
        
    except Exception as e:
        logger.error(f"Smart enrollment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==========================
# Verification Endpoints
# ==========================
@app.post("/verify-face")
async def verify_face(request: VerifyRequest):
    """
    Verify a face against a stored embedding
    """
    if face_model is None:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        # Pass face_model as first argument
        result = verify_student(
            face_model,
            frame,
            request.stored_embedding,
            threshold=request.threshold
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verification error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-multiple")
async def verify_multiple(request: MultipleImageRequest):
    """
    Verify a face against multiple stored embeddings
    """
    if face_model is None:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        # Pass face_model as first argument
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
    """
    Compare two embeddings directly
    """
    try:
        embedding1 = request.get("embedding1")
        embedding2 = request.get("embedding2")
        
        if not embedding1 or not embedding2:
            raise HTTPException(status_code=400, detail="Both embeddings are required")
        
        # Calculate similarity
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
    """
    Check if the person in the image is live
    """
    if face_model is None:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        # Detect faces
        faces = face_model.get(frame)
        
        # Check liveness
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
    """
    Reset the liveness detector for a new student
    """
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
    """
    Get current liveness detection status
    """
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
    """
    Validate if an embedding is properly formatted
    """
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
    """
    Extract embedding from an image without saving
    """
    if face_model is None:
        raise HTTPException(status_code=503, detail="Face model not loaded")
    
    try:
        frame = decode_image(request.image)
        
        # Pass face_model as first argument
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
    
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )