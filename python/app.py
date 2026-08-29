import os
import time
import base64
import logging
from typing import List, Optional, Dict, Any

import fastapi
import fastapi.middleware.cors
import pydantic
import insightface
import cv2
import numpy as np
import dotenv
import supabase as supabase_

# ============================================================
# ENVIRONMENT
# ============================================================

dotenv.load_dotenv()

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================
# PACKAGE IMPORTS
# IMPORTANT:
# The Render start command should be:
#
# uvicorn python.app:app --host 0.0.0.0 --port $PORT
#
# This means "python" is treated as a package.
# ============================================================

from .embeddings import (
    create_embedding,
    create_embedding_with_quality,
    smart_enrollment,
    prepare_embedding_for_db,
    validate_embedding,
    capture_frames_for_enrollment,
    average_embeddings
)

from .verify import (
    get_face_embedding,
    cosine_similarity,
    verify_student,
    verify_against_multiple,
    verify_with_confidence_tracking,
    verify_multiple_with_tracking
)

from .liveness import LivenessDetector
from .matcher import FaceMatcher, OrganizationFaceMatcher

# ============================================================
# SUPABASE CONFIGURATION
# ============================================================

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

supabase: Optional[supabase_.Client] = None

if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = supabase_.create_client(
            SUPABASE_URL,
            SUPABASE_KEY
        )
        logger.info("Supabase client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Supabase: {e}")
else:
    logger.warning(
        "SUPABASE_URL or SUPABASE_SERVICE_KEY is missing"
    )

# ============================================================
# FASTAPI APP
# ============================================================

app = fastapi.FastAPI(
    title="BIU BedCheck Face Engine",
    description="Face Recognition API for BIU BedCheck System",
    version="1.0.0"
)

# ============================================================
# CORS
# ============================================================

app.add_middleware(
    fastapi.middleware.cors.CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# REQUEST / RESPONSE MODELS
# ============================================================

class ImageRequest(pydantic.BaseModel):
    image: str
    student_id: Optional[str] = None
    threshold: Optional[float] = 0.55


class MultipleImageRequest(pydantic.BaseModel):
    image: str
    embeddings: List[List[float]]
    student_ids: List[str]
    threshold: Optional[float] = 0.55


class EnrollmentRequest(pydantic.BaseModel):
    image: str
    student_id: str
    hostel: str
    room: str
    name: Optional[str] = None


class BulkEnrollmentRequest(pydantic.BaseModel):
    frames: List[str]
    student_id: str
    hostel: str
    room: str
    name: Optional[str] = None


class LivenessRequest(pydantic.BaseModel):
    image: str


class VerifyRequest(pydantic.BaseModel):
    image: str
    stored_embedding: List[float]
    threshold: Optional[float] = 0.55


class StudentEmbeddingRequest(pydantic.BaseModel):
    student_id: int


class MatchRequest(pydantic.BaseModel):
    image: str
    organization: str
    threshold: Optional[float] = 0.55


class BatchMatchRequest(pydantic.BaseModel):
    images: List[str]
    organization: str
    threshold: Optional[float] = 0.55


# ============================================================
# GLOBAL MODEL VARIABLES
# ============================================================

face_model = None
MODEL_LOADED = False

# ============================================================
# LOAD INSIGHTFACE MODEL
# ============================================================

try:
    logger.info("===================================")
    logger.info("Loading InsightFace model...")
    logger.info("===================================")

    try:
        face_model = insightface.app.FaceAnalysis(
            name="antelopev2",
            root="./models",
            providers=["CPUExecutionProvider"],
            allowed_modules=[
                "detection",
                "recognition"
            ]
        )

        face_model.prepare(
            ctx_id=0,
            det_size=(640, 640)
        )

        MODEL_LOADED = True

        logger.info("===================================")
        logger.info(" InsightFace antelopev2 Loaded ")
        logger.info("===================================")

    except Exception as e:
        logger.warning(
            f"antelopev2 failed to load: {e}"
        )

        logger.info("Trying buffalo_l model...")

        face_model = insightface.app.FaceAnalysis(
            name="buffalo_l",
            root="./models",
            providers=["CPUExecutionProvider"]
        )

        face_model.prepare(
            ctx_id=0,
            det_size=(320, 320)
        )

        MODEL_LOADED = True

        logger.info("===================================")
        logger.info(" InsightFace buffalo_l Loaded ")
        logger.info("===================================")

except Exception as e:
    logger.error(
        f"Failed to load any InsightFace model: {e}"
    )

    MODEL_LOADED = False
    face_model = None

    logger.warning(
        "Face recognition features will be unavailable"
    )


# ============================================================
# LIVENESS DETECTOR
# ============================================================

liveness_detector = LivenessDetector()


# ============================================================
# FACE MATCHERS
# ============================================================

face_matcher = None
org_face_matcher = None

if supabase and MODEL_LOADED:

    try:
        face_matcher = FaceMatcher(
            supabase,
            threshold=0.55
        )

        org_face_matcher = OrganizationFaceMatcher(
            supabase,
            face_model,
            threshold=0.55
        )

        logger.info("===================================")
        logger.info(" Face Matchers Initialized ")
        logger.info("===================================")

    except Exception as e:
        logger.error(
            f"Failed to initialize face matchers: {e}"
        )

else:

    if not supabase:
        logger.warning(
            "Supabase not configured - face matchers disabled"
        )

    if not MODEL_LOADED:
        logger.warning(
            "Face model not loaded - face matchers disabled"
        )


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def decode_image(image_data: str) -> np.ndarray:

    try:

        if "base64," in image_data:
            image_data = image_data.split(
                "base64,"
            )[1]

        img_bytes = base64.b64decode(
            image_data
        )

        nparr = np.frombuffer(
            img_bytes,
            np.uint8
        )

        frame = cv2.imdecode(
            nparr,
            cv2.IMREAD_COLOR
        )

        if frame is None:
            raise ValueError(
                "Failed to decode image"
            )

        return frame

    except Exception as e:

        logger.error(
            f"Image decoding error: {e}"
        )

        raise fastapi.HTTPException(
            status_code=400,
            detail=f"Invalid image data: {str(e)}"
        )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def home():

    return {
        "status": "running",
        "engine": "InsightFace",
        "model": (
            "antelopev2"
            if MODEL_LOADED
            else "not loaded"
        ),
        "version": "1.0.0",
        "message": "BIU BedCheck Face Engine is Online",
        "matcher_ready": face_matcher is not None,
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
            "student-embedding":
                "/api/student/{student_id}/embedding",
            "extract-embedding": "/extract-embedding",
            "validate-embedding": "/validate-embedding",
            "match-face": "/match-face",
            "match-face-similar":
                "/match-face-similar",
            "batch-match":
                "/batch-match-faces",
            "org-embeddings":
                "/organization/{org_id}/embeddings",
            "face-compare": "/face-compare"
        }
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": (
            "healthy"
            if MODEL_LOADED
            else "degraded"
        ),
        "model_loaded": MODEL_LOADED,
        "supabase_connected": supabase is not None,
        "matcher_ready": face_matcher is not None,
        "timestamp": time.time()
    }


# ============================================================
# MODEL INFO
# ============================================================

@app.get("/model-info")
def model_info():

    return {
        "model": (
            "antelopev2"
            if MODEL_LOADED
            else "not loaded"
        ),
        "embedding_size": 512,
        "detection_size": [640, 640],
        "loaded": MODEL_LOADED
    }


# ============================================================
# STUDENT EMBEDDING
# ============================================================

@app.get(
    "/api/student/{student_id}/embedding"
)
async def get_student_embedding(
    student_id: int
):

    try:

        if not supabase:
            raise fastapi.HTTPException(
                status_code=503,
                detail="Supabase not configured"
            )

        result = (
            supabase
            .table("student_face")
            .select(
                "face_embedding, "
                "confidence_score, "
                "enrollment_status, "
                "is_active"
            )
            .eq("student_id", student_id)
            .eq("is_active", True)
            .execute()
        )

        if not result.data:

            raise fastapi.HTTPException(
                status_code=404,
                detail=(
                    "No face embedding found "
                    "for this student"
                )
            )

        row = result.data[0]

        embedding = row.get(
            "face_embedding"
        )

        if embedding is None:

            raise fastapi.HTTPException(
                status_code=404,
                detail=(
                    "No face embedding found "
                    "for this student"
                )
            )

        return {
            "success": True,
            "embedding": embedding,
            "student_id": student_id,
            "confidence_score":
                row.get("confidence_score"),
            "enrollment_status":
                row.get("enrollment_status")
        }

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Error retrieving embedding "
            f"for student {student_id}: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=(
                f"Error retrieving embedding: {str(e)}"
            )
        )


# ============================================================
# FACE DETECTION
# ============================================================

@app.post("/detect-face")
async def detect_face(
    request: ImageRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    try:

        frame = decode_image(
            request.image
        )

        faces = face_model.get(frame)

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
                    "confidence":
                        float(face.det_score),
                    "width":
                        bbox[2] - bbox[0],
                    "height":
                        bbox[3] - bbox[1]
                })

            except Exception as face_error:

                logger.warning(
                    f"Error processing face: "
                    f"{face_error}"
                )

        return {
            "success": True,
            "detected": True,
            "message":
                f"Detected {len(face_data)} face(s)",
            "faces": face_data,
            "count": len(face_data)
        }

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Face detection error: {e}"
        )

        return {
            "success": False,
            "detected": False,
            "message": f"Error: {str(e)}",
            "faces": [],
            "error": str(e)
        }


# ============================================================
# ENROLL FACE
# ============================================================

@app.post("/enroll-face")
async def enroll_face(
    request: EnrollmentRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    if not supabase:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Supabase not configured"
        )

    try:

        frame = decode_image(
            request.image
        )

        result = create_embedding_with_quality(
            face_model,
            frame,
            min_confidence=0.35,
            min_face_size=60
        )

        if not result["success"]:

            return {
                "success": False,
                "message":
                    result["message"],
                "embedding": None,
                "confidence": 0.0,
                "quality": 0.0
            }

        embedding = prepare_embedding_for_db(
            result["embedding"]
        )

        student_id_int = int(
            request.student_id
        )

        student_res = (
            supabase
            .table("students")
            .select(
                "id, campus, campus_code"
            )
            .eq("id", student_id_int)
            .execute()
        )

        if not student_res.data:

            raise fastapi.HTTPException(
                status_code=404,
                detail=(
                    f"Student "
                    f"{request.student_id} "
                    f"not found."
                )
            )

        student_info = student_res.data[0]

        campus = (
            student_info.get("campus")
            or "Legacy"
        )

        campus_code = (
            student_info.get("campus_code")
            or (
                "LEG"
                if campus == "Legacy"
                else "HER"
            )
        )

        face_record = {
            "student_id": student_id_int,
            "campus": campus,
            "campus_code": campus_code,
            "face_embedding": embedding,
            "face_image_url": None,
            "face_image_path": None,
            "enrollment_status": "enrolled",
            "enrollment_date": "now()",
            "last_verified": None,
            "verification_count": 0,
            "confidence_score":
                float(result["confidence"]),
            "is_active": True,
            "notes": None,
            "enrolled_by": None,
            "enrolled_by_student": True,
            "enrollment_ip": None,
            "enrollment_device": None
        }

        existing = (
            supabase
            .table("student_face")
            .select("id")
            .eq("student_id", student_id_int)
            .eq("campus", campus)
            .execute()
        )

        if existing.data:

            face_res = (
                supabase
                .table("student_face")
                .update(face_record)
                .eq(
                    "id",
                    existing.data[0]["id"]
                )
                .execute()
            )

        else:

            face_res = (
                supabase
                .table("student_face")
                .insert(face_record)
                .execute()
            )

        if not face_res.data:

            raise fastapi.HTTPException(
                status_code=500,
                detail=(
                    "Failed to save face data "
                    "to student_face"
                )
            )

        (
            supabase
            .table("students")
            .update({
                "face_enrolled": True,
                "updated_at": "now()"
            })
            .eq("id", student_id_int)
            .execute()
        )

        return {
            "success": True,
            "embedding": embedding,
            "confidence":
                result["confidence"],
            "quality":
                result["quality_score"],
            "student_id":
                request.student_id,
            "message":
                "Face enrolled and saved to "
                "student_face successfully"
        }

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Enrollment error: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# BULK ENROLLMENT
# ============================================================

@app.post("/enroll-bulk")
async def enroll_bulk(
    request: BulkEnrollmentRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    if not supabase:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Supabase not configured"
        )

    try:

        frames = []

        for img_data in request.frames:

            frame = decode_image(
                img_data
            )

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

                embeddings.append(
                    result["embedding"]
                )

                confidence_scores.append(
                    result["confidence"]
                )

                quality_scores.append(
                    result["quality_score"]
                )

        if len(embeddings) < 3:

            return {
                "success": False,
                "message": (
                    f"Only {len(embeddings)} "
                    "good frames captured. "
                    "Need at least 3."
                ),
                "embedding": None,
                "frames_used":
                    len(embeddings)
            }

        avg_embedding = average_embeddings(
            embeddings,
            weights=quality_scores
        )

        avg_confidence = float(
            np.mean(confidence_scores)
        )

        avg_quality = float(
            np.mean(quality_scores)
        )

        embedding = prepare_embedding_for_db(
            avg_embedding
        )

        student_id_int = int(
            request.student_id
        )

        student_res = (
            supabase
            .table("students")
            .select(
                "id, campus, campus_code"
            )
            .eq("id", student_id_int)
            .execute()
        )

        if not student_res.data:

            raise fastapi.HTTPException(
                status_code=404,
                detail=(
                    f"Student "
                    f"{request.student_id} "
                    "not found."
                )
            )

        student_info = student_res.data[0]

        face_record = {
            "student_id": student_id_int,
            "campus":
                student_info.get("campus"),
            "campus_code":
                student_info.get("campus_code"),
            "face_embedding": embedding,
            "enrollment_status": "enrolled",
            "enrolled_by_student": True,
            "is_active": True,
            "confidence_score":
                avg_confidence
        }

        (
            supabase
            .table("student_face")
            .insert(face_record)
            .execute()
        )

        (
            supabase
            .table("students")
            .update({
                "face_enrolled": True,
                "face_enrolled_at": "now()",
                "face_enrolled_by_student": True
            })
            .eq("id", student_id_int)
            .execute()
        )

        return {
            "success": True,
            "embedding": embedding,
            "confidence":
                avg_confidence,
            "quality":
                avg_quality,
            "frames_used":
                len(embeddings),
            "student_id":
                request.student_id,
            "message": (
                f"Enrolled and saved using "
                f"{len(embeddings)} frames"
            )
        }

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Bulk enrollment error: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# SMART ENROLLMENT
# ============================================================

@app.post("/start-smart-enrollment")
async def start_smart_enrollment(
    request: ImageRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    return {
        "success": True,
        "message": (
            "Smart enrollment ready. "
            "Please send multiple frames "
            "to /enroll-bulk"
        ),
        "frames_needed": 10,
        "min_frames_needed": 3
    }


# ============================================================
# VERIFY FACE
# ============================================================

@app.post("/verify-face")
async def verify_face(
    request: VerifyRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    try:

        frame = decode_image(
            request.image
        )

        result = verify_student(
            face_model,
            frame,
            request.stored_embedding,
            threshold=request.threshold
        )

        return result

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Verification error: {e}"
        )

        return {
            "success": False,
            "verified": False,
            "confidence": 0.0,
            "threshold":
                request.threshold,
            "reason":
                f"Verification error: {str(e)}"
        }


# ============================================================
# VERIFY MULTIPLE
# ============================================================

@app.post("/verify-multiple")
async def verify_multiple(
    request: MultipleImageRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    try:

        frame = decode_image(
            request.image
        )

        return verify_against_multiple(
            face_model,
            frame,
            request.embeddings,
            request.student_ids,
            threshold=request.threshold
        )

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Multiple verification error: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# COMPARE EMBEDDINGS
# ============================================================

@app.post("/compare-embeddings")
async def compare_embeddings(
    request: dict
):

    try:

        embedding1 = request.get(
            "embedding1"
        )

        embedding2 = request.get(
            "embedding2"
        )

        if not embedding1 or not embedding2:

            raise fastapi.HTTPException(
                status_code=400,
                detail=(
                    "Both embeddings are required"
                )
            )

        similarity = cosine_similarity(
            embedding1,
            embedding2
        )

        return {
            "similarity":
                float(similarity),
            "match":
                similarity > 0.55,
            "threshold": 0.55
        }

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Comparison error: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# LIVENESS
# ============================================================

@app.post("/check-liveness")
async def check_liveness(
    request: LivenessRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    try:

        frame = decode_image(
            request.image
        )

        faces = face_model.get(
            frame
        )

        is_live, message, progress = (
            liveness_detector.check_liveness(
                frame,
                faces
            )
        )

        return {
            "is_live": is_live,
            "message": message,
            "progress": int(progress),
            "face_detected":
                len(faces) > 0,
            "faces":
                len(faces)
        }

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Liveness check error: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=str(e)
        )


@app.post("/reset-liveness")
async def reset_liveness():

    try:

        liveness_detector.reset()

        return {
            "success": True,
            "message":
                "Liveness detector reset",
            "phase":
                liveness_detector.phase
        }

    except Exception as e:

        logger.error(
            f"Reset liveness error: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=str(e)
        )


@app.get("/liveness-status")
async def get_liveness_status():

    return {
        "phase":
            liveness_detector.phase,
        "blinks_completed":
            liveness_detector.blinks_completed,
        "head_movement_detected":
            liveness_detector.head_movement_detected,
        "face_positions":
            len(
                liveness_detector.face_positions
            )
    }


# ============================================================
# FACE MATCHING
# ============================================================

@app.post("/match-face")
async def match_face_endpoint(
    request: MatchRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    if not face_matcher:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face matcher not initialized"
        )

    try:

        frame = decode_image(
            request.image
        )

        embedding = get_face_embedding(
            face_model,
            frame
        )

        if embedding is None:

            return {
                "success": False,
                "matched": False,
                "message":
                    "No face detected "
                    "in the image",
                "student_id": None,
                "similarity_score": 0.0
            }

        return face_matcher.match_face(
            organization=
                request.organization,
            face_embedding=
                embedding.tolist(),
            threshold=
                request.threshold or 0.55
        )

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Face match error: {e}"
        )

        return {
            "success": False,
            "matched": False,
            "message": str(e),
            "student_id": None,
            "similarity_score": 0.0
        }


@app.post("/match-face-similar")
async def match_face_similar(
    request: MatchRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    if not org_face_matcher:

        raise fastapi.HTTPException(
            status_code=503,
            detail=(
                "Organization matcher "
                "not initialized"
            )
        )

    try:

        return org_face_matcher.get_similar_person(
            organization=
                request.organization,
            image_data=
                request.image
        )

    except Exception as e:

        logger.error(
            f"Face match error: {e}"
        )

        return {
            "success": False,
            "matched": False,
            "message": str(e),
            "student_id": None,
            "similarity_score": 0.0
        }


@app.post("/batch-match-faces")
async def batch_match_faces(
    request: BatchMatchRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    if not face_matcher:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face matcher not initialized"
        )

    try:

        embeddings = []

        for img_data in request.images:

            frame = decode_image(
                img_data
            )

            embedding = get_face_embedding(
                face_model,
                frame
            )

            if embedding is not None:

                embeddings.append(
                    embedding.tolist()
                )

        if not embeddings:

            return {
                "success": False,
                "message":
                    "No valid faces found "
                    "in images",
                "matches": []
            }

        matches = (
            face_matcher.batch_match_faces(
                organization=
                    request.organization,
                embeddings=embeddings,
                threshold=
                    request.threshold or 0.55
            )
        )

        return {
            "success": True,
            "total_matches":
                len(matches),
            "matches": matches
        }

    except Exception as e:

        logger.error(
            f"Batch match error: {e}"
        )

        return {
            "success": False,
            "message": str(e),
            "matches": []
        }


# ============================================================
# ORGANIZATION EMBEDDINGS
# ============================================================

@app.get(
    "/organization/{org_id}/embeddings"
)
async def get_organization_embeddings(
    org_id: str,
    limit: int = 100
):

    if not supabase:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Supabase not configured"
        )

    try:

        result = (
            supabase
            .table("student_face")
            .select(
                "student_id, "
                "confidence_score, "
                "enrollment_status, "
                "is_active"
            )
            .eq("campus_code", org_id)
            .eq("is_active", True)
            .limit(limit)
            .execute()
        )

        return {
            "success": True,
            "organization": org_id,
            "total":
                len(result.data),
            "embeddings":
                result.data
        }

    except Exception as e:

        logger.error(
            "Error fetching organization "
            f"embeddings: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# FACE COMPARE
# ============================================================

@app.post("/face-compare")
async def face_compare(
    request: MatchRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    if not face_matcher:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face matcher not initialized"
        )

    try:

        frame = decode_image(
            request.image
        )

        embedding = get_face_embedding(
            face_model,
            frame
        )

        if embedding is None:

            return {
                "error":
                    "No matching face found.",
                "match": False
            }

        student_id, similarity = (
            face_matcher.find_similar_embedding(
                organization=
                    request.organization,
                query_embedding=
                    embedding.tolist()
            )
        )

        if student_id is None:

            return {
                "error":
                    "No matching face found.",
                "match": False
            }

        return {
            "embed_id":
                student_id,
            "similarity_score":
                similarity,
            "match": True
        }

    except Exception as e:

        logger.error(
            f"Face compare error: {e}"
        )

        return {
            "error": str(e),
            "match": False
        }


# ============================================================
# VALIDATE EMBEDDING
# ============================================================

@app.post("/validate-embedding")
async def validate_embedding_endpoint(
    request: dict
):

    try:

        embedding = request.get(
            "embedding"
        )

        is_valid = validate_embedding(
            embedding
        )

        return {
            "valid": is_valid,
            "dimension":
                len(embedding)
                if embedding
                else 0,
            "expected_dimension": 512
        }

    except Exception as e:

        logger.error(
            f"Validation error: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# EXTRACT EMBEDDING
# ============================================================

@app.post("/extract-embedding")
async def extract_embedding(
    request: ImageRequest
):

    if not MODEL_LOADED:

        raise fastapi.HTTPException(
            status_code=503,
            detail="Face model not loaded"
        )

    try:

        frame = decode_image(
            request.image
        )

        embedding = get_face_embedding(
            face_model,
            frame
        )

        if embedding is None:

            return {
                "success": False,
                "message":
                    "No face detected",
                "embedding": None
            }

        return {
            "success": True,
            "embedding":
                embedding.tolist(),
            "dimension":
                len(embedding),
            "message":
                "Embedding extracted successfully"
        }

    except fastapi.HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Extract embedding error: {e}"
        )

        raise fastapi.HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.exception_handler(
    fastapi.HTTPException
)
async def http_exception_handler(
    request,
    exc
):

    return fastapi.responses.JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code":
                exc.status_code,
            "detail": exc.detail
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(
    request,
    exc
):

    logger.error(
        f"Unexpected error: {exc}"
    )

    return fastapi.responses.JSONResponse(
        status_code=500,
        content={
            "error": True,
            "status_code": 500,
            "detail":
                "An unexpected error occurred"
        }
    )


# ============================================================
# LOCAL DEVELOPMENT
# IMPORTANT:
# Use python.app:app because this file is
# inside the python package.
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "python.app:app",
        host="0.0.0.0",
        port=int(
            os.getenv("PORT", "8000")
        ),
        reload=False,
        log_level="info"
    )