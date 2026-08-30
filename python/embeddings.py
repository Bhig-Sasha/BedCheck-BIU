# python/embeddings.py

import cv2
import numpy as np
import time
from typing import List, Optional, Dict, Any


def get_largest_face(faces):
    """Return the face with the largest bounding-box area."""
    if not faces:
        return None
    return max(
        faces,
        key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1])
    )


# ==========================================
# CREATE FACE EMBEDDING (Single Frame)
# ==========================================

def create_embedding(face_model, image) -> Dict[str, Any]:
    """
    Detect the largest face and generate its embedding + quality score.

    Returns:
        {
            "success": bool,
            "embedding": list | None,
            "confidence": float,
            "bbox": list | None,
            "quality_score": float,
            "message": str
        }
    """
    faces = face_model.get(image)

    if not faces:
        return {
            "success": False,
            "message": "No face detected.",
            "embedding": None,
            "confidence": 0.0,
            "bbox": None,
            "quality_score": 0.0,
        }

    face = get_largest_face(faces)

    bbox = face.bbox
    face_width = float(bbox[2] - bbox[0])
    face_height = float(bbox[3] - bbox[1])
    face_area = face_width * face_height
    image_area = float(image.shape[0] * image.shape[1])
    size_ratio = face_area / image_area if image_area > 0 else 0.0

    # Quality = detection confidence × size factor
    quality_score = float(face.det_score) * (0.7 + 0.3 * min(size_ratio * 10.0, 1.0))

    return {
        "success": True,
        "embedding": face.embedding.tolist(),
        "confidence": float(face.det_score),
        "bbox": bbox.tolist(),
        "quality_score": quality_score,
        "message": "Face detected successfully.",
    }


# ==========================================
# CREATE EMBEDDING WITH QUALITY CHECK
# ==========================================

def create_embedding_with_quality(
    face_model,
    image,
    min_confidence: float = 0.35,
    min_face_size: int = 60,
) -> Dict[str, Any]:
    """
    Create embedding only if confidence and face size pass thresholds.
    """
    result = create_embedding(face_model, image)

    if not result["success"]:
        return result

    if result["confidence"] < min_confidence:
        return {
            "success": False,
            "message": (
                f"Face detection confidence too low: "
                f"{result['confidence']:.2f} (need {min_confidence})"
            ),
            "embedding": None,
            "confidence": result["confidence"],
            "bbox": result["bbox"],
            "quality_score": 0.0,
        }

    bbox = result["bbox"]
    face_width = bbox[2] - bbox[0]
    face_height = bbox[3] - bbox[1]

    if face_width < min_face_size or face_height < min_face_size:
        return {
            "success": False,
            "message": (
                f"Face too small: {int(face_width)}x{int(face_height)}px "
                f"(minimum {min_face_size}x{min_face_size})"
            ),
            "embedding": None,
            "confidence": result["confidence"],
            "bbox": result["bbox"],
            "quality_score": 0.0,
        }

    return result


# ==========================================
# CAPTURE MULTIPLE FRAMES FOR ENROLLMENT
# ==========================================

def capture_frames_for_enrollment(
    face_model,
    camera,
    num_frames: int = 10,
    min_confidence: float = 0.35,
):
    """
    Capture multiple frames with face detection for enrollment.
    (Used mainly for local testing / webcam flows.)
    """
    embeddings = []
    confidence_scores = []
    quality_scores = []
    bboxes = []

    print(f"Capturing {num_frames} frames for enrollment...")
    print("Please look at the camera and move naturally")
    time.sleep(1)

    for i in range(num_frames):
        ret, frame = camera.read()
        if not ret:
            continue

        result = create_embedding_with_quality(face_model, frame, min_confidence)

        if result["success"]:
            embeddings.append(result["embedding"])
            confidence_scores.append(result["confidence"])
            quality_scores.append(result["quality_score"])
            bboxes.append(result["bbox"])
            print(f"  Frame {i+1}/{num_frames}: ✓ Face detected (conf: {result['confidence']:.2f})")
        else:
            print(f"  Frame {i+1}/{num_frames}: ✗ {result['message']}")

        time.sleep(0.2)

    if len(embeddings) < num_frames * 0.5:
        return {
            "success": False,
            "message": f"Only {len(embeddings)}/{num_frames} good frames captured",
            "embeddings": embeddings,
            "confidence_scores": confidence_scores,
            "quality_scores": quality_scores,
            "frames_captured": len(embeddings),
        }

    return {
        "success": True,
        "message": f"Successfully captured {len(embeddings)} good frames",
        "embeddings": embeddings,
        "confidence_scores": confidence_scores,
        "quality_scores": quality_scores,
        "bboxes": bboxes,
        "frames_captured": len(embeddings),
    }


# ==========================================
# AVERAGE EMBEDDINGS
# ==========================================

def average_embeddings(
    embeddings: List[List[float]],
    weights: Optional[List[float]] = None,
) -> Optional[List[float]]:
    """
    Average multiple embeddings (optionally weighted) and L2-normalize.
    """
    if not embeddings:
        return None

    arr = np.asarray(embeddings, dtype=np.float64)

    if weights is not None:
        w = np.asarray(weights, dtype=np.float64)
        w = w / w.sum()
        avg = np.average(arr, axis=0, weights=w)
    else:
        avg = np.mean(arr, axis=0)

    norm = np.linalg.norm(avg)
    if norm > 0:
        avg = avg / norm

    return avg.tolist()


# ==========================================
# SMART ENROLLMENT
# ==========================================

def smart_enrollment(
    face_model,
    camera,
    num_frames: int = 15,
    min_confidence: float = 0.35,
    min_quality: float = 0.2,
):
    """
    Smart face enrollment with quality filtering and averaging.
    """
    capture_result = capture_frames_for_enrollment(
        face_model, camera, num_frames, min_confidence
    )

    if not capture_result["success"]:
        return {
            "success": False,
            "message": capture_result["message"],
            "embedding": None,
            "confidence": 0.0,
            "quality": 0.0,
            "frames_used": 0,
        }

    good_embeddings = []
    good_qualities = []
    good_confidences = []

    for emb, qual, conf in zip(
        capture_result["embeddings"],
        capture_result["quality_scores"],
        capture_result["confidence_scores"],
    ):
        if qual >= min_quality:
            good_embeddings.append(emb)
            good_qualities.append(qual)
            good_confidences.append(conf)

    if len(good_embeddings) < 3:
        return {
            "success": False,
            "message": f"Only {len(good_embeddings)} high-quality frames. Need at least 3.",
            "embedding": None,
            "confidence": 0.0,
            "quality": 0.0,
            "frames_used": len(good_embeddings),
        }

    final_embedding = average_embeddings(good_embeddings, weights=good_qualities)

    return {
        "success": True,
        "embedding": final_embedding,
        "confidence": float(np.mean(good_confidences)),
        "quality": float(np.mean(good_qualities)),
        "frames_used": len(good_embeddings),
        "message": f"Enrollment successful with {len(good_embeddings)} high-quality frames",
    }


# ==========================================
# PREPARE EMBEDDING FOR DATABASE
# ==========================================

def prepare_embedding_for_db(embedding) -> Optional[List[float]]:
    """
    Convert to list[float] and L2-normalize.
    Always call this before writing to Supabase.
    """
    if embedding is None:
        return None

    if isinstance(embedding, np.ndarray):
        embedding = embedding.tolist()

    vec = [float(x) for x in embedding]
    arr = np.asarray(vec, dtype=np.float64)
    norm = np.linalg.norm(arr)
    if norm > 0:
        arr = arr / norm

    return arr.tolist()


# ==========================================
# VALIDATE EMBEDDING
# ==========================================

def validate_embedding(embedding) -> bool:
    """
    Basic format + dimension check.
    """
    if embedding is None:
        return False
    if not isinstance(embedding, (list, np.ndarray)):
        return False
    if len(embedding) != 512:
        return False
    return True