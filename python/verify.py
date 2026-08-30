# python/verify.py

import cv2
import numpy as np
import time
from collections import deque
from typing import List, Optional, Dict, Any


# ==========================================
# NO MODEL LOADING HERE
# All functions accept face_model as first parameter
# ==========================================

def get_face_embedding(face_model, image):
    """
    Extract face embedding from image using the provided model.
    Returns: 512-dimensional numpy array or None
    """
    faces = face_model.get(image)

    if not faces:
        return None

    # Always take the largest detected face
    face = max(
        faces,
        key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]),
    )
    return face.embedding


def cosine_similarity(a, b) -> float:
    """
    Calculate cosine similarity between two embeddings.
    Returns float in [-1, 1]. Returns 0.0 on any error.
    """
    try:
        a = np.asarray(a, dtype=np.float64)
        b = np.asarray(b, dtype=np.float64)

        if a.shape != b.shape:
            return 0.0

        na = np.linalg.norm(a)
        nb = np.linalg.norm(b)
        if na == 0.0 or nb == 0.0:
            return 0.0

        return float(np.dot(a, b) / (na * nb))
    except Exception:
        return 0.0


def verify_student(
    face_model,
    camera_image,
    stored_embedding,
    threshold: float = 0.55,
) -> Dict[str, Any]:
    """
    Verify a single frame against a stored embedding.
    """
    current_embedding = get_face_embedding(face_model, camera_image)

    if current_embedding is None:
        return {
            "success": False,
            "verified": False,
            "confidence": 0.0,
            "threshold": threshold,
            "reason": "No face detected in the image",
        }

    score = cosine_similarity(current_embedding, stored_embedding)
    is_verified = score >= threshold

    return {
        "success": is_verified,
        "verified": is_verified,
        "confidence": float(score),
        "threshold": threshold,
        "reason": (
            "Face verified successfully"
            if is_verified
            else f"Similarity {score:.2f} below threshold {threshold}"
        ),
    }


def verify_against_multiple(
    face_model,
    camera_image,
    stored_embeddings: List,
    student_ids: List,
    threshold: float = 0.55,
) -> Dict[str, Any]:
    """
    Verify a face against multiple stored embeddings.
    Returns the best match with student ID.
    """
    current_embedding = get_face_embedding(face_model, camera_image)

    if current_embedding is None:
        return {
            "success": False,
            "verified": False,
            "message": "No face detected",
            "student_id": None,
            "confidence": 0.0,
            "threshold": threshold,
            "reason": "No face detected",
        }

    best_match = None
    best_score = -1.0

    for i, embedding in enumerate(stored_embeddings):
        if embedding is None or len(embedding) != 512:
            continue
        score = cosine_similarity(current_embedding, embedding)
        if score > best_score:
            best_score = score
            best_match = student_ids[i]

    if best_score >= threshold:
        return {
            "success": True,
            "verified": True,
            "student_id": best_match,
            "confidence": float(best_score),
            "threshold": threshold,
            "reason": "Match found",
        }

    return {
        "success": False,
        "verified": False,
        "student_id": None,
        "confidence": float(max(best_score, 0.0)),
        "threshold": threshold,
        "reason": (
            f"No match found. Best score {best_score:.2f} "
            f"below threshold {threshold}"
        ),
    }


def detect_face(face_model, image) -> Dict[str, Any]:
    """
    Detect if a face is present in the image.
    Uses the largest face when multiple are present.
    """
    try:
        faces = face_model.get(image)

        if not faces:
            return {"detected": False, "num_faces": 0}

        face = max(
            faces,
            key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]),
        )
        bbox = face.bbox

        return {
            "detected": True,
            "bbox": [float(x) for x in bbox],
            "num_faces": len(faces),
            "confidence": float(face.det_score),
        }
    except Exception as e:
        return {
            "detected": False,
            "num_faces": 0,
            "error": str(e),
        }


def extract_face_embedding(face_model, image) -> Dict[str, Any]:
    """
    Extract face embedding from an image.
    """
    try:
        embedding = get_face_embedding(face_model, image)

        if embedding is not None:
            return {
                "success": True,
                "embedding": embedding.tolist(),
                "dimension": len(embedding),
            }

        return {
            "success": False,
            "message": "No face detected",
            "embedding": None,
        }
    except Exception as e:
        return {
            "success": False,
            "message": str(e),
            "embedding": None,
        }


# ==========================================
# Webcam helpers (local testing only)
# ==========================================

def verify_with_confidence_tracking(
    face_model,
    camera,
    stored_embedding,
    threshold: float = 0.55,
    required_frames: int = 10,
):
    """
    Track confidence scores over multiple frames for stable verification.
    """
    scores = deque(maxlen=20)
    stable_frames = 0

    print("Looking for face...")
    print("Press ESC to cancel")

    while True:
        ret, frame = camera.read()
        if not ret:
            continue

        current_embedding = get_face_embedding(face_model, frame)

        if current_embedding is None:
            stable_frames = 0
            cv2.putText(
                frame, "No face detected", (50, 50),
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2,
            )
        else:
            score = cosine_similarity(current_embedding, stored_embedding)
            scores.append(score)

            if len(scores) >= 10:
                avg_score = float(np.mean(scores))

                if avg_score >= threshold:
                    stable_frames += 1
                else:
                    stable_frames = 0

                color = (0, 255, 0) if avg_score >= threshold else (0, 0, 255)
                cv2.putText(
                    frame, f"Confidence: {avg_score:.2f}", (50, 50),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2,
                )

                progress = min(100, int((stable_frames / required_frames) * 100))
                cv2.putText(
                    frame, f"Verifying: {progress}%", (50, 80),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2,
                )

                if stable_frames >= required_frames:
                    camera.release()
                    cv2.destroyAllWindows()
                    return {
                        "success": True,
                        "verified": True,
                        "confidence": avg_score,
                        "threshold": threshold,
                        "reason": "Verified successfully",
                    }

        cv2.imshow("Face Verification", frame)

        if cv2.waitKey(1) == 27:  # ESC
            break

    camera.release()
    cv2.destroyAllWindows()

    return {
        "success": False,
        "verified": False,
        "message": "Verification cancelled",
        "confidence": 0.0,
        "threshold": threshold,
        "reason": "Verification cancelled",
    }


def verify_multiple_with_tracking(
    face_model,
    camera,
    stored_embeddings,
    student_ids,
    threshold: float = 0.55,
    required_frames: int = 10,
):
    """
    Track confidence scores against multiple students.
    """
    best_student_id = None
    best_scores = deque(maxlen=20)
    stable_frames = 0

    print("Looking for face...")
    print("Press ESC to cancel")

    while True:
        ret, frame = camera.read()
        if not ret:
            continue

        current_embedding = get_face_embedding(face_model, frame)

        if current_embedding is None:
            stable_frames = 0
            cv2.putText(
                frame, "No face detected", (50, 50),
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2,
            )
        else:
            best_score = -1.0
            best_match = None

            for i, embedding in enumerate(stored_embeddings):
                if embedding is None or len(embedding) != 512:
                    continue
                score = cosine_similarity(current_embedding, embedding)
                if score > best_score:
                    best_score = score
                    best_match = student_ids[i]

            best_scores.append(best_score)
            best_student_id = best_match

            if len(best_scores) >= 10:
                avg_score = float(np.mean(best_scores))

                if avg_score >= threshold:
                    stable_frames += 1
                else:
                    stable_frames = 0

                color = (0, 255, 0) if avg_score >= threshold else (0, 0, 255)
                cv2.putText(
                    frame, f"Confidence: {avg_score:.2f}", (50, 50),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2,
                )

                progress = min(100, int((stable_frames / required_frames) * 100))
                cv2.putText(
                    frame, f"Verifying: {progress}%", (50, 80),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2,
                )

                if best_student_id is not None:
                    cv2.putText(
                        frame, f"Student: {best_student_id}", (50, 110),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2,
                    )

                if stable_frames >= required_frames:
                    camera.release()
                    cv2.destroyAllWindows()
                    return {
                        "success": True,
                        "verified": True,
                        "student_id": best_student_id,
                        "confidence": avg_score,
                        "threshold": threshold,
                        "reason": "Verified successfully",
                    }

        cv2.imshow("Face Verification", frame)

        if cv2.waitKey(1) == 27:  # ESC
            break

    camera.release()
    cv2.destroyAllWindows()

    return {
        "success": False,
        "verified": False,
        "message": "Verification cancelled",
        "confidence": 0.0,
        "threshold": threshold,
        "student_id": None,
        "reason": "Verification cancelled",
    }