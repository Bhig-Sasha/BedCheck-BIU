# python/matcher.py

import base64
import json
import logging
import time
from typing import List, Dict, Any, Optional, Tuple

import cv2
import numpy as np

# Relative import when running as python.app
try:
    from .verify import cosine_similarity, get_face_embedding
except ImportError:
    from verify import cosine_similarity, get_face_embedding


logger = logging.getLogger(__name__)

# Max decoded image size (~5 MB raw)
MAX_IMAGE_BYTES = 5 * 1024 * 1024


# ============================================================
# IMAGE DECODING
# ============================================================

def decode_image(image_data: str) -> np.ndarray:
    """
    Decode a Base64-encoded image into an OpenCV BGR image.
    Raises ValueError on any failure.
    """
    try:
        if not image_data:
            raise ValueError("No image data provided")

        if "base64," in image_data:
            image_data = image_data.split("base64,", 1)[1]

        image_data = image_data.strip()

        # Rough size check before decoding (base64 is ~4/3 larger)
        if len(image_data) > MAX_IMAGE_BYTES * 1.4:
            raise ValueError("Image too large")

        try:
            img_bytes = base64.b64decode(image_data, validate=True)
        except Exception:
            padding = len(image_data) % 4
            if padding:
                image_data += "=" * (4 - padding)
            img_bytes = base64.b64decode(image_data)

        if not img_bytes:
            raise ValueError("Decoded image data is empty")

        if len(img_bytes) > MAX_IMAGE_BYTES:
            raise ValueError("Image too large")

        nparr = np.frombuffer(img_bytes, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if frame is None:
            raise ValueError("OpenCV could not decode the image")

        return frame

    except Exception as e:
        logger.error(f"Image decoding error: {e}")
        raise ValueError(f"Invalid image data: {str(e)}")


# ============================================================
# EMBEDDING NORMALIZATION
# ============================================================

def normalize_embedding(embedding: Any) -> Optional[List[float]]:
    """
    Convert an embedding into a clean list of floats.
    Handles list / tuple / np.ndarray / JSON string.
    """
    if embedding is None:
        return None

    try:
        if isinstance(embedding, str):
            embedding = json.loads(embedding)

        if isinstance(embedding, np.ndarray):
            embedding = embedding.flatten().tolist()
        elif isinstance(embedding, tuple):
            embedding = list(embedding)
        elif isinstance(embedding, list):
            embedding = list(embedding)
        else:
            return None

        if not embedding:
            return None

        result = []
        for value in embedding:
            try:
                value = float(value)
                if not np.isfinite(value):
                    return None
                result.append(value)
            except (TypeError, ValueError):
                return None

        return result

    except Exception as e:
        logger.warning(f"Could not normalize embedding: {e}")
        return None


# ============================================================
# FACE MATCHER
# ============================================================

class FaceMatcher:
    """
    Face matching service.
    Searches the student_face table for enrolled faces
    belonging to a specific campus/organization.
    """

    def __init__(
        self,
        supabase_client,
        threshold: float = 0.55,
        cache_ttl: int = 60,
    ):
        self.supabase = supabase_client
        self.threshold = float(threshold)
        self.expected_dimension = 512
        self.cache_ttl = cache_ttl
        # org -> (records, timestamp)
        self._cache: Dict[str, Tuple[List[Dict], float]] = {}

    # --------------------------------------------------------
    # Cache helpers
    # --------------------------------------------------------

    def _get_org_records(self, organization: str, limit: int = 500) -> List[Dict]:
        """Fetch (or return cached) active embeddings for an organization."""
        now = time.time()

        if organization in self._cache:
            records, ts = self._cache[organization]
            if now - ts < self.cache_ttl:
                return records

        result = (
            self.supabase
            .table("student_face")
            .select(
                "student_id, face_embedding, confidence_score, enrollment_status"
            )
            .eq("campus_code", organization)
            .eq("is_active", True)
            .limit(limit)
            .execute()
        )

        records = result.data or []
        self._cache[organization] = (records, now)
        return records

    def invalidate_cache(self, organization: Optional[str] = None):
        """Call after a successful enrollment so new faces are visible immediately."""
        if organization is None:
            self._cache.clear()
        elif organization in self._cache:
            del self._cache[organization]

    # --------------------------------------------------------
    # FIND BEST MATCH
    # --------------------------------------------------------

    def find_similar_embedding(
        self,
        organization: str,
        query_embedding: List[float],
        limit: int = 500,
        threshold: Optional[float] = None,
    ) -> Tuple[Optional[int], float]:
        """
        Returns (student_id, similarity_percentage) or (None, 0.0).
        """
        active_threshold = self.threshold if threshold is None else float(threshold)

        try:
            if not organization:
                logger.warning("No organization provided for face matching")
                return None, 0.0

            normalized_query = normalize_embedding(query_embedding)
            if normalized_query is None:
                logger.warning("Invalid query embedding")
                return None, 0.0

            if len(normalized_query) != self.expected_dimension:
                logger.warning(
                    f"Unexpected query embedding dimension: "
                    f"{len(normalized_query)} (expected {self.expected_dimension})"
                )
                # still try – some old records might be different

            records = self._get_org_records(organization, limit=limit)

            if not records:
                logger.info(f"No active face embeddings for organization: {organization}")
                return None, 0.0

            best_match_id = None
            best_similarity = -1.0

            for record in records:
                student_id = record.get("student_id")
                stored_embedding = record.get("face_embedding")

                if student_id is None:
                    continue

                normalized_stored = normalize_embedding(stored_embedding)
                if normalized_stored is None:
                    continue

                if len(normalized_stored) != len(normalized_query):
                    continue

                try:
                    similarity = float(
                        cosine_similarity(normalized_query, normalized_stored)
                    )
                except Exception as e:
                    logger.warning(f"Comparison failed for student {student_id}: {e}")
                    continue

                if not np.isfinite(similarity):
                    continue

                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match_id = student_id

            if best_match_id is None:
                return None, 0.0

            if best_similarity < active_threshold:
                logger.info(
                    f"No face match above threshold. "
                    f"Best: {best_similarity:.4f}, threshold: {active_threshold:.4f}"
                )
                return None, 0.0

            similarity_percentage = round(best_similarity * 100, 2)
            logger.info(
                f"Face match found: student={best_match_id}, "
                f"similarity={similarity_percentage}%"
            )
            return best_match_id, similarity_percentage

        except Exception as e:
            logger.exception(f"Error finding similar embedding: {e}")
            return None, 0.0

    # --------------------------------------------------------
    # FIND MULTIPLE MATCHES
    # --------------------------------------------------------

    def find_similar_embeddings(
        self,
        organization: str,
        query_embedding: List[float],
        top_n: int = 5,
        threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        active_threshold = self.threshold if threshold is None else float(threshold)

        try:
            normalized_query = normalize_embedding(query_embedding)
            if normalized_query is None:
                return []

            records = self._get_org_records(organization)

            matches = []
            for record in records:
                student_id = record.get("student_id")
                stored_embedding = record.get("face_embedding")

                if student_id is None:
                    continue

                normalized_stored = normalize_embedding(stored_embedding)
                if normalized_stored is None:
                    continue
                if len(normalized_stored) != len(normalized_query):
                    continue

                try:
                    similarity = float(
                        cosine_similarity(normalized_query, normalized_stored)
                    )
                except Exception:
                    continue

                if not np.isfinite(similarity) or similarity < active_threshold:
                    continue

                matches.append({
                    "student_id": student_id,
                    "similarity_score": round(similarity * 100, 2),
                    "confidence_score": record.get("confidence_score"),
                    "enrollment_status": record.get("enrollment_status"),
                })

            matches.sort(key=lambda x: x["similarity_score"], reverse=True)
            return matches[:top_n]

        except Exception as e:
            logger.exception(f"Error finding similar embeddings: {e}")
            return []

    # --------------------------------------------------------
    # MATCH FACE (high-level)
    # --------------------------------------------------------

    def match_face(
        self,
        organization: str,
        face_embedding: List[float],
        threshold: Optional[float] = None,
    ) -> Dict[str, Any]:
        active_threshold = self.threshold if threshold is None else float(threshold)

        student_id, similarity = self.find_similar_embedding(
            organization=organization,
            query_embedding=face_embedding,
            threshold=active_threshold,
        )

        if student_id is None:
            return {
                "success": False,
                "matched": False,
                "message": "No matching face found",
                "student_id": None,
                "similarity_score": 0.0,
                "threshold": active_threshold,
                "student_info": None,
            }

        # Fetch student details
        student_info = None
        try:
            student_result = (
                self.supabase
                .table("students")
                .select("id, name, matric, hostel, room, campus, campus_code")
                .eq("id", student_id)
                .limit(1)
                .execute()
            )
            if student_result.data:
                student_info = student_result.data[0]
        except Exception as e:
            logger.warning(f"Could not fetch student details for {student_id}: {e}")

        return {
            "success": True,
            "matched": True,
            "student_id": student_id,
            "similarity_score": similarity,
            "threshold": active_threshold,
            "student_info": student_info,
            "message": f"Match found with {similarity}% confidence",
        }

    # --------------------------------------------------------
    # BATCH MATCH
    # --------------------------------------------------------

    def batch_match_faces(
        self,
        organization: str,
        embeddings: List[List[float]],
        threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        results = []
        for index, embedding in enumerate(embeddings):
            try:
                result = self.match_face(
                    organization=organization,
                    face_embedding=embedding,
                    threshold=threshold,
                )
                result["index"] = index
                results.append(result)
            except Exception as e:
                logger.error(f"Batch matching error at index {index}: {e}")
                results.append({
                    "success": False,
                    "matched": False,
                    "index": index,
                    "message": str(e),
                    "student_id": None,
                    "similarity_score": 0.0,
                })
        return results


# ============================================================
# ORGANIZATION FACE MATCHER
# ============================================================

class OrganizationFaceMatcher:
    """
    Higher-level matcher:
    Base64 image → face detection → embedding → organization match.
    """

    def __init__(
        self,
        supabase_client,
        face_model,
        threshold: float = 0.55,
    ):
        self.supabase = supabase_client
        self.face_model = face_model
        self.matcher = FaceMatcher(
            supabase_client=supabase_client,
            threshold=threshold,
        )
        self.threshold = float(threshold)

    def get_similar_person(
        self,
        organization: str,
        image_data: str,
    ) -> Dict[str, Any]:
        try:
            if not organization:
                return {
                    "success": False,
                    "matched": False,
                    "message": "Organization is required",
                    "student_id": None,
                    "similarity_score": 0.0,
                }

            if self.face_model is None:
                return {
                    "success": False,
                    "matched": False,
                    "message": "Face model is not loaded",
                    "student_id": None,
                    "similarity_score": 0.0,
                }

            frame = decode_image(image_data)
            embedding = get_face_embedding(self.face_model, frame)

            if embedding is None:
                return {
                    "success": False,
                    "matched": False,
                    "message": "No face detected in image",
                    "student_id": None,
                    "similarity_score": 0.0,
                }

            query_embedding = normalize_embedding(embedding)
            if query_embedding is None:
                return {
                    "success": False,
                    "matched": False,
                    "message": "Could not process face embedding",
                    "student_id": None,
                    "similarity_score": 0.0,
                }

            student_id, similarity = self.matcher.find_similar_embedding(
                organization=organization,
                query_embedding=query_embedding,
            )

            if student_id is None:
                return {
                    "success": False,
                    "matched": False,
                    "message": "No matching face found for this organization",
                    "student_id": None,
                    "similarity_score": 0.0,
                }

            return {
                "success": True,
                "matched": True,
                "student_id": student_id,
                "similarity_score": similarity,
                "message": f"Match found with {similarity}% confidence",
            }

        except Exception as e:
            logger.exception(f"Error in get_similar_person: {e}")
            return {
                "success": False,
                "matched": False,
                "message": f"Error: {str(e)}",
                "student_id": None,
                "similarity_score": 0.0,
            }