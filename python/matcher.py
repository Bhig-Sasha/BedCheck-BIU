# python/matcher.py

import base64
import json
import logging
from typing import List, Dict, Any, Optional, Tuple

import cv2
import numpy as np

from python.verify import cosine_similarity, get_face_embedding


logger = logging.getLogger(__name__)


# ============================================================
# IMAGE DECODING
# ============================================================

def decode_image(image_data: str) -> np.ndarray:
    """
    Decode a Base64-encoded image into an OpenCV BGR image.

    Supports:
        - Raw Base64
        - data:image/jpeg;base64,...
        - data:image/png;base64,...
    """

    try:
        if not image_data:
            raise ValueError("No image data provided")

        # Remove data URL prefix if present
        if "base64," in image_data:
            image_data = image_data.split("base64,", 1)[1]

        # Remove accidental whitespace/newlines
        image_data = image_data.strip()

        # Decode Base64
        try:
            img_bytes = base64.b64decode(
                image_data,
                validate=True
            )
        except Exception:
            # Some clients may send Base64 without strict padding
            padding = len(image_data) % 4

            if padding:
                image_data += "=" * (4 - padding)

            img_bytes = base64.b64decode(image_data)

        if not img_bytes:
            raise ValueError("Decoded image data is empty")

        # Convert bytes to NumPy array
        nparr = np.frombuffer(img_bytes, np.uint8)

        # Decode image
        frame = cv2.imdecode(
            nparr,
            cv2.IMREAD_COLOR
        )

        if frame is None:
            raise ValueError(
                "OpenCV could not decode the image"
            )

        return frame

    except Exception as e:
        logger.error(
            f"Image decoding error: {e}"
        )

        raise ValueError(
            f"Invalid image data: {str(e)}"
        )


# ============================================================
# EMBEDDING NORMALIZATION
# ============================================================

def normalize_embedding(
    embedding: Any
) -> Optional[List[float]]:
    """
    Convert an embedding into a clean list of floats.

    Handles:
        - Python lists
        - tuples
        - NumPy arrays
        - JSON strings
    """

    if embedding is None:
        return None

    try:

        # JSON string from Supabase
        if isinstance(embedding, str):
            embedding = json.loads(embedding)

        # NumPy array
        if isinstance(embedding, np.ndarray):
            embedding = embedding.flatten().tolist()

        # Tuple
        elif isinstance(embedding, tuple):
            embedding = list(embedding)

        # List
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
        logger.warning(
            f"Could not normalize embedding: {e}"
        )
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
        threshold: float = 0.55
    ):
        """
        Initialize the face matcher.

        Args:
            supabase_client:
                Supabase client instance.

            threshold:
                Cosine similarity threshold.
                Default: 0.55
        """

        self.supabase = supabase_client
        self.threshold = float(threshold)

    # ========================================================
    # FIND BEST MATCH
    # ========================================================

    def find_similar_embedding(
        self,
        organization: str,
        query_embedding: List[float],
        limit: int = 100
    ) -> Tuple[Optional[int], float]:
        """
        Find the best matching face for an organization.

        Returns:
            (
                student_id,
                similarity_percentage
            )

        Example:
            (12345, 87.42)

        If no match:
            (None, 0.0)
        """

        try:

            if not organization:
                logger.warning(
                    "No organization provided for face matching"
                )
                return None, 0.0

            normalized_query = normalize_embedding(
                query_embedding
            )

            if normalized_query is None:
                logger.warning(
                    "Invalid query embedding"
                )
                return None, 0.0

            # AntelopeV2 / ArcFace normally produces 512 dimensions
            if len(normalized_query) != 512:
                logger.warning(
                    f"Unexpected query embedding dimension: "
                    f"{len(normalized_query)}"
                )

            result = (
                self.supabase
                .table("student_face")
                .select(
                    "student_id, "
                    "face_embedding, "
                    "confidence_score, "
                    "enrollment_status"
                )
                .eq(
                    "campus_code",
                    organization
                )
                .eq(
                    "is_active",
                    True
                )
                .limit(limit)
                .execute()
            )

            records = result.data or []

            if not records:
                logger.info(
                    "No active face embeddings found for "
                    f"organization: {organization}"
                )

                return None, 0.0

            best_match_id = None
            best_similarity = -1.0

            for record in records:

                student_id = record.get(
                    "student_id"
                )

                stored_embedding = record.get(
                    "face_embedding"
                )

                if student_id is None:
                    continue

                normalized_stored = normalize_embedding(
                    stored_embedding
                )

                if normalized_stored is None:
                    logger.warning(
                        f"Invalid stored embedding for "
                        f"student {student_id}"
                    )
                    continue

                if len(normalized_query) != len(
                    normalized_stored
                ):
                    logger.warning(
                        f"Embedding dimension mismatch for "
                        f"student {student_id}: "
                        f"{len(normalized_query)} vs "
                        f"{len(normalized_stored)}"
                    )
                    continue

                try:

                    similarity = cosine_similarity(
                        normalized_query,
                        normalized_stored
                    )

                    similarity = float(
                        similarity
                    )

                except Exception as similarity_error:

                    logger.warning(
                        "Could not compare embedding for "
                        f"student {student_id}: "
                        f"{similarity_error}"
                    )

                    continue

                if not np.isfinite(similarity):
                    continue

                if similarity > best_similarity:

                    best_similarity = similarity
                    best_match_id = student_id

            # No usable embeddings
            if best_match_id is None:
                return None, 0.0

            # Threshold check
            if best_similarity < self.threshold:

                logger.info(
                    f"No face match above threshold. "
                    f"Best similarity: "
                    f"{best_similarity:.4f}, "
                    f"threshold: {self.threshold:.4f}"
                )

                return None, 0.0

            similarity_percentage = round(
                best_similarity * 100,
                2
            )

            logger.info(
                f"Face match found: student={best_match_id}, "
                f"similarity={similarity_percentage}%"
            )

            return (
                best_match_id,
                similarity_percentage
            )

        except Exception as e:

            logger.exception(
                f"Error finding similar embedding: {e}"
            )

            return None, 0.0

    # ========================================================
    # FIND MULTIPLE MATCHES
    # ========================================================

    def find_similar_embeddings(
        self,
        organization: str,
        query_embedding: List[float],
        top_n: int = 5,
        threshold: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Find the top N matching faces.

        Returns a list sorted from highest similarity
        to lowest similarity.
        """

        active_threshold = (
            self.threshold
            if threshold is None
            else float(threshold)
        )

        try:

            normalized_query = normalize_embedding(
                query_embedding
            )

            if normalized_query is None:
                return []

            result = (
                self.supabase
                .table("student_face")
                .select(
                    "student_id, "
                    "face_embedding, "
                    "confidence_score, "
                    "enrollment_status"
                )
                .eq(
                    "campus_code",
                    organization
                )
                .eq(
                    "is_active",
                    True
                )
                .execute()
            )

            records = result.data or []

            if not records:
                return []

            matches = []

            for record in records:

                student_id = record.get(
                    "student_id"
                )

                stored_embedding = record.get(
                    "face_embedding"
                )

                if student_id is None:
                    continue

                normalized_stored = normalize_embedding(
                    stored_embedding
                )

                if normalized_stored is None:
                    continue

                if len(normalized_query) != len(
                    normalized_stored
                ):
                    continue

                try:

                    similarity = float(
                        cosine_similarity(
                            normalized_query,
                            normalized_stored
                        )
                    )

                except Exception as e:

                    logger.warning(
                        f"Embedding comparison failed "
                        f"for student {student_id}: {e}"
                    )

                    continue

                if not np.isfinite(similarity):
                    continue

                if similarity >= active_threshold:

                    matches.append({
                        "student_id": student_id,
                        "similarity_score": round(
                            similarity * 100,
                            2
                        ),
                        "confidence_score": record.get(
                            "confidence_score"
                        ),
                        "enrollment_status": record.get(
                            "enrollment_status"
                        )
                    })

            # Highest similarity first
            matches.sort(
                key=lambda item: item[
                    "similarity_score"
                ],
                reverse=True
            )

            return matches[:top_n]

        except Exception as e:

            logger.exception(
                f"Error finding similar embeddings: {e}"
            )

            return []

    # ========================================================
    # MATCH FACE
    # ========================================================

    def match_face(
        self,
        organization: str,
        face_embedding: List[float],
        threshold: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Match a face embedding against enrolled
        students belonging to an organization.
        """

        active_threshold = (
            self.threshold
            if threshold is None
            else float(threshold)
        )

        # Temporarily use requested threshold
        original_threshold = self.threshold
        self.threshold = active_threshold

        try:

            student_id, similarity = (
                self.find_similar_embedding(
                    organization=organization,
                    query_embedding=face_embedding
                )
            )

        finally:

            self.threshold = original_threshold

        # No match
        if student_id is None:

            return {
                "success": False,
                "matched": False,
                "message": "No matching face found",
                "student_id": None,
                "similarity_score": 0.0,
                "threshold": active_threshold,
                "student_info": None
            }

        # ====================================================
        # Fetch student details
        # ====================================================

        student_info = None

        try:

            student_result = (
                self.supabase
                .table("students")
                .select(
                    "id, "
                    "name, "
                    "matric, "
                    "hostel, "
                    "room, "
                    "campus, "
                    "campus_code"
                )
                .eq(
                    "id",
                    student_id
                )
                .limit(1)
                .execute()
            )

            if student_result.data:

                student_info = (
                    student_result.data[0]
                )

        except Exception as e:

            logger.warning(
                f"Could not fetch student details "
                f"for {student_id}: {e}"
            )

        return {
            "success": True,
            "matched": True,
            "student_id": student_id,
            "similarity_score": similarity,
            "threshold": active_threshold,
            "student_info": student_info,
            "message": (
                f"Match found with "
                f"{similarity}% confidence"
            )
        }

    # ========================================================
    # BATCH MATCH
    # ========================================================

    def batch_match_faces(
        self,
        organization: str,
        embeddings: List[List[float]],
        threshold: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Match multiple face embeddings.
        """

        results = []

        for index, embedding in enumerate(
            embeddings
        ):

            try:

                result = self.match_face(
                    organization=organization,
                    face_embedding=embedding,
                    threshold=threshold
                )

                result["index"] = index

                results.append(result)

            except Exception as e:

                logger.error(
                    f"Batch matching error at index "
                    f"{index}: {e}"
                )

                results.append({
                    "success": False,
                    "matched": False,
                    "index": index,
                    "message": str(e),
                    "student_id": None,
                    "similarity_score": 0.0
                })

        return results


# ============================================================
# ORGANIZATION FACE MATCHER
# ============================================================

class OrganizationFaceMatcher:
    """
    Higher-level face matcher.

    Handles:
        1. Base64 image decoding
        2. Face detection
        3. Embedding extraction
        4. Organization filtering
        5. Face comparison
    """

    def __init__(
        self,
        supabase_client,
        face_model,
        threshold: float = 0.55
    ):

        self.supabase = supabase_client
        self.face_model = face_model

        self.matcher = FaceMatcher(
            supabase_client=supabase_client,
            threshold=threshold
        )

        self.threshold = float(
            threshold
        )

    # ========================================================
    # GET SIMILAR PERSON
    # ========================================================

    def get_similar_person(
        self,
        organization: str,
        image_data: str
    ) -> Dict[str, Any]:
        """
        Find a matching student from a Base64 image.
        """

        try:

            if not organization:

                return {
                    "success": False,
                    "matched": False,
                    "message": (
                        "Organization is required"
                    ),
                    "student_id": None,
                    "similarity_score": 0.0
                }

            if self.face_model is None:

                return {
                    "success": False,
                    "matched": False,
                    "message": (
                        "Face model is not loaded"
                    ),
                    "student_id": None,
                    "similarity_score": 0.0
                }

            # =================================================
            # Decode image
            # =================================================

            frame = decode_image(
                image_data
            )

            # =================================================
            # Extract face embedding
            # =================================================

            embedding = get_face_embedding(
                self.face_model,
                frame
            )

            if embedding is None:

                return {
                    "success": False,
                    "matched": False,
                    "message": (
                        "No face detected in image"
                    ),
                    "student_id": None,
                    "similarity_score": 0.0
                }

            # =================================================
            # Convert embedding
            # =================================================

            query_embedding = normalize_embedding(
                embedding
            )

            if query_embedding is None:

                return {
                    "success": False,
                    "matched": False,
                    "message": (
                        "Could not process face embedding"
                    ),
                    "student_id": None,
                    "similarity_score": 0.0
                }

            # =================================================
            # Find matching student
            # =================================================

            student_id, similarity = (
                self.matcher.find_similar_embedding(
                    organization=organization,
                    query_embedding=query_embedding
                )
            )

            # =================================================
            # No match
            # =================================================

            if student_id is None:

                return {
                    "success": False,
                    "matched": False,
                    "message": (
                        "No matching face found "
                        "for this organization"
                    ),
                    "student_id": None,
                    "similarity_score": 0.0
                }

            # =================================================
            # Match successful
            # =================================================

            return {
                "success": True,
                "matched": True,
                "student_id": student_id,
                "similarity_score": similarity,
                "message": (
                    f"Match found with "
                    f"{similarity}% confidence"
                )
            }

        except Exception as e:

            logger.exception(
                f"Error in get_similar_person: {e}"
            )

            return {
                "success": False,
                "matched": False,
                "message": f"Error: {str(e)}",
                "student_id": None,
                "similarity_score": 0.0
            }