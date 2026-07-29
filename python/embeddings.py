import cv2
import numpy as np
import time
from collections import deque


# ==========================
# Create Face Embedding (Single Frame)
# ==========================
def create_embedding(face_model, image):
    """
    Detect a face and generate its embedding.

    Args:
        face_model: InsightFace FaceAnalysis model
        image: OpenCV image (numpy array)

    Returns:
        {
            "success": bool,
            "embedding": list,
            "confidence": float,
            "bbox": list,
            "quality_score": float,
            "message": str
        }
    """

    faces = face_model.get(image)

    if len(faces) == 0:
        return {
            "success": False,
            "message": "No face detected.",
            "embedding": None,
            "confidence": 0.0,
            "bbox": None,
            "quality_score": 0.0
        }

    # Use the largest detected face
    face = faces[0]
    
    # Calculate quality score based on detection confidence and face size
    bbox = face.bbox
    face_width = bbox[2] - bbox[0]
    face_height = bbox[3] - bbox[1]
    face_area = face_width * face_height
    image_area = image.shape[0] * image.shape[1]
    size_ratio = face_area / image_area
    
    # Quality score: combination of detection confidence and face size
    quality_score = float(face.det_score) * (0.7 + 0.3 * min(size_ratio * 10, 1.0))

    return {
        "success": True,
        "embedding": face.embedding.tolist(),
        "confidence": float(face.det_score),
        "bbox": face.bbox.tolist(),
        "quality_score": quality_score,
        "message": "Face detected successfully."
    }


# ==========================
# Create Embedding with Quality Check
# ==========================
def create_embedding_with_quality(face_model, image, min_confidence=0.5, min_face_size=100):
    """
    Create embedding with quality checks
    """
    result = create_embedding(face_model, image)
    
    if not result["success"]:
        return result
    
    # Check confidence
    if result["confidence"] < min_confidence:
        return {
            "success": False,
            "message": f"Face detection confidence too low: {result['confidence']:.2f}",
            "embedding": None,
            "confidence": result["confidence"],
            "bbox": result["bbox"],
            "quality_score": 0.0
        }
    
    # Check face size
    bbox = result["bbox"]
    face_width = bbox[2] - bbox[0]
    face_height = bbox[3] - bbox[1]
    
    if face_width < min_face_size or face_height < min_face_size:
        return {
            "success": False,
            "message": f"Face too small: {int(face_width)}x{int(face_height)}px",
            "embedding": None,
            "confidence": result["confidence"],
            "bbox": result["bbox"],
            "quality_score": 0.0
        }
    
    return result


# ==========================
# Capture Multiple Frames for Enrollment
# ==========================
def capture_frames_for_enrollment(face_model, camera, num_frames=10, min_confidence=0.5):
    """
    Capture multiple frames with face detection for enrollment
    
    Args:
        face_model: InsightFace model
        camera: OpenCV VideoCapture object
        num_frames: Number of frames to capture
        min_confidence: Minimum detection confidence
    
    Returns:
        {
            "success": bool,
            "embeddings": list,
            "confidence_scores": list,
            "quality_scores": list,
            "message": str
        }
    """
    
    embeddings = []
    confidence_scores = []
    quality_scores = []
    bboxes = []
    
    print(f"Capturing {num_frames} frames for enrollment...")
    print("Please look at the camera and move naturally")
    
    # Give user time to prepare
    time.sleep(1)
    
    for i in range(num_frames):
        ret, frame = camera.read()
        if not ret:
            continue
        
        # Get embedding with quality check
        result = create_embedding_with_quality(face_model, frame, min_confidence)
        
        if result["success"]:
            embeddings.append(result["embedding"])
            confidence_scores.append(result["confidence"])
            quality_scores.append(result["quality_score"])
            bboxes.append(result["bbox"])
            
            # Show progress
            print(f"  Frame {i+1}/{num_frames}: ✓ Face detected (conf: {result['confidence']:.2f})")
        else:
            print(f"  Frame {i+1}/{num_frames}: ✗ {result['message']}")
        
        # Small delay between frames
        time.sleep(0.2)
    
    if len(embeddings) < num_frames * 0.6:  # Need at least 60% good frames
        return {
            "success": False,
            "message": f"Only {len(embeddings)}/{num_frames} good frames captured",
            "embeddings": embeddings,
            "confidence_scores": confidence_scores,
            "quality_scores": quality_scores,
            "frames_captured": len(embeddings)
        }
    
    return {
        "success": True,
        "message": f"Successfully captured {len(embeddings)} good frames",
        "embeddings": embeddings,
        "confidence_scores": confidence_scores,
        "quality_scores": quality_scores,
        "bboxes": bboxes,
        "frames_captured": len(embeddings)
    }


# ==========================
# Average Embeddings
# ==========================
def average_embeddings(embeddings, weights=None):
    """
    Average multiple embeddings with optional weighting
    
    Args:
        embeddings: List of embeddings (each is a list or numpy array)
        weights: Optional list of weights for each embedding
    
    Returns:
        Averaged embedding as numpy array
    """
    if not embeddings:
        return None
    
    embeddings_array = np.array(embeddings)
    
    if weights is not None:
        weights = np.array(weights) / np.sum(weights)  # Normalize
        avg_embedding = np.average(embeddings_array, axis=0, weights=weights)
    else:
        avg_embedding = np.mean(embeddings_array, axis=0)
    
    # Normalize the averaged embedding
    avg_embedding = avg_embedding / np.linalg.norm(avg_embedding)
    
    return avg_embedding.tolist()


# ==========================
# Smart Enrollment (Combines all above)
# ==========================
def smart_enrollment(face_model, camera, num_frames=15, min_confidence=0.5, min_quality=0.3):
    """
    Smart face enrollment with quality filtering and averaging
    
    Returns:
        {
            "success": bool,
            "embedding": list,  # Final averaged embedding
            "confidence": float,
            "quality": float,
            "frames_used": int,
            "message": str
        }
    """
    
    # Capture frames
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
            "frames_used": 0
        }
    
    # Filter by quality
    embeddings = capture_result["embeddings"]
    quality_scores = capture_result["quality_scores"]
    confidence_scores = capture_result["confidence_scores"]
    
    # Keep only high quality embeddings
    good_embeddings = []
    good_qualities = []
    good_confidences = []
    
    for emb, qual, conf in zip(embeddings, quality_scores, confidence_scores):
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
            "frames_used": len(good_embeddings)
        }
    
    # Average with quality weighting
    final_embedding = average_embeddings(good_embeddings, weights=good_qualities)
    
    # Calculate final confidence and quality
    avg_confidence = np.mean(good_confidences)
    avg_quality = np.mean(good_qualities)
    
    return {
        "success": True,
        "embedding": final_embedding,
        "confidence": float(avg_confidence),
        "quality": float(avg_quality),
        "frames_used": len(good_embeddings),
        "message": f"Enrollment successful with {len(good_embeddings)} high-quality frames"
    }


# ==========================
# Enrollment with Liveness Integration
# ==========================
def enrollment_with_liveness(face_model, camera, liveness_detector):
    """
    Complete enrollment flow with liveness detection
    """
    print("=" * 50)
    print("FACE ENROLLMENT WITH LIVENESS")
    print("=" * 50)
    
    # Reset liveness detector
    liveness_detector.reset()
    
    enrollment_frames = []
    liveness_progress = 0
    
    print("\nPhase 1: Liveness Detection")
    print("- Please look at the camera")
    print("- Blink naturally")
    print("- Move your head slightly")
    print("- Press ESC to cancel")
    print("-" * 50)
    
    while True:
        ret, frame = camera.read()
        if not ret:
            continue
        
        # Detect faces
        faces = face_model.get(frame)
        
        # Check liveness
        is_live, message, progress = liveness_detector.check_liveness(frame, faces)
        liveness_progress = progress
        
        # Display status on frame
        display_frame = frame.copy()
        h, w = display_frame.shape[:2]
        
        # Progress bar
        cv2.rectangle(display_frame, (50, h-50), (w-50, h-20), (50, 50, 50), -1)
        fill_width = int(((w-100) * progress) / 100)
        color = (0, 255, 0) if is_live else (0, 165, 255)
        cv2.rectangle(display_frame, (50, h-50), (50 + fill_width, h-20), color, -1)
        
        # Status message
        cv2.putText(display_frame, message, (50, h-65), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2)
        
        # Face count
        cv2.putText(display_frame, f"Faces: {len(faces)}", (10, 30), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
        
        # If face detected, draw bounding box
        if faces:
            face = faces[0]
            bbox = face.bbox.astype(int)
            color_bbox = (0, 255, 0) if is_live else (0, 165, 255)
            cv2.rectangle(display_frame, (bbox[0], bbox[1]), (bbox[2], bbox[3]), color_bbox, 2)
        
        cv2.imshow("Enrollment", display_frame)
        
        # Check if liveness is complete
        if is_live:
            print("\n✓ Liveness verified!")
            break
        
        # Check for ESC
        if cv2.waitKey(1) == 27:
            cv2.destroyAllWindows()
            return {
                "success": False,
                "message": "Enrollment cancelled",
                "embedding": None
            }
    
    # Phase 2: Capture frames for enrollment
    print("\nPhase 2: Capturing face data")
    print("- Keep looking at the camera")
    print("-" * 50)
    
    # Capture frames
    capture_result = capture_frames_for_enrollment(
        face_model, camera, num_frames=20, min_confidence=0.5
    )
    
    if not capture_result["success"]:
        cv2.destroyAllWindows()
        return {
            "success": False,
            "message": capture_result["message"],
            "embedding": None
        }
    
    # Average embeddings
    avg_embedding = average_embeddings(
        capture_result["embeddings"],
        weights=capture_result["quality_scores"]
    )
    
    cv2.destroyAllWindows()
    
    return {
        "success": True,
        "embedding": avg_embedding,
        "message": f"Enrollment complete! Used {len(capture_result['embeddings'])} frames",
        "confidence": float(np.mean(capture_result["confidence_scores"])),
        "quality": float(np.mean(capture_result["quality_scores"]))
    }


# ==========================
# Test Function
# ==========================
def test_enrollment():
    """
    Test the enrollment process
    """
    import insightface
    from liveness import LivenessDetector
    
    # Load model
    face_model = insightface.app.FaceAnalysis(
        name="buffalo_l",
        providers=["CPUExecutionProvider"]
    )
    face_model.prepare(ctx_id=0)
    
    # Initialize camera
    camera = cv2.VideoCapture(0)
    
    if not camera.isOpened():
        print("Error: Could not open camera")
        return
    
    # Initialize liveness detector
    liveness = LivenessDetector()
    
    print("\n🔐 BIU BedCheck - Face Enrollment Test")
    print("=" * 50)
    
    # Run enrollment
    result = enrollment_with_liveness(face_model, camera, liveness)
    
    camera.release()
    cv2.destroyAllWindows()
    
    # Display result
    print("\n" + "=" * 50)
    print("ENROLLMENT RESULT")
    print("=" * 50)
    
    if result["success"]:
        print("✅ Enrollment successful!")
        print(f"   Message: {result['message']}")
        print(f"   Confidence: {result.get('confidence', 0):.3f}")
        print(f"   Quality: {result.get('quality', 0):.3f}")
        print(f"   Embedding dimension: {len(result['embedding'])}")
    else:
        print(f"❌ Enrollment failed: {result['message']}")
    
    return result


# ==========================
# API Integration Helper
# ==========================
def prepare_embedding_for_db(embedding):
    """
    Prepare embedding for database storage
    """
    if embedding is None:
        return None
    
    # Convert to list if numpy array
    if isinstance(embedding, np.ndarray):
        embedding = embedding.tolist()
    
    # Ensure all values are floats
    embedding = [float(x) for x in embedding]
    
    return embedding


def validate_embedding(embedding):
    """
    Validate embedding format
    """
    if embedding is None:
        return False
    
    if not isinstance(embedding, (list, np.ndarray)):
        return False
    
    if len(embedding) != 512:
        return False
    
    return True


# ==========================
# Main
# ==========================
if __name__ == "__main__":
    test_enrollment()