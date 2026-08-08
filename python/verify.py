import cv2
import numpy as np
import time
from collections import deque

# ==========================================
# NO MODEL LOADING HERE - Model passed from app.py
# All functions now accept face_model as first parameter
# ==========================================

def get_face_embedding(face_model, image):
    """
    Extract face embedding from image using the provided model
    Returns: 512-dimensional numpy array or None
    """
    faces = face_model.get(image)

    if len(faces) == 0:
        return None

    # Take the largest detected face
    face = max(
        faces,
        key=lambda f: (
            (f.bbox[2] - f.bbox[0]) *
            (f.bbox[3] - f.bbox[1])
        )
    )

    return face.embedding


def cosine_similarity(a, b):
    """
    Calculate cosine similarity between two embeddings
    Returns: float between -1 and 1
    """
    a = np.array(a)
    b = np.array(b)

    denominator = np.linalg.norm(a) * np.linalg.norm(b)
    if denominator == 0:
        return 0.0

    return np.dot(a, b) / denominator


def verify_student(face_model, camera_image, stored_embedding, threshold=0.55):
    """
    Verify a single frame against a stored embedding
    """
    current_embedding = get_face_embedding(face_model, camera_image)

    if current_embedding is None:
        return {
            "success": False,
            "message": "No face detected",
            "confidence": 0.0
        }

    score = cosine_similarity(current_embedding, stored_embedding)

    return {
        "success": score >= threshold,
        "confidence": float(score),
        "threshold": threshold,
        "message": "Verified" if score >= threshold else "Face does not match"
    }


def verify_against_multiple(face_model, camera_image, stored_embeddings, student_ids, threshold=0.55):
    """
    Verify a face against multiple stored embeddings
    Returns: Best match with student ID
    """
    current_embedding = get_face_embedding(face_model, camera_image)

    if current_embedding is None:
        return {
            "success": False,
            "message": "No face detected",
            "student_id": None,
            "confidence": 0.0
        }

    best_match = None
    best_score = 0

    for i, embedding in enumerate(stored_embeddings):
        score = cosine_similarity(current_embedding, embedding)
        if score > best_score:
            best_score = score
            best_match = student_ids[i]

    if best_score >= threshold:
        return {
            "success": True,
            "student_id": best_match,
            "confidence": float(best_score),
            "threshold": threshold,
            "message": "Match found"
        }
    else:
        return {
            "success": False,
            "student_id": None,
            "confidence": float(best_score),
            "threshold": threshold,
            "message": "No match found"
        }


def verify_with_confidence_tracking(face_model, camera, stored_embedding, threshold=0.55, required_frames=10):
    """
    Track confidence scores over multiple frames for stable verification
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
            cv2.putText(frame, "No face detected", (50, 50), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
        else:
            score = cosine_similarity(current_embedding, stored_embedding)
            scores.append(score)

            if len(scores) >= 10:
                avg_score = np.mean(scores)
                
                if avg_score >= threshold:
                    stable_frames += 1
                else:
                    stable_frames = 0

                color = (0, 255, 0) if avg_score >= threshold else (0, 0, 255)
                cv2.putText(frame, f"Confidence: {avg_score:.2f}", (50, 50), 
                           cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2)
                
                progress = min(100, int((stable_frames / required_frames) * 100))
                cv2.putText(frame, f"Verifying: {progress}%", (50, 80), 
                           cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)

                if stable_frames >= required_frames:
                    camera.release()
                    cv2.destroyAllWindows()
                    return {
                        "success": True,
                        "confidence": float(avg_score),
                        "message": "Verified successfully"
                    }

        cv2.imshow("Face Verification", frame)

        if cv2.waitKey(1) == 27:  # ESC
            break

    camera.release()
    cv2.destroyAllWindows()

    return {
        "success": False,
        "message": "Verification cancelled",
        "confidence": 0.0
    }


def verify_multiple_with_tracking(face_model, camera, stored_embeddings, student_ids, threshold=0.55, required_frames=10):
    """
    Track confidence scores against multiple students
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
            cv2.putText(frame, "No face detected", (50, 50), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
        else:
            best_score = 0
            best_match = None
            
            for i, embedding in enumerate(stored_embeddings):
                score = cosine_similarity(current_embedding, embedding)
                if score > best_score:
                    best_score = score
                    best_match = student_ids[i]
            
            best_scores.append(best_score)
            best_student_id = best_match

            if len(best_scores) >= 10:
                avg_score = np.mean(best_scores)
                
                if avg_score >= threshold:
                    stable_frames += 1
                else:
                    stable_frames = 0

                color = (0, 255, 0) if avg_score >= threshold else (0, 0, 255)
                cv2.putText(frame, f"Confidence: {avg_score:.2f}", (50, 50), 
                           cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2)
                
                progress = min(100, int((stable_frames / required_frames) * 100))
                cv2.putText(frame, f"Verifying: {progress}%", (50, 80), 
                           cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)

                if best_student_id:
                    cv2.putText(frame, f"Student: {best_student_id}", (50, 110), 
                               cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)

                if stable_frames >= required_frames:
                    camera.release()
                    cv2.destroyAllWindows()
                    return {
                        "success": True,
                        "student_id": best_student_id,
                        "confidence": float(avg_score),
                        "message": "Verified successfully"
                    }

        cv2.imshow("Face Verification", frame)

        if cv2.waitKey(1) == 27:  # ESC
            break

    camera.release()
    cv2.destroyAllWindows()

    return {
        "success": False,
        "message": "Verification cancelled",
        "confidence": 0.0,
        "student_id": None
    }


# ==========================================
# Test Functions (Pass model from app.py)
# ==========================================

def test_single_verification(face_model):
    """
    Test verification against a single embedding
    """
    camera = cv2.VideoCapture(0)
    
    print("=" * 50)
    print("SINGLE VERIFICATION TEST")
    print("=" * 50)
    print("1. Look at camera to capture reference")
    print("2. Press SPACE to capture reference")
    print("3. Then verify against it")
    print("=" * 50)
    
    # Capture reference
    while True:
        ret, frame = camera.read()
        if not ret:
            continue
        
        cv2.putText(frame, "Look at camera. Press SPACE to capture", (50, 50), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
        cv2.imshow("Capture Reference", frame)
        
        key = cv2.waitKey(1)
        if key == 32:  # SPACE
            reference_embedding = get_face_embedding(face_model, frame)
            if reference_embedding is not None:
                print("✓ Reference captured!")
                break
            else:
                print("✗ No face detected. Try again.")
        elif key == 27:  # ESC
            camera.release()
            cv2.destroyAllWindows()
            return
    
    # Now verify
    print("\nNow verifying against reference...")
    result = verify_with_confidence_tracking(face_model, camera, reference_embedding)
    print(f"\nResult: {result}")


def test_multiple_verification(face_model):
    """
    Test verification against multiple embeddings
    """
    camera = cv2.VideoCapture(0)
    
    print("=" * 50)
    print("MULTIPLE VERIFICATION TEST")
    print("=" * 50)
    print("Create 3 reference faces:")
    
    embeddings = []
    student_ids = []
    
    for i in range(3):
        print(f"\nPress SPACE to capture Student {i+1}")
        
        while True:
            ret, frame = camera.read()
            if not ret:
                continue
            
            cv2.putText(frame, f"Capturing Student {i+1}", (50, 50), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            cv2.imshow(f"Capture Student {i+1}", frame)
            
            key = cv2.waitKey(1)
            if key == 32:  # SPACE
                embedding = get_face_embedding(face_model, frame)
                if embedding is not None:
                    embeddings.append(embedding)
                    student_ids.append(f"Student_{i+1}")
                    print(f"✓ Student {i+1} captured!")
                    break
                else:
                    print("✗ No face detected. Try again.")
            elif key == 27:  # ESC
                camera.release()
                cv2.destroyAllWindows()
                return
    
    # Now verify against all
    print("\nNow verifying against all students...")
    result = verify_multiple_with_tracking(face_model, camera, embeddings, student_ids)
    print(f"\nResult: {result}")


if __name__ == "__main__":
    print("=" * 50)
    print("VERIFY MODULE")
    print("=" * 50)
    print("This module no longer loads its own model.")
    print("It expects face_model to be passed from app.py.")
    print("To test, import and call test functions with a model.")
    print("")
    print("Example usage in app.py:")
    print("  from verify import test_single_verification")
    print("  test_single_verification(face_model)")
    print("")
    print("Choose test:")
    print("1. Single verification")
    print("2. Multiple verification")
    choice = input("Enter choice (1 or 2): ")
    
    if choice == "1":
        print("\n⚠️  This requires a face_model parameter.")
        print("Please run from app.py or pass the model manually.")
    elif choice == "2":
        print("\n⚠️  This requires a face_model parameter.")
        print("Please run from app.py or pass the model manually.")
    else:
        print("Invalid choice")