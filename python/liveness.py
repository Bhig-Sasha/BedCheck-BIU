from liveness import LivenessDetector

# Create detector instance (shared across requests)
liveness_detector = LivenessDetector()

@app.post("/check-liveness")
async def check_liveness(image_data: dict):
    """
    Check if the person is live
    """
    # Decode image
    img_bytes = base64.b64decode(image_data["image"])
    nparr = np.frombuffer(img_bytes, np.uint8)
    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    # Detect faces
    faces = face_model.get(frame)
    
    # Check liveness
    is_live, message, progress = liveness_detector.check_liveness(frame, faces)
    
    return {
        "is_live": is_live,
        "message": message,
        "progress": progress
    }

@app.post("/reset-liveness")
async def reset_liveness():
    """Reset liveness detector for new student"""
    liveness_detector.reset()
    return {"status": "reset"}