import cv2
import numpy as np
import time
import math
from collections import deque

class LivenessDetector:
    def __init__(self):
        self.eye_aspect_ratio_threshold = 0.25
        self.blink_frames = 3
        self.blink_counter = 0
        self.blink_total = 0
        self.blink_detected = False
        self.face_positions = deque(maxlen=30)
        self.head_movement_detected = False
        self.movement_threshold = 30
        self.phase = "initial"
        self.last_blink_time = 0
        self.blink_required = 2
        self.blinks_completed = 0

    def detect_blink(self, face, frame):
        bbox = face.bbox
        x1, y1, x2, y2 = bbox.astype(int)
        face_height = y2 - y1
        face_width = x2 - x1
        
        left_eye_y1 = y1 + int(face_height * 0.25)
        left_eye_y2 = y1 + int(face_height * 0.45)
        left_eye_x1 = x1 + int(face_width * 0.15)
        left_eye_x2 = x1 + int(face_width * 0.45)
        
        right_eye_y1 = y1 + int(face_height * 0.25)
        right_eye_y2 = y1 + int(face_height * 0.45)
        right_eye_x1 = x1 + int(face_width * 0.55)
        right_eye_x2 = x1 + int(face_width * 0.85)
        
        left_eye = frame[left_eye_y1:left_eye_y2, left_eye_x1:left_eye_x2]
        right_eye = frame[right_eye_y1:right_eye_y2, right_eye_x1:right_eye_x2]
        
        if left_eye.size == 0 or right_eye.size == 0:
            return False
        
        left_eye_gray = cv2.cvtColor(left_eye, cv2.COLOR_BGR2GRAY) if len(left_eye.shape) == 3 else left_eye
        right_eye_gray = cv2.cvtColor(right_eye, cv2.COLOR_BGR2GRAY) if len(right_eye.shape) == 3 else right_eye
        
        left_variance = np.var(left_eye_gray)
        right_variance = np.var(right_eye_gray)
        avg_variance = (left_variance + right_variance) / 2
        
        is_blinking = avg_variance < 200
        return is_blinking

    def track_head_movement(self, face):
        bbox = face.bbox
        center_x = (bbox[0] + bbox[2]) / 2
        center_y = (bbox[1] + bbox[3]) / 2
        self.face_positions.append((center_x, center_y))
        if len(self.face_positions) < 10:
            return False
        positions = list(self.face_positions)
        start_pos = positions[0]
        end_pos = positions[-1]
        distance = math.sqrt(
            (end_pos[0] - start_pos[0]) ** 2 +
            (end_pos[1] - start_pos[1]) ** 2
        )
        if distance > self.movement_threshold:
            self.head_movement_detected = True
            return True
        return False

    def check_liveness(self, frame, faces):
        if len(faces) == 0:
            return False, "No face detected", 0
        
        face = max(faces, key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]))
        is_blinking = self.detect_blink(face, frame)
        moved = self.track_head_movement(face)
        
        if self.phase == "initial":
            if is_blinking:
                self.blink_counter += 1
            else:
                if self.blink_counter > 0:
                    self.blink_total += 1
                    self.blinks_completed += 1
                    self.blink_counter = 0
                    self.last_blink_time = time.time()
                    if self.blinks_completed >= self.blink_required:
                        self.phase = "movement"
                        return False, "Great! Now move your head slightly", 40
            progress = min(40, (self.blinks_completed / self.blink_required) * 40)
            return False, "Please blink naturally", progress
            
        elif self.phase == "movement":
            if moved:
                self.phase = "complete"
                return True, "Liveness verified! ✓", 100
            if time.time() - self.last_blink_time > 15:
                self.phase = "initial"
                self.blinks_completed = 0
                return False, "Let's start over. Please blink", 0
            return False, "Please move your head slightly", 70
            
        elif self.phase == "complete":
            return True, "Liveness verified! ✓", 100
        
        return False, "Processing...", 50

    def reset(self):
        self.phase = "initial"
        self.blink_counter = 0
        self.blink_total = 0
        self.blinks_completed = 0
        self.blink_detected = False
        self.head_movement_detected = False
        self.face_positions.clear()
        self.last_blink_time = time.time()