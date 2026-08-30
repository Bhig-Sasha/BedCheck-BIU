# python/liveness.py

import time
import math
import uuid
from collections import deque
from typing import Dict, Tuple, Optional

import cv2
import numpy as np


class LivenessDetector:
    """
    Per-session liveness state machine.
    Phases: initial → movement → complete
    """

    def __init__(self):
        self.blink_counter = 0
        self.blinks_completed = 0
        self.blink_required = 2
        self.face_positions = deque(maxlen=30)
        self.head_movement_detected = False
        self.movement_threshold = 25.0
        self.phase = "initial"          # initial | movement | complete
        self.last_blink_time = time.time()
        self.created_at = time.time()

    # ------------------------------------------------------------------
    # Blink detection (variance heuristic – replace later with EAR)
    # ------------------------------------------------------------------
    def detect_blink(self, face, frame) -> bool:
        bbox = face.bbox.astype(int)
        x1, y1, x2, y2 = bbox
        h = y2 - y1
        w = x2 - x1

        if h <= 10 or w <= 10:
            return False

        # Approximate eye regions
        left_eye = frame[
            y1 + int(h * 0.25) : y1 + int(h * 0.45),
            x1 + int(w * 0.15) : x1 + int(w * 0.45),
        ]
        right_eye = frame[
            y1 + int(h * 0.25) : y1 + int(h * 0.45),
            x1 + int(w * 0.55) : x1 + int(w * 0.85),
        ]

        if left_eye.size == 0 or right_eye.size == 0:
            return False

        def variance(roi):
            gray = (
                cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
                if len(roi.shape) == 3
                else roi
            )
            return float(np.var(gray))

        avg_var = (variance(left_eye) + variance(right_eye)) / 2.0
        return avg_var < 180.0

    # ------------------------------------------------------------------
    # Head movement
    # ------------------------------------------------------------------
    def track_head_movement(self, face) -> bool:
        bbox = face.bbox
        cx = (bbox[0] + bbox[2]) / 2.0
        cy = (bbox[1] + bbox[3]) / 2.0
        self.face_positions.append((cx, cy))

        if len(self.face_positions) < 8:
            return False

        start = self.face_positions[0]
        end = self.face_positions[-1]
        dist = math.hypot(end[0] - start[0], end[1] - start[1])

        if dist > self.movement_threshold:
            self.head_movement_detected = True
            return True
        return False

    # ------------------------------------------------------------------
    # Main check
    # ------------------------------------------------------------------
    def check_liveness(self, frame, faces) -> Tuple[bool, str, int]:
        """
        Returns:
            (is_live, message, progress 0-100)
        """
        if not faces:
            return False, "No face detected", 0

        # Always use the largest face
        face = max(
            faces,
            key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]),
        )

        is_blinking = self.detect_blink(face, frame)
        moved = self.track_head_movement(face)

        # ---------- Phase: initial (blinks) ----------
        if self.phase == "initial":
            if is_blinking:
                self.blink_counter += 1
            else:
                if self.blink_counter >= 1:
                    self.blinks_completed += 1
                    self.blink_counter = 0
                    self.last_blink_time = time.time()

                    if self.blinks_completed >= self.blink_required:
                        self.phase = "movement"
                        return False, "Great! Now move your head slightly", 40

            progress = min(
                40,
                int((self.blinks_completed / self.blink_required) * 40),
            )
            return False, "Please blink naturally", progress

        # ---------- Phase: movement ----------
        if self.phase == "movement":
            if moved:
                self.phase = "complete"
                return True, "Liveness verified! ✓", 100

            # Timeout after 15 s
            if time.time() - self.last_blink_time > 15:
                self.reset()
                return False, "Timeout – please blink again", 0

            return False, "Please move your head slightly", 70

        # ---------- Phase: complete ----------
        return True, "Liveness verified! ✓", 100

    def reset(self):
        self.phase = "initial"
        self.blink_counter = 0
        self.blinks_completed = 0
        self.head_movement_detected = False
        self.face_positions.clear()
        self.last_blink_time = time.time()


# ======================================================================
# Session manager – prevents concurrent users from sharing state
# ======================================================================

class LivenessManager:
    """
    Holds one LivenessDetector per session_id.
    Clients should send (or receive) a session_id with every request.
    """

    def __init__(self, ttl_seconds: int = 120):
        self._sessions: Dict[str, LivenessDetector] = {}
        self.ttl = ttl_seconds

    def _cleanup(self):
        now = time.time()
        expired = [
            sid
            for sid, det in self._sessions.items()
            if now - det.created_at > self.ttl
        ]
        for sid in expired:
            del self._sessions[sid]

    def get_or_create(
        self, session_id: Optional[str] = None
    ) -> Tuple[str, LivenessDetector]:
        """
        Returns (session_id, detector).
        If session_id is missing or expired, a new one is created.
        """
        self._cleanup()

        if not session_id or session_id not in self._sessions:
            session_id = str(uuid.uuid4())
            self._sessions[session_id] = LivenessDetector()

        return session_id, self._sessions[session_id]

    def reset(self, session_id: str):
        if session_id in self._sessions:
            self._sessions[session_id].reset()