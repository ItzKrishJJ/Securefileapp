from fastapi import FastAPI
from pydantic import BaseModel
import base64
import numpy as np
import math
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="ML File Intelligence Engine")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class PredictRequest(BaseModel):
    file_name: str
    file_size: int
    first_bytes_b64: str

class PredictResponse(BaseModel):
    file_type: str
    anomaly_score: float
    expected_compression_ratio: float
    recommend_signature: bool
    sensitivity: str

def entropy(data: bytes):
    if len(data) == 0:
        return 0
    freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = freq / len(data)
    return -np.sum(probs[probs > 0] * np.log2(probs[probs > 0]))

@app.post("/analyze", response_model=PredictResponse)
async def analyze(req: PredictRequest):

    data = base64.b64decode(req.first_bytes_b64)
    ent = entropy(data)  # 0 to 8 range

    # infer file type from extension
    name_low = req.file_name.lower()
    if name_low.endswith((".jpg", ".jpeg", ".png")):
        ftype = "image"
        compression_est = 0.95
    elif name_low.endswith((".pdf", ".docx", ".txt", ".xlsx")):
        ftype = "document"
        compression_est = 0.50
    elif name_low.endswith((".mp4", ".avi", ".mkv")):
        ftype = "video"
        compression_est = 0.98
    elif name_low.endswith((".exe", ".bin", ".dll")):
        ftype = "binary"
        compression_est = 0.99
    else:
        ftype = "unknown"
        compression_est = 0.85

    # anomaly heuristic
    anomaly = 1.0 - (ent / 8.0)

    # recommended cryptographic sensitivity rules
    if anomaly > 0.3:
        sensitivity = "high"
        signature = True
    else:
        sensitivity = "medium"
        signature = False

    return PredictResponse(
        file_type=ftype,
        anomaly_score=float(round(anomaly, 3)),
        expected_compression_ratio=float(compression_est),
        recommend_signature=signature,
        sensitivity=sensitivity
    )
