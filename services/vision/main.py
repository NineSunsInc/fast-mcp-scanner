import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException
from paddleocr import PaddleOCR
import numpy as np
import cv2
import io
from PIL import Image
from presidio_analyzer import AnalyzerEngine
import logging
from pydantic import BaseModel

app = FastAPI(title="Citadel Vision Engine")

# Initialize Presidio Analyzer (Loads NLP Model)
print("🧠 Loading Presidio NLP Engine...")
analyzer = AnalyzerEngine()
print("✅ Presidio Loaded")

# Initialize PaddleOCR (Loads model into memory once)
# v3 Change: use_angle_cls -> use_textline_orientation
# v3 Change: show_log removed (controlled via logging config)
ocr = PaddleOCR(use_textline_orientation=True, lang='en') 

class TextRequest(BaseModel):
    text: str

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "vision-analysis-sidecar"}

@app.post("/analyze")
async def analyze_text(req: TextRequest):
    # Analyze text for PII
    results = analyzer.analyze(text=req.text, language='en')
    
    # Transform to simple JSON
    pii_found = []
    for r in results:
        pii_found.append({
            "type": r.entity_type,
            "score": r.score,
            "start": r.start,
            "end": r.end,
            "text": req.text[r.start:r.end] # Return snippet for debugging/logging
        })
    
    return {"pii": pii_found, "count": len(pii_found)}

@app.post("/scan")
async def scan_image(file: UploadFile = File(...)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(400, "Invalid file type")

    try:
        # 1. Read Bytes
        contents = await file.read()
        
        # 2. Preprocess (Convert to strict numpy array for Paddle)
        image = Image.open(io.BytesIO(contents)).convert("RGB")
        img_np = np.array(image)
        
        # 3. CV2 Preprocessing (The "Robust" Pipeline)
        # Note: Paddle handles simple inversion, but for "White on White" hidden text, 
        # we might want to run multiple passes (Normal, Inverted) if risk is high.
        # For this MVP, we pass raw.
        # Ensure BGR for CV2 if needed, but Paddle works with RGB often.
        img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)

        # 4. Inference
        result = ocr.ocr(img_bgr, cls=True)
        
        # 5. Extract Text
        extracted_text = []
        confidences = []
        
        # Result structure: [ [ [ [x1,y1].. ], (text, conf) ] ... ]
        if result and result[0]:
            for line in result[0]:
                text = line[1][0]
                conf = line[1][1]
                extracted_text.append(text)
                confidences.append(conf)
        
        full_text = " ".join(extracted_text)
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

        return {
            "text": full_text,
            "confidence": avg_conf,
            "segments": len(extracted_text)
        }

    except Exception as e:
        print(f"OCR Error: {e}")
        raise HTTPException(500, f"OCR Processing Failed: {str(e)}")

def start():
    """Entry point for poetry/script"""
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)

if __name__ == "__main__":
    start()
