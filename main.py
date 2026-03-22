from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Campus Fortress - 3 Tier Adaptive Security")

# 🔥 CORS (VERY IMPORTANT)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------
# Trusted Networks
# -------------------------------
TRUSTED_NETWORKS = {
    "00:14:22:01:10:01": {"gateway": "192.168.10.1", "max_rtt": 45, "min_rtt": 5},
}

# -------------------------------
# Device DB
# -------------------------------
KNOWN_DEVICES = {
    "device123": {"trust": 1.0},
    "device999": {"trust": 0.4},
}

# -------------------------------
# Memory
# -------------------------------
USER_HISTORY = {}
LAST_RESULT = {}

# -------------------------------
# Request Model
# -------------------------------
class RequestData(BaseModel):
    bssid: str
    gateway_ip: str
    rtt: int
    login_time_hour: int
    login_attempts: int
    session_duration_mins: int
    device_id: str


# -------------------------------
# MAIN API
# -------------------------------
@app.post("/api/v2/authenticate")
async def authenticate(data: RequestData):

    global LAST_RESULT
    explanations = []

    # -------- NETWORK --------
    network_score = 0
    bssid = data.bssid.replace("-", ":").upper()

    if bssid not in TRUSTED_NETWORKS:
        network_score = 100
        explanations.append("Unknown network")
    else:
        safe = TRUSTED_NETWORKS[bssid]

        if data.gateway_ip != safe["gateway"]:
            network_score += 40
            explanations.append("Gateway mismatch")

        if data.rtt < safe["min_rtt"] or data.rtt > safe["max_rtt"]:
            network_score += 30
            explanations.append("Latency issue")

    # -------- BEHAVIOR --------
    behavior_score = min(50, (data.login_attempts ** 1.5)) * 0.6
    behavior_score += min(40, data.session_duration_mins * 3) * 0.4

    if data.login_attempts > 3:
        explanations.append("Multiple login attempts")

    if data.session_duration_mins > 5:
        explanations.append("Long session")

    # -------- DEVICE --------
    device = KNOWN_DEVICES.get(data.device_id, {"trust": 0.2})
    device_penalty = (1 - device["trust"]) * 40

    if device["trust"] < 0.5:
        explanations.append("Untrusted device")

    # -------- HISTORY --------
    history = USER_HISTORY.get(data.device_id, 0)
    history_penalty = min(30, history * 5)

    if history > 2:
        explanations.append("Repeated suspicious activity")

    USER_HISTORY[data.device_id] = history + 1

    # -------- FINAL SCORE --------
    final_score = int(
        network_score * 0.4 +
        behavior_score * 0.4 +
        device_penalty * 0.1 +
        history_penalty * 0.1
    )

    final_score = min(100, final_score)

    # -------- DECISION --------
    if final_score <= 30:
        action = "ALLOW"
    elif final_score <= 70:
        action = "FALLBACK"
    else:
        action = "DENY"

    # -------- STORE RESULT --------
    LAST_RESULT = {
        "action": action,
        "final_score": final_score,
        "explanations": explanations
    }

    return JSONResponse(content=LAST_RESULT)


# -------------------------------
# FRONTEND FETCH API
# -------------------------------
@app.get("/api/v2/latest")
async def get_latest():
    return LAST_RESULT