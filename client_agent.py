import requests
import random
import time
from datetime import datetime

URL = "http://127.0.0.1:8000/api/v2/authenticate"

while True:
    data = {
        "bssid": "00:14:22:01:10:01",
        "gateway_ip": "192.168.10.1",
        "rtt": random.randint(5, 60),
        "login_time_hour": datetime.now().hour,
        "login_attempts": random.randint(1, 6),
        "session_duration_mins": random.randint(1, 10),
        "device_id": random.choice(["device123", "device999", "unknown_device"])
    }

    try:
        res = requests.post(URL, json=data)
        print(res.json())
    except:
        print("Server not running!")

    time.sleep(3)
    