#!/usr/bin/env python3

import os
import json
import platform
from datetime import datetime
from typing import Optional, Dict, Any

class Session:
    def __init__(self, target: Optional[str] = None):
        self.target     = target
        self.start_time = datetime.now()
        self.results: Dict[str, Any] = {}
        self.metadata = {
            "tool":    "CypherX",
            "version": "1.0.0",
            "target":  target,
            "started": self.start_time.isoformat(),
            "os":      platform.system(),
        }

    def add(self, module: str, data: Any):
        self.results[module] = {"data": data, "time": datetime.now().isoformat()}

    def save(self, output_dir: str = "results") -> str:
        os.makedirs(output_dir, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = (self.target or "session").replace("/","_").replace(".","_")
        path = os.path.join(output_dir, f"{name}_{ts}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "metadata": self.metadata,
                "results":  self.results,
                "duration": str(datetime.now() - self.start_time),
            }, f, indent=4, ensure_ascii=False, default=str)
        return path


