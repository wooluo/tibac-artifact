"""Minimal OpenAI-compatible chat client (stdlib only: urllib)."""
from __future__ import annotations

import json
import os
import time
import urllib.request


class LLMClient:
    def __init__(self, endpoint: str | None = None, api_key: str | None = None,
                 model: str = "glm-4-flash", timeout: int = 60):
        self.endpoint = endpoint or os.environ.get(
            "GLM_ENDPOINT", "https://open.bigmodel.cn/api/paas/v4/chat/completions")
        key = api_key or os.environ.get("GLM_API_KEY") or self._read_key_file()
        self.api_key = key
        self.model = model
        self.timeout = timeout
        self.calls = 0

    @staticmethod
    def _read_key_file() -> str:
        for p in (os.path.expanduser("~/.glm_key"),):
            if os.path.exists(p):
                return open(p).read().strip()
        raise SystemExit("GLM_API_KEY not set and ~/.glm_key missing")

    def chat(self, messages: list, temperature: float = 0.7,
             max_tokens: int = 512, retries: int = 4) -> str:
        body = json.dumps({"model": self.model, "messages": messages,
                           "temperature": temperature,
                           "max_tokens": max_tokens}).encode()
        last = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    self.endpoint, data=body,
                    headers={"Authorization": f"Bearer {self.api_key}",
                             "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    d = json.loads(r.read())
                self.calls += 1
                return d["choices"][0]["message"]["content"] or ""
            except Exception as e:  # noqa: BLE001 - network/HTTP errors
                last = e
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"LLM call failed after {retries} retries: {last}")
