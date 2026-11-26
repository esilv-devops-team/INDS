import json
import os

import httpx

API_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_MODEL = "deepseek-flash"
TIMEOUT_SECONDS = 30
MAX_TEXT = 1500
MAX_EVIDENCE = 10
RISK_LEVELS = ("Low", "Medium", "High", "Critical")
TEXT_FIELDS = ("summary", "classification", "explanation", "impact", "recommended_action", "justification", "uncertainty")

SYSTEM_PROMPT = """You are the security analyst of INDS, a network defense system that protects a small local network.
You receive one incident detected by INDS as JSON. Private data was removed: devices are called device-<id>,
other addresses are lan host, external host, access point or unknown.
Answer with one JSON object only, using exactly these keys:
- summary: one short sentence for the administrator
- classification: short name of the threat
- explanation: what is happening, in simple words
- risk_level: one of Low, Medium, High, Critical
- evidence: list of short facts taken from the incident that support your answer
- impact: what this could do to the network
- recommended_action: block (cut the source device off) or monitor (no action, keep watching)
- justification: why you recommend this action
- confidence: integer from 0 to 100
- uncertainty: what you are not sure about, or what could make this a false positive
Only use facts from the incident. Never write commands or firewall rules."""


class DeepSeekError(Exception):
    def __init__(self, message, retry=True):
        super().__init__(message)
        self.retry = retry


def model_name():
    return os.environ.get("INDS_DEEPSEEK_MODEL", "").strip() or DEFAULT_MODEL


def check_assessment(answer):
    if not isinstance(answer, dict):
        raise DeepSeekError("DeepSeek did not answer with a JSON object.")
    assessment = {}
    for field in TEXT_FIELDS:
        value = answer.get(field)
        if not isinstance(value, str) or not value.strip():
            raise DeepSeekError(f"DeepSeek answer is missing {field}.")
        assessment[field] = value.strip()[:MAX_TEXT]
    assessment["recommended_action"] = assessment["recommended_action"].lower()

    risk = str(answer.get("risk_level", "")).strip().capitalize()
    if risk not in RISK_LEVELS:
        raise DeepSeekError("DeepSeek answer has an invalid risk level.")
    assessment["risk_level"] = risk

    evidence = answer.get("evidence")
    if not isinstance(evidence, list) or not evidence or not all(isinstance(item, str) and item.strip() for item in evidence):
        raise DeepSeekError("DeepSeek answer has no evidence list.")
    assessment["evidence"] = [item.strip()[:MAX_TEXT] for item in evidence[:MAX_EVIDENCE]]

    confidence = answer.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 100:
        raise DeepSeekError("DeepSeek answer has an invalid confidence.")
    assessment["confidence"] = round(confidence)
    return assessment


def ask_deepseek(context):
    key = os.environ.get("INDS_DEEPSEEK_API_KEY", "").strip()
    if not key:
        raise DeepSeekError("DeepSeek API key not configured.", retry=False)

    body = {
        "model": model_name(),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Incident JSON:\n" + json.dumps(context)},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2,
        "max_tokens": 1500,
        "stream": False,
    }
    try:
        response = httpx.post(API_URL, json=body, headers={"Authorization": f"Bearer {key}"}, timeout=TIMEOUT_SECONDS)
    except httpx.TimeoutException:
        raise DeepSeekError("DeepSeek did not answer in time.") from None
    except httpx.HTTPError:
        raise DeepSeekError("Could not reach the DeepSeek API.") from None

    if response.status_code in (401, 402, 403):
        raise DeepSeekError(f"DeepSeek refused the request (HTTP {response.status_code}).", retry=False)
    if response.status_code != 200:
        raise DeepSeekError(f"DeepSeek returned an error (HTTP {response.status_code}).")

    try:
        content = response.json()["choices"][0]["message"]["content"]
        answer = json.loads(content)
    except (ValueError, KeyError, IndexError, TypeError):
        raise DeepSeekError("DeepSeek did not return valid JSON.") from None
    return check_assessment(answer)
