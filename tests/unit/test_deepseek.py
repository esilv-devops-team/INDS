import json

import httpx
import pytest

from backend.services import deepseek
from backend.services.deepseek import DeepSeekError, ask_deepseek, check_assessment

KEY = "sk-test-123"
CONTEXT = {"incident_id": 4, "threat_type": "PORT_SCAN", "source": "device-2", "target": "device-5"}


def good_answer(**changes):
    answer = {
        "summary": "device-2 is scanning the ports of device-5.",
        "classification": "Port scan",
        "explanation": "device-2 tried 25 different ports on device-5 in one minute.",
        "risk_level": "High",
        "evidence": ["25 distinct ports in 60 seconds", "device-2 joined 20 minutes before"],
        "impact": "The attacker can find open services on the camera.",
        "recommended_action": "Block",
        "justification": "The device is new and the scan is still going on.",
        "confidence": 85,
        "uncertainty": "It could be a network tool run by the owner.",
    }
    answer.update(changes)
    return answer


def reply(status=200, content=None, body=None):
    if body is None:
        body = {"choices": [{"message": {"content": content if content is not None else json.dumps(good_answer())}}]}
    return httpx.Response(status, json=body)


@pytest.fixture
def calls(monkeypatch):
    monkeypatch.setenv("INDS_DEEPSEEK_API_KEY", KEY)
    monkeypatch.delenv("INDS_DEEPSEEK_MODEL", raising=False)
    sent = []
    answers = []

    def fake_post(url, json, headers, timeout):
        sent.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(deepseek.httpx, "post", fake_post)
    return sent, answers


def test_successful_analysis(calls):
    sent, answers = calls
    answers.append(reply())
    assessment = ask_deepseek(CONTEXT)

    assert assessment["risk_level"] == "High"
    assert assessment["recommended_action"] == "block"
    assert assessment["confidence"] == 85
    assert assessment["evidence"] == ["25 distinct ports in 60 seconds", "device-2 joined 20 minutes before"]

    request, = sent
    assert request["url"] == "https://api.deepseek.com/chat/completions"
    assert request["headers"] == {"Authorization": f"Bearer {KEY}"}
    assert request["json"]["model"] == "deepseek-flash"
    assert request["json"]["response_format"] == {"type": "json_object"}
    assert "JSON" in request["json"]["messages"][0]["content"]
    assert json.loads(request["json"]["messages"][1]["content"].split("\n", 1)[1]) == CONTEXT


def test_model_can_be_changed(calls, monkeypatch):
    sent, answers = calls
    monkeypatch.setenv("INDS_DEEPSEEK_MODEL", "deepseek-v4-pro")
    answers.append(reply())
    ask_deepseek(CONTEXT)
    assert sent[0]["json"]["model"] == "deepseek-v4-pro"


def test_missing_key_is_not_retried(monkeypatch):
    monkeypatch.delenv("INDS_DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(DeepSeekError) as error:
        ask_deepseek(CONTEXT)
    assert str(error.value) == "DeepSeek API key not configured."
    assert error.value.retry is False


@pytest.mark.parametrize("problem, message, retry", [
    (httpx.ReadTimeout("slow"), "DeepSeek did not answer in time.", True),
    (httpx.ConnectError("offline"), "Could not reach the DeepSeek API.", True),
    (reply(401, body={"error": "bad key"}), "DeepSeek refused the request (HTTP 401).", False),
    (reply(402, body={"error": "no balance"}), "DeepSeek refused the request (HTTP 402).", False),
    (reply(500, body={"error": "busy"}), "DeepSeek returned an error (HTTP 500).", True),
    (reply(429, body={"error": "too many"}), "DeepSeek returned an error (HTTP 429).", True),
    (reply(content="this is not json"), "DeepSeek did not return valid JSON.", True),
    (reply(body={"choices": []}), "DeepSeek did not return valid JSON.", True),
    (reply(content="[1, 2]"), "DeepSeek did not answer with a JSON object.", True),
])
def test_failures(calls, problem, message, retry):
    _, answers = calls
    answers.append(problem)
    with pytest.raises(DeepSeekError) as error:
        ask_deepseek(CONTEXT)
    assert str(error.value) == message
    assert error.value.retry is retry
    assert KEY not in str(error.value)


@pytest.mark.parametrize("changes, message", [
    ({"summary": " "}, "missing summary"),
    ({"justification": None}, "missing justification"),
    ({"recommended_action": 3}, "missing recommended_action"),
    ({"risk_level": "Extreme"}, "invalid risk level"),
    ({"evidence": []}, "no evidence list"),
    ({"evidence": "port scan"}, "no evidence list"),
    ({"evidence": ["ok", ""]}, "no evidence list"),
    ({"confidence": 120}, "invalid confidence"),
    ({"confidence": "high"}, "invalid confidence"),
    ({"confidence": True}, "invalid confidence"),
])
def test_invalid_answers(changes, message):
    with pytest.raises(DeepSeekError, match=message):
        check_assessment(good_answer(**changes))


def test_answer_is_cleaned():
    assessment = check_assessment(good_answer(
        risk_level="critical", confidence=72.6, summary="  Scan.  ", evidence=["x" * 2000] + ["fact"] * 15, extra="ignored",
    ))
    assert assessment["risk_level"] == "Critical"
    assert assessment["confidence"] == 73
    assert assessment["summary"] == "Scan."
    assert len(assessment["evidence"]) == 10
    assert len(assessment["evidence"][0]) == 1500
    assert "extra" not in assessment
