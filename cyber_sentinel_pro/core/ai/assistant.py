import asyncio
from typing import Optional, Dict
from core.utils.ai_client import get_client, _select_model


async def _chat(messages, max_tokens: int = 600, temperature: float = 0.2) -> Optional[str]:
    client = get_client()
    if not client:
        return None
    model = _select_model(client)
    try:
        resp = await asyncio.to_thread(
            client.chat.completions.create,
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return resp.choices[0].message.content
    except Exception:
        return None


async def explain_threat(context: str) -> Optional[str]:
    msgs = [
        {"role": "system", "content": "You are a cybersecurity threat assistant."},
        {"role": "user", "content": f"Explain the threat:\n{context}"},
    ]
    return await _chat(msgs)


async def summarize_logs(title: str, logs: str) -> Optional[str]:
    msgs = [
        {"role": "system", "content": "Summarize logs, extract anomalies and recommendations."},
        {"role": "user", "content": f"Title: {title}\nLogs:\n{logs}"},
    ]
    return await _chat(msgs)


async def analyze_packets(summary: str) -> Optional[str]:
    msgs = [
        {"role": "system", "content": "Analyze network packets for suspicious activity and IoCs."},
        {"role": "user", "content": summary},
    ]
    return await _chat(msgs)


async def risk_rating(evidence: Dict) -> Optional[str]:
    msgs = [
        {"role": "system", "content": "Rate risk (Low/Medium/High/Critical) and justify succinctly."},
        {"role": "user", "content": str(evidence)},
    ]
    return await _chat(msgs)


async def recommend_actions(context: str) -> Optional[str]:
    msgs = [
        {"role": "system", "content": "Recommend prioritized actions with justifications."},
        {"role": "user", "content": context},
    ]
    return await _chat(msgs)


async def qa(query: str, data: str) -> Optional[str]:
    msgs = [
        {"role": "system", "content": "Answer natural language security questions using provided data."},
        {"role": "user", "content": f"Question: {query}\nData:\n{data}"},
    ]
    return await _chat(msgs)
