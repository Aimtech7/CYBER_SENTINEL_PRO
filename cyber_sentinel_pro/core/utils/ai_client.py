from typing import Optional

from openai import OpenAI
from .secure_storage import load_secret


def get_client() -> Optional[OpenAI]:
    api_key = load_secret('openai_api_key')
    if not api_key:
        return None
    try:
        return OpenAI(api_key=api_key)
    except Exception:
        return None


def summarize(title: str, content: str, max_tokens: int = 400) -> Optional[str]:
    client = get_client()
    if not client:
        return None
    prompt = f"You are an expert cybersecurity analyst. Title: {title}. Analyze the following data and produce a concise security summary with key findings, risks, and recommendations.\n\n=== Data Start ===\n{content}\n=== Data End ==="
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a precise, concise cybersecurity assistant."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception:
        return None

