from typing import Optional, Tuple

from openai import OpenAI
from .secure_storage import load_secret, load_setting
import time


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
    model = load_setting('openai_model', 'gpt-4o-mini')
    for attempt in range(3):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a precise, concise cybersecurity assistant."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=max_tokens,
                temperature=0.2,
            )
            return resp.choices[0].message.content
        except Exception:
            time.sleep(0.8 * (attempt + 1))
    return None


def probe() -> Tuple[bool, str]:
    client = get_client()
    if not client:
        return False, 'No OpenAI API key saved.'
    model = load_setting('openai_model', 'gpt-4o-mini')
    last_err = None
    for attempt in range(3):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a precise assistant."},
                    {"role": "user", "content": "Return the word OK."},
                ],
                max_tokens=5,
                temperature=0,
            )
            txt = (resp.choices[0].message.content or '').strip().lower()
            if 'ok' in txt:
                return True, 'OpenAI test succeeded.'
            return True, 'OpenAI responded.'
        except Exception as exc:
            last_err = exc
            time.sleep(0.8 * (attempt + 1))
    return False, f'OpenAI error: {last_err}'
