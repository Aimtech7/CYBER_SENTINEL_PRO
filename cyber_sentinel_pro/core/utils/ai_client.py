from typing import Optional, Tuple
import time

from openai import OpenAI
from .secure_storage import load_secret, load_setting

_CACHED_MODEL: Optional[str] = None
import time


def get_client() -> Optional[OpenAI]:
    api_key = load_secret('openai_api_key')
    if not api_key:
        return None
    try:
        return OpenAI(api_key=api_key)
    except Exception:
        return None


def _select_model(client: OpenAI) -> str:
    global _CACHED_MODEL
    if _CACHED_MODEL:
        return _CACHED_MODEL
    desired = (load_setting('openai_model', '') or '').strip()
    if desired:
        _CACHED_MODEL = desired
        return _CACHED_MODEL
    try:
        resp = client.models.list()
        names = [m.id for m in getattr(resp, 'data', [])]
        priority = [
            'gpt-4o-mini',
            'gpt-4o',
            'o3-mini',
            'gpt-4.1-mini',
            'gpt-3.5-turbo',
        ]
        for p in priority:
            for n in names:
                if n == p:
                    _CACHED_MODEL = n
                    return n
        # heuristic fallbacks
        for n in names:
            if 'gpt-4o' in n and 'mini' in n:
                _CACHED_MODEL = n
                return n
        for n in names:
            if 'gpt-4o' in n:
                _CACHED_MODEL = n
                return n
    except Exception:
        pass
    _CACHED_MODEL = 'gpt-4o-mini'
    return _CACHED_MODEL


def summarize(title: str, content: str, max_tokens: int = 400) -> Optional[str]:
    client = get_client()
    if not client:
        return None
    prompt = f"You are an expert cybersecurity analyst. Title: {title}. Analyze the following data and produce a concise security summary with key findings, risks, and recommendations.\n\n=== Data Start ===\n{content}\n=== Data End ==="
    model = _select_model(client)
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
    model = _select_model(client)
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
