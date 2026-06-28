"""
voice_io.py — speech I/O providers (Phase 9)

Lets Mapache speak its responses and transcribe audio, behind a provider
abstraction so the heavy/optional dependencies stay optional:

- `TTSProvider` — `speak(text)` (out loud) / `synthesize(text, path)` (to a file).
- `STTProvider` — `transcribe(path) -> str`.

The defaults are `NullTTS` / `NullSTT`: dependency-free no-ops that make the whole
subsystem safe to wire in unconditionally (voice simply does nothing until enabled
with a real backend). Real backends are constructed only when their package is
importable — `pyttsx3` for offline local TTS, `faster-whisper`/`openai-whisper`
for STT — so the default install needs nothing and tests run offline. Backend
selection mirrors the H/I pattern: a config dict picks the provider, and an
unavailable choice degrades to the null provider with a warning rather than
crashing. Local backends keep voice on-box (OPSEC); a cloud TTS (e.g. ElevenLabs)
would be an explicit, keyed opt-in like the cloud model providers (G).
"""

from __future__ import annotations

from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Interfaces + null defaults
# --------------------------------------------------------------------------- #


class TTSProvider:
    name = "base"

    def available(self) -> bool:
        return True

    def speak(self, text: str) -> None:
        raise NotImplementedError

    def synthesize(self, text: str, out_path: str) -> Optional[str]:
        raise NotImplementedError


class STTProvider:
    name = "base"

    def available(self) -> bool:
        return True

    def transcribe(self, audio_path: str) -> str:
        raise NotImplementedError


class NullTTS(TTSProvider):
    """No-op TTS. `speak` returns the text it *would* have spoken (handy in tests
    and dumb terminals); nothing is played."""

    name = "null"

    def speak(self, text: str) -> str:
        return text or ""

    def synthesize(self, text: str, out_path: str) -> Optional[str]:
        return None


class NullSTT(STTProvider):
    name = "null"

    def transcribe(self, audio_path: str) -> str:
        return ""


# --------------------------------------------------------------------------- #
# Optional real backends (constructed only when the package imports)
# --------------------------------------------------------------------------- #


class Pyttsx3TTS(TTSProvider):
    """Offline, local TTS via pyttsx3 (SAPI5/NSSpeech/espeak). Keeps voice on-box."""

    name = "pyttsx3"

    def __init__(self) -> None:
        import pyttsx3  # noqa: F401  (raises ImportError if absent → factory falls back)
        self._pyttsx3 = pyttsx3

    def _engine(self):
        return self._pyttsx3.init()

    def speak(self, text: str) -> None:
        if not text:
            return
        eng = self._engine()
        eng.say(text)
        eng.runAndWait()

    def synthesize(self, text: str, out_path: str) -> Optional[str]:
        eng = self._engine()
        eng.save_to_file(text, out_path)
        eng.runAndWait()
        return out_path


class WhisperSTT(STTProvider):
    """Local STT via faster-whisper (preferred) or openai-whisper."""

    name = "whisper"

    def __init__(self, model: str = "base") -> None:
        self._model_name = model
        self._impl = None
        try:
            from faster_whisper import WhisperModel
            self._impl = ("faster", WhisperModel(model))
        except ImportError:
            import whisper  # raises ImportError if neither is installed
            self._impl = ("openai", whisper.load_model(model))

    def transcribe(self, audio_path: str) -> str:
        kind, model = self._impl
        if kind == "faster":
            segments, _info = model.transcribe(audio_path)
            return " ".join(s.text.strip() for s in segments).strip()
        return (model.transcribe(audio_path) or {}).get("text", "").strip()


# --------------------------------------------------------------------------- #
# Factories + manager
# --------------------------------------------------------------------------- #


def make_tts(name: str) -> tuple[TTSProvider, Optional[str]]:
    """(provider, warning). Unknown/unavailable backend → NullTTS + a warning."""
    key = (name or "null").lower()
    if key in ("", "null", "none"):
        return NullTTS(), None
    if key == "pyttsx3":
        try:
            return Pyttsx3TTS(), None
        except ImportError:
            return NullTTS(), "pyttsx3 not installed; TTS disabled (pip install pyttsx3)"
    return NullTTS(), f"unknown TTS backend {name!r}; TTS disabled"


def make_stt(name: str) -> tuple[STTProvider, Optional[str]]:
    key = (name or "null").lower()
    if key in ("", "null", "none"):
        return NullSTT(), None
    if key == "whisper":
        try:
            return WhisperSTT(), None
        except ImportError:
            return NullSTT(), "whisper not installed; STT disabled (pip install faster-whisper)"
    return NullSTT(), f"unknown STT backend {name!r}; STT disabled"


class VoiceManager:
    """Bundles a TTS + STT provider and an enabled flag for the CLI."""

    def __init__(self, tts: TTSProvider, stt: STTProvider, enabled: bool = False) -> None:
        self.tts = tts
        self.stt = stt
        self.enabled = enabled

    def speak(self, text: str) -> Optional[str]:
        if not self.enabled or not text:
            return None
        try:
            return self.tts.speak(text)
        except Exception:
            return None  # voice must never break a turn

    def transcribe(self, audio_path: str) -> str:
        try:
            return self.stt.transcribe(audio_path)
        except Exception:
            return ""

    def describe(self) -> str:
        state = "on" if self.enabled else "off"
        return f"voice {state} (tts={self.tts.name}, stt={self.stt.name})"


def voice_from_config(spec: Optional[dict]) -> tuple[VoiceManager, list[str]]:
    """Build a VoiceManager from a config dict; returns (manager, warnings)."""
    spec = spec or {}
    tts, w1 = make_tts(str(spec.get("tts", "null")))
    stt, w2 = make_stt(str(spec.get("stt", "null")))
    warnings = [w for w in (w1, w2) if w]
    return VoiceManager(tts, stt, enabled=bool(spec.get("enabled", False))), warnings
