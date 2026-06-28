"""voice — speech I/O for Mapache (Phase 9): optional TTS/STT behind a null default."""

from .voice_io import (TTSProvider, STTProvider, NullTTS, NullSTT,
                       VoiceManager, make_tts, make_stt, voice_from_config)

__all__ = [
    "TTSProvider", "STTProvider", "NullTTS", "NullSTT",
    "VoiceManager", "make_tts", "make_stt", "voice_from_config",
]
