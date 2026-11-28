#!/usr/bin/env python3
"""Local human-sounding neural TTS generator powered by Kokoro-82M (kokoro-onnx).

Synthesizes per-beat WAV audio segments with natural conversational phrasing,
clean sentence-boundary breath pauses, SHA-256 verified model files, and
sample-accurate timing metadata so video actions, highlights, and captions
remain strictly synchronized.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

MODEL_URL = "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/kokoro-v1.0.onnx"
VOICES_URL = "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/voices-v1.0.bin"
MODEL_SHA256 = "7d5df8ecf7d4b1878015a32686053fd0eebe2bc377234608764cc0ef3636a6c5"
VOICES_SHA256 = "bca610b8308e8d99f32e6fe4197e7ec01679264efed0cac9140fe9c29f1fbf7d"

DEFAULT_VOICE = "am_michael"
DEFAULT_SPEED = 0.98
DEFAULT_LANG = "en-us"
SAMPLE_RATE = 24000
DOWNLOAD_TIMEOUT_SEC = 120


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject any HTTP redirect that downgrades away from HTTPS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme.lower() != "https":
            raise ValueError(f"Refusing non-HTTPS redirect to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(path: Path, expected_sha256: str) -> None:
    actual = sha256_file(path)
    if actual.lower() != expected_sha256.lower():
        raise ValueError(
            f"SHA-256 mismatch for {path.name}: expected {expected_sha256}, got {actual}."
        )


def download_verified(url: str, dest: Path, expected_sha256: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Refusing non-HTTPS model URL: {url}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(HttpsOnlyRedirectHandler())
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=dest.parent,
            prefix=f".{dest.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            digest = hashlib.sha256()
            with opener.open(url, timeout=DOWNLOAD_TIMEOUT_SEC) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    tmp_file.write(chunk)
                    digest.update(chunk)

        actual = digest.hexdigest()
        if actual.lower() != expected_sha256.lower():
            raise ValueError(
                f"Downloaded {dest.name} failed SHA-256 verification: expected {expected_sha256}, got {actual}."
            )
        os.replace(tmp_path, dest)
        tmp_path = None
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def ensure_model_files(model_dir: Path, allow_download: bool) -> tuple[Path, Path]:
    model_path = model_dir / "kokoro-v1.0.onnx"
    voices_path = model_dir / "voices-v1.0.bin"

    targets = (
        (MODEL_URL, model_path, MODEL_SHA256),
        (VOICES_URL, voices_path, VOICES_SHA256),
    )

    for url, dest, expected_sha in targets:
        if dest.exists():
            verify_checksum(dest, expected_sha)
            continue
        if not allow_download:
            raise FileNotFoundError(
                f"Kokoro-82M model file not found: {dest}. "
                "Pass --download or set KOKORO_MODEL_DIR to a directory containing "
                "verified kokoro-v1.0.onnx and voices-v1.0.bin."
            )
        print(f"[kokoro-tts] Downloading verified {dest.name}...", file=sys.stderr)
        download_verified(url, dest, expected_sha)

    return model_path, voices_path


def split_sentences(text: str) -> list[str]:
    cleaned = re.sub(r"\s+", " ", text.strip())
    if not cleaned:
        return []
    parts = re.split(r"(?<=[.!?])\s+", cleaned)
    return [part.strip() for part in parts if part.strip()]


def trim_edge_silence(np_mod: Any, samples: Any, threshold: float = 0.004, pad_samples: int = 1200) -> Any:
    if samples.size == 0:
        return samples
    above = np_mod.flatnonzero(np_mod.abs(samples) > threshold)
    if above.size == 0:
        return samples
    start = max(0, int(above[0]) - pad_samples)
    end = min(samples.size, int(above[-1]) + pad_samples)
    return samples[start:end]


def synthesize_beat(
    np_mod: Any,
    kokoro: Any,
    text: str,
    voice: str,
    speed: float,
    lang: str,
    lead_in_ms: int = 140,
    sentence_pause_ms: int = 190,
    tail_pause_ms: int = 340,
) -> tuple[Any, int]:
    sentences = split_sentences(text)
    if not sentences:
        raise ValueError("Narration beat text must not be empty.")

    chunks = []
    if lead_in_ms > 0:
        chunks.append(np_mod.zeros(int(SAMPLE_RATE * lead_in_ms / 1000.0), dtype=np_mod.float32))

    sentence_gap = np_mod.zeros(int(SAMPLE_RATE * sentence_pause_ms / 1000.0), dtype=np_mod.float32)

    sr = SAMPLE_RATE
    for idx, sentence in enumerate(sentences):
        raw_samples, sr = kokoro.create(sentence, voice=voice, speed=speed, lang=lang)
        trimmed = trim_edge_silence(np_mod, np_mod.asarray(raw_samples, dtype=np_mod.float32))
        chunks.append(trimmed)
        if idx < len(sentences) - 1 and sentence_pause_ms > 0:
            chunks.append(sentence_gap)

    if tail_pause_ms > 0:
        chunks.append(np_mod.zeros(int(sr * tail_pause_ms / 1000.0), dtype=np_mod.float32))

    combined = np_mod.concatenate(chunks)
    peak = float(np_mod.max(np_mod.abs(combined))) if combined.size else 0.0
    if peak > 0.96:
        combined = combined * (0.96 / peak)
    return combined, sr


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate natural Kokoro-82M narration segments.")
    parser.add_argument("--beats", required=True, help="Path to JSON file containing [{id, narration}, ...]")
    parser.add_argument("--out-dir", required=True, help="Output directory for beat WAV files and narration-timings.json")
    parser.add_argument("--voice", default=os.environ.get("PR_VIDEO_TTS_VOICE", DEFAULT_VOICE))
    parser.add_argument("--speed", type=float, default=float(os.environ.get("PR_VIDEO_TTS_SPEED", str(DEFAULT_SPEED))))
    parser.add_argument("--lang", default=DEFAULT_LANG)
    parser.add_argument("--model-dir", default=os.environ.get("KOKORO_MODEL_DIR", str(Path.home() / ".cache" / "kokoro-onnx")))
    parser.add_argument("--download", action="store_true", help="Download SHA-256 verified Kokoro-82M weights if missing")
    args = parser.parse_args()

    if not (0.5 <= args.speed <= 2.0):
        print(f"[kokoro-tts] ERROR: --speed must be between 0.5 and 2.0 (got {args.speed}).", file=sys.stderr)
        return 2

    try:
        import numpy as np
        import soundfile as sf
        from kokoro_onnx import Kokoro
    except ImportError:
        print(
            "[kokoro-tts] ERROR: Required TTS packages are missing. "
            "Install with: python3 -m pip install kokoro-onnx soundfile numpy",
            file=sys.stderr,
        )
        return 2

    model_path, voices_path = ensure_model_files(Path(args.model_dir), allow_download=args.download)
    kokoro = Kokoro(str(model_path), str(voices_path))

    available_voices = set(kokoro.get_voices())
    if args.voice not in available_voices:
        print(
            f"[kokoro-tts] ERROR: Unknown voice '{args.voice}'. Available sample: {sorted(available_voices)[:12]}",
            file=sys.stderr,
        )
        return 2

    beats_raw = json.loads(Path(args.beats).read_text(encoding="utf-8"))
    if not isinstance(beats_raw, list) or len(beats_raw) == 0:
        print("[kokoro-tts] ERROR: Beats JSON must be a non-empty list.", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    total_duration = 0.0
    for index, beat in enumerate(beats_raw, start=1):
        if not isinstance(beat, dict):
            print(f"[kokoro-tts] ERROR: Beat {index} must be a JSON object.", file=sys.stderr)
            return 2
        beat_id = str(beat.get("id") or f"beat-{index:02d}")
        narration = str(beat.get("narration") or "").strip()
        if not narration:
            print(f"[kokoro-tts] ERROR: Beat '{beat_id}' has empty narration.", file=sys.stderr)
            return 2

        samples, sr = synthesize_beat(
            np_mod=np,
            kokoro=kokoro,
            text=narration,
            voice=args.voice,
            speed=args.speed,
            lang=args.lang,
        )
        duration_sec = round(len(samples) / float(sr), 3)
        wav_name = f"{index:02d}-{re.sub(r'[^a-zA-Z0-9_-]+', '-', beat_id)}.wav"
        wav_path = out_dir / wav_name
        sf.write(str(wav_path), samples, sr, subtype="PCM_16")
        results.append(
            {
                "id": beat_id,
                "narration": narration,
                "wavFile": wav_name,
                "wavPath": str(wav_path),
                "sampleRate": sr,
                "durationSec": duration_sec,
            }
        )
        total_duration += duration_sec

    manifest = {
        "provider": "kokoro-onnx",
        "model": model_path.name,
        "voice": args.voice,
        "speed": args.speed,
        "lang": args.lang,
        "totalDurationSec": round(total_duration, 3),
        "segments": results,
    }
    timings_path = out_dir / "narration-timings.json"
    timings_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
