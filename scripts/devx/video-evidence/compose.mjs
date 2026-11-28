import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MAX_BUFFER_BYTES = 32 * 1024 * 1024;

function runBinary(bin, args, label, options = {}) {
  const result = spawnSync(bin, args, {
    encoding: "utf8",
    maxBuffer: MAX_BUFFER_BYTES,
    ...options,
  });
  if (result.error) {
    throw new Error(`[video-evidence] ${label} failed to spawn ${bin}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(
      `[video-evidence] ${label} failed (exit ${result.status}):\n${result.stderr || result.stdout}`,
    );
  }
  return result;
}

export function probeMedia(filePath) {
  const result = runBinary(
    "ffprobe",
    ["-v", "error", "-print_format", "json", "-show_format", "-show_streams", filePath],
    `ffprobe ${path.basename(filePath)}`,
  );
  return JSON.parse(result.stdout);
}

export function formatSrtTime(seconds) {
  const totalMs = Math.max(0, Math.round(seconds * 1000));
  const ms = totalMs % 1000;
  const totalSec = Math.floor(totalMs / 1000);
  const s = totalSec % 60;
  const totalMin = Math.floor(totalSec / 60);
  const m = totalMin % 60;
  const h = Math.floor(totalMin / 60);
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")},${String(ms).padStart(3, "0")}`;
}

export function formatVttTime(seconds) {
  return formatSrtTime(seconds).replace(",", ".");
}

export function formatAssTime(seconds) {
  const totalCs = Math.max(0, Math.round(seconds * 100));
  const cs = totalCs % 100;
  const totalSec = Math.floor(totalCs / 100);
  const s = totalSec % 60;
  const totalMin = Math.floor(totalSec / 60);
  const m = totalMin % 60;
  const h = Math.floor(totalMin / 60);
  return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}.${String(cs).padStart(2, "0")}`;
}

export function formatMmSs(seconds) {
  const totalSec = Math.max(0, Math.floor(seconds));
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

export function wrapTwoLines(text, maxLineLen = 62) {
  const normalized = String(text ?? "").trim();
  if (normalized.length <= maxLineLen) return normalized;
  const words = normalized.split(/\s+/).filter(Boolean);
  if (words.length <= 1) return normalized;

  const mid = Math.ceil(normalized.length / 2);
  let bestSplit = 1;
  let bestDiff = Infinity;
  let len = 0;
  for (let i = 0; i < words.length - 1; i++) {
    len += words[i].length + (i > 0 ? 1 : 0);
    const diff = Math.abs(len - mid);
    if (diff < bestDiff) {
      bestDiff = diff;
      bestSplit = i + 1;
    }
  }
  return `${words.slice(0, bestSplit).join(" ")}\n${words.slice(bestSplit).join(" ")}`;
}

/**
 * Splits a narration segment into balanced, legible caption cues (<= 2 lines, <= 62 chars/line)
 * strictly distributed across the beat's speaking window with guaranteed cueEnd > cueStart.
 */
export function buildCaptionCues(text, startSec, durationSec) {
  const words = String(text ?? "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (words.length === 0 || !(durationSec > 0)) return [];

  const maxCharsPerCue = 112;
  const rawCues = [];
  let current = [];
  let currentLen = 0;

  for (const word of words) {
    const nextLen = currentLen + (current.length ? 1 : 0) + word.length;
    if (nextLen > maxCharsPerCue && current.length > 0) {
      rawCues.push(current.join(" "));
      current = [word];
      currentLen = word.length;
    } else {
      current.push(word);
      currentLen = nextLen;
    }
  }
  if (current.length > 0) {
    rawCues.push(current.join(" "));
  }

  const lead = Math.min(0.08, durationSec * 0.1);
  const tail = Math.min(0.18, durationSec * 0.15);
  const speakingStart = startSec + lead;
  const speakingEnd = Math.max(speakingStart + 0.1, startSec + durationSec - tail);
  const speakingWindow = speakingEnd - speakingStart;

  const totalWeight = rawCues.reduce((sum, c) => sum + Math.max(1, c.length), 0);
  let cursor = speakingStart;

  return rawCues.map((cueText, idx) => {
    const cueStart = Number(cursor.toFixed(3));
    const cueEnd =
      idx === rawCues.length - 1
        ? Number(speakingEnd.toFixed(3))
        : Number(
            Math.min(
              speakingEnd - 0.02 * (rawCues.length - 1 - idx),
              cursor + (Math.max(1, cueText.length) / totalWeight) * speakingWindow,
            ).toFixed(3),
          );
    cursor = cueEnd;
    return {
      startSec: cueStart,
      endSec: Math.max(Number((cueStart + 0.02).toFixed(3)), cueEnd),
      text: wrapTwoLines(cueText, 62),
    };
  });
}

function escapeAssText(text) {
  return text
    .replace(/\\/g, "\\\\")
    .replace(/\{/g, "\\{")
    .replace(/\}/g, "\\}")
    .replace(/\n/g, "\\N");
}

function buildAssDocument(cues) {
  // Explicit 1920x1080 PlayRes ensures exact pixel font sizing (~28px) and a clean
  // bottom subtitle pill that never obscures main application controls.
  const header = [
    "[Script Info]",
    "ScriptType: v4.00+",
    "PlayResX: 1920",
    "PlayResY: 1080",
    "WrapStyle: 2",
    "ScaledBorderAndShadow: yes",
    "",
    "[V4+ Styles]",
    "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding",
    "Style: EngineeringCaption,Inter,28,&H00FFFFFF,&H00FFFFFF,&H260F172A,&H260F172A,0,0,0,0,100,100,0,0,3,10,0,2,160,160,30,1",
    "",
    "[Events]",
    "Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text",
  ];

  const events = cues.map(
    (cue) =>
      `Dialogue: 0,${formatAssTime(cue.startSec)},${formatAssTime(cue.endSec)},EngineeringCaption,,0,0,0,,${escapeAssText(cue.text)}`,
  );

  return [...header, ...events, ""].join("\n");
}

export function parseVolumedetect(stderrText) {
  const meanMatch = stderrText.match(/mean_volume:\s*([-\d.]+)\s*dB/);
  const maxMatch = stderrText.match(/max_volume:\s*([-\d.]+)\s*dB/);
  const hist0Match = stderrText.match(/histogram_0db:\s*(\d+)/);

  const meanVolumeDb = meanMatch ? Number(meanMatch[1]) : -99;
  const maxVolumeDb = maxMatch ? Number(maxMatch[1]) : -99;
  const histogram0db = hist0Match ? Number(hist0Match[1]) : 0;

  const audioAudible = meanVolumeDb > -40 && maxVolumeDb > -25;
  // In FFmpeg volumedetect (16-bit PCM), digital full-scale clipping registers at 0.0 dB.
  const audioClipping = maxVolumeDb >= -0.1 && histogram0db > 50;

  return { meanVolumeDb, maxVolumeDb, histogram0db, audioAudible, audioClipping };
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(filePath, "r");
  const buf = Buffer.alloc(1024 * 1024);
  try {
    let bytesRead = 0;
    while ((bytesRead = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      hash.update(buf.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}

/**
 * Composes synchronized per-beat video & Kokoro WAV narration into a single
 * 1920x1080 @ 30fps H.264/AAC MP4 with crisp burned-in 1080p captions, plus .ass, .srt, .vtt, transcript.txt.
 */
export function composeEvidenceVideo({ beats, outDir, finalMp4Name = "demo.mp4" }) {
  if (!Array.isArray(beats) || beats.length === 0) {
    throw new Error("composeEvidenceVideo requires at least one beat.");
  }
  if (path.basename(finalMp4Name) !== finalMp4Name) {
    throw new Error(
      `finalMp4Name must be a simple filename without path separators: ${finalMp4Name}`,
    );
  }

  const resolvedOutDir = path.resolve(outDir);
  const workDir = path.join(resolvedOutDir, "work");
  fs.mkdirSync(workDir, { recursive: true });

  const alignedVideoNames = [];
  const alignedAudioNames = [];
  const beatTimeline = [];
  const allCues = [];
  const transcriptLines = [];

  let cursorSec = 0;

  try {
    for (let i = 0; i < beats.length; i++) {
      const beat = beats[i];
      if (!beat?.rawVideoPath || !fs.existsSync(beat.rawVideoPath)) {
        throw new Error(`Missing raw video for beat ${i + 1}: ${String(beat?.rawVideoPath)}`);
      }
      if (!beat?.audioWavPath || !fs.existsSync(beat.audioWavPath)) {
        throw new Error(`Missing narration WAV for beat ${i + 1}: ${String(beat?.audioWavPath)}`);
      }

      const videoProbe = probeMedia(beat.rawVideoPath);
      const rawVideoDuration = Number(videoProbe.format?.duration ?? 0);
      if (!(rawVideoDuration > 0)) {
        throw new Error(`Raw beat video has zero duration: ${beat.rawVideoPath}`);
      }

      const audioProbe = probeMedia(beat.audioWavPath);
      const rawAudioDuration = Number(audioProbe.format?.duration ?? 0);
      if (!(rawAudioDuration > 0)) {
        throw new Error(`Beat narration WAV has zero duration: ${beat.audioWavPath}`);
      }

      // Quantize to exact 30fps frame boundaries so 30fps video & 48kHz audio (1600 samples/frame) never drift.
      const rawTarget = Math.max(rawVideoDuration, rawAudioDuration + 0.15);
      const targetFrames = Math.ceil(rawTarget * 30);
      const targetDuration = Number((targetFrames / 30).toFixed(6));
      const videoPadSec = Math.max(0, targetDuration - rawVideoDuration);

      const alignedVideoName = `beat-${String(i + 1).padStart(2, "0")}-video.mp4`;
      const alignedVideoPath = path.join(workDir, alignedVideoName);
      const vfParts = [
        "scale=1920:1080:force_original_aspect_ratio=decrease",
        "pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=#0B0F19",
        "fps=30",
        "setsar=1",
      ];
      if (videoPadSec > 0.02) {
        vfParts.push(`tpad=stop_mode=clone:stop_duration=${videoPadSec.toFixed(3)}`);
      }

      runBinary(
        "ffmpeg",
        [
          "-y",
          "-nostats",
          "-loglevel",
          "warning",
          "-i",
          beat.rawVideoPath,
          "-vf",
          vfParts.join(","),
          "-t",
          targetDuration.toFixed(6),
          "-an",
          "-c:v",
          "libx264",
          "-preset",
          "veryfast",
          "-crf",
          "16",
          "-pix_fmt",
          "yuv420p",
          "-r",
          "30",
          alignedVideoPath,
        ],
        `align video beat ${i + 1}`,
      );

      const alignedAudioName = `beat-${String(i + 1).padStart(2, "0")}-audio.wav`;
      const alignedAudioPath = path.join(workDir, alignedAudioName);
      runBinary(
        "ffmpeg",
        [
          "-y",
          "-nostats",
          "-loglevel",
          "warning",
          "-i",
          beat.audioWavPath,
          "-af",
          `aresample=48000,aformat=channel_layouts=stereo,apad=whole_dur=${targetDuration.toFixed(6)}`,
          "-t",
          targetDuration.toFixed(6),
          "-c:a",
          "pcm_s16le",
          alignedAudioPath,
        ],
        `align audio beat ${i + 1}`,
      );

      alignedVideoNames.push(alignedVideoName);
      alignedAudioNames.push(alignedAudioName);

      const beatStart = cursorSec;
      const beatEnd = cursorSec + targetDuration;
      beatTimeline.push({
        id: beat.id,
        criterion: beat.criterion,
        assertion: beat.assertion,
        status: beat.status ?? "passed",
        startSec: Number(beatStart.toFixed(3)),
        endSec: Number(beatEnd.toFixed(3)),
        timestamp: formatMmSs(beatStart),
        narration: beat.narration,
      });

      allCues.push(...buildCaptionCues(beat.narration, beatStart, rawAudioDuration));
      transcriptLines.push(`[${formatMmSs(beatStart)}] (${beat.criterion})\n${beat.narration}\n`);
      cursorSec = beatEnd;
    }

    // Write synchronized .ass (1080p burn-in), .srt, .vtt, and transcript.txt
    const assPath = path.join(resolvedOutDir, "captions.ass");
    const srtPath = path.join(resolvedOutDir, "captions.srt");
    const vttPath = path.join(resolvedOutDir, "captions.vtt");
    const transcriptPath = path.join(resolvedOutDir, "transcript.txt");

    const srtContent = allCues
      .map(
        (cue, idx) =>
          `${idx + 1}\n${formatSrtTime(cue.startSec)} --> ${formatSrtTime(cue.endSec)}\n${cue.text}\n`,
      )
      .join("\n");
    const vttContent =
      "WEBVTT\n\n" +
      allCues
        .map(
          (cue, idx) =>
            `${idx + 1}\n${formatVttTime(cue.startSec)} --> ${formatVttTime(cue.endSec)}\n${cue.text}\n`,
        )
        .join("\n");

    fs.writeFileSync(assPath, buildAssDocument(allCues), "utf8");
    fs.writeFileSync(srtPath, srtContent, "utf8");
    fs.writeFileSync(vttPath, vttContent, "utf8");
    fs.writeFileSync(transcriptPath, transcriptLines.join("\n"), "utf8");

    // Concatenate using relative filenames inside workDir so FFmpeg's default safe-path guard stays active.
    const videoListPath = path.join(workDir, "video-concat.txt");
    const audioListPath = path.join(workDir, "audio-concat.txt");
    fs.writeFileSync(
      videoListPath,
      alignedVideoNames.map((name) => `file '${name}'`).join("\n") + "\n",
      "utf8",
    );
    fs.writeFileSync(
      audioListPath,
      alignedAudioNames.map((name) => `file '${name}'`).join("\n") + "\n",
      "utf8",
    );

    const concatVideoPath = path.join(workDir, "concat-video.mp4");
    const concatAudioPath = path.join(workDir, "concat-audio.wav");
    runBinary(
      "ffmpeg",
      [
        "-y",
        "-nostats",
        "-loglevel",
        "warning",
        "-f",
        "concat",
        "-i",
        "video-concat.txt",
        "-c",
        "copy",
        concatVideoPath,
      ],
      "concat video segments",
      { cwd: workDir },
    );
    runBinary(
      "ffmpeg",
      [
        "-y",
        "-nostats",
        "-loglevel",
        "warning",
        "-f",
        "concat",
        "-i",
        "audio-concat.txt",
        "-c",
        "copy",
        concatAudioPath,
      ],
      "concat audio segments",
      { cwd: workDir },
    );

    // Final encode: run with cwd=resolvedOutDir and constant local `subtitles=captions.ass` (zero filtergraph path escaping risk).
    const finalMp4Path = path.join(resolvedOutDir, finalMp4Name);
    runBinary(
      "ffmpeg",
      [
        "-y",
        "-nostats",
        "-loglevel",
        "warning",
        "-i",
        concatVideoPath,
        "-i",
        concatAudioPath,
        "-vf",
        "subtitles=captions.ass",
        "-af",
        "loudnorm=I=-16:TP=-1.5:LRA=11,aresample=48000",
        "-c:v",
        "libx264",
        "-profile:v",
        "high",
        "-level",
        "4.1",
        "-preset",
        "medium",
        "-crf",
        "18",
        "-pix_fmt",
        "yuv420p",
        "-r",
        "30",
        "-c:a",
        "aac",
        "-b:a",
        "192k",
        "-ac",
        "2",
        "-ar",
        "48000",
        "-movflags",
        "+faststart",
        "-shortest",
        finalMp4Path,
      ],
      "final MP4 encode with burned 1080p captions and normalized narration",
      { cwd: resolvedOutDir },
    );

    return {
      finalMp4Path,
      assPath,
      srtPath,
      vttPath,
      transcriptPath,
      beatTimeline,
    };
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

/**
 * Inspects final MP4 with ffprobe + volumedetect and extracts representative beat keyframes.
 */
export function inspectEvidenceVideo(mp4Path, beatTimeline, keyframesDir) {
  fs.mkdirSync(keyframesDir, { recursive: true });
  const probe = probeMedia(mp4Path);
  const videoStream = (probe.streams ?? []).find((s) => s.codec_type === "video");
  const audioStream = (probe.streams ?? []).find((s) => s.codec_type === "audio");

  if (!videoStream) {
    throw new Error("Final MP4 is missing a video stream.");
  }
  if (!audioStream) {
    throw new Error("Final MP4 is missing an audio stream.");
  }

  const volResult = runBinary(
    "ffmpeg",
    ["-i", mp4Path, "-af", "volumedetect", "-f", "null", "-"],
    "audio volumedetect",
  );
  const { meanVolumeDb, maxVolumeDb, histogram0db, audioAudible, audioClipping } =
    parseVolumedetect(volResult.stderr);

  const keyframes = [];
  for (let i = 0; i < beatTimeline.length; i++) {
    const beat = beatTimeline[i];
    const midSec = Number(((beat.startSec + beat.endSec) / 2).toFixed(3));
    const frameFile = `beat-${String(i + 1).padStart(2, "0")}-${beat.id.replace(/[^a-zA-Z0-9_-]+/g, "-")}.png`;
    const framePath = path.join(keyframesDir, frameFile);
    runBinary(
      "ffmpeg",
      [
        "-y",
        "-nostats",
        "-loglevel",
        "warning",
        "-ss",
        String(midSec),
        "-i",
        mp4Path,
        "-frames:v",
        "1",
        framePath,
      ],
      `extract keyframe beat ${i + 1}`,
    );
    keyframes.push({
      beatId: beat.id,
      timestampSec: midSec,
      file: frameFile,
      path: framePath,
    });
  }

  const fpsParts = String(videoStream.avg_frame_rate || "30/1").split("/");
  const fps =
    fpsParts.length === 2 && Number(fpsParts[1]) > 0
      ? Math.round(Number(fpsParts[0]) / Number(fpsParts[1]))
      : Number(fpsParts[0]) || 0;

  const stat = fs.statSync(mp4Path);
  const sha256 = sha256File(mp4Path);

  return {
    codec: videoStream.codec_name,
    pixelFormat: videoStream.pix_fmt,
    width: Number(videoStream.width),
    height: Number(videoStream.height),
    fps,
    audioCodec: audioStream.codec_name,
    audioSampleRate: Number(audioStream.sample_rate),
    durationSec: Number(Number(probe.format?.duration ?? 0).toFixed(2)),
    fileSizeBytes: stat.size,
    sha256,
    meanVolumeDb,
    maxVolumeDb,
    histogram0db,
    audioAudible,
    audioClipping,
    keyframes,
  };
}
