//! Audio module -- voice note capture, Opus encoding, chunking for transport.
//!
//! MVP: voice note mode only (record -> encode -> chunk -> send as file attachment).
//! Phase 2: experimental near-real-time chunked audio stream.

use crate::models::{AudioChunk, VoiceNote};
use anyhow::Result;
use chrono::Utc;

/// Target bitrate for voice notes: 16kbps mono.
pub const VOICE_NOTE_BITRATE: u32 = 16_000;
/// Sample rate for voice notes.
pub const VOICE_NOTE_SAMPLE_RATE: u32 = 16_000;
/// Chunk duration in milliseconds.
pub const CHUNK_DURATION_MS: u32 = 2_000;
/// Approximate bytes per chunk at 16kbps: 2s * 16kbps / 8 = 4000 bytes.
pub const CHUNK_RAW_SIZE: usize = 4_000;
/// Encrypted chunk overhead (nonce + tag + fingerprint).
pub const CHUNK_OVERHEAD: usize = 24 + 16 + 8;

/// Voice note builder -- accumulates audio data and produces chunks.
pub struct VoiceNoteBuilder {
    note_id: [u8; 32],
    raw_frames: Vec<u8>,
    sample_rate: u32,
    started_at: chrono::DateTime<Utc>,
}

impl VoiceNoteBuilder {
    pub fn new() -> Self {
        let mut note_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut note_id);
        Self {
            note_id,
            raw_frames: Vec::new(),
            sample_rate: VOICE_NOTE_SAMPLE_RATE,
            started_at: Utc::now(),
        }
    }

    /// Append raw PCM audio data (16-bit mono, 16kHz).
    /// In production this would come from cpal audio input callback.
    pub fn append_pcm(&mut self, data: &[u8]) {
        self.raw_frames.extend_from_slice(data);
    }

    /// Finalize the recording and produce a VoiceNote + chunks.
    /// Opus encoding happens here (placeholder: pass-through).
    pub fn finalize(self, sender_key: &[u8]) -> Result<(VoiceNote, Vec<AudioChunk>)> {
        // In production: encode raw_frames with audiopus Encoder
        // Placeholder: use raw data as "encoded" for scaffolding
        let encoded = self.raw_frames;

        let duration_ms = (encoded.len() as u32 * 8) / (VOICE_NOTE_BITRATE / 1000);
        let chunk_count = (encoded.len() + CHUNK_RAW_SIZE - 1) / CHUNK_RAW_SIZE;

        let note = VoiceNote {
            note_id: self.note_id,
            duration_ms,
            sample_rate: self.sample_rate,
            codec: "opus".to_string(),
            chunk_count: chunk_count as u32,
            total_size: encoded.len() as u64,
            sender_key: sender_key.to_vec(),
            timestamp: self.started_at,
        };

        let chunks: Vec<AudioChunk> = encoded
            .chunks(CHUNK_RAW_SIZE)
            .enumerate()
            .map(|(i, data)| {
                let chunk_duration = if i == chunk_count - 1 {
                    // last chunk may be shorter
                    ((data.len() as u32) * 8) / (VOICE_NOTE_BITRATE / 1000)
                } else {
                    CHUNK_DURATION_MS
                };
                AudioChunk {
                    note_id: self.note_id,
                    chunk_index: i as u32,
                    data: data.to_vec(),
                    duration_ms: chunk_duration,
                }
            })
            .collect();

        Ok((note, chunks))
    }
}

/// Bandwidth and quality parameters for live audio (Phase 2).
pub struct LiveAudioConfig {
    /// Opus frame duration in ms (20ms standard).
    pub frame_duration_ms: u32,
    /// Frames bundled per network packet.
    pub frames_per_packet: u32,
    /// Target bitrate in bps.
    pub bitrate: u32,
    /// Jitter buffer depth in ms.
    pub jitter_buffer_ms: u32,
    /// Max acceptable RTT before fallback to voice notes.
    pub max_rtt_ms: u32,
    /// Max acceptable packet loss rate before fallback.
    pub max_loss_pct: f32,
}

impl Default for LiveAudioConfig {
    fn default() -> Self {
        Self {
            frame_duration_ms: 20,
            frames_per_packet: 5,
            bitrate: 16_000,
            jitter_buffer_ms: 80,
            max_rtt_ms: 500,
            max_loss_pct: 0.10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voice_note_builder() {
        let mut builder = VoiceNoteBuilder::new();
        // Simulate 4 seconds of audio at 16kbps = 8000 bytes
        let fake_audio = vec![0u8; 8000];
        builder.append_pcm(&fake_audio);

        let (note, chunks) = builder.finalize(&[1u8; 32]).unwrap();
        assert_eq!(note.codec, "opus");
        assert_eq!(chunks.len(), 2); // 8000 / 4000 = 2 chunks
        assert_eq!(note.chunk_count, 2);
    }
}
