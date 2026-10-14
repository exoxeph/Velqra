// SPDX-License-Identifier: GPL-3.0-only
//! Native-messaging style framing: a 4-byte native-endian length, then that many bytes of UTF-8 JSON.
//! The decoder rejects an oversize or empty header before it allocates anything for the payload.

use thiserror::Error;

/// Largest envelope the core accepts from the browser side (spec 5.2).
pub const MAX_ENVELOPE: usize = 256 * 1024;
/// Largest pre-session (handshake) frame.
pub const MAX_HANDSHAKE: usize = 1024;
/// Chrome's limit for a message from the host to the browser.
pub const MAX_TO_BROWSER: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FrameError {
    #[error("frame too large")]
    TooLarge,
    #[error("empty frame")]
    Zero,
    #[error("truncated frame")]
    Truncated,
}

pub struct FrameDecoder {
    max: usize,
    header: [u8; 4],
    header_len: usize,
    /// Payload length of the frame being read; 0 while a header is being read.
    want: usize,
    payload: Vec<u8>,
    failed: Option<FrameError>,
}

impl FrameDecoder {
    pub fn new(max: usize) -> Self {
        Self {
            max,
            header: [0; 4],
            header_len: 0,
            want: 0,
            payload: Vec::new(),
            failed: None,
        }
    }

    fn fail(&mut self, e: FrameError) -> FrameError {
        self.failed = Some(e);
        self.payload = Vec::new();
        self.want = 0;
        self.header_len = 0;
        e
    }

    /// Feeds bytes and returns every complete frame. After an error the decoder stays failed.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if self.want == 0 {
                let take = (4 - self.header_len).min(bytes.len() - i);
                self.header[self.header_len..self.header_len + take]
                    .copy_from_slice(&bytes[i..i + take]);
                self.header_len += take;
                i += take;
                if self.header_len == 4 {
                    let n = u32::from_ne_bytes(self.header) as usize;
                    self.header_len = 0;
                    if n == 0 {
                        return Err(self.fail(FrameError::Zero));
                    }
                    // the size is judged from the header alone, before any payload memory is reserved
                    if n > self.max {
                        return Err(self.fail(FrameError::TooLarge));
                    }
                    self.want = n;
                    self.payload = Vec::with_capacity(n);
                }
            } else {
                let take = (self.want - self.payload.len()).min(bytes.len() - i);
                self.payload.extend_from_slice(&bytes[i..i + take]);
                i += take;
                if self.payload.len() == self.want {
                    out.push(std::mem::take(&mut self.payload));
                    self.want = 0;
                }
            }
        }
        Ok(out)
    }

    /// Changes the size limit for frames whose header has not been read yet (a connection starts
    /// at the small handshake limit and is widened only after authentication). A frame already
    /// in progress that exceeds the new limit fails the decoder.
    pub fn set_max(&mut self, max: usize) {
        self.max = max;
        if self.want > max && self.failed.is_none() {
            self.fail(FrameError::TooLarge);
        }
    }

    /// Ok only when the stream ended exactly on a frame boundary.
    pub fn finish(&self) -> Result<(), FrameError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.want != 0 || self.header_len != 0 {
            return Err(FrameError::Truncated);
        }
        Ok(())
    }

    /// Bytes currently reserved for a partial payload (tests use it to prove memory stays bounded).
    pub fn buffered_capacity(&self) -> usize {
        self.payload.capacity()
    }
}

pub fn encode_frame(payload: &[u8], max: usize) -> Result<Vec<u8>, FrameError> {
    if payload.is_empty() {
        return Err(FrameError::Zero);
    }
    if payload.len() > max {
        return Err(FrameError::TooLarge);
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_ne_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn encode_round_trips_and_enforces_limits() {
        let f = encode_frame(b"{}", 10).unwrap();
        assert_eq!(f, frame(b"{}"));
        assert_eq!(encode_frame(b"", 10), Err(FrameError::Zero));
        assert_eq!(encode_frame(&[b'a'; 11], 10), Err(FrameError::TooLarge));
        assert!(encode_frame(&[b'a'; 10], 10).is_ok());
    }

    #[test]
    fn header_values_zero_max_over_max_and_u32_max() {
        let max = 64;
        let mut d = FrameDecoder::new(max);
        assert_eq!(d.feed(&0u32.to_ne_bytes()), Err(FrameError::Zero));
        let mut d = FrameDecoder::new(max);
        assert!(d.feed(&(max as u32).to_ne_bytes()).unwrap().is_empty());
        assert!(d.buffered_capacity() <= max + 8);
        let mut d = FrameDecoder::new(max);
        assert_eq!(
            d.feed(&((max + 1) as u32).to_ne_bytes()),
            Err(FrameError::TooLarge)
        );
        let mut d = FrameDecoder::new(max);
        assert_eq!(d.feed(&u32::MAX.to_ne_bytes()), Err(FrameError::TooLarge));
        assert!(
            d.buffered_capacity() <= 8,
            "allocated for an oversize frame"
        );
    }

    #[test]
    fn once_failed_the_decoder_stays_failed() {
        let mut d = FrameDecoder::new(8);
        assert_eq!(d.feed(&u32::MAX.to_ne_bytes()), Err(FrameError::TooLarge));
        assert_eq!(d.feed(&frame(b"ok")), Err(FrameError::TooLarge));
        assert_eq!(d.finish(), Err(FrameError::TooLarge));
    }

    #[test]
    fn two_frames_in_one_read_and_split_at_every_offset() {
        let mut stream = frame(b"{\"a\":1}");
        stream.extend(frame(b"{\"b\":2}"));
        let mut one = FrameDecoder::new(64);
        let all = one.feed(&stream).unwrap();
        assert_eq!(all, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
        assert!(one.finish().is_ok());
        for cut in 0..=stream.len() {
            let mut d = FrameDecoder::new(64);
            let mut got = d.feed(&stream[..cut]).unwrap();
            got.extend(d.feed(&stream[cut..]).unwrap());
            assert_eq!(got, all, "split at {cut}");
            assert!(d.finish().is_ok());
        }
    }

    #[test]
    fn truncation_is_reported_everywhere_except_on_a_frame_boundary() {
        let mut stream = frame(b"{\"a\":1}");
        let boundary = stream.len();
        stream.extend(frame(b"{\"b\":2}"));
        for cut in 0..=stream.len() {
            let mut d = FrameDecoder::new(64);
            d.feed(&stream[..cut]).unwrap();
            let at_boundary = cut == 0 || cut == boundary || cut == stream.len();
            assert_eq!(d.finish().is_ok(), at_boundary, "cut {cut}");
        }
    }

    #[test]
    fn invalid_utf8_is_passed_through_not_a_panic() {
        let mut d = FrameDecoder::new(64);
        let got = d.feed(&frame(&[0xff, 0xfe, 0x00])).unwrap();
        assert_eq!(got, vec![vec![0xff, 0xfe, 0x00]]);
    }

    #[test]
    fn a_stream_of_many_frames_never_grows_the_buffer_past_the_limit() {
        let mut d = FrameDecoder::new(256);
        for i in 0..2000u32 {
            let payload = vec![b'x'; 1 + (i as usize % 200)];
            d.feed(&frame(&payload)).unwrap();
            assert!(d.buffered_capacity() <= 256 + 8);
        }
    }

    proptest! {
        #[test]
        fn arbitrary_chunking_equals_one_shot(
            payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..300), 1..8),
            chunk in 1usize..50,
        ) {
            let mut stream = Vec::new();
            for p in &payloads { stream.extend(frame(p)); }
            let mut d = FrameDecoder::new(300);
            let mut got = Vec::new();
            for c in stream.chunks(chunk) { got.extend(d.feed(c).unwrap()); }
            prop_assert_eq!(got, payloads);
            prop_assert!(d.finish().is_ok());
        }
    }

    #[test]
    fn the_limit_can_be_widened_after_authentication_but_not_used_before() {
        let mut d = FrameDecoder::new(8);
        assert_eq!(d.feed(&frame(&[b'x'; 20])), Err(FrameError::TooLarge));
        let mut d = FrameDecoder::new(8);
        assert!(d.feed(&frame(b"abc")).is_ok());
        d.set_max(64);
        assert_eq!(d.feed(&frame(&[b'x'; 20])).unwrap().len(), 1);
        d.set_max(4);
        assert_eq!(d.feed(&frame(&[b'x'; 20])), Err(FrameError::TooLarge));
    }
}
