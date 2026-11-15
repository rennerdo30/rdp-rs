//! Helper updates (protocol 1.2, RDP-61): a paired Remora sends the helper
//! a newer `remora-agent.exe`. Remora took it from its own GitHub release
//! and checked it against that release's `SHA256SUMS.txt`; here the helper
//! checks the size and BLAKE3 hash Remora stated, and the encrypted, paired
//! channel carries it. Owner decision 2026-11-15: pairing and checksum, no
//! release signing key.
//!
//! Wire: `UpdateBegin` (version, size, hash), `UpdateData` chunks in order,
//! `UpdateEnd`, all with the begin's `request_id`; the helper answers
//! `UpdateResult` and, once installed, restarts.

use crate::msg::{MAX_VERSION_TEXT, Message};

/// The largest helper accepted (the release build is under 2 MiB).
pub const MAX_HELPER_SIZE: u64 = 32 << 20;
/// Bytes per `UpdateData`.
pub const CHUNK: usize = 64 << 10;

/// BLAKE3 of the update, as `UpdateBegin` states it.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// The messages that send `exe` as helper `version` (Remora's side).
pub fn messages(version: &str, exe: &[u8]) -> Vec<Message> {
    let mut v = vec![Message::UpdateBegin {
        version: crate::wire::truncate(version, MAX_VERSION_TEXT).to_string(),
        size: exe.len() as u64,
        hash: hash(exe),
    }];
    let mut offset = 0u64;
    for chunk in exe.chunks(CHUNK) {
        v.push(Message::UpdateData {
            offset,
            data: chunk.to_vec(),
        });
        offset += chunk.len() as u64;
    }
    v.push(Message::UpdateEnd);
    v
}

/// The helper's side: collects one update and checks it.
#[derive(Debug)]
pub struct Receiver {
    version: String,
    size: u64,
    hash: [u8; 32],
    data: Vec<u8>,
}

impl Receiver {
    /// An update of `size` bytes as `version`; refused when the size is
    /// out of bounds or it is the version already running.
    pub fn begin(
        version: &str,
        size: u64,
        hash: [u8; 32],
        running: &str,
    ) -> Result<Receiver, &'static str> {
        if size == 0 || size > MAX_HELPER_SIZE {
            return Err("size out of bounds");
        }
        if version.is_empty() || version == running {
            return Err("not another version");
        }
        Ok(Receiver {
            version: version.to_string(),
            size,
            hash,
            data: Vec::new(),
        })
    }

    /// The next chunk: it must continue exactly where the last one ended.
    pub fn data(&mut self, offset: u64, bytes: &[u8]) -> Result<(), &'static str> {
        if offset != self.data.len() as u64 {
            return Err("chunk out of order");
        }
        if offset + bytes.len() as u64 > self.size {
            return Err("more bytes than announced");
        }
        self.data.extend_from_slice(bytes);
        Ok(())
    }

    /// All of it, when complete and matching the announced hash.
    pub fn finish(self) -> Result<(String, Vec<u8>), &'static str> {
        if self.data.len() as u64 != self.size {
            return Err("fewer bytes than announced");
        }
        if hash(&self.data) != self.hash {
            return Err("hash mismatch");
        }
        Ok((self.version, self.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive(msgs: &[Message], running: &str) -> Result<(String, Vec<u8>), &'static str> {
        let mut r = None;
        for m in msgs {
            match m {
                Message::UpdateBegin {
                    version,
                    size,
                    hash,
                } => r = Some(Receiver::begin(version, *size, *hash, running)?),
                Message::UpdateData { offset, data } => r.as_mut().unwrap().data(*offset, data)?,
                Message::UpdateEnd => return r.take().unwrap().finish(),
                _ => unreachable!(),
            }
        }
        Err("no end")
    }

    #[test]
    fn an_update_arrives_whole_and_checked() {
        let exe: Vec<u8> = (0..(CHUNK * 2 + 123)).map(|i| (i * 7) as u8).collect();
        let msgs = messages("0.1.0-beta.9", &exe);
        assert_eq!(msgs.len(), 1 + 3 + 1);
        let (v, got) = receive(&msgs, "0.1.0-beta.8").unwrap();
        assert_eq!((v.as_str(), got), ("0.1.0-beta.9", exe.clone()));
        // The same version as the running one: refused.
        assert!(receive(&msgs, "0.1.0-beta.9").is_err());
        // A changed byte, a missing chunk, a chunk out of order: refused.
        let mut bad = msgs.clone();
        if let Message::UpdateData { data, .. } = &mut bad[2] {
            data[0] ^= 1;
        }
        assert_eq!(receive(&bad, "x"), Err("hash mismatch"));
        let mut short = msgs.clone();
        short.remove(3);
        assert!(receive(&short, "x").is_err());
        let mut swapped = msgs.clone();
        swapped.swap(1, 2);
        assert_eq!(receive(&swapped, "x"), Err("chunk out of order"));
    }

    #[test]
    fn sizes_are_bounded() {
        assert!(Receiver::begin("2", 0, [0; 32], "1").is_err());
        assert!(Receiver::begin("2", MAX_HELPER_SIZE + 1, [0; 32], "1").is_err());
        let mut r = Receiver::begin("2", 4, [0; 32], "1").unwrap();
        assert_eq!(
            r.data(0, &[1, 2, 3, 4, 5]),
            Err("more bytes than announced")
        );
    }
}
