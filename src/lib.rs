//! Simple append-only-log data structure

use std::hash::{Hash, Hasher};
use std::option;
use std::result;

use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::{Keypair, PublicKey, Signature};

mod crypto;

// Convenience function to hash value with Blake2b
fn generate_hash<H: Hash>(value: &H) -> u64 {
    let mut hasher = crypto::Blake2bHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[derive(Default, PartialEq, Eq)]
struct LogEntryContent {
    data: Vec<u8>,
    hash_previous: u64,
    sequence_number: u64,
}

impl LogEntryContent {
    // Returns a new LogEntryContent
    fn new(hash_previous: u64, data: Vec<u8>, sequence_number: u64) -> Self {
        Self {
            data,
            hash_previous,
            sequence_number,
        }
    }

    // Convert this content to bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = self.data.clone();
        result.write_u64::<BigEndian>(self.hash_previous).unwrap();
        result.write_u64::<BigEndian>(self.sequence_number).unwrap();
        result
    }
}

#[derive(PartialEq, Eq)]
struct LogEntry {
    content: LogEntryContent,
    signature: Signature,
}

impl LogEntry {
    // Returns new LogEntry instance with content and
    // signature of it.
    fn sign(content: LogEntryContent, keypair: &Keypair) -> Self {
        // Sign the content and attach it to itself
        let signature = crypto::sign_data(&keypair.public, &keypair.secret, &content.to_bytes());

        Self {
            content,
            signature: signature,
        }
    }

    // Checks if the entries where written by the owner of that key.
    fn verify(&self, public_key: &PublicKey) -> bool {
        crypto::verify_data(&public_key, &self.content.to_bytes(), &self.signature)
            .is_ok()
    }
}

impl Hash for LogEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.content.hash_previous.hash(state);
        self.content.sequence_number.hash(state);
        self.signature.to_bytes().hash(state);
    }
}

/// Append-only-log data-structure.
#[derive(Default)]
pub struct Log {
    entries: Vec<LogEntry>,
    keypair: Keypair,
}

impl Log {
    /// Returns new instance of append-only-log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            keypair: crypto::generate_keypair(),
        }
    }

    /// Add a new entry to the log with arbitrary data.
    pub fn append(&mut self, data: &[u8]) {
        // Define sequence number
        let sequence_number = self.len() + 1;

        // Generate hash of previous entry when one is given
        let mut hash_previous = 0;
        if sequence_number > 1 {
            let entry_previous = &self.entries[sequence_number - 2];
            hash_previous = generate_hash(entry_previous);
        }

        // Create content of entry and sign it
        let content = LogEntryContent::new(hash_previous, data.to_vec(), sequence_number as u64);
        let entry = LogEntry::sign(content, &self.keypair);

        // Append entry to log
        self.entries.push(entry);
    }

    /// Returns the current number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the log does not contain any entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the stored data at this position of the log.
    pub fn get(&self, index: usize) -> option::Option<Vec<u8>> {
        match self.entries.get(index) {
            Some(entry) => Some(entry.content.data.clone()),
            None => None,
        }
    }

    /// Returns the hash of an entry of the log.
    pub fn hash(&self, index: usize) -> option::Option<u64> {
        match self.entries.get(index) {
            Some(entry) => Some(generate_hash(entry)),
            None => None,
        }
    }

    /// Checks if order of all entries and theire signatures are correct.
    pub fn verify(
        &self,
        public_key: &PublicKey,
    ) -> result::Result<(), ()> {
        let mut sequence_number = 0;

        let has_invalid_entries = self.entries.iter().any(|entry| {
            let hash_previous = entry.content.hash_previous.clone();

            // Regenerate hashes pointing at the previous entries
            // and see if they are consistant with the log
            if sequence_number > 0 {
                let entry_previous = &self.entries[sequence_number - 1];
                let id_previous_check = generate_hash(entry_previous);

                if id_previous_check != hash_previous {
                    return true
                }
            }

            // Check if the entries are numbered sequentially
            sequence_number += 1;
            if sequence_number as u64 != entry.content.sequence_number {
                return true
            }

            // Verify signature, check if its invalid
            !entry.verify(&public_key)
        });

        if has_invalid_entries {
            Err(())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod log {
    use super::*;

    #[test]
    fn get() {
        let mut log = Log::new();

        assert!(log.is_empty());

        log.append(b"Hello, Test!");
        log.append(b"1, 2, 3");

        assert_eq!(log.len(), 2);
        assert_eq!(log.is_empty(), false);

        assert_eq!(log.get(0), Some(b"Hello, Test!".to_vec()));
        assert_eq!(log.get(1), Some(b"1, 2, 3".to_vec()));
        assert_eq!(log.get(2), None);
    }

    #[test]
    fn hash() {
        let mut log = Log::new();
        let mut log_same = Log::new();

        log.append(b"Test");
        log_same.append(b"Test");

        // Hashes should be different even with same contents
        // since the keypairs of the logs are different
        assert_ne!(log.hash(0).unwrap(), log_same.hash(0).unwrap());

        // Hashes should be same when content is same
        // and getting signed with the same keypair
        let keypair = crypto::generate_keypair();

        let content = LogEntryContent::new(0, vec![1, 2, 3], 1);
        let content_same = LogEntryContent::new(0, vec![1, 2, 3], 1);

        assert_eq!(
            generate_hash(&LogEntry::sign(content, &keypair)),
            generate_hash(&LogEntry::sign(content_same, &keypair)),
        );
    }

    #[test]
    fn verify() {
        let mut log = Log::new();
        let public_key = log.keypair.public;
        let wrong_keypair = crypto::generate_keypair();

        log.append(b"Test");
        log.append(b"1, 2, 3");

        log.verify(&public_key).unwrap();
        log.verify(&wrong_keypair.public).unwrap_err();
    }
}
