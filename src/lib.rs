use std::fmt;
use std::hash::{Hash, Hasher};

use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::{Keypair, PublicKey, Signature};

mod crypto;

fn generate_hash<H: Hash>(public_key: &PublicKey, value: &H) -> u64 {
    let mut hasher = crypto::Blake2bHasher::new(&public_key);
    value.hash(&mut hasher);
    hasher.finish()
}

#[derive(Default, PartialEq, Eq)]
struct LogEntry {
    data: Vec<u8>,
    id: u64,
    id_previous: u64,
    sequence_number: u64,
    signature: Option<Signature>,
}

impl LogEntry {
    fn new(id_previous: u64, data: Vec<u8>, sequence_number: u64) -> Self {
        Self {
            data,
            id: 0,
            id_previous,
            sequence_number,
            signature: None,
        }
    }

    /// Returns the entry as bytes, excluding the signature
    fn as_bytes(&self) -> Vec<u8> {
        let mut result = self.data.clone();
        result.write_u64::<BigEndian>(self.id).unwrap();
        result.write_u64::<BigEndian>(self.id_previous).unwrap();
        result.write_u64::<BigEndian>(self.sequence_number).unwrap();
        result
    }

    /// Generates a hash as an entry identifier and a signature
    fn sign(&mut self, keypair: &Keypair) {
        // Hash the entry itself and use this as its id
        self.id = generate_hash(&keypair.public, self);

        // Sign the entry and attach it to itself
        let signature = crypto::sign_data(&keypair.public, &keypair.secret, &self.as_bytes());
        self.signature = Some(signature);
    }

    /// Checks if the entries where written by the owner of that key
    fn verify(&self, public_key: &PublicKey) -> bool {
        match self.signature {
            None => false,
            Some(signature) => {
                crypto::verify_data(&public_key, &self.as_bytes(), &signature)
                    .is_err()
            }
        }
    }
}

impl Hash for LogEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id_previous.hash(state);
        self.sequence_number.hash(state);
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "LogEntry(id={}, id_previous={}, seq_num={}, data={:?})",
            self.id, self.id_previous, self.sequence_number, self.data
        )
    }
}

#[derive(Default)]
pub struct Log {
    entries: Vec<LogEntry>,
    keypair: Keypair,
}

impl Log {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            keypair: crypto::generate_keypair(),
        }
    }

    pub fn append(&mut self, data: &[u8]) {
        let sequence_number = self.len() + 1;
        let mut id_previous = 0;

        if sequence_number > 1 {
            let entry_previous = &self.entries[sequence_number - 2];
            id_previous = generate_hash(&self.keypair.public, entry_previous);
        }

        let mut entry_new = LogEntry::new(id_previous, data.to_vec(), sequence_number as u64);
        entry_new.sign(&self.keypair);

        self.entries.push(entry_new);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, index: usize) -> std::option::Option<Vec<u8>> {
        match self.entries.get(index) {
            Some(entry) => Some(entry.data.clone()),
            None => None,
        }
    }

    pub fn verify(
        &self,
        public_key: &PublicKey,
    ) -> std::result::Result<(), ()> {
        let mut sequence_number = 0;

        let has_invalid_entries = self.entries.iter().any(|entry| {
            let id_previous = entry.id_previous.clone();

            // Regenerate hashes pointing at the previous entries
            // and see if they are consistant with the log
            if sequence_number > 0 {
                let entry_previous = &self.entries[sequence_number - 1];

                let key_previous_check = generate_hash(&public_key, entry_previous);

                if key_previous_check != id_previous {
                    return true
                }
            }

            // Check if the entries are numbered sequentially
            sequence_number += 1;
            if sequence_number as u64 != entry.sequence_number {
                return true
            }

            // Verify signature
            entry.verify(&public_key)
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
