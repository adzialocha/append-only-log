use ed25519_dalek::{Keypair, PublicKey, Signature};

mod crypto;

const HASH_LENGTH: usize = 64;

fn entry_as_bytes(
    backlink: &Option<Vec<u8>>,
    data: &[u8],
    sequence_number: usize,
) -> Vec<u8> {
    let mut bytes = Vec::new();

    match backlink {
        Some(link) => {
            bytes.append(&mut link.clone())
        },
        None => {},
    }

    bytes.append(&mut data.to_vec());
    bytes.append(&mut sequence_number.to_be_bytes().to_vec());

    bytes
}

fn hash_entry(public_key: &PublicKey, entry: &LogEntry) -> Vec<u8> {
    let bytes = entry_as_bytes(
        &entry.backlink,
        &entry.data,
        entry.sequence_number
    );

    crypto::hash_data(public_key.as_bytes(), &bytes, HASH_LENGTH).as_bytes().to_vec()
}

struct LogEntry {
    backlink: Option<Vec<u8>>,
    data: Vec<u8>,
    sequence_number: usize,
    signature: Signature,
}

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

        let backlink = match sequence_number {
            1 => None,
            _ => {
                let previous_entry = self.entries.get( sequence_number - 2).unwrap();

                let hashed_entry = hash_entry(
                    &self.keypair.public,
                    previous_entry
                );

                Some(hashed_entry)
            },
        };

        let encoded = entry_as_bytes(
            &backlink,
            &data,
            sequence_number,
        );

        let signature = crypto::sign_data(
            &self.keypair.public,
            &self.keypair.secret,
            &encoded,
        );

        self.entries.push(LogEntry {
            backlink,
            data: data.to_vec(),
            sequence_number,
            signature,
        });
    }

    pub fn len(&self) -> usize {
        self.entries.len()
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
            let backlink = entry.backlink.clone();

            let encoded = entry_as_bytes(
                &entry.backlink,
                &entry.data,
                entry.sequence_number,
            );

            // Verify backlink
            if sequence_number > 0 {
                let previous_entry = self.entries.get(sequence_number - 1).unwrap();

                let hashed_entry = hash_entry(
                    &self.keypair.public,
                    previous_entry
                );

                if backlink.unwrap() != hashed_entry {
                    return true
                }
            }

            // Verify sequence number
            sequence_number += 1;
            if sequence_number != entry.sequence_number {
                return true
            }

            // Verify signature
            crypto::verify_data(
                &public_key,
                &encoded,
                &entry.signature
            ).is_err()
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

        log.append(b"Hello, Test!");
        log.append(b"1, 2, 3");

        assert_eq!(log.len(), 2);

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
