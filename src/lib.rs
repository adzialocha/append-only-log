use ed25519_dalek::{Keypair, PublicKey, Signature};

mod crypto;

struct LogEntry {
    data: Vec<u8>,
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
        let signature = crypto::sign_data(
            &self.keypair.public,
            &self.keypair.secret,
            &data
        );

        self.entries.push(LogEntry {
            data: data.to_vec(),
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
        let has_invalid_entries = self.entries.iter().any(|entry| {
            crypto::verify_data(
                &public_key,
                &entry.data,
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
