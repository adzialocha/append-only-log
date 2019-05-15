use ed25519_dalek::{Keypair, Signature};

mod crypto;

pub struct LogEntry {
    data: Vec<u8>,
    signature: Signature,
}

pub struct Log {
    entries: Vec<LogEntry>,
    keypair: Keypair,
    length: usize,
}

impl Log {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            keypair: crypto::generate_keypair(),
            length: 0,
        }
    }

    pub fn add(&mut self, data: &[u8]) {
        let signature = crypto::sign_data(
            &self.keypair.public,
            &self.keypair.secret,
            &data,
        );

        self.entries.push(LogEntry {
            data: data.to_vec(),
            signature,
        });

        self.length += 1;
    }

    pub fn len(self) -> usize {
        self.length
    }
}

#[test]
fn add() {
    let mut log = Log::new();

    log.add(b"Test");
    log.add(b"Hello");

    assert_eq!(log.len(), 2);
}
