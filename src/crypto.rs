use blake2_rfc::blake2b::{blake2b, Blake2bResult};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
use rand::rngs::OsRng;
use sha2::Sha512;

pub fn generate_keypair() -> Keypair {
  let mut cspring: OsRng = OsRng::new().unwrap();

  Keypair::generate::<Sha512, _>(&mut cspring)
}

pub fn hash_data(
    public_key: &[u8],
    data: &[u8],
    length: usize
) -> Blake2bResult {
    blake2b(length, public_key, data)
}

pub fn sign_data(
  public_key: &PublicKey,
  secret_key: &SecretKey,
  data: &[u8],
) -> Signature {
  secret_key.expand::<Sha512>().sign::<Sha512>(data, public_key)
}

pub fn verify_data(
  public_key: &PublicKey,
  data: &[u8],
  signature: &Signature,
) -> std::result::Result<(), ()> {
    if public_key.verify::<Sha512>(data, signature).is_ok() {
        Ok(())
    } else {
        Err(())
    }
}

#[test]
fn can_hash_data() {
    let length = 16;
    let data = b"Hello, Test!";
    let hash = hash_data(&[], data, length);
    let wrong_hash = hash_data(&[1, 2, 3], data, length);

    assert_eq!(hash.len(), length);
    assert_eq!(hash.as_bytes(), &[103, 145, 101, 12, 173, 108, 196, 62, 21, 86, 47, 194, 99, 83, 53, 112]);
    assert_ne!(hash.as_bytes(), wrong_hash.as_bytes());
}

#[test]
fn can_verify_signed_data() {
    let keypair = generate_keypair();
    let data = b"Hello, Test!";
    let signature = sign_data(&keypair.public, &keypair.secret, data);

    verify_data(&keypair.public, data, &signature).unwrap();
    verify_data(&keypair.public, b"Wrong Payload", &signature).unwrap_err();
}
