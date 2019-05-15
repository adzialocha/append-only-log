use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
use rand::rngs::OsRng;
use sha2::Sha512;

pub fn generate_keypair() -> Keypair {
  let mut cspring: OsRng = OsRng::new().unwrap();

  Keypair::generate::<Sha512, _>(&mut cspring)
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
        return Ok(())
    }

    Err(())
}

#[test]
fn can_verify_signed_data() {
    let keypair = generate_keypair();
    let data = b"Hello, Test!";
    let signature = sign_data(&keypair.public, &keypair.secret, data);

    verify_data(&keypair.public, data, &signature).unwrap();
    verify_data(&keypair.public, b"Wrong Payload", &signature).unwrap_err();
}
