use forceone_core::vault;

fn main() {
    println!("AI Infinity Force One — core engine starting up.");

    let plaintext = b"forceone vault online";
    let passphrase = b"changeme";

    match vault::crypto::encrypt(plaintext, passphrase) {
        Ok(envelope) => match vault::crypto::decrypt(&envelope, passphrase) {
            Ok(decrypted) if decrypted == plaintext => {
                println!("vault::crypto self-test passed.");
            }
            Ok(_) => eprintln!("vault::crypto self-test FAILED: mismatch."),
            Err(e) => eprintln!("vault::crypto decrypt error: {e}"),
        },
        Err(e) => eprintln!("vault::crypto encrypt error: {e}"),
    }
}
