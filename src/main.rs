use ai_infinity_force_one::{Action, Principal, Vault};

fn main() {
    let mut vault = Vault::new();

    let alice = Principal::new("alice");
    let mallory = Principal::new("mallory");

    // Zero-trust: mallory gets nothing unless explicitly granted.
    vault.grant(alice.clone(), &[Action::Read, Action::Write]);

    let passphrase = "correct horse battery staple";
    let secret = b"the launch codes are 1234";

    let blob = vault
        .put_secret(&alice, passphrase, "launch-codes", secret)
        .expect("alice is authorized to write");

    let recovered = vault
        .get_secret(&alice, passphrase, "launch-codes", &blob)
        .expect("alice is authorized to read");
    println!("alice recovered: {}", String::from_utf8_lossy(&recovered));

    // Mallory has no grant — this is denied and still logged.
    match vault.get_secret(&mallory, passphrase, "launch-codes", &blob) {
        Ok(_) => println!("mallory should NOT have been able to read this"),
        Err(_) => println!("mallory was denied, as expected"),
    }

    println!("\n--- audit trail ---");
    for event in vault.audit_log().events() {
        println!(
            "{} | {:<8} action={:<6?} resource={:<15} allowed={}",
            event.timestamp.to_rfc3339(),
            event.principal.id,
            event.action,
            event.resource,
            event.allowed
        );
    }

    println!(
        "\naudit chain intact: {}",
        vault.audit_log().verify_integrity()
    );
}
