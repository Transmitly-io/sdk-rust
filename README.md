# Transmitly Rust SDK

Rust client for the Transmitly API.

```toml
[dependencies]
transmitly = { path = "sdk/rust" }
serde_json = "1"
```

```rust
use transmitly::{Client, EmailMessage};

let tx = Client::new(std::env::var("TRANSMITLY_API_KEY")?);

let accepted = tx.send_email(
    &EmailMessage::new(
        "Notify <notify@mail.acme.com>",
        vec!["ada@example.net".to_string()],
        "Your workspace is ready",
    )
    .html("<p>Welcome.</p>")
    .tags([("flow".to_string(), "onboarding".to_string())].into()),
)?;
```

`send_email` generates an idempotency key. Use `send_email_with_idempotency` to
control it yourself; retries with the same key return the original message.

## Resources

```rust
tx.get_email(message_id)?;
tx.list_messages(&[("status", "bounced"), ("limit", "20")])?;
tx.deliveries(message_id)?;
tx.list_domains()?;
tx.create_domain("mail.acme.com")?;
tx.verify_domain(domain_id)?;
tx.list_suppressions()?;
tx.add_suppression(serde_json::json!({
    "email": "bounce@example.net",
    "reason": "manual"
}))?;
tx.list_webhooks()?;
tx.create_webhook(serde_json::json!({
    "url": "https://api.acme.com/hooks",
    "events": ["email.delivered_to_mx"]
}))?;
tx.inbound_routes()?;
tx.usage()?;
tx.events(&[("limit", "50")])?;
tx.health()?;
```

Management resources return `serde_json::Value` so new fields do not require an
SDK release. Non-2xx responses return `Error::Api` with `status`, `code`,
`message` and `details`.

## Attachments and scheduling

```rust
let attachment = transmitly::Attachment::from_file("invoice.pdf")?;

tx.send_email(
    &EmailMessage::new(
        "Notify <notify@mail.acme.com>",
        vec!["ada@example.net".to_string()],
        "November invoice",
    )
    .html("<p>Attached.</p>")
    .schedule("in 2 hours")
    .attachments(vec![attachment]),
)?;
```

## Axum webhook

```rust
async fn webhook(headers: HeaderMap, body: String) -> StatusCode {
    let signature = headers
        .get("Transmitly-Signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if !transmitly::verify_webhook(&body, signature, &std::env::var("TRANSMITLY_WEBHOOK_SECRET").unwrap()) {
        return StatusCode::BAD_REQUEST;
    }

    // Deserialize and handle only after the signature passes.
    StatusCode::OK
}
```

Domain, webhook and inbound management require an API key with the `admin`
scope.

```bash
cargo test
cargo package
```
