//! Dependency-light Rust client for the Transmitly email API.
//!
//! ```no_run
//! use transmitly::{Client, EmailMessage};
//!
//! let tx = Client::new(std::env::var("TRANSMITLY_API_KEY").unwrap());
//! let accepted = tx.send_email(
//!     &EmailMessage::new(
//!         "Notify <notify@mail.acme.com>",
//!         vec!["ada@example.net".to_string()],
//!         "Your workspace is ready",
//!     )
//!     .html("<p>Welcome.</p>"),
//! )?;
//! println!("{}", accepted.id);
//! # Ok::<(), transmitly::Error>(())
//! ```

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::hash::{BuildHasher, Hasher};

pub const DEFAULT_BASE_URL: &str = "https://transmitly.io";

/// A non-2xx response or a transport failure.
#[derive(Debug)]
pub enum Error {
    Api {
        status: u16,
        code: String,
        message: String,
        details: Option<Value>,
    },
    Transport(String),
    Decode(String),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Api { message, code, .. } if !code.is_empty() => {
                write!(f, "{message} ({code})")
            }
            Error::Api { message, .. } => write!(f, "{message}"),
            Error::Transport(message) | Error::Decode(message) | Error::Invalid(message) => {
                write!(f, "{message}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// A file attached to a message. Use base64 content or a public HTTPS path.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Attachment {
    pub filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
}

impl Attachment {
    pub fn from_file(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        use base64::Engine;
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        Ok(Self {
            filename: path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("attachment")
                .to_string(),
            content: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            path: None,
            content_type: None,
            content_id: None,
        })
    }
}

/// The message payload for `POST /v1/emails`.
#[derive(Debug, Clone, Serialize)]
pub struct EmailMessage {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_data: Option<std::collections::BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bcc: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<Attachment>>,
}

impl EmailMessage {
    pub fn new(from: impl Into<String>, to: Vec<String>, subject: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to,
            subject: subject.into(),
            html: None,
            text: None,
            reply_to: None,
            stream: None,
            tags: None,
            headers: None,
            template_id: None,
            template_data: None,
            test_mode: None,
            cc: None,
            bcc: None,
            scheduled_at: None,
            topic: None,
            attachments: None,
        }
    }

    pub fn html(mut self, value: impl Into<String>) -> Self {
        self.html = Some(value.into());
        self
    }

    pub fn text(mut self, value: impl Into<String>) -> Self {
        self.text = Some(value.into());
        self
    }

    pub fn reply_to(mut self, value: impl Into<String>) -> Self {
        self.reply_to = Some(value.into());
        self
    }

    pub fn stream(mut self, value: impl Into<String>) -> Self {
        self.stream = Some(value.into());
        self
    }

    pub fn topic(mut self, value: impl Into<String>) -> Self {
        self.topic = Some(value.into());
        self
    }

    pub fn schedule(mut self, value: impl Into<String>) -> Self {
        self.scheduled_at = Some(value.into());
        self
    }

    pub fn test_mode(mut self, value: bool) -> Self {
        self.test_mode = Some(value);
        self
    }

    pub fn cc(mut self, value: Vec<String>) -> Self {
        self.cc = Some(value);
        self
    }

    pub fn bcc(mut self, value: Vec<String>) -> Self {
        self.bcc = Some(value);
        self
    }

    pub fn tags(mut self, value: std::collections::BTreeMap<String, String>) -> Self {
        self.tags = Some(value);
        self
    }

    pub fn attachments(mut self, value: Vec<Attachment>) -> Self {
        self.attachments = Some(value);
        self
    }
}

/// The accepted message returned by `POST /v1/emails`.
#[derive(Debug, Clone, Deserialize)]
pub struct EmailAccepted {
    pub id: String,
    pub status: String,
    pub recipients: u32,
    pub warning: Option<String>,
    pub test_mode: Option<bool>,
}

/// Dependency-light client for the Transmitly email API.
#[derive(Clone)]
pub struct Client {
    api_key: String,
    base_url: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_base_url(api_key, DEFAULT_BASE_URL)
    }

    pub fn with_base_url(api_key: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(15))
                .build(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn send_email(&self, message: &EmailMessage) -> Result<EmailAccepted, Error> {
        self.send_email_with_idempotency(message, None)
    }

    pub fn send_email_with_idempotency(
        &self,
        message: &EmailMessage,
        idempotency_key: Option<&str>,
    ) -> Result<EmailAccepted, Error> {
        if message.from.trim().is_empty() {
            return Err(Error::Invalid("from is required".into()));
        }
        if message.to.is_empty() {
            return Err(Error::Invalid("to is required".into()));
        }
        if message.subject.trim().is_empty() {
            return Err(Error::Invalid("subject is required".into()));
        }
        if message.html.is_none() && message.text.is_none() && message.template_id.is_none() {
            return Err(Error::Invalid("html, text or template_id is required".into()));
        }

        let key = idempotency_key
            .map(ToString::to_string)
            .unwrap_or_else(new_idempotency_key);
        let payload = self.request(
            "POST",
            "/v1/emails",
            Some(serde_json::to_value(message).map_err(|e| Error::Decode(e.to_string()))?),
            &[],
            &[("Idempotency-Key", key.as_str())],
        )?;
        serde_json::from_value(payload).map_err(|e| Error::Decode(e.to_string()))
    }

    pub fn get_email(&self, id: &str) -> Result<Value, Error> {
        self.request("GET", &format!("/v1/emails/{}", encode(id)), None, &[], &[])
    }

    pub fn list_messages(&self, query: &[(&str, &str)]) -> Result<Value, Error> {
        self.request("GET", "/v1/messages", None, query, &[])
    }

    pub fn get_message(&self, id: &str) -> Result<Value, Error> {
        self.request("GET", &format!("/v1/messages/{}", encode(id)), None, &[], &[])
    }

    pub fn deliveries(&self, id: &str) -> Result<Value, Error> {
        self.request(
            "GET",
            &format!("/v1/messages/{}/deliveries", encode(id)),
            None,
            &[],
            &[],
        )
    }

    pub fn list_domains(&self) -> Result<Value, Error> {
        self.request("GET", "/v1/domains", None, &[], &[])
    }

    pub fn create_domain(&self, domain: &str) -> Result<Value, Error> {
        self.request(
            "POST",
            "/v1/domains",
            Some(serde_json::json!({ "domain": domain })),
            &[],
            &[],
        )
    }

    pub fn verify_domain(&self, id: &str) -> Result<Value, Error> {
        self.request(
            "POST",
            &format!("/v1/domains/{}/verify", encode(id)),
            Some(serde_json::json!({})),
            &[],
            &[],
        )
    }

    pub fn delete_domain(&self, id: &str) -> Result<Value, Error> {
        self.request("DELETE", &format!("/v1/domains/{}", encode(id)), None, &[], &[])
    }

    pub fn list_suppressions(&self, query: &[(&str, &str)]) -> Result<Value, Error> {
        self.request("GET", "/v1/suppressions", None, query, &[])
    }

    pub fn add_suppression(&self, input: Value) -> Result<Value, Error> {
        self.request("POST", "/v1/suppressions", Some(input), &[], &[])
    }

    pub fn delete_suppression(&self, id: &str) -> Result<Value, Error> {
        self.request(
            "DELETE",
            &format!("/v1/suppressions/{}", encode(id)),
            None,
            &[],
            &[],
        )
    }

    pub fn list_webhooks(&self) -> Result<Value, Error> {
        self.request("GET", "/v1/webhooks", None, &[], &[])
    }

    pub fn create_webhook(&self, input: Value) -> Result<Value, Error> {
        self.request("POST", "/v1/webhooks", Some(input), &[], &[])
    }

    pub fn delete_webhook(&self, id: &str) -> Result<Value, Error> {
        self.request("DELETE", &format!("/v1/webhooks/{}", encode(id)), None, &[], &[])
    }

    pub fn inbound_routes(&self) -> Result<Value, Error> {
        self.request("GET", "/v1/inbound/routes", None, &[], &[])
    }

    pub fn create_inbound_route(&self, input: Value) -> Result<Value, Error> {
        self.request("POST", "/v1/inbound/routes", Some(input), &[], &[])
    }

    pub fn delete_inbound_route(&self, id: &str) -> Result<Value, Error> {
        self.request(
            "DELETE",
            &format!("/v1/inbound/routes/{}", encode(id)),
            None,
            &[],
            &[],
        )
    }

    pub fn usage(&self) -> Result<Value, Error> {
        self.request("GET", "/v1/usage", None, &[], &[])
    }

    pub fn events(&self, query: &[(&str, &str)]) -> Result<Value, Error> {
        self.request("GET", "/v1/events", None, query, &[])
    }

    pub fn health(&self) -> Result<Value, Error> {
        self.request("GET", "/v1/health", None, &[], &[])
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Result<Value, Error> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = match method {
            "GET" => self.agent.get(&url),
            "POST" => self.agent.post(&url),
            "PATCH" => self.agent.patch(&url),
            "PUT" => self.agent.put(&url),
            "DELETE" => self.agent.delete(&url),
            other => return Err(Error::Invalid(format!("unsupported method: {other}"))),
        };
        request = request.set("Accept", "application/json");
        if path != "/v1/health" {
            request = request.set("Authorization", &format!("Bearer {}", self.api_key));
        }
        for (name, value) in headers {
            request = request.set(name, value);
        }
        for (name, value) in query {
            request = request.query(name, value);
        }

        let response = match body {
            Some(body) => request.send_json(body),
            None => request.call(),
        };

        match response {
            Ok(response) => decode(response),
            Err(ureq::Error::Status(_, response)) => {
                let status = response.status();
                let raw = response.into_string().unwrap_or_default();
                let payload = serde_json::from_str::<Value>(&raw).ok();
                let error = payload.as_ref().and_then(|value| value.get("error"));
                let code = error
                    .and_then(|value| value.get("code"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let message = error
                    .and_then(|value| value.get("message"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| format!("Request failed ({status})"));
                Err(Error::Api {
                    status,
                    code,
                    message,
                    details: error.and_then(|value| value.get("details")).cloned(),
                })
            }
            Err(ureq::Error::Transport(error)) => Err(Error::Transport(error.to_string())),
        }
    }
}

fn new_idempotency_key() -> String {
    let mut first = std::collections::hash_map::RandomState::new().build_hasher();
    first.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0),
    );
    let mut second = std::collections::hash_map::RandomState::new().build_hasher();
    second.write_u64(first.finish());
    format!(
        "{:016x}-{:016x}",
        first.finish(),
        second.finish()
    )
}

fn decode(response: ureq::Response) -> Result<Value, Error> {
    let raw = response
        .into_string()
        .map_err(|error| Error::Decode(error.to_string()))?;
    if raw.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&raw).map_err(|error| Error::Decode(error.to_string()))
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// Verify a webhook delivery. Pass the raw request body, the
/// `Transmitly-Signature` header and the endpoint signing secret.
pub fn verify_webhook(raw_body: &str, signature_header: &str, secret: &str) -> bool {
    verify_webhook_with_tolerance(raw_body, signature_header, secret, 300)
}

pub fn verify_webhook_with_tolerance(
    raw_body: &str,
    signature_header: &str,
    secret: &str,
    tolerance_seconds: u64,
) -> bool {
    let mut timestamp: Option<u64> = None;
    let mut signature: Option<&str> = None;
    for part in signature_header.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        match key {
            "t" => timestamp = value.parse().ok(),
            "v1" => signature = Some(value),
            _ => {}
        }
    }
    let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
        return false;
    };
    if tolerance_seconds > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        if now.abs_diff(timestamp) > tolerance_seconds {
            return false;
        }
    }
    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(format!("{timestamp}.{raw_body}").as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    constant_time_eq(signature.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}
