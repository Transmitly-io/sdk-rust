use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use transmitly::{verify_webhook, Client, EmailMessage};

struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn one_shot_server(status: u16, response: &'static str) -> (String, thread::JoinHandle<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let captured = read_request(&mut stream);
        let body = response.as_bytes();
        let reply = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            response
        );
        stream.write_all(reply.as_bytes()).unwrap();
        captured
    });
    (format!("http://{address}"), handle)
}

fn read_request(stream: &mut TcpStream) -> Captured {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).unwrap();
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().trim().to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    let content_length = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut chunk).unwrap();
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = String::from_utf8_lossy(&buffer[header_end..header_end + content_length]).to_string();

    Captured {
        request_line,
        headers,
        body,
    }
}

#[test]
fn sends_payload_and_idempotency_key() {
    let (base_url, handle) = one_shot_server(
        202,
        "{\"id\":\"msg_123\",\"status\":\"accepted\",\"recipients\":1}",
    );
    let client = Client::with_base_url("txk_test", base_url);
    let accepted = client
        .send_email_with_idempotency(
            &EmailMessage::new(
                "Notify <notify@acme.com>",
                vec!["ada@example.net".to_string()],
                "Welcome",
            )
            .html("<p>Hi</p>"),
            Some("welcome-1"),
        )
        .unwrap();

    assert_eq!(accepted.id, "msg_123");
    let captured = handle.join().unwrap();
    assert_eq!(captured.request_line, "POST /v1/emails HTTP/1.1");
    assert_eq!(captured.header("authorization"), Some("Bearer txk_test"));
    assert_eq!(captured.header("idempotency-key"), Some("welcome-1"));
    let payload: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(payload["from"], "Notify <notify@acme.com>");
    assert_eq!(payload["to"][0], "ada@example.net");
}

#[test]
fn maps_api_errors() {
    let (base_url, handle) = one_shot_server(
        409,
        "{\"error\":{\"code\":\"idempotency_conflict\",\"message\":\"Already used\"}}",
    );
    let client = Client::with_base_url("txk_test", base_url);
    let error = client
        .send_email(
            &EmailMessage::new("a@acme.com", vec!["b@example.net".to_string()], "s").text("t"),
        )
        .unwrap_err();
    handle.join().unwrap();

    match error {
        transmitly::Error::Api {
            status,
            code,
            message,
            ..
        } => {
            assert_eq!(status, 409);
            assert_eq!(code, "idempotency_conflict");
            assert_eq!(message, "Already used");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn validates_before_network() {
    let client = Client::new("txk_test");
    let error = client
        .send_email(&EmailMessage::new("a@acme.com", Vec::new(), "s").text("t"))
        .unwrap_err();
    assert!(matches!(error, transmitly::Error::Invalid(_)));
}

#[test]
fn verifies_webhook_signatures() {
    let secret = "whsec_test";
    let body = "{\"type\":\"email.delivered_to_mx\"}";
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{timestamp}.{body}").as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let header = format!("t={timestamp},v1={signature}");

    assert!(verify_webhook(body, &header, secret));
    assert!(!verify_webhook(body, &header, "wrong"));
    assert!(!verify_webhook(
        body,
        &format!("t={},v1={signature}", timestamp - 400),
        secret
    ));
    assert!(!verify_webhook(body, "garbage", secret));
}


#[test]
fn live_smoke_when_configured() {
    let Ok(api_key) = std::env::var("TRANSMITLY_API_KEY") else {
        return;
    };
    let base_url = std::env::var("TRANSMITLY_BASE_URL")
        .unwrap_or_else(|_| "https://transmitly.io".to_string());
    let client = Client::with_base_url(api_key, base_url);
    let accepted = client
        .send_email(
            &EmailMessage::new(
                "Notify <notify@transmitly.io>",
                vec!["sdk-rust@transmitly.test".to_string()],
                "Rust SDK smoke",
            )
            .text("hello")
            .test_mode(true),
        )
        .unwrap();
    assert_eq!(accepted.status, "accepted");
    assert_eq!(accepted.test_mode, Some(true));
}
