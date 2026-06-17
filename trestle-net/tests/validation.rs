use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use trestle::diagnostic::{AnnotatedDiagnostic, Diagnostic, Severity};
use trestle::fingerprint::Fingerprint;
use trestle::scanning::signatures;
use trestle::secrets::values::classify::{NamedSecret, ValueClass};
use trestle::source::SourceFileSpan;
use trestle::validation::{SecretValidator, ValidationStatus};
use trestle_net::validation::{ValidationConfig, ValidationService};

const GITHUB: &str = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const STRIPE: &str = "sk_live_aaaaaaaaaaaaaaaaaaaaaaaa";

struct MockApi {
  base: String,
  requests: Arc<AtomicUsize>,
}

fn mock_api(status: u16) -> MockApi {
  let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock listener");
  let addr = listener.local_addr().expect("mock addr");
  let base = format!("http://{addr}");
  let requests = Arc::new(AtomicUsize::new(0));
  let counter = requests.clone();

  std::thread::spawn(move || {
    for stream in listener.incoming() {
      let Ok(mut stream) = stream else {
        break;
      };

      counter.fetch_add(1, Ordering::SeqCst);

      let peek = stream.try_clone().expect("clone stream");
      let mut reader = BufReader::new(peek);
      let mut line = String::new();
      while reader.read_line(&mut line).unwrap_or(0) != 0 {
        if line == "\r\n" {
          break;
        }
        line.clear();
      }

      let response = format!(
        "HTTP/1.1 {status} STATUS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
      );
      stream.write_all(response.as_bytes()).ok();
      stream.flush().ok();
    }
  });

  MockApi { base, requests }
}

fn finding(secret: &str) -> AnnotatedDiagnostic {
  let signature =
    signatures::scan(secret).expect("secret should match a signature");
  let value_class = ValueClass::Secret(NamedSecret::Signature(signature));

  AnnotatedDiagnostic::bare(Diagnostic::SecretValue {
    source_span: SourceFileSpan {
      file_abs_path: PathBuf::from("config.env"),
      file_span: None,
    },
    value_class,
    severity: Severity::Warning,
    file_type: None,
    fingerprint: Fingerprint::compute("test", secret.as_bytes()),
    from_content_scan: true,
  })
}

fn validate(
  secret: &str,
  key: &str,
  base: String,
  occurrences: usize,
) -> Vec<Option<ValidationStatus>> {
  let (sender, receiver) = mpsc::channel();
  let mut endpoints = HashMap::new();
  endpoints.insert(key.to_owned(), base);

  let config = ValidationConfig {
    timeout: Duration::from_secs(5),
    endpoints,
  };

  let service =
    ValidationService::new(&config, sender).expect("build validation service");

  for _ in 0..occurrences {
    service.submit(finding(secret), secret);
  }

  service.finish();
  drop(service);

  receiver.iter().map(|a| a.validation()).collect()
}

fn github(status: u16) -> Option<ValidationStatus> {
  let api = mock_api(status);
  validate(GITHUB, "github", api.base.clone(), 1)
    .into_iter()
    .next()
    .flatten()
}

#[test]
fn live_when_provider_returns_200() {
  assert_eq!(github(200), Some(ValidationStatus::Live));
}

#[test]
fn inactive_when_provider_returns_401() {
  assert_eq!(github(401), Some(ValidationStatus::Inactive));
}

#[test]
fn unknown_when_provider_returns_500() {
  assert_eq!(github(500), Some(ValidationStatus::Unknown));
}

#[test]
fn live_when_stripe_returns_403() {
  let api = mock_api(403);
  let status = validate(STRIPE, "stripe", api.base.clone(), 1)
    .into_iter()
    .next()
    .flatten();
  assert_eq!(status, Some(ValidationStatus::Live));
}

#[test]
fn identical_secret_is_validated_once() {
  let api = mock_api(200);
  let statuses = validate(GITHUB, "github", api.base.clone(), 3);

  assert_eq!(statuses.len(), 3);
  assert!(
    statuses
      .iter()
      .all(|status| *status == Some(ValidationStatus::Live))
  );
  assert_eq!(api.requests.load(Ordering::SeqCst), 1);
}
