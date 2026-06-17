mod providers;

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;

use trestle::diagnostic::AnnotatedDiagnostic;
use trestle::options::Options;
use trestle::secrets::values::classify::ValueClass;
use trestle::validation::{SecretValidator, ValidationStatus};

use providers::ProviderId;

const USER_AGENT: &str = concat!("trestle-net/", env!("CARGO_PKG_VERSION"));
const MAX_PACING_JITTER_MILLIS: u64 = 500;

pub fn make_validator(
  options: &Options,
  output: Sender<AnnotatedDiagnostic>,
) -> Option<Arc<dyn SecretValidator>> {
  let config = ValidationConfig {
    timeout: Duration::from_secs(options.validate_timeout_seconds),
    endpoints: HashMap::new(),
  };

  ValidationService::new(&config, output)
    .map(|service| Arc::new(service) as Arc<dyn SecretValidator>)
}

#[derive(Clone, Debug)]
pub struct ValidationConfig {
  pub timeout: Duration,
  pub endpoints: HashMap<String, String>,
}

pub(crate) struct ValidationOutcome {
  pub status: ValidationStatus,
}

impl ValidationOutcome {
  pub(crate) fn live() -> Self {
    Self {
      status: ValidationStatus::Live,
    }
  }

  pub(crate) fn inactive() -> Self {
    Self {
      status: ValidationStatus::Inactive,
    }
  }

  pub(crate) fn unknown(_detail: impl Into<String>) -> Self {
    Self {
      status: ValidationStatus::Unknown,
    }
  }
}

pub(crate) struct Credential<'a> {
  pub primary: &'a str,
}

pub(crate) struct ValidationContext {
  client: reqwest::Client,
  endpoints: HashMap<String, String>,
}

impl ValidationContext {
  pub(crate) fn client(&self) -> &reqwest::Client {
    &self.client
  }

  pub(crate) fn base(
    &self,
    provider: ProviderId,
    default: &'static str,
  ) -> String {
    self
      .endpoints
      .get(provider.key())
      .cloned()
      .unwrap_or_else(|| default.to_owned())
  }
}

fn provider_for(value_class: &ValueClass) -> Option<ProviderId> {
  let ValueClass::Secret(named) = value_class else {
    return None;
  };

  providers::provider_for_named(named)
}

pub(crate) fn redact(text: &str, secret: &str) -> String {
  if secret.is_empty() {
    return text.to_owned();
  }

  text.replace(secret, "[REDACTED]")
}

type SharedResult = Arc<OnceCell<ValidationStatus>>;

pub struct ValidationService {
  runtime: Runtime,
  context: Arc<ValidationContext>,
  output: Sender<AnnotatedDiagnostic>,
  hosts: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
  results: Mutex<HashMap<(ProviderId, String), SharedResult>>,
  tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl SecretValidator for ValidationService {
  fn handles(&self, value_class: &ValueClass) -> bool {
    provider_for(value_class).is_some()
  }

  fn submit(&self, finding: AnnotatedDiagnostic, secret: &str) {
    match finding.diagnostic.value_class().and_then(provider_for) {
      Some(provider) => self.spawn(finding, provider, secret.to_owned()),
      None => {
        self.output.send(finding).ok();
      }
    }
  }

  fn finish(&self) {
    self.drain();
  }
}

impl ValidationService {
  pub fn new(
    config: &ValidationConfig,
    output: Sender<AnnotatedDiagnostic>,
  ) -> Option<Self> {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
      .enable_all()
      .build()
    {
      Ok(runtime) => runtime,
      Err(err) => {
        eprintln!("Warning: could not start validation runtime. {err}");
        return None;
      }
    };

    let client = match build_client(config.timeout) {
      Ok(client) => client,
      Err(err) => {
        eprintln!("Warning: could not build validation client. {err}");
        return None;
      }
    };

    let context = Arc::new(ValidationContext {
      client,
      endpoints: config.endpoints.clone(),
    });

    Some(Self {
      runtime,
      context,
      output,
      hosts: Mutex::new(HashMap::new()),
      results: Mutex::new(HashMap::new()),
      tasks: Mutex::new(Vec::new()),
    })
  }

  fn spawn(
    &self,
    mut finding: AnnotatedDiagnostic,
    provider: ProviderId,
    secret: String,
  ) {
    let result = self.result_cell(provider, &secret);
    let host = providers::host_for(provider, &self.context);
    let host_lock = self.host_lock(host);
    let context = self.context.clone();
    let output = self.output.clone();

    let handle = self.runtime.spawn(async move {
      let status = *result
        .get_or_init(|| async {
          let _guard = host_lock.lock().await;

          let credential = Credential { primary: &secret };
          let outcome =
            providers::dispatch(provider, &credential, &context).await;

          let jitter = fastrand::u64(0..=MAX_PACING_JITTER_MILLIS);
          tokio::time::sleep(Duration::from_millis(jitter)).await;

          outcome.status
        })
        .await;

      finding.validation = Some(status);
      output.send(finding).ok();
    });

    if let Ok(mut tasks) = self.tasks.lock() {
      tasks.push(handle);
    }
  }

  fn result_cell(&self, provider: ProviderId, secret: &str) -> SharedResult {
    let mut results = match self.results.lock() {
      Ok(results) => results,
      Err(poisoned) => poisoned.into_inner(),
    };

    results
      .entry((provider, secret.to_owned()))
      .or_insert_with(|| Arc::new(OnceCell::new()))
      .clone()
  }

  fn drain(&self) {
    let handles: Vec<JoinHandle<()>> = match self.tasks.lock() {
      Ok(mut tasks) => std::mem::take(&mut tasks),
      Err(poisoned) => std::mem::take(&mut poisoned.into_inner()),
    };

    self.runtime.block_on(async {
      for handle in handles {
        handle.await.ok();
      }
    });
  }

  fn host_lock(&self, host: String) -> Arc<AsyncMutex<()>> {
    let mut hosts = match self.hosts.lock() {
      Ok(hosts) => hosts,
      Err(poisoned) => poisoned.into_inner(),
    };

    hosts
      .entry(host)
      .or_insert_with(|| Arc::new(AsyncMutex::new(())))
      .clone()
  }
}

fn build_client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
  reqwest::Client::builder()
    .user_agent(USER_AGENT)
    .timeout(timeout)
    .build()
}
