use std::cell::RefCell;

use regex::Regex;

#[derive(Debug, Eq, PartialEq)]
pub struct Signature {
  pub name: &'static str,
  pub env_var: &'static str,
  pub pattern: &'static str,
}

impl Signature {
  pub fn is_public(&self) -> bool {
    match self.name {
      #[cfg(feature = "signature-sentry-dsn")]
      "Sentry DSN" => true,
      #[cfg(feature = "signature-stripe-publishable")]
      "Stripe publishable key" => true,
      _ => false,
    }
  }
}

thread_local! {
  static REGEX_CACHE: RefCell<Vec<Option<Regex>>> = RefCell::new(
    Vec::new()
  );
}

pub fn scan(value: &str) -> Option<&'static Signature> {
  REGEX_CACHE.with(|cache| {
    let mut cache = cache.borrow_mut();

    if cache.is_empty() {
      cache.extend(SIGNATURES.iter().map(|sig| Regex::new(sig.pattern).ok()));
    }

    for (i, sig) in SIGNATURES.iter().enumerate() {
      if let Some(re) = cache.get(i).and_then(|r| r.as_ref()) {
        if re.is_match(value) {
          return Some(sig);
        }
      }
    }

    None
  })
}

const SIGNATURES: &[Signature] = &[
  #[cfg(feature = "signature-adafruit")]
  Signature {
    name: "Adafruit IO key",
    env_var: "ADAFRUIT_IO_KEY",
    pattern: r"(?-u:\b)aio_[a-zA-Z0-9]{28}(?-u:\b)",
  },
  #[cfg(feature = "signature-age")]
  Signature {
    name: "Age secret key",
    env_var: "AGE_SECRET_KEY",
    pattern: r"AGE-SECRET-KEY-1[a-z0-9]{58}",
  },
  #[cfg(feature = "signature-alchemy")]
  Signature {
    name: "Alchemy API key",
    env_var: "ALCHEMY_API_KEY",
    pattern: r"(?-u:\b)alcht_[a-zA-Z0-9]{30}(?-u:\b)",
  },
  #[cfg(feature = "signature-apify")]
  Signature {
    name: "Apify API token",
    env_var: "APIFY_API_TOKEN",
    pattern: r"(?-u:\b)apify_api_[A-Za-z0-9]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-anthropic")]
  Signature {
    name: "Anthropic API key",
    env_var: "ANTHROPIC_API_KEY",
    pattern: r"(?-u:\b)sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA(?-u:\b)",
  },
  #[cfg(feature = "signature-argon2")]
  Signature {
    name: "Argon2 password hash",
    env_var: "ARGON2_PASSWORD_HASH",
    // PHC-string form: $argon2{i|d|id}$v=<n>$m=<n>,t=<n>,p=<n>$<base64 salt>$<base64 hash>.
    pattern: r"\$argon2(?:id|i|d)\$(?:v=[0-9]+\$)?m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+",
  },
  #[cfg(feature = "signature-artifactory")]
  Signature {
    name: "Artifactory token",
    env_var: "ARTIFACTORY_TOKEN",
    pattern: r"(?-u:\b)(?:AKCp[A-Za-z0-9]{69}|cmVmd[A-Za-z0-9]{59})(?-u:\b)",
  },
  #[cfg(feature = "signature-atlassian")]
  Signature {
    name: "Atlassian API token",
    env_var: "ATLASSIAN_API_TOKEN",
    pattern: r"(?-u:\b)ATATT3[A-Za-z0-9_\-=]{100,}(?-u:\b)",
  },
  #[cfg(feature = "signature-aws")]
  Signature {
    name: "AWS access key",
    env_var: "AWS_ACCESS_KEY_ID",
    pattern: r"(?-u:\b)AKIA[A-Z0-9]{16}(?-u:\b)",
  },
  #[cfg(feature = "signature-aws-temp")]
  Signature {
    name: "AWS temporary access key",
    env_var: "AWS_ACCESS_KEY_ID",
    pattern: r"(?-u:\b)ASIA[A-Z0-9]{16}(?-u:\b)",
  },
  #[cfg(feature = "signature-bcrypt")]
  Signature {
    name: "bcrypt password hash",
    env_var: "BCRYPT_PASSWORD_HASH",
    // Modular crypt format used by every bcrypt implementation:
    //   $2[abxy]$<cost>$<22-char salt><31-char hash>
    // Salt and hash use bcrypt's modified base64 alphabet (./A-Za-z0-9).
    // Total length is always exactly 60 characters.
    pattern: r"\$2[abxy]\$[0-9]{2}\$[A-Za-z0-9./]{53}",
  },
  #[cfg(feature = "signature-atbb")]
  Signature {
    name: "Bitbucket app password",
    env_var: "BITBUCKET_APP_PASSWORD",
    pattern: r"(?-u:\b)ATBB[A-Za-z0-9_=.\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-axiom")]
  Signature {
    name: "Axiom API token",
    env_var: "AXIOM_API_TOKEN",
    pattern: r"(?-u:\b)xaat-[A-Za-z0-9]{32,}(?-u:\b)",
  },
  #[cfg(feature = "signature-azure-connection")]
  Signature {
    name: "Azure connection key",
    env_var: "AZURE_STORAGE_CONNECTION_STRING",
    // Exact format per Microsoft Purview spec:
    //   86 base64 chars + "==" (512-bit account key).
    // https://learn.microsoft.com/en-us/purview/sit-defn-azure-storage-account-key
    pattern: r"(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/]{86}==",
  },
  #[cfg(feature = "signature-azure-entra")]
  Signature {
    name: "Azure Entra refresh token",
    env_var: "AZURE_REFRESH_TOKEN",
    pattern: r"0\.A[A-Za-z0-9_\-.]{100,}",
  },
  #[cfg(feature = "signature-buildkite")]
  Signature {
    name: "Buildkite agent token",
    env_var: "BUILDKITE_AGENT_TOKEN",
    pattern: r"(?-u:\b)bkua_[a-z0-9]{40}(?-u:\b)",
  },
  #[cfg(feature = "signature-brevo")]
  Signature {
    name: "Brevo API key",
    env_var: "BREVO_API_KEY",
    pattern: r"(?-u:\b)xkeysib-[A-Za-z0-9_\-]{50,}(?-u:\b)",
  },
  #[cfg(feature = "signature-circleci")]
  Signature {
    name: "CircleCI personal access token",
    env_var: "CIRCLECI_PERSONAL_ACCESS_TOKEN",
    pattern: r"(?-u:\b)CCIPAT_[a-zA-Z0-9]{22}_[a-fA-F0-9]{40}(?-u:\b)",
  },
  #[cfg(feature = "signature-clojars")]
  Signature {
    name: "Clojars deploy token",
    env_var: "CLOJARS_DEPLOY_TOKEN",
    pattern: r"(?-u:\b)CLOJARS_[a-z0-9]{60,}(?-u:\b)",
  },
  #[cfg(feature = "signature-contentful")]
  Signature {
    name: "Contentful personal access token",
    env_var: "CONTENTFUL_PERSONAL_ACCESS_TOKEN",
    pattern: r"(?-u:\b)CFPAT-[A-Za-z0-9_\-]{40,}(?-u:\b)",
  },
  #[cfg(feature = "signature-databricks")]
  Signature {
    name: "Databricks API token",
    env_var: "DATABRICKS_TOKEN",
    pattern: r"(?-u:\b)dapi[a-f0-9]{32}(?-u:\b)",
  },
  #[cfg(feature = "signature-digitalocean")]
  Signature {
    name: "DigitalOcean token",
    env_var: "DIGITALOCEAN_TOKEN",
    pattern: r"(?-u:\b)do[opr]_v1_[a-f0-9]{64}(?-u:\b)",
  },
  #[cfg(feature = "signature-discord-bot")]
  Signature {
    name: "Discord bot token",
    env_var: "DISCORD_BOT_TOKEN",
    // Three base64url segments separated by dots: 23-26 char user/snowflake
    // (legacy "M" prefix or current "N"/"O"), 6 char timestamp, 27+ char
    // HMAC. Modern tokens emit longer HMACs.
    pattern: r"(?-u:\b)[MNO][A-Za-z0-9_\-]{22,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}(?-u:\b)",
  },
  #[cfg(feature = "signature-discord")]
  Signature {
    name: "Discord webhook URL",
    env_var: "DISCORD_WEBHOOK_URL",
    pattern: r"https://(?:discord(?:app)?\.com|canary\.discord\.com)/api/webhooks/[0-9]{17,}/[A-Za-z0-9_\-]{60,}",
  },
  #[cfg(feature = "signature-docker")]
  Signature {
    name: "Docker personal access token",
    env_var: "DOCKER_PAT",
    pattern: r"(?-u:\b)dckr_pat_[A-Za-z0-9_\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-doppler")]
  Signature {
    name: "Doppler token",
    env_var: "DOPPLER_TOKEN",
    pattern: r"dp\.(?:pt|ct|sa|st)\.[A-Za-z0-9]{20,}",
  },
  #[cfg(feature = "signature-dynatrace")]
  Signature {
    name: "Dynatrace API token",
    env_var: "DYNATRACE_API_TOKEN",
    pattern: r"(?-u:\b)dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}(?-u:\b)",
  },
  #[cfg(feature = "signature-figma")]
  Signature {
    name: "Figma personal access token",
    env_var: "FIGMA_PERSONAL_ACCESS_TOKEN",
    pattern: r"(?-u:\b)figd_[A-Za-z0-9_\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-flutterwave")]
  Signature {
    name: "Flutterwave secret key",
    env_var: "FLW_SECRET_KEY",
    pattern: r"(?-u:\b)FLWSECK(?:_TEST)?-[A-Za-z0-9_\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-flyio")]
  Signature {
    name: "Fly.io access token",
    env_var: "FLY_API_TOKEN",
    pattern: r"(?-u:\b)fo1_[A-Za-z0-9_\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-github")]
  Signature {
    name: "GitHub token",
    env_var: "GITHUB_TOKEN",
    pattern: r"(?-u:\b)(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})(?-u:\b)",
  },
  #[cfg(feature = "signature-gitlab")]
  Signature {
    name: "GitLab token",
    env_var: "GITLAB_TOKEN",
    pattern: r"(?-u:\b)gl(?:pat|ptt|rt|soat|dt|cbt|imt|agent|ffct|ft|oas)-[A-Za-z0-9_\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-google")]
  Signature {
    name: "Google credential",
    env_var: "GOOGLE_API_KEY",
    pattern: r"(?-u:\b)(?:AIza[A-Za-z0-9\-_]{35}|GOCSPX-[A-Za-z0-9\-_]{28})(?-u:\b)",
  },
  #[cfg(feature = "signature-google-oauth")]
  Signature {
    name: "Google OAuth access token",
    env_var: "GOOGLE_OAUTH_ACCESS_TOKEN",
    // ya29.<opaque base64url payload, length variable but always 20+>.
    // Optional secondary "." separated segments appear in some variants.
    pattern: r"(?-u:\b)ya29\.[A-Za-z0-9_\-]{20,}(?:\.[A-Za-z0-9_\-]+)*(?-u:\b)",
  },
  #[cfg(feature = "signature-grafana")]
  Signature {
    name: "Grafana token",
    env_var: "GRAFANA_API_KEY",
    pattern: r"(?-u:\b)glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}(?-u:\b)|glc_[A-Za-z0-9+/\-_]{20,}={0,2}",
  },
  #[cfg(feature = "signature-groq")]
  Signature {
    name: "Groq API key",
    env_var: "GROQ_API_KEY",
    pattern: r"(?-u:\b)gsk_[A-Za-z0-9]{48,}(?-u:\b)",
  },
  #[cfg(feature = "signature-hashicorp-vault")]
  Signature {
    name: "HashiCorp Vault token",
    env_var: "VAULT_TOKEN",
    pattern: r"(?-u:\b)hv[sbr]\.[A-Za-z0-9_\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-heroku")]
  Signature {
    name: "Heroku API key",
    env_var: "HEROKU_API_KEY",
    pattern: r"(?-u:\b)HRKU-[A-Za-z0-9_\-]{30,}(?-u:\b)",
  },
  #[cfg(feature = "signature-honeycomb")]
  Signature {
    name: "Honeycomb API key",
    env_var: "HONEYCOMB_API_KEY",
    pattern: r"(?-u:\b)hc(?:aic|acc|xik|xck)_[a-f0-9]{32}(?-u:\b)",
  },
  #[cfg(feature = "signature-huggingface")]
  Signature {
    name: "Hugging Face access token",
    env_var: "HF_TOKEN",
    pattern: r"(?-u:\b)hf_[A-Za-z0-9]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-infracost")]
  Signature {
    name: "Infracost API token",
    env_var: "INFRACOST_API_KEY",
    pattern: r"(?-u:\b)ico-[A-Za-z0-9]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-jwt")]
  Signature {
    name: "JSON Web Token",
    env_var: "JWT",
    // Three base64url-encoded segments separated by dots. Both the header
    // and payload are JSON objects, so they always begin with `eyJ` (the
    // base64url encoding of `{"`). The signature segment is empty when the
    // algorithm is "none" but the trailing dot is still present.
    // RFC 7519 (JWT): https://www.rfc-editor.org/rfc/rfc7519
    // RFC 7515 (JWS Compact Serialization): https://www.rfc-editor.org/rfc/rfc7515
    pattern: r"(?-u:\b)eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}(?-u:\b)",
  },
  #[cfg(feature = "signature-langsmith")]
  Signature {
    name: "LangSmith API token",
    env_var: "LANGSMITH_API_KEY",
    pattern: r"(?-u:\b)lsv2_pt_[a-f0-9]{32,}(?-u:\b)",
  },
  #[cfg(feature = "signature-launchdarkly")]
  Signature {
    name: "LaunchDarkly SDK key",
    env_var: "LAUNCHDARKLY_SDK_KEY",
    // "sdk-" or "api-" followed by a v4 UUID. Mobile keys ("mob-") are
    // client-side and not sensitive, so they're intentionally excluded.
    pattern: r"(?-u:\b)(?:sdk|api)-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}(?-u:\b)",
  },
  #[cfg(feature = "signature-linear")]
  Signature {
    name: "Linear API key",
    env_var: "LINEAR_API_KEY",
    pattern: r"(?-u:\b)lin_api_[A-Za-z0-9]{30,}(?-u:\b)",
  },
  #[cfg(feature = "signature-netlify")]
  Signature {
    name: "Netlify personal access token",
    env_var: "NETLIFY_AUTH_TOKEN",
    pattern: r"(?-u:\b)nfp_[a-zA-Z0-9_]{36}(?-u:\b)",
  },
  #[cfg(feature = "signature-newrelic")]
  Signature {
    name: "New Relic API key",
    env_var: "NEW_RELIC_API_KEY",
    pattern: r"(?-u:\b)NR(?:AK|II|JS)-[A-Za-z0-9]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-notion")]
  Signature {
    name: "Notion integration token",
    env_var: "NOTION_API_KEY",
    pattern: r"(?-u:\b)ntn_[A-Za-z0-9]{40,}(?-u:\b)",
  },
  #[cfg(feature = "signature-npm")]
  Signature {
    name: "NPM access token",
    env_var: "NPM_TOKEN",
    pattern: r"(?-u:\b)npm_[A-Za-z0-9]{36,}(?-u:\b)",
  },
  #[cfg(feature = "signature-nuget")]
  Signature {
    name: "NuGet API key",
    env_var: "NUGET_API_KEY",
    pattern: r"(?-u:\b)oy2[A-Za-z0-9]{40,}(?-u:\b)",
  },
  #[cfg(feature = "signature-1password")]
  Signature {
    name: "1Password credential",
    env_var: "OP_SERVICE_ACCOUNT_TOKEN",
    pattern: r"(?-u:\b)(?:A3-[A-Z0-9]{6}-[A-Z0-9]{5,11}(?:-[A-Z0-9]{5}){3}|ops_eyJ[A-Za-z0-9+/\-_]{250,}={0,3})(?-u:\b)",
  },
  #[cfg(feature = "signature-openai")]
  Signature {
    name: "OpenAI API key",
    env_var: "OPENAI_API_KEY",
    // The high-signal anchor is the literal infix "T3BlbkFJ" (base64 of
    // "OpenAI") that appears in every real OpenAI key, both the legacy
    // "sk-" form and the current "sk-proj-/svcacct-/admin-" variants.
    // Segment lengths around the infix are 20 (legacy) or 58/74 (current).
    pattern: r"(?-u:\b)(?:sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_\-]{74}|[A-Za-z0-9_\-]{58})T3BlbkFJ(?:[A-Za-z0-9_\-]{74}|[A-Za-z0-9_\-]{58})|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?-u:\b)",
  },
  #[cfg(feature = "signature-perplexity")]
  Signature {
    name: "Perplexity API key",
    env_var: "PERPLEXITY_API_KEY",
    pattern: r"(?-u:\b)pplx-[A-Za-z0-9]{48}(?-u:\b)",
  },
  #[cfg(feature = "signature-planetscale")]
  Signature {
    name: "PlanetScale token",
    env_var: "PLANETSCALE_TOKEN",
    pattern: r"(?-u:\b)pscale_(?:tkn|oauth|pw)_[A-Za-z0-9_\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-posthog")]
  Signature {
    name: "PostHog key",
    env_var: "POSTHOG_PERSONAL_API_KEY",
    // PostHog uses single-letter type indicators after "ph":
    //   phx_ personal API key - sensitive
    //   phs_ feature-flag secure / server-side key - sensitive
    //   pha_ OAuth access token - sensitive
    //   phr_ OAuth refresh token - sensitive
    pattern: r"(?-u:\b)ph[sxar]_[A-Za-z0-9_]{32,}(?-u:\b)",
  },
  #[cfg(feature = "signature-postman")]
  Signature {
    name: "Postman API key",
    env_var: "POSTMAN_API_KEY",
    pattern: r"(?-u:\b)PMAK-[A-Za-z0-9\-]{30,}(?-u:\b)",
  },
  #[cfg(feature = "signature-pbkdf2")]
  Signature {
    name: "PBKDF2 password hash",
    env_var: "PBKDF2_PASSWORD_HASH",
    // PHC modular-crypt form:
    //   $pbkdf2[-<algo>]$<iterations>$<base64 salt>$<base64 hash>
    // Also covers Django's variant `pbkdf2_<algo>$...$...$...` which has
    // an underscore rather than a leading dollar sign.
    pattern: r"(?:\$pbkdf2(?:-(?:sha1|sha224|sha256|sha384|sha512))?|pbkdf2_(?:sha1|sha224|sha256|sha384|sha512))\$[0-9]+\$[A-Za-z0-9+/_\-=]+\$[A-Za-z0-9+/_\-=]+",
  },
  #[cfg(feature = "signature-pulumi")]
  Signature {
    name: "Pulumi access token",
    env_var: "PULUMI_ACCESS_TOKEN",
    pattern: r"(?-u:\b)pul-[a-f0-9]{40}(?-u:\b)",
  },
  #[cfg(feature = "signature-pypi")]
  Signature {
    name: "PyPI API token",
    env_var: "PYPI_API_TOKEN",
    pattern: r"(?-u:\b)pypi-[A-Za-z0-9_\-]{50,}(?-u:\b)",
  },
  #[cfg(feature = "signature-razorpay")]
  Signature {
    name: "Razorpay key",
    env_var: "RAZORPAY_KEY_SECRET",
    pattern: r"(?-u:\b)rzp_(?:live|test)_[A-Za-z0-9]{14,}(?-u:\b)",
  },
  #[cfg(feature = "signature-render")]
  Signature {
    name: "Render API key",
    env_var: "RENDER_API_KEY",
    pattern: r"(?-u:\b)rnd_[A-Za-z0-9]{40,}(?-u:\b)",
  },
  #[cfg(feature = "signature-replicate")]
  Signature {
    name: "Replicate API token",
    env_var: "REPLICATE_API_TOKEN",
    pattern: r"(?-u:\b)r8_[A-Za-z0-9]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-rubygems")]
  Signature {
    name: "RubyGems API key",
    env_var: "RUBYGEMS_API_KEY",
    pattern: r"(?-u:\b)rubygems_[a-f0-9]{48}(?-u:\b)",
  },
  #[cfg(feature = "signature-scrypt")]
  Signature {
    name: "scrypt password hash",
    env_var: "SCRYPT_PASSWORD_HASH",
    // PHC modular-crypt form:
    //   $scrypt$ln=<n>,r=<n>,p=<n>$<base64 salt>$<base64 hash>
    pattern: r"\$scrypt\$ln=[0-9]+,r=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+",
  },
  #[cfg(feature = "signature-sendgrid")]
  Signature {
    name: "SendGrid API key",
    env_var: "SENDGRID_API_KEY",
    pattern: r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
  },
  #[cfg(feature = "signature-sentry")]
  Signature {
    name: "Sentry auth token",
    env_var: "SENTRY_AUTH_TOKEN",
    pattern: r"(?-u:\b)sntrys_[A-Za-z0-9]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-sentry-dsn")]
  Signature {
    name: "Sentry DSN",
    env_var: "SENTRY_DSN",
    // DSN format per Sentry's official spec:
    //   https://docs.sentry.io/concepts/key-terms/dsn-explainer/
    // Modern DSNs are
    //   https://<32-hex-public-key>@<host>/<project-id>
    // The legacy form embedding a secret
    //   https://<public>:<secret>@<host>/<project-id>
    // is deprecated but still accepted.
    pattern: r"(?-u:\b)https://[a-f0-9]{32}(?::[a-f0-9]{32})?@[A-Za-z0-9.\-]+\.ingest(?:\.[a-z]{2})?\.sentry\.io/[0-9]+(?-u:\b)",
  },
  #[cfg(feature = "signature-shopify")]
  Signature {
    name: "Shopify access token",
    env_var: "SHOPIFY_ACCESS_TOKEN",
    pattern: r"(?-u:\b)shp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32,}(?-u:\b)",
  },
  #[cfg(feature = "signature-slack")]
  Signature {
    name: "Slack token",
    env_var: "SLACK_BOT_TOKEN",
    pattern: r"(?-u:\b)(?:xox[bpare]|xapp)-[A-Za-z0-9\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-slack-webhook")]
  Signature {
    name: "Slack webhook URL",
    env_var: "SLACK_WEBHOOK_URL",
    pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
  },
  #[cfg(feature = "signature-square")]
  Signature {
    name: "Square access token",
    env_var: "SQUARE_ACCESS_TOKEN",
    pattern: r"(?-u:\b)(?:EAAA|sq0atp-)[A-Za-z0-9_\-+=]{22,60}(?-u:\b)",
  },
  #[cfg(feature = "signature-sonar")]
  Signature {
    name: "SonarQube/SonarCloud token",
    env_var: "SONAR_TOKEN",
    pattern: r"(?-u:\b)sq[aup]_[a-f0-9]{40}(?-u:\b)",
  },
  #[cfg(feature = "signature-sourcegraph")]
  Signature {
    name: "Sourcegraph access token",
    env_var: "SRC_ACCESS_TOKEN",
    pattern: r"(?-u:\b)sg[psd]_[A-Za-z0-9_]{16,}(?-u:\b)",
  },
  #[cfg(feature = "signature-stripe")]
  Signature {
    name: "Stripe secret key",
    env_var: "STRIPE_SECRET_KEY",
    pattern: r"(?-u:\b)(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-stripe-publishable")]
  Signature {
    name: "Stripe publishable key",
    env_var: "STRIPE_PUBLISHABLE_KEY",
    pattern: r"(?-u:\b)pk_(?:live|test)_[A-Za-z0-9]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-supabase")]
  Signature {
    name: "Supabase service token",
    env_var: "SUPABASE_SERVICE_ROLE_KEY",
    pattern: r"(?-u:\b)sbp_[a-f0-9]{40}(?-u:\b)",
  },
  #[cfg(feature = "signature-tailscale")]
  Signature {
    name: "Tailscale key",
    env_var: "TAILSCALE_AUTHKEY",
    pattern: r"(?-u:\b)tskey-(?:auth|api|scim)-[A-Za-z0-9_\-]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-telegram")]
  Signature {
    name: "Telegram bot token",
    env_var: "TELEGRAM_BOT_TOKEN",
    pattern: r"(?-u:\b)[0-9]{8,10}:[A-Za-z0-9_\-]{35}(?-u:\b)",
  },
  #[cfg(feature = "signature-twilio")]
  Signature {
    name: "Twilio Account SID",
    env_var: "TWILIO_ACCOUNT_SID",
    // 2-letter resource-type prefix + 32 hex digits, total 34 characters.
    // Account SIDs use "AC"; API Keys (which authenticate alongside an
    // auth token) use "SK".
    // https://www.twilio.com/docs/glossary/what-is-a-sid
    pattern: r"(?-u:\b)(?:AC|SK)[0-9a-fA-F]{32}(?-u:\b)",
  },
  #[cfg(feature = "signature-typeform")]
  Signature {
    name: "Typeform personal access token",
    env_var: "TYPEFORM_PERSONAL_ACCESS_TOKEN",
    pattern: r"(?-u:\b)tfp_[A-Za-z0-9_\-]{30,}(?-u:\b)",
  },
  #[cfg(feature = "signature-vercel")]
  Signature {
    name: "Vercel access token",
    env_var: "VERCEL_TOKEN",
    // Vercel introduced typed prefixes in 2024:
    //   vcp_ personal access token
    //   vci_ integration token
    //   vca_ app access token
    //   vcr_ app refresh token
    //   vck_ API key
    //   vcs_ support access token
    // The suffix is opaque base62, typically around 56 chars.
    // https://vercel.com/docs/sign-in-with-vercel/tokens
    pattern: r"(?-u:\b)vc[pcakrs]_[A-Za-z0-9]{40,}(?-u:\b)",
  },
  #[cfg(feature = "signature-xata")]
  Signature {
    name: "Xata API key",
    env_var: "XATA_API_KEY",
    pattern: r"(?-u:\b)xau_[A-Za-z0-9]{20,}(?-u:\b)",
  },
  #[cfg(feature = "signature-yandex")]
  Signature {
    name: "Yandex Cloud IAM token",
    env_var: "YC_TOKEN",
    pattern: r"(?-u:\b)AQVN[A-Za-z0-9_\-]{35,38}(?-u:\b)",
  },
];
