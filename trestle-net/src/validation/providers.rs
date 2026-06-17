use trestle::secrets::values::classify::NamedSecret;

use super::{Credential, ValidationContext, ValidationOutcome, redact};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProviderId {
  AWSBedrock,
  AdafruitIO,
  Alchemy,
  Apify,
  Artifactory,
  Atlassian,
  Axiom,
  Buildkite,
  CircleCI,
  ClickHouseCloud,
  Contentful,
  Cratesio,
  Databricks,
  DigitalOcean,
  Discord,
  Doppler,
  Duffel,
  Figma,
  Flexport,
  Flutterwave,
  Flyio,
  Frameio,
  GitHub,
  GitLab,
  GoogleCloudStorageHMACKey,
  GoogleOAuth20,
  Grafana,
  Groq,
  Harnessio,
  Heroku,
  Honeycomb,
  HuggingFace,
  InstagramGraphAPI,
  LangSmith,
  Netlify,
  NewRelic,
  Notion,
  Npm,
  OpenAI,
  OpenRouter,
  Paddle,
  Pinecone,
  Postman,
  Prefect,
  Pulumi,
  Render,
  Replicate,
  Resend,
  Rootly,
  SaladCloud,
  SendGrid,
  Sentry,
  SourcegraphCody,
  Square,
  Stripe,
  Supabase,
  Telegram,
  TerraformCloud,
  Typeform,
  Ubidots,
  Vercel,
  XAIGrok,
  Yandex,
}

impl ProviderId {
  pub fn key(&self) -> &'static str {
    match self {
      ProviderId::AWSBedrock => "aws-bedrock",
      ProviderId::AdafruitIO => "adafruit",
      ProviderId::Alchemy => "alchemy",
      ProviderId::Apify => "apify",
      ProviderId::Artifactory => "artifactory",
      ProviderId::Atlassian => "atlassian",
      ProviderId::Axiom => "axiom",
      ProviderId::Buildkite => "buildkite",
      ProviderId::CircleCI => "circleci",
      ProviderId::ClickHouseCloud => "clickhouse",
      ProviderId::Contentful => "contentful",
      ProviderId::Cratesio => "crates",
      ProviderId::Databricks => "databricks",
      ProviderId::DigitalOcean => "digitalocean",
      ProviderId::Discord => "discord",
      ProviderId::Doppler => "doppler",
      ProviderId::Duffel => "duffel",
      ProviderId::Figma => "figma",
      ProviderId::Flexport => "flexport",
      ProviderId::Flutterwave => "flutterwave",
      ProviderId::Flyio => "flyio",
      ProviderId::Frameio => "frameio",
      ProviderId::GitHub => "github",
      ProviderId::GitLab => "gitlab",
      ProviderId::GoogleCloudStorageHMACKey => "gcs-hmac",
      ProviderId::GoogleOAuth20 => "google-oauth",
      ProviderId::Grafana => "grafana",
      ProviderId::Groq => "groq",
      ProviderId::Harnessio => "harness",
      ProviderId::Heroku => "heroku",
      ProviderId::Honeycomb => "honeycomb",
      ProviderId::HuggingFace => "huggingface",
      ProviderId::InstagramGraphAPI => "instagram",
      ProviderId::LangSmith => "langsmith",
      ProviderId::Netlify => "netlify",
      ProviderId::NewRelic => "newrelic",
      ProviderId::Notion => "notion",
      ProviderId::Npm => "npm",
      ProviderId::OpenAI => "openai",
      ProviderId::OpenRouter => "openrouter",
      ProviderId::Paddle => "paddle",
      ProviderId::Pinecone => "pinecone",
      ProviderId::Postman => "postman",
      ProviderId::Prefect => "prefect",
      ProviderId::Pulumi => "pulumi",
      ProviderId::Render => "render",
      ProviderId::Replicate => "replicate",
      ProviderId::Resend => "resend",
      ProviderId::Rootly => "rootly",
      ProviderId::SaladCloud => "saladcloud",
      ProviderId::SendGrid => "sendgrid",
      ProviderId::Sentry => "sentry",
      ProviderId::SourcegraphCody => "sourcegraph-cody",
      ProviderId::Square => "square",
      ProviderId::Stripe => "stripe",
      ProviderId::Supabase => "supabase",
      ProviderId::Telegram => "telegram",
      ProviderId::TerraformCloud => "terraform-cloud",
      ProviderId::Typeform => "typeform",
      ProviderId::Ubidots => "ubidots",
      ProviderId::Vercel => "vercel",
      ProviderId::XAIGrok => "xai",
      ProviderId::Yandex => "yandex",
    }
  }
}

#[derive(Clone, Copy)]
enum Method {
  Get,
}

#[derive(Clone, Copy)]
enum Auth {
  Header {
    name: &'static str,
    prefix: &'static str,
  },
  Query {
    name: &'static str,
  },
  PathToken,
}

struct Simple {
  id: ProviderId,
  base: &'static str,
  path: &'static str,
  method: Method,
  auth: Auth,
  extra: &'static [(&'static str, &'static str)],
  live: &'static [u16],
  inactive: &'static [u16],
}

const SIMPLE: &[Simple] = &[
  Simple {
    id: ProviderId::AWSBedrock,
    base: "https://bedrock.{region}.amazonaws.com",
    path: "/foundation-models",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Content-Type", "application/json")],
    live: &[200],
    inactive: &[403],
  },
  Simple {
    id: ProviderId::AdafruitIO,
    base: "https://io.adafruit.com",
    path: "/api/v2/user",
    method: Method::Get,
    auth: Auth::Header {
      name: "X-AIO-Key",
      prefix: "",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Alchemy,
    base: "https://eth-mainnet.g.alchemy.com",
    path: "/v2/{token}/getNFTs/?owner=vitalik.eth",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Apify,
    base: "https://api.apify.com",
    path: "/v2/acts?token={token}&my=true&offset=10&limit=99&desc=true",
    method: Method::Get,
    auth: Auth::Query { name: "token" },
    extra: &[],
    live: &[200],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Artifactory,
    base: "https://{domain}",
    path: "/artifactory/api/system/ping",
    method: Method::Get,
    auth: Auth::Header {
      name: "X-JFrog-Art-Api",
      prefix: "",
    },
    extra: &[],
    live: &[200],
    inactive: &[401, 403, 302],
  },
  Simple {
    id: ProviderId::Atlassian,
    base: "https://api.atlassian.com",
    path: "/admin/v1/orgs",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Accept", "application/json")],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Axiom,
    base: "https://api.axiom.co",
    path: "/v2/datasets",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[403],
  },
  Simple {
    id: ProviderId::Buildkite,
    base: "https://api.buildkite.com",
    path: "/v2/access-token",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::CircleCI,
    base: "https://circleci.com",
    path: "/api/v2/me",
    method: Method::Get,
    auth: Auth::Header {
      name: "Circle-Token",
      prefix: "",
    },
    extra: &[("Accept", "application/json")],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::ClickHouseCloud,
    base: "https://api.clickhouse.cloud",
    path: "/v1/organizations",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Contentful,
    base: "https://api.contentful.com",
    path: "/organizations",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Cratesio,
    base: "https://crates.io",
    path: "/api/v1/me",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Databricks,
    base: "https://{domain}",
    path: "/api/2.0/preview/scim/v2/Me",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::DigitalOcean,
    base: "https://api.digitalocean.com",
    path: "/v2/account",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Discord,
    base: "https://discord.com",
    path: "/api/v8/users/{user_id}",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bot ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Doppler,
    base: "https://api.doppler.com",
    path: "/v3/me",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Accept", "application/json")],
    live: &[200, 299],
    inactive: &[400, 401, 403, 404],
  },
  Simple {
    id: ProviderId::Duffel,
    base: "https://api.duffel.com",
    path: "/air/airlines",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[
      ("Accept", "application/json"),
      ("Duffel-Version", "v2"),
      ("Accept-Encoding", "gzip"),
    ],
    live: &[200],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Figma,
    base: "https://api.figma.com",
    path: "/v1/me",
    method: Method::Get,
    auth: Auth::Header {
      name: "X-Figma-Token",
      prefix: "",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[403],
  },
  Simple {
    id: ProviderId::Flexport,
    base: "https://logistics-api.flexport.com",
    path: "/logistics/api/2024-04/webhooks",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 403],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Flutterwave,
    base: "https://api.flutterwave.com",
    path: "/v3/subaccounts",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Flyio,
    base: "https://api.machines.dev",
    path: "/v1/apps?org_slug=",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Accept", "application/json")],
    live: &[400, 400],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Frameio,
    base: "https://api.frame.io",
    path: "/v2/me",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Content-Type", "application/json")],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::GitHub,
    base: "https://api.github.com",
    path: "/user",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "token ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::GitLab,
    base: "https://gitlab.com",
    path: "/api/v4/user",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 403, 403],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::GoogleCloudStorageHMACKey,
    base: "https://storage.googleapis.com",
    path: "/storage/v1/projects/{projectId}/hmacKeys/{accessId}",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Content-Type", "application/json")],
    live: &[200],
    inactive: &[401, 403, 404, 429],
  },
  Simple {
    id: ProviderId::GoogleOAuth20,
    base: "https://www.googleapis.com",
    path: "/oauth2/v3/tokeninfo?access_token={token}",
    method: Method::Get,
    auth: Auth::Query {
      name: "access_token",
    },
    extra: &[],
    live: &[200],
    inactive: &[400],
  },
  Simple {
    id: ProviderId::Grafana,
    base: "https://grafana.com",
    path: "/api/v1/tokens?region=us",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Groq,
    base: "https://api.groq.com",
    path: "/openai/v1/models",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Harnessio,
    base: "https://app.harness.io",
    path: "/ng/api/user/currentUser",
    method: Method::Get,
    auth: Auth::Header {
      name: "x-api-key",
      prefix: "",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Heroku,
    base: "https://api.heroku.com",
    path: "/account",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Accept", "application/vnd.heroku+json")],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Honeycomb,
    base: "https://api.honeycomb.io",
    path: "/1/auth",
    method: Method::Get,
    auth: Auth::Header {
      name: "X-Honeycomb-Team",
      prefix: "",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::HuggingFace,
    base: "https://huggingface.co",
    path: "/api/whoami-v2",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::InstagramGraphAPI,
    base: "https://graph.instagram.com",
    path: "/me",
    method: Method::Get,
    auth: Auth::Query {
      name: "access_token",
    },
    extra: &[],
    live: &[200],
    inactive: &[400, 401],
  },
  Simple {
    id: ProviderId::LangSmith,
    base: "https://api.smith.langchain.com",
    path: "/api/v1/api-key",
    method: Method::Get,
    auth: Auth::Header {
      name: "X-API-Key",
      prefix: "",
    },
    extra: &[],
    live: &[200],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Netlify,
    base: "https://api.netlify.com",
    path: "/api/v1/sites",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401, 401],
  },
  Simple {
    id: ProviderId::NewRelic,
    base: "https://api.newrelic.com",
    path: "/v2/users.json",
    method: Method::Get,
    auth: Auth::Header {
      name: "X-Api-Key",
      prefix: "",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Notion,
    base: "https://api.notion.com",
    path: "/v1/users",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Notion-Version", "2022-06-28")],
    live: &[200, 299, 403],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Npm,
    base: "https://registry.npmjs.org",
    path: "/-/whoami",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::OpenAI,
    base: "https://api.openai.com",
    path: "/v1/me",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Content-Type", "application/json")],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::OpenRouter,
    base: "https://openrouter.ai",
    path: "/api/v1/key",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Paddle,
    base: "https://api.paddle.com",
    path: "/notification-settings",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[403],
  },
  Simple {
    id: ProviderId::Pinecone,
    base: "https://api.pinecone.io",
    path: "/indexes",
    method: Method::Get,
    auth: Auth::Header {
      name: "Api-Key",
      prefix: "",
    },
    extra: &[("X-Pinecone-Api-Version", "2024-07")],
    live: &[200],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Postman,
    base: "https://api.getpostman.com",
    path: "/collections",
    method: Method::Get,
    auth: Auth::Header {
      name: "x-api-key",
      prefix: "",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Prefect,
    base: "https://api.prefect.cloud",
    path: "/auth/login",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Pulumi,
    base: "https://api.pulumi.com",
    path: "/api/user/stacks",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "token ",
    },
    extra: &[
      ("Accept", "application/vnd.pulumi+8"),
      ("Content-Type", "application/json"),
    ],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Render,
    base: "https://api.render.com",
    path: "/v1/services?limit=1",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Accept", "application/json")],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Replicate,
    base: "https://api.replicate.com",
    path: "/v1/account",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Resend,
    base: "https://api.resend.com",
    path: "/emails",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("User-Agent", "(required by Resend API")],
    live: &[200],
    inactive: &[403],
  },
  Simple {
    id: ProviderId::Rootly,
    base: "https://api.rootly.com",
    path: "/v1/incidents",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 404],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::SaladCloud,
    base: "https://api.salad.com",
    path: "/api/public",
    method: Method::Get,
    auth: Auth::Header {
      name: "Salad-Api-Key",
      prefix: "",
    },
    extra: &[],
    live: &[204],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::SendGrid,
    base: "https://api.sendgrid.com",
    path: "/v3/scopes",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Content-Type", "application/json")],
    live: &[200, 403],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Sentry,
    base: "https://sentry.io",
    path: "/api/0/auth/validate",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 403, 200, 403],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::SourcegraphCody,
    base: "https://cody-gateway.sourcegraph.com",
    path: "/v1/limits",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Square,
    base: "https://connect.squareup.com",
    path: "/v2/merchants",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 403, 200, 403],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Stripe,
    base: "https://api.stripe.com",
    path: "/v1/charges",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Content-Type", "application/json")],
    live: &[200, 403],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Supabase,
    base: "https://api.supabase.com",
    path: "/v1/projects",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Telegram,
    base: "https://api.telegram.org",
    path: "/bot{token}/getMe",
    method: Method::Get,
    auth: Auth::PathToken,
    extra: &[],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::TerraformCloud,
    base: "https://app.terraform.io",
    path: "/api/v2/account/details",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[401],
  },
  Simple {
    id: ProviderId::Typeform,
    base: "https://api.typeform.com",
    path: "/me",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Ubidots,
    base: "https://industrial.api.ubidots.com",
    path: "/api/v1.6/variables/",
    method: Method::Get,
    auth: Auth::Header {
      name: "X-Auth-Token",
      prefix: "",
    },
    extra: &[("Content-Type", "application/json")],
    live: &[200, 299],
    inactive: &[401, 403],
  },
  Simple {
    id: ProviderId::Vercel,
    base: "https://api.vercel.com",
    path: "/www/user",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[],
    live: &[200, 299],
    inactive: &[403],
  },
  Simple {
    id: ProviderId::XAIGrok,
    base: "https://api.x.ai",
    path: "/v1/api-key",
    method: Method::Get,
    auth: Auth::Header {
      name: "Authorization",
      prefix: "Bearer ",
    },
    extra: &[("Content-Type", "application/json")],
    live: &[200],
    inactive: &[400, 401],
  },
  Simple {
    id: ProviderId::Yandex,
    base: "https://dictionary.yandex.net",
    path: "/api/v1/dicservice.json/getLangs?key={token}",
    method: Method::Get,
    auth: Auth::Query { name: "key" },
    extra: &[],
    live: &[200, 299],
    inactive: &[403],
  },
];

pub(super) fn provider_for_named(named: &NamedSecret) -> Option<ProviderId> {
  match named {
    NamedSecret::Signature(signature) => provider_for_signature(signature.name),
    NamedSecret::Service(service) => provider_for_service(service.keyword),
    _ => None,
  }
}

fn provider_for_signature(name: &str) -> Option<ProviderId> {
  let provider = match name {
    "AWS Bedrock API key" => ProviderId::AWSBedrock,
    "Adafruit IO key" => ProviderId::AdafruitIO,
    "Alchemy API key" => ProviderId::Alchemy,
    "Apify API token" => ProviderId::Apify,
    "Artifactory token" => ProviderId::Artifactory,
    "Atlassian API token" => ProviderId::Atlassian,
    "Axiom API token" => ProviderId::Axiom,
    "Buildkite agent token" => ProviderId::Buildkite,
    "CircleCI personal access token" => ProviderId::CircleCI,
    "ClickHouse Cloud API key" => ProviderId::ClickHouseCloud,
    "Contentful personal access token" => ProviderId::Contentful,
    "crates.io API token" => ProviderId::Cratesio,
    "Databricks API token" => ProviderId::Databricks,
    "DigitalOcean token" => ProviderId::DigitalOcean,
    "Discord webhook URL" => ProviderId::Discord,
    "Doppler token" => ProviderId::Doppler,
    "Duffel access token" => ProviderId::Duffel,
    "Figma personal access token" => ProviderId::Figma,
    "Flexport API token" => ProviderId::Flexport,
    "Flutterwave secret key" => ProviderId::Flutterwave,
    "Fly.io access token" => ProviderId::Flyio,
    "Frame.io token" => ProviderId::Frameio,
    "GitHub token" => ProviderId::GitHub,
    "GitLab token" => ProviderId::GitLab,
    "Google Cloud Storage HMAC key ID" => ProviderId::GoogleCloudStorageHMACKey,
    "Google OAuth access token" => ProviderId::GoogleOAuth20,
    "Grafana token" => ProviderId::Grafana,
    "Groq API key" => ProviderId::Groq,
    "Harness API key" => ProviderId::Harnessio,
    "Heroku API key" => ProviderId::Heroku,
    "Honeycomb API key" => ProviderId::Honeycomb,
    "Hugging Face access token" => ProviderId::HuggingFace,
    "Instagram access token" => ProviderId::InstagramGraphAPI,
    "LangSmith API token" => ProviderId::LangSmith,
    "Netlify personal access token" => ProviderId::Netlify,
    "New Relic API key" => ProviderId::NewRelic,
    "Notion integration token" => ProviderId::Notion,
    "NPM access token" => ProviderId::Npm,
    "OpenAI API key" => ProviderId::OpenAI,
    "OpenRouter API key" => ProviderId::OpenRouter,
    "Paddle API key" => ProviderId::Paddle,
    "Pinecone API key" => ProviderId::Pinecone,
    "Postman API key" => ProviderId::Postman,
    "Prefect API token" => ProviderId::Prefect,
    "Pulumi access token" => ProviderId::Pulumi,
    "Render API key" => ProviderId::Render,
    "Replicate API token" => ProviderId::Replicate,
    "Resend API key" => ProviderId::Resend,
    "Rootly API key" => ProviderId::Rootly,
    "SaladCloud API key" => ProviderId::SaladCloud,
    "SendGrid API key" => ProviderId::SendGrid,
    "Sentry auth token" => ProviderId::Sentry,
    "Sourcegraph Cody API key" => ProviderId::SourcegraphCody,
    "Square access token" => ProviderId::Square,
    "Stripe secret key" => ProviderId::Stripe,
    "Supabase service token" => ProviderId::Supabase,
    "Telegram bot token" => ProviderId::Telegram,
    "HashiCorp Terraform Cloud token" => ProviderId::TerraformCloud,
    "Typeform personal access token" => ProviderId::Typeform,
    "Ubidots API token" => ProviderId::Ubidots,
    "Vercel access token" => ProviderId::Vercel,
    "xAI API key" => ProviderId::XAIGrok,
    "Yandex Cloud IAM token" => ProviderId::Yandex,
    _ => return None,
  };

  Some(provider)
}

fn provider_for_service(keyword: &str) -> Option<ProviderId> {
  let provider = match keyword {
    "adafruit" => ProviderId::AdafruitIO,
    "alchemy" => ProviderId::Alchemy,
    "buildkite" => ProviderId::Buildkite,
    "circleci" => ProviderId::CircleCI,
    "contentful" => ProviderId::Contentful,
    "discord" => ProviderId::Discord,
    "heroku" => ProviderId::Heroku,
    "netlify" => ProviderId::Netlify,
    "notion" => ProviderId::Notion,
    "pinecone" => ProviderId::Pinecone,
    "render" => ProviderId::Render,
    "sentry" => ProviderId::Sentry,
    "square" => ProviderId::Square,
    "supabase" => ProviderId::Supabase,
    "telegram" => ProviderId::Telegram,
    "typeform" => ProviderId::Typeform,
    "vercel" => ProviderId::Vercel,
    "yandex" => ProviderId::Yandex,
    _ => return None,
  };

  Some(provider)
}

pub(super) async fn dispatch(
  provider: ProviderId,
  credential: &Credential<'_>,
  context: &ValidationContext,
) -> ValidationOutcome {
  match simple_spec(provider) {
    Some(spec) => validate_simple(spec, credential, context).await,
    None => ValidationOutcome::unknown(
      "no validator is implemented for this provider",
    ),
  }
}

fn simple_spec(provider: ProviderId) -> Option<&'static Simple> {
  SIMPLE.iter().find(|spec| spec.id == provider)
}

pub(super) fn host_for(
  provider: ProviderId,
  context: &ValidationContext,
) -> String {
  match simple_spec(provider) {
    Some(spec) => host_of(&context.base(provider, spec.base)),
    None => provider.key().to_owned(),
  }
}

fn host_of(url: &str) -> String {
  let after_scheme = url.split("://").nth(1).unwrap_or(url);

  after_scheme
    .split('/')
    .next()
    .unwrap_or(after_scheme)
    .to_owned()
}

async fn validate_simple(
  spec: &Simple,
  credential: &Credential<'_>,
  context: &ValidationContext,
) -> ValidationOutcome {
  let base = context.base(spec.id, spec.base);

  let path = match spec.auth {
    Auth::PathToken => spec.path.replace("{token}", credential.primary),
    _ => spec.path.to_owned(),
  };

  let url = format!("{base}{path}");

  let mut request = match spec.method {
    Method::Get => context.client().get(url),
  };

  match spec.auth {
    Auth::Header { name, prefix } => {
      request = request.header(name, format!("{prefix}{}", credential.primary));
    }
    Auth::Query { name } => {
      request = request.query(&[(name, credential.primary)]);
    }
    Auth::PathToken => {}
  }

  for (name, value) in spec.extra {
    request = request.header(*name, *value);
  }

  let result = request.send().await;

  outcome_from(result, credential.primary, spec.live, spec.inactive)
}

fn outcome_from(
  result: reqwest::Result<reqwest::Response>,
  secret: &str,
  live: &[u16],
  inactive: &[u16],
) -> ValidationOutcome {
  match result {
    Ok(response) => {
      let code = response.status().as_u16();

      if live.contains(&code) {
        ValidationOutcome::live()
      } else if inactive.contains(&code) {
        ValidationOutcome::inactive()
      } else {
        ValidationOutcome::unknown(format!("unexpected response status {code}"))
      }
    }
    Err(error) => {
      ValidationOutcome::unknown(redact(&error.to_string(), secret))
    }
  }
}
