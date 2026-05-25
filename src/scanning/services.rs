use std::{cell::RefCell, collections::HashMap};

use regex::RegexSet;

#[derive(Debug, Eq, PartialEq)]
pub struct Service {
  pub keyword: &'static str,
  pub display_name: &'static str,
  pub env_var: &'static str,
  pub patterns: &'static [&'static str],
}

impl Service {
  pub fn by_keyword(keyword: &str) -> Option<&'static Service> {
    SERVICES.iter().find(|service| service.keyword == keyword)
  }
}

thread_local! {
  static REGEX_CACHE: RefCell<HashMap<&'static str, Option<RegexSet>>> = RefCell::new(
    HashMap::new()
  );
}

impl Service {
  pub fn matches(&self, value: &str) -> bool {
    REGEX_CACHE.with(|cache| {
      let mut cache = cache.borrow_mut();
      let entry = cache
        .entry(self.keyword)
        .or_insert_with(|| RegexSet::new(self.patterns).ok());
      entry.as_ref().is_some_and(|r| r.is_match(value))
    })
  }
}

macro_rules! define_services {
  (
    services: [ $(
      $( #[$meta:meta] )*
      (
        $service:literal,
        $service_display:literal,
        $service_env_var:literal,
        [ $( $service_pattern:literal ),* $(,)? ]
      )
    ),* $(,)? ],
  ) => {
    pub const SERVICE_KEYWORDS: &[&str] = &[
      $( $( #[$meta] )* $service ),*
    ];

    const SERVICES: &[Service] = &[
      $(
        $( #[$meta] )*
        Service {
          keyword: $service,
          display_name: $service_display,
          env_var: $service_env_var,
          patterns: &[ $( $service_pattern ),* ],
        }
      ),*
    ];
  };
}

define_services!(
  services: [
    #[cfg(feature = "service-adafruit")]
    ("adafruit", "Adafruit", "ADAFRUIT_IO_KEY", [r"^[a-z0-9_\-]{32}$"]),
    #[cfg(feature = "service-adobe")]
    ("adobe", "Adobe", "ADOBE_API_KEY", [r"^[a-f0-9]{32}$"]),
    #[cfg(feature = "service-airtable")]
    ("airtable", "Airtable", "AIRTABLE_API_KEY", [
      r"^pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}$",
      r"^[a-z0-9]{17}$",
    ]),
    #[cfg(feature = "service-aiven")]
    ("aiven", "Aiven", "AIVEN_API_TOKEN", [r"^[a-zA-Z0-9/+=]{372}$"]),
    #[cfg(feature = "service-alchemy")]
    ("alchemy", "Alchemy", "ALCHEMY_API_KEY", [r"^[a-zA-Z0-9_\-]{32}$"]),
    #[cfg(feature = "service-algolia")]
    ("algolia", "Algolia", "ALGOLIA_API_KEY", [r"^[a-z0-9]{32}$"]),
    #[cfg(feature = "service-alibaba")]
    ("alibaba", "Alibaba Cloud", "ALIBABA_CLOUD_ACCESS_KEY_SECRET", [
      r"^[a-zA-Z0-9]{30,}$",
    ]),
    #[cfg(feature = "service-amplitude")]
    ("amplitude", "Amplitude", "AMPLITUDE_API_KEY", [r"^[a-f0-9]{32}$"]),
    #[cfg(feature = "service-assemblyai")]
    ("assemblyai", "AssemblyAI", "ASSEMBLYAI_API_KEY", [r"^[0-9a-z]{32}$"]),
    #[cfg(feature = "service-asana")]
    ("asana", "Asana", "ASANA_ACCESS_TOKEN", [
      r"^[0-9]+/[0-9]{16,}(?:/[0-9]{16,})?:[A-Za-z0-9]{32,}$",
      r"^[0-9]{16}$",
      r"^[a-z0-9]{32}$",
    ]),
    #[cfg(feature = "service-auth0")]
    ("auth0", "Auth0", "AUTH0_CLIENT_SECRET", [r"^[a-zA-Z0-9_\-]{32,}$"]),
    #[cfg(feature = "service-azure")]
    ("azure", "Azure", "AZURE_CLIENT_SECRET", [
      r"^[a-zA-Z0-9+/=_\-]{32,}$",
      r"^[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34}$",
    ]),
    #[cfg(feature = "service-azuredevops")]
    ("azuredevops", "Azure DevOps", "AZURE_DEVOPS_PAT", [r"^[a-z0-9]{52}$"]),
    #[cfg(feature = "service-backstage")]
    ("backstage", "Backstage", "BACKSTAGE_TOKEN", [r"^[a-zA-Z0-9_\-]{32,}$"]),
    #[cfg(feature = "service-beamer")]
    ("beamer", "Beamer", "BEAMER_API_KEY", [r"^b_[a-zA-Z0-9=_+/\-]{44}$"]),
    #[cfg(feature = "service-bugsnag")]
    ("bugsnag", "Bugsnag", "BUGSNAG_API_KEY", [
      r"^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$",
    ]),
    #[cfg(feature = "service-buildkite")]
    ("buildkite", "Buildkite", "BUILDKITE_AGENT_TOKEN", [r"^[a-f0-9]{40}$"]),
    #[cfg(feature = "service-bitbucket")]
    ("bitbucket", "Bitbucket", "BITBUCKET_APP_PASSWORD", [
      r"^[a-z0-9]{32}$",
      r"^[a-z0-9=_\-]{64}$",
    ]),
    #[cfg(feature = "service-bittrex")]
    ("bittrex", "Bittrex", "BITTREX_API_SECRET", [r"^[a-z0-9]{32}$"]),
    #[cfg(feature = "service-clickup")]
    ("clickup", "ClickUp", "CLICKUP_API_TOKEN", [
      r"^pk_[0-9]{7,9}_[0-9A-Z]{32}$",
    ]),
    #[cfg(feature = "service-cloudflare")]
    ("cloudflare", "Cloudflare", "CLOUDFLARE_API_TOKEN", [
      r"^v1\.0-[A-Za-z0-9\-]{171}$",
      r"^[a-zA-Z0-9_\-]{40}$",
      r"^[a-zA-Z0-9_\-]{37}$",
    ]),
    #[cfg(feature = "service-circleci")]
    ("circleci", "CircleCI", "CIRCLECI_TOKEN", [r"^[a-fA-F0-9]{40}$"]),
    #[cfg(feature = "service-codacy")]
    ("codacy", "Codacy", "CODACY_API_TOKEN", [r"^[0-9A-Za-z]{20}$"]),
    #[cfg(feature = "service-codeclimate")]
    ("codeclimate", "Code Climate", "CODECLIMATE_API_TOKEN", [
      r"^[a-f0-9]{40}$",
    ]),
    #[cfg(feature = "service-codecov")]
    ("codecov", "Codecov", "CODECOV_TOKEN", [r"^[a-z0-9]{32}$"]),
    #[cfg(feature = "service-cohere")]
    ("cohere", "Cohere", "COHERE_API_KEY", [r"^[a-zA-Z0-9]{40}$"]),
    #[cfg(feature = "service-coinbase")]
    ("coinbase", "Coinbase", "COINBASE_API_KEY", [r"^[a-z0-9_\-]{64}$"]),
    #[cfg(feature = "service-confluent")]
    ("confluent", "Confluent", "CONFLUENT_API_SECRET", [
      r"^[a-zA-Z0-9]{16}$",
      r"^[a-zA-Z0-9+/]{64}$",
    ]),
    #[cfg(feature = "service-contentful")]
    ("contentful", "Contentful", "CONTENTFUL_ACCESS_TOKEN", [
      r"^[a-z0-9=_\-]{43}$",
    ]),
    #[cfg(feature = "service-coveralls")]
    ("coveralls", "Coveralls", "COVERALLS_REPO_TOKEN", [
      r"^[a-zA-Z0-9\-]{37}$",
    ]),
    #[cfg(feature = "service-cosmosdb")]
    ("cosmosdb", "Azure CosmosDB", "AZURE_COSMOS_KEY", [
      r"^[a-zA-Z0-9+/]{80,}={0,2}$",
    ]),
    #[cfg(feature = "service-crowdin")]
    ("crowdin", "Crowdin", "CROWDIN_API_TOKEN", [r"^[0-9A-Za-z]{80}$"]),
    #[cfg(feature = "service-datadog")]
    ("datadog", "Datadog", "DATADOG_API_KEY", [
      r"^[a-zA-Z0-9\-]{40}$",
      r"^[a-zA-Z0-9\-]{32}$",
    ]),
    #[cfg(feature = "service-deepgram")]
    ("deepgram", "Deepgram", "DEEPGRAM_API_KEY", [r"^[0-9a-z]{40}$"]),
    #[cfg(feature = "service-deepseek")]
    ("deepseek", "DeepSeek", "DEEPSEEK_API_KEY", [r"^sk-[a-z0-9]{32}$"]),
    #[cfg(feature = "service-discord")]
    ("discord", "Discord", "DISCORD_BOT_TOKEN", [
      r"^[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}$",
      r"^[a-f0-9]{64}$",
      r"^[0-9]{18}$",
      r"^[a-z0-9=_\-]{32}$",
    ]),
    #[cfg(feature = "service-droneci")]
    ("droneci", "Drone CI", "DRONE_TOKEN", [r"^[a-zA-Z0-9]{32}$"]),
    #[cfg(feature = "service-elevenlabs")]
    ("elevenlabs", "ElevenLabs", "ELEVENLABS_API_KEY", [
      r"^[a-f0-9]{32}$",
      r"^sk_[a-f0-9]{48}$",
    ]),
    #[cfg(feature = "service-eth")]
    ("eth", "Ethereum", "ETH_PRIVATE_KEY", [
      r"^(?:0x)?[a-fA-F0-9]{64}$",
    ]),
    #[cfg(feature = "service-ethereum")]
    ("ethereum", "Ethereum", "ETHEREUM_PRIVATE_KEY", [
      r"^(?:0x)?[a-fA-F0-9]{64}$",
    ]),
    #[cfg(feature = "service-etherscan")]
    ("etherscan", "Etherscan", "ETHERSCAN_API_KEY", [r"^[A-Z0-9]{34}$"]),
    #[cfg(feature = "service-eventbrite")]
    ("eventbrite", "Eventbrite", "EVENTBRITE_API_KEY", [r"^[0-9A-Z]{20}$"]),
    #[cfg(feature = "service-etsy")]
    ("etsy", "Etsy", "ETSY_API_KEY", [r"^[a-z0-9]{24}$"]),
    #[cfg(feature = "service-facebook")]
    ("facebook", "Facebook", "FACEBOOK_ACCESS_TOKEN", [r"^[a-f0-9]{32}$"]),
    #[cfg(feature = "service-fastly")]
    ("fastly", "Fastly", "FASTLY_API_TOKEN", [r"^[a-zA-Z0-9=_\-]{32}$"]),
    #[cfg(feature = "service-fireworks")]
    ("fireworks", "Fireworks AI", "FIREWORKS_API_KEY", [
      r"^[a-zA-Z0-9]{32,}$",
    ]),
    #[cfg(feature = "service-finicity")]
    ("finicity", "Finicity", "FINICITY_APP_KEY", [
      r"^[a-f0-9]{32}$",
      r"^[a-z0-9]{20}$",
    ]),
    #[cfg(feature = "service-finnhub")]
    ("finnhub", "Finnhub", "FINNHUB_API_KEY", [r"^[a-z0-9]{20}$"]),
    #[cfg(feature = "service-flickr")]
    ("flickr", "Flickr", "FLICKR_API_KEY", [r"^[a-z0-9]{32}$"]),
    #[cfg(feature = "service-freshbooks")]
    ("freshbooks", "FreshBooks", "FRESHBOOKS_ACCESS_TOKEN", [
      r"^[a-z0-9]{64}$",
    ]),
    #[cfg(feature = "service-gitter")]
    ("gitter", "Gitter", "GITTER_TOKEN", [r"^[a-z0-9_\-]{40}$"]),
    #[cfg(feature = "service-gocardless")]
    ("gocardless", "GoCardless", "GOCARDLESS_ACCESS_TOKEN", [
      r"^live_[a-zA-Z0-9\-_=]{40}$",
    ]),
    #[cfg(feature = "service-infura")]
    ("infura", "Infura", "INFURA_PROJECT_ID", [r"^[a-f0-9]{32}$"]),
    #[cfg(feature = "service-jumpcloud")]
    ("jumpcloud", "JumpCloud", "JUMPCLOUD_API_KEY", [
      r"^[a-zA-Z0-9]{40}$",
    ]),
    #[cfg(feature = "service-heroku")]
    ("heroku", "Heroku", "HEROKU_API_KEY", [
      r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    ]),
    #[cfg(feature = "service-hubspot")]
    ("hubspot", "HubSpot", "HUBSPOT_ACCESS_TOKEN", [
      r"^[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}$",
    ]),
    #[cfg(feature = "service-intercom")]
    ("intercom", "Intercom", "INTERCOM_ACCESS_TOKEN", [
      r"^[a-zA-Z0-9=_+/\-]{60}$",
    ]),
    #[cfg(feature = "service-kraken")]
    ("kraken", "Kraken", "KRAKEN_PRIVATE_KEY", [r"^[a-z0-9/=_+\-]{80,90}$"]),
    #[cfg(feature = "service-kucoin")]
    ("kucoin", "KuCoin", "KUCOIN_API_SECRET", [
      r"^[a-f0-9]{24}$",
      r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    ]),
    #[cfg(feature = "service-launchdarkly")]
    ("launchdarkly", "LaunchDarkly", "LAUNCHDARKLY_SDK_KEY", [
      r"^(?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12}$",
      r"^[a-z0-9=_\-]{40}$",
    ]),
    #[cfg(feature = "service-linkedin")]
    ("linkedin", "LinkedIn", "LINKEDIN_CLIENT_SECRET", [
      r"^[a-z0-9]{14}$",
      r"^[a-z0-9]{16}$",
    ]),
    #[cfg(feature = "service-looker")]
    ("looker", "Looker", "LOOKER_API_SECRET", [
      r"^[a-z0-9]{20}$",
      r"^[a-z0-9]{24}$",
    ]),
    #[cfg(feature = "service-mailchimp")]
    ("mailchimp", "Mailchimp", "MAILCHIMP_API_KEY", [
      r"^[a-f0-9]{32}-us\d\d$",
    ]),
    #[cfg(feature = "service-mandrill")]
    ("mandrill", "Mandrill", "MANDRILL_API_KEY", [r"^[A-Za-z0-9_\-]{22}$"]),
    #[cfg(feature = "service-mailgun")]
    ("mailgun", "Mailgun", "MAILGUN_API_KEY", [
      r"^key-[a-f0-9]{32}$",
      r"^pubkey-[a-f0-9]{32}$",
      r"^[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}$",
      r"^[a-zA-Z0-9\-]{72}$",
    ]),
    #[cfg(feature = "service-mapbox")]
    ("mapbox", "Mapbox", "MAPBOX_ACCESS_TOKEN", [
      r"^sk\.[a-zA-Z0-9.\-]{80,240}$",
      r"^pk\.[a-z0-9]{60}\.[a-z0-9]{22}$",
    ]),
    #[cfg(feature = "service-mistral")]
    ("mistral", "Mistral AI", "MISTRAL_API_KEY", [r"^[a-zA-Z0-9]{32}$"]),
    #[cfg(feature = "service-mixpanel")]
    ("mixpanel", "Mixpanel", "MIXPANEL_TOKEN", [r"^[a-zA-Z0-9\-]{32}$"]),
    #[cfg(feature = "service-mattermost")]
    ("mattermost", "Mattermost", "MATTERMOST_TOKEN", [r"^[a-z0-9]{26}$"]),
    #[cfg(feature = "service-meraki")]
    ("meraki", "Cisco Meraki", "MERAKI_API_KEY", [r"^[0-9a-f]{40}$"]),
    #[cfg(feature = "service-messagebird")]
    ("messagebird", "MessageBird", "MESSAGEBIRD_API_KEY", [
      r"^[a-z0-9]{25}$",
    ]),
    #[cfg(feature = "service-netlify")]
    ("netlify", "Netlify", "NETLIFY_AUTH_TOKEN", [
      r"^[a-zA-Z0-9=_\-]{40,46}$",
    ]),
    #[cfg(feature = "service-notion")]
    ("notion", "Notion", "NOTION_API_KEY", [
      r"^secret_[A-Za-z0-9]{43}$",
    ]),
    #[cfg(feature = "service-nytimes")]
    ("nytimes", "NY Times", "NYTIMES_API_KEY", [r"^[a-z0-9=_\-]{32}$"]),
    #[cfg(feature = "service-moralis")]
    ("moralis", "Moralis", "MORALIS_API_KEY", [r"^[a-zA-Z0-9]{32,}$"]),
    #[cfg(feature = "service-okta")]
    ("okta", "Okta", "OKTA_API_TOKEN", [r"^00[a-zA-Z0-9=_\-]{40}$"]),
    #[cfg(feature = "service-optimizely")]
    ("optimizely", "Optimizely", "OPTIMIZELY_API_TOKEN", [
      r"^[0-9A-Za-z\-:]{54}$",
    ]),
    #[cfg(feature = "service-opsgenie")]
    ("opsgenie", "Opsgenie", "OPSGENIE_API_KEY", [
      r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
    ]),
    #[cfg(feature = "service-pagerduty")]
    ("pagerduty", "PagerDuty", "PAGERDUTY_API_KEY", [
      r"^[a-zA-Z0-9+/=_\-]{20}$",
    ]),
    #[cfg(feature = "service-pipedream")]
    ("pipedream", "Pipedream", "PIPEDREAM_API_KEY", [r"^[a-z0-9]{32}$"]),
    #[cfg(feature = "service-plaid")]
    ("plaid", "Plaid", "PLAID_SECRET", [
      r"^access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
      r"^[a-z0-9]{24}$",
      r"^[a-z0-9]{30}$",
    ]),
    #[cfg(feature = "service-pinecone")]
    ("pinecone", "Pinecone", "PINECONE_API_KEY", [
      r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
    ]),
    #[cfg(feature = "service-postmark")]
    ("postmark", "Postmark", "POSTMARK_SERVER_TOKEN", [
      r"^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$",
    ]),
    #[cfg(feature = "service-privateai")]
    ("privateai", "Private AI", "PRIVATEAI_API_KEY", [
      r"^[a-z0-9]{32}$",
    ]),
    #[cfg(feature = "service-qdrant")]
    ("qdrant", "Qdrant", "QDRANT_API_KEY", [r"^[a-zA-Z0-9_\-]{32,}$"]),
    #[cfg(feature = "service-railway")]
    ("railway", "Railway", "RAILWAY_TOKEN", [
      r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
    ]),
    #[cfg(feature = "service-rapidapi")]
    ("rapidapi", "RapidAPI", "RAPIDAPI_KEY", [r"^[a-z0-9_\-]{50}$"]),
    #[cfg(feature = "service-render")]
    ("render", "Render", "RENDER_API_KEY", [r"^rnd_[a-zA-Z0-9]{32,}$"]),
    #[cfg(feature = "service-shodan")]
    ("shodan", "Shodan", "SHODAN_API_KEY", [r"^[a-zA-Z0-9]{32}$"]),
    #[cfg(feature = "service-segment")]
    ("segment", "Segment", "SEGMENT_WRITE_KEY", [
      r"^[A-Za-z0-9_\-]{43}\.[A-Za-z0-9_\-]{43}$",
      r"^[a-zA-Z0-9]{32}$",
    ]),
    #[cfg(feature = "service-sendbird")]
    ("sendbird", "Sendbird", "SENDBIRD_APP_TOKEN", [r"^[a-f0-9]{40}$"]),
    #[cfg(feature = "service-semaphore")]
    ("semaphore", "Semaphore CI", "SEMAPHORE_API_TOKEN", [
      r"^[a-f0-9]{32,}$",
    ]),
    #[cfg(feature = "service-sentry")]
    ("sentry", "Sentry", "SENTRY_DSN", [r"^[a-f0-9]{64}$"]),
    #[cfg(feature = "service-sparkpost")]
    ("sparkpost", "SparkPost", "SPARKPOST_API_KEY", [
      r"^[a-zA-Z0-9]{40}$",
    ]),
    #[cfg(feature = "service-snyk")]
    ("snyk", "Snyk", "SNYK_TOKEN", [
      r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    ]),
    #[cfg(feature = "service-sonar")]
    ("sonar", "SonarQube", "SONAR_TOKEN", [r"^[a-z0-9=_\-]{40}$"]),
    #[cfg(feature = "service-square")]
    ("square", "Square", "SQUARE_ACCESS_TOKEN", [r"^[\w\-+=]{22,60}$"]),
    #[cfg(feature = "service-statuspage")]
    ("statuspage", "Statuspage", "STATUSPAGE_API_KEY", [
      r"^[0-9a-z\-]{36}$",
    ]),
    #[cfg(feature = "service-storyblok")]
    ("storyblok", "Storyblok", "STORYBLOK_API_TOKEN", [
      r"^[0-9A-Za-z]{22}tt$",
    ]),
    #[cfg(feature = "service-squarespace")]
    ("squarespace", "Squarespace", "SQUARESPACE_API_KEY", [
      r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    ]),
    #[cfg(feature = "service-sumo")]
    ("sumo", "Sumo Logic", "SUMO_ACCESS_KEY", [
      r"^su[a-zA-Z0-9]{12}$",
      r"^[a-z0-9]{64}$",
    ]),
    #[cfg(feature = "service-supabase")]
    ("supabase", "Supabase", "SUPABASE_KEY", [r"^[a-zA-Z0-9_\-]{32,}$"]),
    #[cfg(feature = "service-todoist")]
    ("todoist", "Todoist", "TODOIST_API_TOKEN", [r"^[0-9a-z]{40}$"]),
    #[cfg(feature = "service-together")]
    ("together", "Together AI", "TOGETHER_API_KEY", [r"^[a-f0-9]{64}$"]),
    #[cfg(feature = "service-telegram")]
    ("telegram", "Telegram", "TELEGRAM_BOT_TOKEN", [
      r"^[0-9]{5,16}:A[A-Za-z0-9_\-]{34}$",
    ]),
    #[cfg(feature = "service-travis")]
    ("travis", "Travis CI", "TRAVIS_API_TOKEN", [r"^[a-zA-Z0-9_]{22}$"]),
    #[cfg(feature = "service-twitch")]
    ("twitch", "Twitch", "TWITCH_CLIENT_SECRET", [r"^[a-z0-9]{30}$"]),
    #[cfg(feature = "service-typeform")]
    ("typeform", "Typeform", "TYPEFORM_PERSONAL_ACCESS_TOKEN", [
      r"^[a-zA-Z0-9]{44}$",
    ]),
    #[cfg(feature = "service-uptimerobot")]
    ("uptimerobot", "UptimeRobot", "UPTIMEROBOT_API_KEY", [
      r"^[a-zA-Z0-9]{9}-[a-zA-Z0-9]{24}$",
    ]),
    #[cfg(feature = "service-vercel")]
    ("vercel", "Vercel", "VERCEL_TOKEN", [r"^[a-zA-Z0-9]{24}$"]),
    #[cfg(feature = "service-virustotal")]
    ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", [r"^[a-f0-9]{64}$"]),
    #[cfg(feature = "service-vultr")]
    ("vultr", "Vultr", "VULTR_API_KEY", [r"^[A-Z0-9]{36}$"]),
    #[cfg(feature = "service-wandb")]
    ("wandb", "Weights & Biases", "WANDB_API_KEY", [r"^[0-9a-f]{40}$"]),
    #[cfg(feature = "service-webflow")]
    ("webflow", "Webflow", "WEBFLOW_API_TOKEN", [r"^[a-zA-Z0-9]{64}$"]),
    #[cfg(feature = "service-yandex")]
    ("yandex", "Yandex", "YANDEX_OAUTH_TOKEN", [
      r"^t1\.[A-Z0-9a-z_\-]+={0,2}\.[A-Z0-9a-z_\-]{86}={0,2}$",
      r"^YC[a-zA-Z0-9_\-]{38}$",
    ]),
    #[cfg(feature = "service-weaviate")]
    ("weaviate", "Weaviate", "WEAVIATE_API_KEY", [r"^[a-zA-Z0-9]{32,}$"]),
    #[cfg(feature = "service-zendesk")]
    ("zendesk", "Zendesk", "ZENDESK_API_TOKEN", [r"^[a-zA-Z0-9_\-]{40}$"]),
    #[cfg(feature = "service-zerotier")]
    ("zerotier", "ZeroTier", "ZEROTIER_API_TOKEN", [r"^[0-9a-zA-Z]{32}$"]),
  ],
);
