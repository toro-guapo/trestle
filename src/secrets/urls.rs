use percent_encoding::percent_decode_str;
use url::Url;

use crate::{
  processing::SourceContext,
  secrets::{
    names::{classify::classify_normalized_name, normalize::normalize_name},
    values::{
      classify::{
        NamedSecret, ValueClass, classify_named_value, is_placeholder,
      },
      normalize::{NormalizedValue, normalize_value},
    },
  },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlSecretLocation {
  Userinfo,
  Query(Vec<String>),
  Fragment(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlSecret {
  pub kind: UrlKind,
  pub location: UrlSecretLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlKind {
  // Relational databases.
  Postgres,
  Mysql,
  Mssql,
  Oracle,
  Db2,
  Cockroach,
  Clickhouse,
  Snowflake,
  Vertica,

  // Document / key-value stores.
  Mongodb,
  Couchdb,
  Couchbase,
  Cassandra,
  Dynamodb,
  Elasticsearch,
  Redis,
  Etcd,
  Memcached,

  // Streaming / messaging.
  Kafka,
  Rabbit,
  Mqtt,
  Nats,
  Pulsar,
  Stomp,

  // Big data / query engines.
  Hive,
  Presto,
  Druid,
  Pinot,
  Hdfs,

  // Mail.
  Smtp,
  Imap,
  Pop3,

  // Directory / auth.
  Ldap,

  // File transfer / shell.
  Ftp,
  Sftp,
  Ssh,

  // Object storage.
  S3,
  Gcs,
  AzureBlob,

  // VCS.
  Git,

  // Real-time / web.
  Http,
  Websocket,

  // Other.
  Coordination,
  Generic,
}

impl UrlKind {
  pub fn from_scheme(scheme: &str) -> Self {
    match scheme {
      // Relational.
      "postgres" | "postgresql" | "jdbc:postgresql" => Self::Postgres,
      "mysql" | "mariadb" | "jdbc:mysql" | "jdbc:mariadb" => Self::Mysql,
      "mssql" | "sqlserver" | "jdbc:sqlserver" => Self::Mssql,
      "oracle" | "jdbc:oracle" | "oracle:thin" => Self::Oracle,
      "db2" | "jdbc:db2" => Self::Db2,
      "cockroachdb" | "postgresql+cockroachdb" => Self::Cockroach,
      "clickhouse" | "clickhouse+native" | "clickhouse+http" => {
        Self::Clickhouse
      }
      "snowflake" => Self::Snowflake,
      "vertica" | "jdbc:vertica" => Self::Vertica,
      // Document / kv.
      "mongodb" | "mongodb+srv" => Self::Mongodb,
      "couchdb" | "couchdb+ssl" | "couch" => Self::Couchdb,
      "couchbase" | "couchbases" => Self::Couchbase,
      "cassandra" | "cassandras" | "cql" => Self::Cassandra,
      "dynamodb" => Self::Dynamodb,
      "elasticsearch" | "elastic" | "es" | "elasticsearch+https" => {
        Self::Elasticsearch
      }
      "redis" | "rediss" | "redis+sentinel" => Self::Redis,
      "etcd" | "etcd+ssl" => Self::Etcd,
      "memcache" | "memcached" => Self::Memcached,
      // Streaming / messaging.
      "kafka" | "kafka+ssl" | "kafkas" => Self::Kafka,
      "amqp" | "amqps" => Self::Rabbit,
      "mqtt" | "mqtts" | "mqtt+ssl" | "ws+mqtt" | "wss+mqtt" => Self::Mqtt,
      "nats" | "tls" | "nats+tls" | "tls+nats" => Self::Nats,
      "pulsar" | "pulsar+ssl" => Self::Pulsar,
      "stomp" | "stomp+ssl" | "stomps" => Self::Stomp,
      // Big data / query engines.
      "hive" | "hive2" | "jdbc:hive" | "jdbc:hive2" => Self::Hive,
      "presto" | "presto+https" | "jdbc:presto" | "trino" | "jdbc:trino" => {
        Self::Presto
      }
      "druid" | "jdbc:druid" => Self::Druid,
      "pinot" | "jdbc:pinot" => Self::Pinot,
      "hdfs" | "webhdfs" | "swebhdfs" => Self::Hdfs,
      // Mail.
      "smtp" | "smtps" | "submission" | "smtp+starttls" => Self::Smtp,
      "imap" | "imaps" => Self::Imap,
      "pop3" | "pop3s" => Self::Pop3,
      // Directory / auth.
      "ldap" | "ldaps" | "ldap+tls" => Self::Ldap,
      // File transfer / shell.
      "ftp" | "ftps" => Self::Ftp,
      "sftp" => Self::Sftp,
      "ssh" | "ssh+git" | "git+ssh" => Self::Ssh,
      // Object storage.
      "s3" | "s3a" | "s3n" => Self::S3,
      "gs" | "gcs" => Self::Gcs,
      "azure" | "azureblob" | "abfs" | "abfss" | "wasb" | "wasbs" => {
        Self::AzureBlob
      }
      // VCS.
      "git" | "git+https" | "git+http" => Self::Git,
      // Real-time / web.
      "http" | "https" => Self::Http,
      "ws" | "wss" => Self::Websocket,
      // Coordination / discovery.
      "zookeeper" | "zk" | "consul" => Self::Coordination,
      _ => Self::Generic,
    }
  }

  pub fn env_prefix(self) -> &'static str {
    match self {
      Self::Postgres => "POSTGRES",
      Self::Mysql => "MYSQL",
      Self::Mssql => "MSSQL",
      Self::Oracle => "ORACLE",
      Self::Db2 => "DB2",
      Self::Cockroach => "COCKROACH",
      Self::Clickhouse => "CLICKHOUSE",
      Self::Snowflake => "SNOWFLAKE",
      Self::Vertica => "VERTICA",
      Self::Mongodb => "MONGO",
      Self::Couchdb => "COUCHDB",
      Self::Couchbase => "COUCHBASE",
      Self::Cassandra => "CASSANDRA",
      Self::Dynamodb => "DYNAMODB",
      Self::Elasticsearch => "ELASTICSEARCH",
      Self::Redis => "REDIS",
      Self::Etcd => "ETCD",
      Self::Memcached => "MEMCACHED",
      Self::Kafka => "KAFKA",
      Self::Rabbit => "RABBITMQ",
      Self::Mqtt => "MQTT",
      Self::Nats => "NATS",
      Self::Pulsar => "PULSAR",
      Self::Stomp => "STOMP",
      Self::Hive => "HIVE",
      Self::Presto => "PRESTO",
      Self::Druid => "DRUID",
      Self::Pinot => "PINOT",
      Self::Hdfs => "HDFS",
      Self::Smtp => "SMTP",
      Self::Imap => "IMAP",
      Self::Pop3 => "POP3",
      Self::Ldap => "LDAP",
      Self::Ftp => "FTP",
      Self::Sftp => "SFTP",
      Self::Ssh => "SSH",
      Self::S3 => "S3",
      Self::Gcs => "GCS",
      Self::AzureBlob => "AZURE",
      Self::Git => "GIT",
      Self::Http => "API",
      Self::Websocket => "WEBSOCKET",
      Self::Coordination => "COORDINATION",
      Self::Generic => "SERVICE",
    }
  }

  pub fn display_name(self) -> &'static str {
    match self {
      Self::Postgres => "PostgreSQL",
      Self::Mysql => "MySQL",
      Self::Mssql => "SQL Server",
      Self::Oracle => "Oracle",
      Self::Db2 => "Db2",
      Self::Cockroach => "CockroachDB",
      Self::Clickhouse => "ClickHouse",
      Self::Snowflake => "Snowflake",
      Self::Vertica => "Vertica",
      Self::Mongodb => "MongoDB",
      Self::Couchdb => "CouchDB",
      Self::Couchbase => "Couchbase",
      Self::Cassandra => "Cassandra",
      Self::Dynamodb => "DynamoDB",
      Self::Elasticsearch => "Elasticsearch",
      Self::Redis => "Redis",
      Self::Etcd => "etcd",
      Self::Memcached => "Memcached",
      Self::Kafka => "Kafka",
      Self::Rabbit => "RabbitMQ",
      Self::Mqtt => "MQTT",
      Self::Nats => "NATS",
      Self::Pulsar => "Pulsar",
      Self::Stomp => "STOMP",
      Self::Hive => "Hive",
      Self::Presto => "Presto",
      Self::Druid => "Druid",
      Self::Pinot => "Pinot",
      Self::Hdfs => "HDFS",
      Self::Smtp => "SMTP",
      Self::Imap => "IMAP",
      Self::Pop3 => "POP3",
      Self::Ldap => "LDAP",
      Self::Ftp => "FTP",
      Self::Sftp => "SFTP",
      Self::Ssh => "SSH",
      Self::S3 => "S3",
      Self::Gcs => "Google Cloud Storage",
      Self::AzureBlob => "Azure Blob Storage",
      Self::Git => "Git",
      Self::Http => "HTTP",
      Self::Websocket => "WebSocket",
      Self::Coordination => "coordination service",
      Self::Generic => "service",
    }
  }
}

pub fn classify_url(
  value: &NormalizedValue,
  context: &SourceContext,
) -> Option<ValueClass> {
  let parsed = Url::parse(value.original()).ok()?;

  if !parsed.has_authority() {
    return None;
  }

  if is_placeholder(value) {
    return None;
  }

  let kind = UrlKind::from_scheme(parsed.scheme());

  // 1. Password embedded in userinfo (scheme://user:password@host).
  if let Some(password) = parsed.password()
    && !password.is_empty()
    && let Ok(password) = percent_decode_str(password).decode_utf8()
  {
    let normalized_value = normalize_value(&password);
    if !is_placeholder(&normalized_value) {
      return Some(ValueClass::Secret(NamedSecret::Url(UrlSecret {
        kind,
        location: UrlSecretLocation::Userinfo,
      })));
    }
  }

  // 2. Query-string key=value pairs.
  if parsed.query().is_some() {
    let keys = find_secret_params(parsed.query_pairs(), context);
    if !keys.is_empty() {
      return Some(ValueClass::Secret(NamedSecret::Url(UrlSecret {
        kind,
        location: UrlSecretLocation::Query(keys),
      })));
    }
  }

  // 3. Fragment key=value pairs (OAuth implicit flow, etc.).
  if let Some(fragment) = parsed.fragment() {
    let keys =
      find_secret_params(form_urlencoded::parse(fragment.as_bytes()), context);
    if !keys.is_empty() {
      return Some(ValueClass::Secret(NamedSecret::Url(UrlSecret {
        kind,
        location: UrlSecretLocation::Fragment(keys),
      })));
    }
  }

  None
}

fn find_secret_params<'a>(
  pairs: impl Iterator<
    Item = (std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>),
  >,
  context: &SourceContext,
) -> Vec<String> {
  let mut keys = Vec::new();
  for (key, value) in pairs {
    if key.is_empty() || value.is_empty() {
      continue;
    }

    let name = normalize_name(&key);
    let norm_value = normalize_value(&value);

    let Some(name_class) = classify_normalized_name(&name) else {
      continue;
    };

    if classify_named_value(&name_class, &norm_value, context).is_some() {
      keys.push(key.into_owned());
    }
  }
  keys
}
