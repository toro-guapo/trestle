use std::path::Path;

use crate::{processing::SourceContext, schemas};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
  // Config formats
  DotEnv,
  EditorConfig,
  Esmtprc,
  FlaskEnv,
  GitConfig,
  GitCredentials,
  Ini,
  Netrc,
  Npmrc,
  Pgpass,
  Properties,
  Pypirc,

  // Languages
  Astro,
  Blade,
  CSharp,
  Dart,
  Dockerfile,
  Ejs,
  Erb,
  Go,
  Groovy,
  Hcl,
  Html,
  Java,
  JavaScript,
  Json,
  Kotlin,
  Liquid,
  Php,
  Plist,
  PowerShell,
  Python,
  Razor,
  Redis,
  Ruby,
  Rust,
  Shell,
  Sql,
  Svelte,
  Swift,
  Toml,
  Twig,
  TypeScript,
  Vue,
  Xml,
  Yaml,

  // CI/CD schemas
  AwsCodeBuild,
  AzurePipelines,
  BitbucketPipelines,
  Buildkite,
  CircleCi,
  DockerCompose,
  Drone,
  GithubActions,
  GitlabCi,
  Jupyter,
  K8sSecret,
  McpConfig,
  PackageJson,
  TravisCi,
  VscodeTasks,

  // Binary formats
  Der,
  Gpg,
  Jceks,
  Jks,
  KeePass,

  // Text formats
  Pem,
  Putty,
  RailsMasterKey,
}

impl std::fmt::Display for FileType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let name = match self {
      Self::DotEnv => ".env",
      Self::EditorConfig => "EditorConfig",
      Self::Esmtprc => ".esmtprc",
      Self::FlaskEnv => "Flask .env",
      Self::GitConfig => "Git config",
      Self::GitCredentials => ".git-credentials",
      Self::Ini => "INI",
      Self::Netrc => ".netrc",
      Self::Npmrc => ".npmrc",
      Self::Pgpass => ".pgpass",
      Self::Properties => "Properties",
      Self::Pypirc => ".pypirc",

      Self::Astro => "Astro",
      Self::Blade => "Blade",
      Self::CSharp => "C#",
      Self::Dart => "Dart",
      Self::Dockerfile => "Dockerfile",
      Self::Ejs => "EJS",
      Self::Erb => "ERB",
      Self::Go => "Go",
      Self::Groovy => "Groovy",
      Self::Hcl => "HCL",
      Self::Html => "HTML",
      Self::Java => "Java",
      Self::JavaScript => "JavaScript",
      Self::Json => "JSON",
      Self::Kotlin => "Kotlin",
      Self::Liquid => "Liquid",
      Self::Php => "PHP",
      Self::Plist => "Plist",
      Self::PowerShell => "PowerShell",
      Self::Python => "Python",
      Self::Razor => "Razor",
      Self::Redis => "Redis config",
      Self::Ruby => "Ruby",
      Self::Rust => "Rust",
      Self::Shell => "Shell",
      Self::Sql => "SQL",
      Self::Svelte => "Svelte",
      Self::Swift => "Swift",
      Self::Toml => "TOML",
      Self::Twig => "Twig",
      Self::TypeScript => "TypeScript",
      Self::Vue => "Vue",
      Self::Xml => "XML",
      Self::Yaml => "YAML",

      Self::AwsCodeBuild => "AWS CodeBuild",
      Self::AzurePipelines => "Azure Pipelines",
      Self::BitbucketPipelines => "Bitbucket Pipelines",
      Self::Buildkite => "Buildkite",
      Self::CircleCi => "CircleCI",
      Self::DockerCompose => "Docker Compose",
      Self::Drone => "Drone CI",
      Self::GithubActions => "GitHub Actions",
      Self::GitlabCi => "GitLab CI",
      Self::Jupyter => "Jupyter Notebook",
      Self::K8sSecret => "Kubernetes Secret",
      Self::McpConfig => "MCP config",
      Self::PackageJson => "package.json",
      Self::TravisCi => "Travis CI",
      Self::VscodeTasks => "VS Code Tasks",

      Self::Der => "DER certificate",
      Self::Gpg => "GPG keyring",
      Self::Jceks => "JCEKS keystore",
      Self::Jks => "JKS keystore",
      Self::KeePass => "KeePass database",

      Self::Pem => "PEM",
      Self::Putty => "PuTTY private key",
      Self::RailsMasterKey => "Rails master key",
    };
    write!(f, "{name}")
  }
}

#[cfg(feature = "lang-astro")]
pub mod astro;
#[cfg(feature = "lang-blade")]
pub mod blade;
#[cfg(feature = "lang-config")]
pub mod config;
#[cfg(feature = "lang-csharp")]
pub mod csharp;
#[cfg(feature = "lang-dart")]
pub mod dart;
#[cfg(feature = "lang-dockerfile")]
pub mod dockerfile;
#[cfg(feature = "lang-ejs")]
pub mod ejs;
#[cfg(any(
  feature = "lang-blade",
  feature = "lang-erb",
  feature = "lang-razor",
  feature = "lang-twig"
))]
pub mod embed;
#[cfg(feature = "lang-erb")]
pub mod erb;
#[cfg(feature = "lang-go")]
pub mod go;
#[cfg(feature = "lang-groovy")]
pub mod groovy;
#[cfg(feature = "lang-hcl")]
pub mod hcl;
#[cfg(feature = "lang-html")]
pub mod html;
#[cfg(feature = "lang-java")]
pub mod java;
#[cfg(feature = "lang-javascript")]
pub mod javascript;
#[cfg(feature = "lang-json")]
pub mod json;
#[cfg(feature = "lang-kotlin")]
pub mod kotlin;
#[cfg(feature = "lang-liquid")]
pub mod liquid;
#[cfg(feature = "lang-php")]
pub mod php;
#[cfg(feature = "lang-plist")]
pub mod plist;
#[cfg(feature = "lang-powershell")]
pub mod powershell;
#[cfg(feature = "lang-python")]
pub mod python;
#[cfg(feature = "lang-razor")]
pub mod razor;
#[cfg(feature = "lang-redis")]
pub mod redis;
#[cfg(feature = "lang-ruby")]
pub mod ruby;
#[cfg(feature = "lang-rust")]
pub mod rust;
#[cfg(any(
  feature = "lang-astro",
  feature = "lang-svelte",
  feature = "lang-vue",
  feature = "lang-html"
))]
pub mod sfc;
#[cfg(feature = "lang-shell")]
pub mod shell;
#[cfg(feature = "lang-sql")]
pub mod sql;
#[cfg(feature = "lang-svelte")]
pub mod svelte;
#[cfg(feature = "lang-swift")]
pub mod swift;
#[cfg(feature = "lang-toml")]
pub mod toml;
#[cfg(feature = "lang-twig")]
pub mod twig;
#[cfg(feature = "lang-vue")]
pub mod vue;
#[cfg(feature = "lang-xml")]
pub mod xml;
#[cfg(feature = "lang-yaml")]
pub mod yaml;

pub fn is_redis_conf_filename(file_name_lower: &str) -> bool {
  if !file_name_lower.ends_with(".conf") {
    return false;
  }

  file_name_lower == "redis.conf"
    || file_name_lower.starts_with("redis-")
    || file_name_lower == "sentinel.conf"
    || file_name_lower.starts_with("sentinel-")
}

pub fn is_env_file(path: &Path) -> bool {
  matches!(
    file_type_from_path(path),
    Some(FileType::DotEnv | FileType::FlaskEnv)
  )
}

pub fn is_wp_config_file(path: &Path) -> bool {
  path
    .file_name()
    .and_then(|f| f.to_str())
    .map(|n| n.eq_ignore_ascii_case("wp-config.php"))
    .unwrap_or(false)
}

pub fn is_credential_file(path: &Path) -> bool {
  is_env_file(path) || is_wp_config_file(path)
}

pub fn is_declarative_config_file(path: &Path) -> bool {
  matches!(
    file_type_from_path(path),
    Some(
      FileType::DotEnv
        | FileType::FlaskEnv
        | FileType::GitConfig
        | FileType::Npmrc
        | FileType::Pypirc
        | FileType::EditorConfig
        | FileType::Ini
        | FileType::Properties
        | FileType::Json
        | FileType::Yaml
        | FileType::Toml
        | FileType::Xml
        | FileType::Hcl
        | FileType::Plist
    )
  )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDatabaseFile {
  SystemAccount,
  Htpasswd,
  Htdigest,
}

pub fn user_database_file(path: &Path) -> Option<UserDatabaseFile> {
  path
    .file_name()
    .and_then(|f| f.to_str())
    .map(str::to_ascii_lowercase)
    .and_then(|name| match name.as_str() {
      "shadow" | "gshadow" | "passwd" | "master.passwd" => {
        Some(UserDatabaseFile::SystemAccount)
      }
      ".htpasswd" => Some(UserDatabaseFile::Htpasswd),
      ".htdigest" => Some(UserDatabaseFile::Htdigest),
      _ => None,
    })
}

pub fn is_user_database_file(path: &Path) -> bool {
  user_database_file(path).is_some()
}

pub fn file_type_from_path(path: &Path) -> Option<FileType> {
  let file_name_lower = path
    .file_name()
    .and_then(|f| f.to_str())
    .map(str::to_ascii_lowercase)
    .unwrap_or_default();

  let extension_lower = path
    .extension()
    .and_then(|e| e.to_str())
    .map(str::to_ascii_lowercase);

  if file_name_lower == ".env" || file_name_lower.starts_with(".env.") {
    return Some(FileType::DotEnv);
  }
  if file_name_lower == ".flaskenv" {
    return Some(FileType::FlaskEnv);
  }
  if file_name_lower == ".gitconfig" {
    return Some(FileType::GitConfig);
  }
  if file_name_lower == ".git-credentials" {
    return Some(FileType::GitCredentials);
  }
  if file_name_lower == ".npmrc" {
    return Some(FileType::Npmrc);
  }
  if file_name_lower == ".pypirc" {
    return Some(FileType::Pypirc);
  }
  if file_name_lower == ".editorconfig" {
    return Some(FileType::EditorConfig);
  }
  if file_name_lower == ".ftpconfig" {
    return Some(FileType::Json);
  }
  if file_name_lower == ".netrc" || file_name_lower == "_netrc" {
    return Some(FileType::Netrc);
  }
  if file_name_lower == ".pgpass" {
    return Some(FileType::Pgpass);
  }
  if file_name_lower == ".esmtprc" {
    return Some(FileType::Esmtprc);
  }
  if file_name_lower == "dockerfile"
    || file_name_lower.starts_with("dockerfile.")
    || file_name_lower.ends_with(".dockerfile")
  {
    return Some(FileType::Dockerfile);
  }
  if is_redis_conf_filename(&file_name_lower) {
    return Some(FileType::Redis);
  }
  if matches!(
    file_name_lower.as_str(),
    "gemfile" | "rakefile" | "podfile" | "guardfile" | "vagrantfile"
  ) {
    return Some(FileType::Ruby);
  }
  if file_name_lower == "jenkinsfile"
    || file_name_lower.starts_with("jenkinsfile.")
    || file_name_lower.ends_with(".jenkinsfile")
  {
    return Some(FileType::Groovy);
  }
  if file_name_lower.ends_with(".blade.php") {
    return Some(FileType::Blade);
  }

  match extension_lower.as_deref() {
    Some("astro") => Some(FileType::Astro),
    Some("cs" | "csx") => Some(FileType::CSharp),
    Some("js" | "jsx" | "mjs" | "cjs") => Some(FileType::JavaScript),
    Some("ts" | "tsx" | "mts" | "cts") => Some(FileType::TypeScript),
    Some("dart") => Some(FileType::Dart),
    Some("ejs") => Some(FileType::Ejs),
    Some("erb") => Some(FileType::Erb),
    Some("go") => Some(FileType::Go),
    Some("groovy" | "gradle" | "gvy" | "gy") => Some(FileType::Groovy),
    Some("html" | "htm" | "xhtml") => Some(FileType::Html),
    Some("java") => Some(FileType::Java),
    Some("kt" | "kts") => Some(FileType::Kotlin),
    Some("json" | "jsonc" | "tfstate") => Some(FileType::Json),
    Some("liquid") => Some(FileType::Liquid),
    Some("php") => Some(FileType::Php),
    Some("py" | "pyi") => Some(FileType::Python),
    Some("razor" | "cshtml") => Some(FileType::Razor),
    Some("rb" | "rake" | "gemspec") => Some(FileType::Ruby),
    Some("rs") => Some(FileType::Rust),
    Some("sh" | "bash" | "zsh") => Some(FileType::Shell),
    Some("sql" | "psql" | "pgsql" | "ddl") => Some(FileType::Sql),
    Some("svelte") => Some(FileType::Svelte),
    Some("swift") => Some(FileType::Swift),
    Some("vue") => Some(FileType::Vue),
    Some("tf" | "tfvars" | "hcl") => Some(FileType::Hcl),
    Some("plist") => Some(FileType::Plist),
    Some("ps1" | "psm1" | "psd1") => Some(FileType::PowerShell),
    Some("properties") => Some(FileType::Properties),
    Some("ini" | "cfg" | "conf" | "cnf") => Some(FileType::Ini),
    Some("env") => Some(FileType::DotEnv),
    Some(
      "xml" | "config" | "csproj" | "vbproj" | "fsproj" | "props" | "targets",
    ) => Some(FileType::Xml),
    Some("toml") => Some(FileType::Toml),
    Some("twig") => Some(FileType::Twig),
    Some("yml" | "yaml") => Some(FileType::Yaml),
    Some("ipynb") => Some(FileType::Jupyter),
    None => Some(FileType::Ini),
    Some(_) => None,
  }
}

pub fn parse(context: &SourceContext) -> Option<FileType> {
  if let Some(file_type) = schemas::parse(context) {
    return Some(file_type);
  }

  let file_type = resolve_file_type(context, context.file_abs_path)?;

  if dispatch_parse(context, file_type) {
    Some(file_type)
  } else {
    None
  }
}

fn resolve_file_type(context: &SourceContext, path: &Path) -> Option<FileType> {
  let initial = file_type_from_path(path);

  if initial == Some(FileType::Ini) && path.extension().is_none() {
    let source = context.body.unwrap_or("");

    if looks_like_whole_file_secret(source) {
      return None;
    }

    if let Some(interp) = shebang_interpreter(source)
      && let Some(ft) = filetype_from_interpreter(interp)
    {
      return Some(ft);
    }
  }

  initial
}

fn looks_like_whole_file_secret(source: &str) -> bool {
  let first = source.trim_start();
  first.starts_with("-----BEGIN ") || first.starts_with("PuTTY-User-Key-File-")
}

fn dispatch_parse(context: &SourceContext, file_type: FileType) -> bool {
  match file_type {
    #[cfg(feature = "lang-astro")]
    FileType::Astro => astro::parse(context),
    #[cfg(feature = "lang-blade")]
    FileType::Blade => blade::parse(context),
    #[cfg(feature = "lang-csharp")]
    FileType::CSharp => csharp::parse(context),
    #[cfg(feature = "lang-javascript")]
    FileType::JavaScript | FileType::TypeScript => javascript::parse(context),
    #[cfg(feature = "lang-dart")]
    FileType::Dart => dart::parse(context),
    #[cfg(feature = "lang-go")]
    FileType::Go => go::parse(context),
    #[cfg(feature = "lang-groovy")]
    FileType::Groovy => groovy::parse(context),
    #[cfg(feature = "lang-java")]
    FileType::Java => java::parse(context),
    #[cfg(feature = "lang-json")]
    FileType::Json => json::parse(context),
    #[cfg(feature = "lang-kotlin")]
    FileType::Kotlin => kotlin::parse(context),
    #[cfg(feature = "lang-liquid")]
    FileType::Liquid => liquid::parse(context),
    #[cfg(feature = "lang-php")]
    FileType::Php => php::parse(context),
    #[cfg(feature = "lang-python")]
    FileType::Python => python::parse(context),
    #[cfg(feature = "lang-razor")]
    FileType::Razor => razor::parse(context),
    #[cfg(feature = "lang-ruby")]
    FileType::Ruby => ruby::parse(context),
    #[cfg(feature = "lang-rust")]
    FileType::Rust => rust::parse(context),
    #[cfg(feature = "lang-shell")]
    FileType::Shell => shell::parse(context),
    #[cfg(feature = "lang-sql")]
    FileType::Sql => sql::parse(context),
    #[cfg(feature = "lang-svelte")]
    FileType::Svelte => svelte::parse(context),
    #[cfg(feature = "lang-swift")]
    FileType::Swift => swift::parse(context),
    #[cfg(feature = "lang-vue")]
    FileType::Vue => vue::parse(context),
    #[cfg(feature = "lang-hcl")]
    FileType::Hcl => hcl::parse(context),
    #[cfg(feature = "lang-html")]
    FileType::Html => html::parse(context),
    #[cfg(feature = "lang-plist")]
    FileType::Plist => plist::parse(context),
    #[cfg(feature = "lang-powershell")]
    FileType::PowerShell => powershell::parse(context),
    #[cfg(feature = "lang-dockerfile")]
    FileType::Dockerfile => dockerfile::parse(context),
    #[cfg(feature = "lang-ejs")]
    FileType::Ejs => ejs::parse(context),
    #[cfg(feature = "lang-erb")]
    FileType::Erb => erb::parse(context),
    #[cfg(feature = "lang-redis")]
    FileType::Redis => redis::parse(context),
    #[cfg(feature = "lang-xml")]
    FileType::Xml => xml::parse(context),
    #[cfg(feature = "lang-toml")]
    FileType::Toml => toml::parse(context),
    #[cfg(feature = "lang-twig")]
    FileType::Twig => twig::parse(context),
    #[cfg(feature = "lang-yaml")]
    FileType::Yaml => yaml::parse(context),
    #[cfg(feature = "lang-config")]
    FileType::DotEnv
    | FileType::FlaskEnv
    | FileType::GitConfig
    | FileType::Npmrc
    | FileType::Pypirc
    | FileType::EditorConfig
    | FileType::Ini
    | FileType::Properties => config::parse(context),
    #[cfg(feature = "lang-config")]
    FileType::GitCredentials => config::parse_git_credentials(context),
    #[cfg(feature = "lang-config")]
    FileType::Netrc => config::parse_netrc(context),
    #[cfg(feature = "lang-config")]
    FileType::Pgpass => config::parse_pgpass(context),
    #[cfg(feature = "lang-config")]
    FileType::Esmtprc => config::parse_esmtprc(context),
    _ => false,
  }
}

fn filetype_from_interpreter(interpreter: &str) -> Option<FileType> {
  if matches!(interpreter, "sh" | "bash" | "zsh" | "ksh" | "ash" | "dash") {
    return Some(FileType::Shell);
  }
  if interpreter.starts_with("python") {
    return Some(FileType::Python);
  }
  if interpreter.starts_with("ruby") {
    return Some(FileType::Ruby);
  }
  if interpreter.starts_with("node") || matches!(interpreter, "deno" | "bun") {
    return Some(FileType::JavaScript);
  }
  if interpreter == "php" {
    return Some(FileType::Php);
  }
  None
}

fn shebang_interpreter(source: &str) -> Option<&str> {
  let first_line = source.lines().next()?;
  let rest = first_line.strip_prefix("#!")?.trim_start();
  let mut tokens = rest.split_ascii_whitespace();
  let first = tokens.next()?;
  let basename = first.rsplit('/').next().unwrap_or(first);

  if basename == "env" {
    let interp = tokens.next()?;
    Some(interp.rsplit('/').next().unwrap_or(interp))
  } else {
    Some(basename)
  }
}
