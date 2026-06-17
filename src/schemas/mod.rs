use std::path::Path;

use crate::languages::FileType;
use crate::processing::{RunContext, SourceContext};

#[cfg(feature = "schema-aws-codebuild")]
pub mod aws_codebuild;
#[cfg(feature = "schema-azure-pipelines")]
pub mod azure_pipelines;
#[cfg(feature = "schema-bitbucket-pipelines")]
pub mod bitbucket_pipelines;
#[cfg(feature = "schema-buildkite")]
pub mod buildkite;
#[cfg(feature = "schema-circleci")]
pub mod circleci;
#[cfg(feature = "schema-docker-compose")]
pub mod docker_compose;
#[cfg(feature = "schema-drone")]
pub mod drone;
#[cfg(feature = "schema-github-actions")]
pub mod github_actions;
#[cfg(feature = "schema-gitlab-ci")]
pub mod gitlab_ci;
#[cfg(feature = "schema-jupyter")]
pub mod jupyter;
#[cfg(feature = "schema-k8s-secret")]
pub mod k8s_secret;
#[cfg(feature = "schema-mcp-config")]
pub mod mcp_config;
#[cfg(feature = "schema-package-json")]
pub mod package_json;
#[cfg(feature = "schema-travis-ci")]
pub mod travis_ci;
#[cfg(feature = "schema-vscode-tasks")]
pub mod vscode_tasks;

pub struct SchemaValue<'a> {
  pub run: &'a RunContext,
  pub file_abs_path: &'a Path,
  pub path: &'a [&'a str],
  pub key: &'a str,
  pub value: &'a str,
  pub parent_line: usize,
  pub parent_col: usize,
}

type SchemaHandler = fn(&SchemaValue) -> bool;

pub fn parse(context: &SourceContext) -> Option<FileType> {
  let path = context.file_abs_path;
  let file_name = path.file_name()?.to_str()?;

  #[cfg(feature = "schema-jupyter")]
  if matches!(path.extension().and_then(|e| e.to_str()), Some("ipynb")) {
    return jupyter::parse(context);
  }

  #[cfg(feature = "lang-json")]
  {
    let match_result: Option<(SchemaHandler, FileType)> = match file_name {
      #[cfg(feature = "schema-package-json")]
      "package.json" => Some((package_json::handle, FileType::PackageJson)),
      #[cfg(feature = "schema-vscode-tasks")]
      "tasks.json" => Some((vscode_tasks::handle, FileType::VscodeTasks)),
      #[cfg(feature = "schema-docker-compose")]
      "docker-compose.json" | "compose.json" => {
        Some((docker_compose::handle, FileType::DockerCompose))
      }
      #[cfg(feature = "schema-mcp-config")]
      "claude_desktop_config.json" | "mcp.json" | ".mcp.json" => {
        Some((mcp_config::handle, FileType::McpConfig))
      }
      _ => None,
    };

    if let Some((handler, file_type)) = match_result {
      return parse_json_schema(context, handler, file_type);
    }
  }

  #[cfg(feature = "lang-yaml")]
  {
    let match_result: Option<(SchemaHandler, FileType)> = match file_name {
      #[cfg(feature = "schema-azure-pipelines")]
      "azure-pipelines.yml" | "azure-pipelines.yaml" => {
        Some((azure_pipelines::handle, FileType::AzurePipelines))
      }
      #[cfg(feature = "schema-aws-codebuild")]
      "buildspec.yml" | "buildspec.yaml" => {
        Some((aws_codebuild::handle, FileType::AwsCodeBuild))
      }
      #[cfg(feature = "schema-bitbucket-pipelines")]
      "bitbucket-pipelines.yml" => {
        Some((bitbucket_pipelines::handle, FileType::BitbucketPipelines))
      }
      #[cfg(feature = "schema-docker-compose")]
      "docker-compose.yml"
      | "docker-compose.yaml"
      | "compose.yml"
      | "compose.yaml" => {
        Some((docker_compose::handle, FileType::DockerCompose))
      }
      #[cfg(feature = "schema-drone")]
      ".drone.yml" | ".drone.yaml" => Some((drone::handle, FileType::Drone)),
      #[cfg(feature = "schema-gitlab-ci")]
      ".gitlab-ci.yml" => Some((gitlab_ci::handle, FileType::GitlabCi)),
      #[cfg(feature = "schema-travis-ci")]
      ".travis.yml" => Some((travis_ci::handle, FileType::TravisCi)),
      _ => None,
    };

    if let Some((handler, file_type)) = match_result {
      return parse_yaml_schema(context, handler, file_type);
    }

    let path_str = path.to_str().unwrap_or_default();

    #[cfg(feature = "schema-github-actions")]
    if (path_str.contains(".github/workflows/")
      || path_str.contains(".github\\workflows\\"))
      && matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml" | "yaml")
      )
    {
      return parse_yaml_schema(
        context,
        github_actions::handle,
        FileType::GithubActions,
      );
    }

    #[cfg(feature = "schema-circleci")]
    if path_str.ends_with(".circleci/config.yml")
      || path_str.ends_with(".circleci/config.yaml")
      || path_str.ends_with(".circleci\\config.yml")
      || path_str.ends_with(".circleci\\config.yaml")
    {
      return parse_yaml_schema(context, circleci::handle, FileType::CircleCi);
    }

    #[cfg(feature = "schema-buildkite")]
    if (path_str.contains(".buildkite/") || path_str.contains(".buildkite\\"))
      && matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml" | "yaml")
      )
    {
      return parse_yaml_schema(
        context,
        buildkite::handle,
        FileType::Buildkite,
      );
    }

    #[cfg(feature = "schema-k8s-secret")]
    if matches!(
      path.extension().and_then(|e| e.to_str()),
      Some("yml" | "yaml")
    ) && context
      .body
      .is_some_and(k8s_secret::looks_like_k8s_manifest)
    {
      return parse_yaml_schema(
        context,
        k8s_secret::handle,
        FileType::K8sSecret,
      );
    }
  }

  None
}

#[cfg(feature = "lang-json")]
fn parse_json_schema(
  context: &SourceContext,
  handler: SchemaHandler,
  file_type: FileType,
) -> Option<FileType> {
  use crate::languages::json;

  let schema_context = SourceContext {
    run: context.run,
    file_abs_path: context.file_abs_path,
    file_extension: Some("json"),
    body: context.body,
    file_type: Some(file_type),
    parent_line: 0,
    parent_col: 0,
    #[cfg(feature = "services")]
    file_services: vec![],
    directives: std::cell::OnceCell::new(),
  };

  json::parse_with_options(
    &schema_context,
    &json::JsonOptions {
      on_value: Some(&handler),
    },
  )
  .then_some(file_type)
}

#[cfg(feature = "lang-yaml")]
fn parse_yaml_schema(
  context: &SourceContext,
  handler: SchemaHandler,
  file_type: FileType,
) -> Option<FileType> {
  use crate::languages::yaml;

  let schema_context = SourceContext {
    run: context.run,
    file_abs_path: context.file_abs_path,
    file_extension: Some("yaml"),
    body: context.body,
    file_type: Some(file_type),
    parent_line: 0,
    parent_col: 0,
    #[cfg(feature = "services")]
    file_services: vec![],
    directives: std::cell::OnceCell::new(),
  };

  yaml::parse_with_options(
    &schema_context,
    &yaml::YamlOptions {
      on_value: Some(&handler),
      embedded: false,
    },
  )
  .then_some(file_type)
}

#[cfg(feature = "lang-shell")]
pub fn parse_shell_value(info: &SchemaValue) {
  parse_shell_value_with(info, info.value);
}

pub fn parse_shell_value_with(info: &SchemaValue, body: &str) {
  let context = SourceContext {
    run: info.run,
    file_abs_path: info.file_abs_path,
    file_extension: None,
    body: Some(body),
    file_type: Some(FileType::Shell),
    parent_line: info.parent_line,
    parent_col: info.parent_col,
    #[cfg(feature = "services")]
    file_services: vec![],
    directives: std::cell::OnceCell::new(),
  };
  crate::languages::shell::parse(&context);
}
