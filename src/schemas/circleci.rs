use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  // jobs.build.steps[].run: "PASSWORD=secret ./deploy.sh"
  // jobs.build.steps[].run.command: "..."
  if info.path.len() >= 2
    && info.path.first() == Some(&"jobs")
    && (info.key == "run" || info.key == "command")
  {
    super::parse_shell_value(info);
    return true;
  }
  false
}
