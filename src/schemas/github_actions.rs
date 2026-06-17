use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  // jobs.build.steps[].run: "PASSWORD=secret ./deploy.sh"
  if info.path.len() >= 2
    && info.path.first() == Some(&"jobs")
    && info.key == "run"
  {
    super::parse_shell_value(info);
    return true;
  }

  false
}
