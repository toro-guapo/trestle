use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  // pipelines.default[].step.script[]: "PASSWORD=secret ./deploy.sh"
  if info.key == "script" {
    super::parse_shell_value(info);
    return true;
  }
  false
}
