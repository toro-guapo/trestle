use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  // steps[].commands[]: "PASSWORD=secret ./deploy.sh"
  if info.key == "commands" {
    super::parse_shell_value(info);
    return true;
  }
  false
}
