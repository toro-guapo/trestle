use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  // steps[].command: "PASSWORD=secret ./deploy.sh"
  // steps[].commands[]: "..."
  if info.key == "command" || info.key == "commands" {
    super::parse_shell_value(info);
    return true;
  }
  false
}
