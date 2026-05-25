use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  // phases.build.commands[]: "PASSWORD=secret ./deploy.sh"
  // phases.build.finally[]: "..."
  if info.path.len() >= 2
    && info.path.first() == Some(&"phases")
    && (info.key == "commands" || info.key == "finally")
  {
    super::parse_shell_value(info);
    return true;
  }
  false
}
