use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  if info.path == ["tasks"] && info.key == "command" {
    super::parse_shell_value(info);
    return true;
  }
  false
}
