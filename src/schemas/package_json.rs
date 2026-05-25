use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  if info.path == ["scripts"] {
    super::parse_shell_value(info);
    return true;
  }
  false
}
