use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  if info.key == "script"
    || info.key == "before_script"
    || info.key == "after_script"
  {
    super::parse_shell_value(info);
    return true;
  }
  false
}
