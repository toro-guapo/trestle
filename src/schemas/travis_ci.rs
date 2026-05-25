use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  if info.path.is_empty()
    && (info.key == "script"
      || info.key == "before_script"
      || info.key == "after_script"
      || info.key == "before_install"
      || info.key == "install")
  {
    super::parse_shell_value(info);
    return true;
  }
  false
}
