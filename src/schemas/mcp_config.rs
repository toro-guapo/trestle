use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  if info.path.len() == 2
    && info.path.first() == Some(&"mcpServers")
    && info.key == "command"
  {
    super::parse_shell_value(info);
    return true;
  }
  false
}
