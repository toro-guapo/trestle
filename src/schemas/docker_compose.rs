use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  // services.web.command: "PASSWORD=secret ./start.sh"
  // services.web.entrypoint: "PASSWORD=secret ./entry.sh"
  if info.path.len() == 2
    && info.path.first() == Some(&"services")
    && (info.key == "command" || info.key == "entrypoint")
  {
    super::parse_shell_value(info);
    return true;
  }
  false
}
