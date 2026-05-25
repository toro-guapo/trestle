use crate::schemas::SchemaValue;

pub fn handle(info: &SchemaValue) -> bool {
  // steps[].script: "PASSWORD=secret ./deploy.sh"
  // steps[].bash: "..."
  // steps[].powershell: "..."
  if info.key == "script" || info.key == "bash" || info.key == "powershell" {
    super::parse_shell_value(info);
    return true;
  }
  false
}
