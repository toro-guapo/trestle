use std::path::Path;

pub fn is_credentials_key_file(path: &Path) -> bool {
  let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
    return false;
  };

  if name.eq_ignore_ascii_case("master.key") {
    return true;
  }

  is_environment_credentials_key(path, name)
}

fn is_environment_credentials_key(path: &Path, name: &str) -> bool {
  if !has_key_extension(name) {
    return false;
  }

  let Some(parent) = path.parent() else {
    return false;
  };

  if !directory_is(parent, "credentials") {
    return false;
  }

  parent
    .parent()
    .is_some_and(|grandparent| directory_is(grandparent, "config"))
}

fn has_key_extension(name: &str) -> bool {
  Path::new(name)
    .extension()
    .and_then(|extension| extension.to_str())
    .is_some_and(|extension| extension.eq_ignore_ascii_case("key"))
}

fn directory_is(path: &Path, name: &str) -> bool {
  path
    .file_name()
    .and_then(|component| component.to_str())
    .is_some_and(|component| component.eq_ignore_ascii_case(name))
}

pub fn is_key_material(content: &str) -> bool {
  let trimmed = content.trim();

  trimmed.len() == 32 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
}
