use std::fmt::Display;

pub const EXIT_CODE_SUCCESS: i32 = 0;
pub const EXIT_CODE_FINDINGS: i32 = 1;
pub const EXIT_CODE_ERROR: i32 = 2;

pub struct ExitCodeInfo {
  pub code: i32,
  pub description: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/exit_codes.rs"));

pub fn exit_with_findings() -> ! {
  std::process::exit(EXIT_CODE_FINDINGS);
}

pub fn exit_with_error(message: impl Display) -> ! {
  eprintln!("{message}");
  std::process::exit(EXIT_CODE_ERROR);
}
