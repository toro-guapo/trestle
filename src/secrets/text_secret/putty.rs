use crate::secrets::putty::Finding;

pub fn is_whole_file(content: &str, findings: &[Finding]) -> bool {
  if findings.is_empty() {
    return false;
  }
  let ranges: Vec<_> = findings.iter().map(|f| f.byte_range.clone()).collect();
  super::is_only_filler_around(content, &ranges)
}
