use crate::languages::embed::{self, Region};
use crate::languages::{html, php};
use crate::processing::SourceContext;

// Blade (.blade.php, Laravel) is HTML with embedded PHP via `<?php ?>`,
// `@php ... @endphp`, `{{ }}` / `{!! !!}` echoes, and directives. The markup is
// scanned as HTML with the PHP regions masked, and the PHP code is scanned as
// PHP with the markup masked.
pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let (regions, echoes) = blade_regions(source);

  let markup = html::scan(context, &embed::mask_markup(source, &regions));
  let code = php::scan(context, &embed::build_code(source, &regions, b"<?php"));

  let mut echoed = false;
  for (start, end) in echoes {
    if scan_echo(context, source, start, end) {
      echoed = true;
    }
  }

  markup || code || echoed
}

const ECHO_OPEN: &str = "<?=";

fn scan_echo(
  context: &SourceContext,
  source: &str,
  start: usize,
  end: usize,
) -> bool {
  let Some(raw) = source.get(start..end) else {
    return false;
  };
  let trimmed = raw.trim_start();
  let expr = trimmed.trim_end();
  if expr.is_empty() {
    return false;
  }
  let expr_start = start + (raw.len() - trimmed.len());

  let body = format!("{ECHO_OPEN}{expr}?>");
  let child = SourceContext {
    run: context.run,
    file_abs_path: context.file_abs_path,
    file_extension: context.file_extension,
    body: Some(&body),
    file_type: context.file_type,
    #[cfg(feature = "services")]
    file_services: context.file_services.clone(),
    parent_line: embed::line_at(source, expr_start),
    parent_col: embed::char_column(source, expr_start)
      .saturating_sub(ECHO_OPEN.len()),
    directives: std::cell::OnceCell::new(),
  };

  php::scan(&child, &body)
}

fn blade_regions(source: &str) -> (Vec<Region>, Vec<(usize, usize)>) {
  let bytes = source.as_bytes();
  let mut regions = Vec::new();
  let mut echoes = Vec::new();
  let mut i = 0;

  while i < bytes.len() {
    if embed::matches_at(bytes, i, b"<?php") {
      let start = i + 5;
      let (full_end, end) = match embed::find_from(source, start, "?>") {
        Some(p) => (p + 2, p),
        None => (bytes.len(), bytes.len()),
      };
      regions.push(Region::code(i, full_end, start, end, None));
      i = full_end;
    } else if embed::matches_at(bytes, i, b"<?=") {
      let end =
        embed::find_from(source, i + 3, "?>").map_or(bytes.len(), |p| p + 2);
      regions.push(Region::mask(i, end));
      echoes.push((i + 3, end.saturating_sub(2)));
      i = end;
    } else if embed::matches_at(bytes, i, b"{{--") {
      let end =
        embed::find_from(source, i + 4, "--}}").map_or(bytes.len(), |p| p + 4);
      regions.push(Region::mask(i, end));
      i = end;
    } else if embed::matches_at(bytes, i, b"{!!") {
      let end =
        embed::find_from(source, i + 3, "!!}").map_or(bytes.len(), |p| p + 3);
      regions.push(Region::mask(i, end));
      echoes.push((i + 3, end.saturating_sub(3)));
      i = end;
    } else if embed::matches_at(bytes, i, b"{{") {
      let end =
        embed::find_from(source, i + 2, "}}").map_or(bytes.len(), |p| p + 2);
      regions.push(Region::mask(i, end));
      echoes.push((i + 2, end.saturating_sub(2)));
      i = end;
    } else if is_php_directive(bytes, i) {
      if bytes.get(i + 4) == Some(&b'(') {
        let (full_end, (start, end)) = match_paren(bytes, i + 4);
        regions.push(Region::code(i, full_end, start, end, Some(end)));
        i = full_end;
      } else {
        let start = i + 4;
        let (full_end, end) = match embed::find_from(source, start, "@endphp") {
          Some(p) => (p + 7, p),
          None => (bytes.len(), bytes.len()),
        };
        regions.push(Region::code(i, full_end, start, end, None));
        i = full_end;
      }
    } else {
      i += 1;
    }
  }

  (regions, echoes)
}

fn is_php_directive(bytes: &[u8], i: usize) -> bool {
  embed::matches_at(bytes, i, b"@php")
    && bytes
      .get(i + 4)
      .is_none_or(|c| *c == b'(' || c.is_ascii_whitespace())
}

fn match_paren(bytes: &[u8], open: usize) -> (usize, (usize, usize)) {
  let start = open + 1;
  let mut i = start;
  let mut depth = 1usize;

  while i < bytes.len() {
    match bytes[i] {
      b'\'' => i = skip_quoted(bytes, i, b'\''),
      b'"' => i = skip_quoted(bytes, i, b'"'),
      b'(' => {
        depth += 1;
        i += 1;
      }
      b')' => {
        depth -= 1;
        i += 1;
        if depth == 0 {
          return (i, (start, i - 1));
        }
      }
      _ => i += 1,
    }
  }

  (bytes.len(), (start, bytes.len()))
}

fn skip_quoted(bytes: &[u8], i: usize, quote: u8) -> usize {
  let mut j = i + 1;
  while j < bytes.len() {
    match bytes[j] {
      b'\\' => j += 2,
      c if c == quote => return j + 1,
      _ => j += 1,
    }
  }
  bytes.len()
}
