use crate::diagnostic::{
  AssignmentType, SourceFileSpan, SourceSpan, check_assignment, check_value,
  offset_to_position,
};
use crate::languages::embed::{self, Region};
use crate::languages::html;
use crate::processing::SourceContext;
use crate::secrets::{
  names::normalize::normalize_name, values::normalize::normalize_value,
};

// Twig (.twig, Symfony) is HTML with its own templating language: `{{ }}`
// output, `{% %}` tags, `{# #}` comments.
struct TwigContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted: Vec<(usize, usize)>,
}

impl TwigContext<'_> {
  fn already_emitted(&self, start: usize, end: usize) -> bool {
    self
      .emitted
      .iter()
      .any(|(rs, re)| *rs <= start && *re >= end)
  }

  fn record_emitted(&mut self, start: usize, end: usize) {
    self.emitted.push((start, end));
  }
}

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let regions = twig_regions(source);

  let markup = html::scan(context, &embed::mask_markup(source, &regions));

  let mut ctx = TwigContext {
    source,
    source_context: context,
    emitted: Vec::new(),
  };
  let mut scanned = false;
  for region in &regions {
    if let Some(code) = &region.code {
      scan_expression(&mut ctx, code.start, code.end);
      scanned = true;
    }
  }

  markup || scanned
}

fn twig_regions(source: &str) -> Vec<Region> {
  let bytes = source.as_bytes();
  let mut regions = Vec::new();
  let mut i = 0;

  while i < bytes.len() {
    if embed::matches_at(bytes, i, b"{#") {
      let end =
        embed::find_from(source, i + 2, "#}").map_or(bytes.len(), |p| p + 2);
      regions.push(Region::mask(i, end));
      i = end;
    } else if embed::matches_at(bytes, i, b"{{") {
      let (full_end, start, end) = region_bounds(source, i + 2, "}}");
      regions.push(Region::code(i, full_end, start, end, None));
      i = full_end;
    } else if embed::matches_at(bytes, i, b"{%") {
      let (full_end, start, end) = region_bounds(source, i + 2, "%}");
      regions.push(Region::code(i, full_end, start, end, None));
      i = full_end;
    } else {
      i += 1;
    }
  }

  regions
}

// Returns (index past the close, inner start, inner end), stripping the `-`/`~`
// whitespace-trim markers Twig allows on either delimiter.
fn region_bounds(
  source: &str,
  mut start: usize,
  close: &str,
) -> (usize, usize, usize) {
  let bytes = source.as_bytes();
  while bytes.get(start).is_some_and(|c| *c == b'-' || *c == b'~') {
    start += 1;
  }
  match embed::find_from(source, start, close) {
    Some(p) => {
      let end = if p > start
        && bytes.get(p - 1).is_some_and(|c| *c == b'-' || *c == b'~')
      {
        p - 1
      } else {
        p
      };
      (p + 2, start, end)
    }
    None => (bytes.len(), start, bytes.len()),
  }
}

fn scan_expression(ctx: &mut TwigContext, start: usize, end: usize) {
  let source = ctx.source;
  let bytes = source.as_bytes();
  let set = parse_set(bytes, start, end);

  let mut i = start;
  while i < end {
    let quote = bytes[i];
    if quote == b'"' || quote == b'\'' {
      let (after, content_start, content_end, literal) =
        scan_string(bytes, i, end, quote);
      if literal {
        let name = match set {
          Some((name_start, name_end, value_pos))
            if skip_whitespace(bytes, value_pos, end) == i =>
          {
            source.get(name_start..name_end)
          }
          _ => None,
        };
        emit_string(ctx, name, i, after, content_start, content_end);
      }
      i = after;
    } else {
      i += 1;
    }
  }
}

// Recognizes `set <ident> = ...`, returning (name start, name end, the offset
// just past `=`). Block form (`{% set x %}…{% endset %}`) and comparisons
// (`==`) are rejected.
fn parse_set(
  bytes: &[u8],
  start: usize,
  end: usize,
) -> Option<(usize, usize, usize)> {
  let i = skip_whitespace(bytes, start, end);
  if !embed::matches_at(bytes, i, b"set") {
    return None;
  }
  let after_keyword = i + 3;
  if !bytes
    .get(after_keyword)
    .is_some_and(u8::is_ascii_whitespace)
  {
    return None;
  }

  let name_start = skip_whitespace(bytes, after_keyword, end);
  let mut name_end = name_start;
  while name_end < end
    && (bytes[name_end].is_ascii_alphanumeric() || bytes[name_end] == b'_')
  {
    name_end += 1;
  }
  if name_end == name_start {
    return None;
  }

  let equals = skip_whitespace(bytes, name_end, end);
  if bytes.get(equals) != Some(&b'=') || bytes.get(equals + 1) == Some(&b'=') {
    return None;
  }

  Some((name_start, name_end, equals + 1))
}

// Scans a `"..."` or `'...'` string from its opening quote, returning (index
// past the close, content start, content end, is_literal). Double-quoted
// strings with `#{ }` interpolation are not literals.
fn scan_string(
  bytes: &[u8],
  open: usize,
  end: usize,
  quote: u8,
) -> (usize, usize, usize, bool) {
  let content_start = open + 1;
  let mut interpolated = false;
  let mut j = content_start;

  while j < end {
    match bytes[j] {
      b'\\' => j += 2,
      c if c == quote => return (j + 1, content_start, j, !interpolated),
      b'#' if quote == b'"' && bytes.get(j + 1) == Some(&b'{') => {
        interpolated = true;
        j += 1;
      }
      _ => j += 1,
    }
  }

  (end, content_start, end, !interpolated)
}

fn emit_string(
  ctx: &mut TwigContext,
  name: Option<&str>,
  span_start: usize,
  span_end: usize,
  content_start: usize,
  content_end: usize,
) {
  if ctx.already_emitted(span_start, span_end) {
    return;
  }
  let Some(value) = ctx.source.get(content_start..content_end) else {
    return;
  };
  if value.is_empty() {
    return;
  }

  let normalized = normalize_value(&value.to_owned());
  let diagnostic = match name {
    Some(n) => check_assignment(
      &normalize_name(&n.to_owned()),
      &normalized,
      AssignmentType::Variable,
      ctx.source_context,
      || compute_span(ctx, span_start, span_end),
    ),
    None => check_value(&normalized, ctx.source_context, || {
      compute_span(ctx, span_start, span_end)
    }),
  };

  if let Some(d) = diagnostic {
    ctx.record_emitted(span_start, span_end);
    ctx.source_context.emit_diagnostic(d);
  }
}

fn skip_whitespace(bytes: &[u8], from: usize, end: usize) -> usize {
  let mut i = from;
  while i < end && bytes[i].is_ascii_whitespace() {
    i += 1;
  }
  i
}

fn compute_span(ctx: &TwigContext, start: usize, end: usize) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, start),
      end: offset_to_position(ctx.source, end),
    }),
  }
}
