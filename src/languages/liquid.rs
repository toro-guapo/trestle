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

struct LiquidContext<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  emitted: Vec<(usize, usize)>,
}

impl LiquidContext<'_> {
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

  let regions = liquid_regions(source);

  let markup = html::scan(context, &embed::mask_markup(source, &regions));

  let mut ctx = LiquidContext {
    source,
    source_context: context,
    emitted: Vec::new(),
  };
  let mut scanned = false;
  for region in &regions {
    if let Some(code) = &region.code {
      let is_output =
        source.as_bytes().get(region.full_start + 1) == Some(&b'{');
      scan_region(&mut ctx, code.start, code.end, is_output);
      scanned = true;
    }
  }

  markup || scanned
}

// `{{ }}` output and `{% %}` tags are scanned; `{% comment %}`/`{% raw %}`
// blocks are masked from both the markup and the Liquid scan.
fn liquid_regions(source: &str) -> Vec<Region> {
  let bytes = source.as_bytes();
  let mut regions = Vec::new();
  let mut i = 0;

  while i < bytes.len() {
    if embed::matches_at(bytes, i, b"{{") {
      let (full_end, start, end) = region_bounds(source, i + 2, "}}");
      regions.push(Region::code(i, full_end, start, end, None));
      i = full_end;
    } else if embed::matches_at(bytes, i, b"{%") {
      let (full_end, start, end) = region_bounds(source, i + 2, "%}");
      match first_word(bytes, start, end) {
        Some("comment") => {
          let block_end = block_end(source, full_end, "endcomment");
          regions.push(Region::mask(i, block_end));
          i = block_end;
        }
        Some("raw") => {
          let block_end = block_end(source, full_end, "endraw");
          regions.push(Region::mask(i, block_end));
          i = block_end;
        }
        _ => {
          regions.push(Region::code(i, full_end, start, end, None));
          i = full_end;
        }
      }
    } else {
      i += 1;
    }
  }

  regions
}

// Returns (index past the close, inner start, inner end), stripping the `-`
// whitespace-trim markers Liquid allows on either delimiter.
fn region_bounds(
  source: &str,
  mut start: usize,
  close: &str,
) -> (usize, usize, usize) {
  let bytes = source.as_bytes();
  while bytes.get(start) == Some(&b'-') {
    start += 1;
  }
  match embed::find_from(source, start, close) {
    Some(p) => {
      let end = if p > start && bytes.get(p - 1) == Some(&b'-') {
        p - 1
      } else {
        p
      };
      (p + 2, start, end)
    }
    None => (bytes.len(), start, bytes.len()),
  }
}

// The end of a `{% tag %}...{% endtag %}` block: the offset past the closing
// `%}` of the `end` tag, or the end of the source if unterminated.
fn block_end(source: &str, from: usize, end_tag: &str) -> usize {
  match embed::find_from(source, from, end_tag) {
    Some(p) => {
      embed::find_from(source, p, "%}").map_or(source.len(), |q| q + 2)
    }
    None => source.len(),
  }
}

fn first_word(bytes: &[u8], start: usize, end: usize) -> Option<&str> {
  let i = skip_whitespace(bytes, start, end);
  let mut j = i;
  while j < end && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
    j += 1;
  }
  std::str::from_utf8(bytes.get(i..j)?)
    .ok()
    .filter(|w| !w.is_empty())
}

fn scan_region(
  ctx: &mut LiquidContext,
  start: usize,
  end: usize,
  is_output: bool,
) {
  scan_strings(ctx, start, end);

  let _ = is_output;
}

// Hardcoded literals: a `"..."`/`'...'` string in the region. When it is the
// value of `{% assign name = "..." %}`, the name gives it context.
fn scan_strings(ctx: &mut LiquidContext, start: usize, end: usize) {
  let source = ctx.source;
  let bytes = source.as_bytes();
  let assignment = parse_assign(bytes, start, end);

  let mut i = start;
  while i < end {
    let quote = bytes[i];
    if quote == b'"' || quote == b'\'' {
      let (after, content_start, content_end) =
        scan_string(bytes, i, end, quote);
      let name = match assignment {
        Some((name_start, name_end, value_pos))
          if skip_whitespace(bytes, value_pos, end) == i =>
        {
          source.get(name_start..name_end)
        }
        _ => None,
      };
      emit_string(ctx, name, i, after, content_start, content_end);
      i = after;
    } else {
      i += 1;
    }
  }
}

// Recognizes `assign <ident> = ...`, returning (name start, name end, the
// offset just past `=`).
fn parse_assign(
  bytes: &[u8],
  start: usize,
  end: usize,
) -> Option<(usize, usize, usize)> {
  let i = skip_whitespace(bytes, start, end);
  if !embed::matches_at(bytes, i, b"assign") {
    return None;
  }
  let after_keyword = i + 6;
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

// Scans a `"..."`/`'...'` string from its opening quote, returning (index past
// the close, content start, content end). Liquid string literals are plain.
fn scan_string(
  bytes: &[u8],
  open: usize,
  end: usize,
  quote: u8,
) -> (usize, usize, usize) {
  let content_start = open + 1;
  let mut j = content_start;
  while j < end {
    if bytes[j] == quote {
      return (j + 1, content_start, j);
    }
    j += 1;
  }
  (end, content_start, end)
}

fn emit_string(
  ctx: &mut LiquidContext,
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

fn compute_span(
  ctx: &LiquidContext,
  start: usize,
  end: usize,
) -> SourceFileSpan {
  SourceFileSpan {
    file_abs_path: ctx.source_context.file_abs_path.to_path_buf(),
    file_span: Some(SourceSpan {
      start: offset_to_position(ctx.source, start),
      end: offset_to_position(ctx.source, end),
    }),
  }
}
