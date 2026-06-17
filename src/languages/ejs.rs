use crate::languages::embed::{self, Region};
use crate::languages::{html, javascript};
use crate::processing::SourceContext;

// EJS (.ejs) is HTML with embedded JavaScript via `<% %>` scriptlets and
// `<%= %>` / `<%- %>` output tags. The markup is scanned as HTML with the
// JavaScript masked.
pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let regions = ejs_regions(source);

  let markup = html::scan(context, &embed::mask_markup(source, &regions));

  let mut scanned = false;
  for region in &regions {
    let Some(code) = &region.code else {
      continue;
    };

    let Some(raw) = source.get(code.start..code.end) else {
      continue;
    };
    let trimmed = raw.trim_start();
    let expr = trimmed.trim_end();
    if expr.is_empty() {
      continue;
    }

    let expr_start = code.start + (raw.len() - trimmed.len());
    let child = child_context(context, source, expr, expr_start);

    let fired = if is_output(source, region) {
      javascript::scan_client_expression(&child)
    } else {
      javascript::scan_expression(&child)
    };
    scanned = fired || scanned;
  }

  markup || scanned
}

fn child_context<'a>(
  context: &'a SourceContext<'a>,
  source: &str,
  expr: &'a str,
  expr_start: usize,
) -> SourceContext<'a> {
  SourceContext {
    run: context.run,
    file_abs_path: context.file_abs_path,
    file_extension: context.file_extension,
    body: Some(expr),
    file_type: context.file_type,
    #[cfg(feature = "services")]
    file_services: context.file_services.clone(),
    parent_line: embed::line_at(source, expr_start),
    parent_col: embed::char_column(source, expr_start),
    directives: std::cell::OnceCell::new(),
  }
}

// `<%= %>` (escaped) and `<%- %>` (raw) render their expression into the page.
fn is_output(source: &str, region: &Region) -> bool {
  matches!(
    source.as_bytes().get(region.full_start + 2),
    Some(b'=') | Some(b'-')
  )
}

// Locates EJS's JavaScript regions. `<% %>` scriptlets and `<%= %>` / `<%- %>`
// output tags carry JavaScript and are scanned; `<%# %>` comments and the `<%%`
// literal escape are not. `_` whitespace-slurp and `-` trim markers on either
// delimiter are stripped from the scanned expression.
fn ejs_regions(source: &str) -> Vec<Region> {
  let bytes = source.as_bytes();
  let mut regions = Vec::new();
  let mut i = 0;

  while i < bytes.len() {
    if !embed::matches_at(bytes, i, b"<%") {
      i += 1;
      continue;
    }

    match bytes.get(i + 2) {
      // `<%%` escapes a literal `<%`; not a region.
      Some(b'%') => i += 2,
      // `<%# ... %>` comment: masked from markup, not scanned as JavaScript.
      Some(b'#') => {
        let end =
          embed::find_from(source, i + 3, "%>").map_or(bytes.len(), |p| p + 2);
        regions.push(Region::mask(i, end));
        i = end;
      }
      // `<% ... %>` / `<%= ... %>` / `<%- ... %>`: a scriptlet or output tag.
      _ => {
        let mut start = i + 2;
        while bytes
          .get(start)
          .is_some_and(|c| *c == b'=' || *c == b'-' || *c == b'_')
        {
          start += 1;
        }

        let (full_end, end) = match embed::find_from(source, start, "%>") {
          Some(p) => {
            let end = if p > start
              && bytes.get(p - 1).is_some_and(|c| *c == b'-' || *c == b'_')
            {
              p - 1
            } else {
              p
            };
            (p + 2, end)
          }
          None => (bytes.len(), bytes.len()),
        };

        regions.push(Region::code(i, full_end, start, end, None));
        i = full_end;
      }
    }
  }

  regions
}
