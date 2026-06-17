use crate::languages::embed::{self, Region};
use crate::languages::{html, ruby};
use crate::processing::SourceContext;

// ERB (.erb, Rails/ERuby) is HTML with embedded Ruby via `<% %>` (code) and
// `<%= %>` (output). The markup is scanned as HTML with the Ruby masked, and the
// Ruby is scanned as Ruby with the markup masked.
pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let regions = erb_regions(source);

  let markup = html::scan(context, &embed::mask_markup(source, &regions));
  let spans = output_spans(context, source, &regions);
  let code =
    ruby::scan(context, &embed::build_code(source, &regions, b""), &spans);

  markup || code
}

fn output_spans(
  _context: &SourceContext,
  _source: &str,
  _regions: &[Region],
) -> Vec<(usize, usize)> {
  Vec::new()
}

// Locates ERB's Ruby regions. `<% %>` (code) and `<%= %>` / `<%== %>` (output)
// carry Ruby and are scanned; `<%# %>` comments and the `<%%` literal escape are
// not. `-` whitespace-trim markers on either delimiter are stripped.
fn erb_regions(source: &str) -> Vec<Region> {
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
      // `<%# ... %>` comment: masked from markup, not scanned as Ruby.
      Some(b'#') => {
        let end =
          embed::find_from(source, i + 3, "%>").map_or(bytes.len(), |p| p + 2);
        regions.push(Region::mask(i, end));
        i = end;
      }
      // `<% ... %>` / `<%= ... %>` / `<%- ... -%>`: Ruby code or output.
      _ => {
        let mut start = i + 2;
        while bytes.get(start).is_some_and(|c| *c == b'=' || *c == b'-') {
          start += 1;
        }

        let (full_end, end) = match embed::find_from(source, start, "%>") {
          Some(p) => {
            let end = if p > start && bytes.get(p - 1) == Some(&b'-') {
              p - 1
            } else {
              p
            };
            (p + 2, end)
          }
          None => (bytes.len(), bytes.len()),
        };

        regions.push(Region::code(i, full_end, start, end, Some(end)));
        i = full_end;
      }
    }
  }

  regions
}
