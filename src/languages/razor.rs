use crate::languages::embed::{self, Region};
use crate::languages::{csharp, html};
use crate::processing::SourceContext;

pub fn parse(context: &SourceContext) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let (regions, output_spans) = csharp_regions(source);

  let markup = html::scan(context, &embed::mask_markup(source, &regions));
  let code = csharp::scan(
    context,
    &embed::build_code(source, &regions, b""),
    &output_spans,
  );

  markup || code
}

// Returns the C# code regions along with the byte ranges of output expressions
// (`@expr`, `@(expr)`), whose value renders into the page.
fn csharp_regions(source: &str) -> (Vec<Region>, Vec<(usize, usize)>) {
  let bytes = source.as_bytes();
  let mut regions = Vec::new();
  let mut outputs = Vec::new();
  let mut i = 0;

  while i < bytes.len() {
    if bytes[i] != b'@' {
      i += 1;
      continue;
    }

    match bytes.get(i + 1) {
      Some(b'@') => i += 2,
      Some(b'*') => {
        let end =
          find_subsequence(bytes, i + 2, b"*@").map_or(bytes.len(), |p| p + 2);
        regions.push(Region::mask(i, end));
        i = end;
      }
      // `@{ ... }` is a statement block, not output.
      Some(b'{') => {
        let (end, (start, inner_end)) =
          match_delimited(bytes, i + 1, b'{', b'}');
        regions.push(Region::code(i, end, start, inner_end, None));
        i = end;
      }
      // `@( expr )` renders `expr`.
      Some(b'(') => {
        let (end, (start, inner_end)) =
          match_delimited(bytes, i + 1, b'(', b')');
        regions.push(Region::code(i, end, start, inner_end, Some(inner_end)));
        outputs.push((start, inner_end));
        i = end;
      }
      Some(&c) if c.is_ascii_alphabetic() || c == b'_' => {
        let word_end = identifier_end(bytes, i + 1);
        let brace = skip_spaces(bytes, word_end);
        let keyword = source.get(i + 1..word_end).unwrap_or("");
        if matches!(keyword, "code" | "functions")
          && bytes.get(brace) == Some(&b'{')
        {
          let (end, (start, inner_end)) =
            match_delimited(bytes, brace, b'{', b'}');
          regions.push(Region::code(i, end, start, inner_end, None));
          i = end;
        } else {
          let chain_end = implicit_chain_end(bytes, word_end);
          // A control-flow or directive keyword (`@if`, `@foreach`, `@model`)
          // is not an output expression.
          let is_output = !is_non_output_keyword(keyword);
          if bytes.get(chain_end) == Some(&b'(') {
            // The whole call, receiver included, is the C# expression
            // (`@Environment.GetEnvironmentVariable("X")`), so scan from `@`
            // through the closing paren - not just the parenthesized arguments.
            let (end, _) = match_delimited(bytes, chain_end, b'(', b')');
            let semi = is_output.then_some(end);
            regions.push(Region::code(i, end, i + 1, end, semi));
            if is_output {
              outputs.push((i + 1, end));
            }
            i = end;
          } else if is_output {
            // `@token` / `@Model.ApiKey` - an implicit expression.
            regions.push(Region::code(
              i,
              chain_end,
              i + 1,
              chain_end,
              Some(chain_end),
            ));
            outputs.push((i + 1, chain_end));
            i = chain_end;
          } else {
            i = word_end;
          }
        }
      }
      _ => i += 1,
    }
  }

  (regions, outputs)
}

fn is_non_output_keyword(keyword: &str) -> bool {
  matches!(
    keyword,
    "if"
      | "else"
      | "for"
      | "foreach"
      | "while"
      | "do"
      | "switch"
      | "case"
      | "default"
      | "using"
      | "lock"
      | "try"
      | "catch"
      | "finally"
      | "fixed"
      | "checked"
      | "unchecked"
      | "return"
      | "throw"
      | "yield"
      | "break"
      | "continue"
      | "goto"
      | "await"
      | "new"
      | "model"
      | "inject"
      | "inherits"
      | "page"
      | "namespace"
      | "implements"
      | "typeparam"
      | "section"
      | "layout"
      | "rendermode"
      | "addTagHelper"
      | "removeTagHelper"
      | "tagHelperPrefix"
      | "attribute"
      | "preservewhitespace"
      | "code"
      | "functions"
  )
}

fn match_delimited(
  bytes: &[u8],
  open: usize,
  open_ch: u8,
  close_ch: u8,
) -> (usize, (usize, usize)) {
  let inner_start = open + 1;
  let mut i = inner_start;
  let mut depth = 1usize;

  while i < bytes.len() {
    let b = bytes[i];
    if b == b'@' && bytes.get(i + 1) == Some(&b'"') {
      i = skip_verbatim_string(bytes, i + 1);
    } else if b == b'"' {
      i = skip_string(bytes, i);
    } else if b == b'\'' {
      i = skip_char(bytes, i);
    } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
      i = find_subsequence(bytes, i + 2, b"\n").map_or(bytes.len(), |p| p);
    } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
      i = find_subsequence(bytes, i + 2, b"*/").map_or(bytes.len(), |p| p + 2);
    } else if b == open_ch {
      depth += 1;
      i += 1;
    } else if b == close_ch {
      depth -= 1;
      i += 1;
      if depth == 0 {
        return (i, (inner_start, i - 1));
      }
    } else {
      i += 1;
    }
  }

  (bytes.len(), (inner_start, bytes.len()))
}

fn skip_string(bytes: &[u8], i: usize) -> usize {
  if bytes.get(i + 1) == Some(&b'"') && bytes.get(i + 2) == Some(&b'"') {
    return find_subsequence(bytes, i + 3, b"\"\"\"")
      .map_or(bytes.len(), |p| p + 3);
  }

  let mut j = i + 1;
  while j < bytes.len() {
    match bytes[j] {
      b'\\' => j += 2,
      b'"' => return j + 1,
      _ => j += 1,
    }
  }

  bytes.len()
}

fn skip_verbatim_string(bytes: &[u8], i: usize) -> usize {
  let mut j = i + 1;

  while j < bytes.len() {
    if bytes[j] == b'"' {
      if bytes.get(j + 1) == Some(&b'"') {
        j += 2;
      } else {
        return j + 1;
      }
    } else {
      j += 1;
    }
  }

  bytes.len()
}

fn skip_char(bytes: &[u8], i: usize) -> usize {
  let mut j = i + 1;

  while j < bytes.len() {
    match bytes[j] {
      b'\\' => j += 2,
      b'\'' => return j + 1,
      _ => j += 1,
    }
  }

  bytes.len()
}

fn find_subsequence(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || from > bytes.len() {
    return None;
  }

  (from..=bytes.len().saturating_sub(needle.len()))
    .find(|&k| &bytes[k..k + needle.len()] == needle)
}

fn identifier_end(bytes: &[u8], from: usize) -> usize {
  let mut j = from;
  while j < bytes.len()
    && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
  {
    j += 1;
  }
  j
}

fn implicit_chain_end(bytes: &[u8], from: usize) -> usize {
  let mut j = from;
  while bytes.get(j) == Some(&b'.')
    && bytes
      .get(j + 1)
      .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
  {
    j = identifier_end(bytes, j + 1);
  }
  j
}

fn skip_spaces(bytes: &[u8], from: usize) -> usize {
  let mut j = from;
  while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
    j += 1;
  }
  j
}
