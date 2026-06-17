use yaml_rust2::{
  parser::{Event, MarkedEventReceiver, Parser},
  scanner::{Marker, TScalarStyle},
};

use crate::{
  diagnostic::{
    AssignmentType, SourceFileSpan, check_assignment,
    check_assignment_in_scope, check_value, compute_file_span,
  },
  processing::SourceContext,
  schemas::SchemaValue,
  secrets::{
    names::normalize::normalize_name, values::normalize::normalize_value,
  },
};

pub type SchemaHandler<'a> = &'a dyn Fn(&SchemaValue) -> bool;

pub struct YamlOptions<'a> {
  pub on_value: Option<SchemaHandler<'a>>,
  pub embedded: bool,
}

struct StackEntry {
  is_mapping: bool,
  parent_key: Option<String>,
  name_field: Option<String>,
  value_field: Option<(String, Marker, TScalarStyle)>,
}

struct YamlHandler<'a> {
  source: &'a str,
  source_context: &'a SourceContext<'a>,
  stack: Vec<StackEntry>,
  pending_key: Option<(String, Marker)>,
  on_value: Option<SchemaHandler<'a>>,
  embedded: bool,
}

impl MarkedEventReceiver for YamlHandler<'_> {
  fn on_event(&mut self, ev: Event, mark: Marker) {
    match ev {
      Event::MappingStart(..) => {
        let parent_key = self.pending_key.take().map(|(key, _)| key);
        self.stack.push(StackEntry {
          is_mapping: true,
          parent_key,
          name_field: None,
          value_field: None,
        });
      }
      Event::MappingEnd => {
        self.check_name_value_pair();
        self.stack.pop();
      }
      Event::SequenceStart(..) => {
        let parent_key = self.pending_key.take().map(|(key, _)| key);
        self.stack.push(StackEntry {
          is_mapping: false,
          parent_key,
          name_field: None,
          value_field: None,
        });
      }
      Event::SequenceEnd => {
        self.stack.pop();
      }
      Event::Scalar(value, style, ..) => {
        self.process_scalar(value, style, mark);
      }
      Event::Alias(..) => {
        self.pending_key.take();
      }
      _ => {}
    }
  }
}

impl YamlHandler<'_> {
  fn process_scalar(
    &mut self,
    value: String,
    style: TScalarStyle,
    mark: Marker,
  ) {
    let is_mapping = self.stack.last().is_some_and(|entry| entry.is_mapping);

    if is_mapping {
      if let Some((key, _)) = self.pending_key.take() {
        // Track name/key and value fields for correlation.
        if key == "name" || key == "key" {
          if let Some(entry) = self.stack.last_mut() {
            entry.name_field = Some(value.clone());
          }
        } else if key == "value"
          && let Some(entry) = self.stack.last_mut()
        {
          entry.value_field = Some((value.clone(), mark, style));
        }

        if value.is_empty() {
          return;
        }

        // Call schema handler if present.
        let handled = if let Some(handler) = self.on_value {
          let path_owned: Vec<String> = self
            .stack
            .iter()
            .filter_map(|e| e.parent_key.clone())
            .collect();
          let path: Vec<&str> = path_owned.iter().map(|s| s.as_str()).collect();
          let info = SchemaValue {
            run: self.source_context.run,
            file_abs_path: self.source_context.file_abs_path,
            path: &path,
            key: &key,
            value: &value,
            parent_line: self.source_context.parent_line
              + mark.line().saturating_sub(1),
            parent_col: self.source_context.parent_col + mark.col(),
          };
          handler(&info)
        } else {
          false
        };

        if !handled {
          let scope_owned: Vec<String> = self
            .stack
            .iter()
            .filter_map(|e| e.parent_key.clone())
            .collect();
          let scope: Vec<&str> =
            scope_owned.iter().map(String::as_str).collect();
          if let Some(d) = check_assignment_in_scope(
            &scope,
            &normalize_name(&key),
            &normalize_value(&value),
            AssignmentType::Element,
            self.source_context,
            || scalar_span(self, mark, style, value.len()),
          ) {
            self.source_context.emit_diagnostic(d);
          }

          embedded_scan(self, &value, mark);
        }
      } else {
        self.pending_key = Some((value, mark));
      }
    } else {
      // Sequence element.
      if !value.is_empty() {
        if let Some(d) =
          check_value(&normalize_value(&value), self.source_context, || {
            scalar_span(self, mark, style, value.len())
          })
        {
          self.source_context.emit_diagnostic(d);
        }

        embedded_scan(self, &value, mark);
      }
    }
  }

  /// At MappingEnd, check if this mapping had a name/key + value pair.
  fn check_name_value_pair(&mut self) {
    let (name, value, value_mark, value_style) = {
      let Some(entry) = self.stack.last() else {
        return;
      };
      let Some(name) = entry.name_field.as_ref() else {
        return;
      };
      let Some((value, mark, style)) = entry.value_field.as_ref() else {
        return;
      };
      (name.clone(), value.clone(), *mark, *style)
    };

    if !value.is_empty() {
      if let Some(d) = check_assignment(
        &normalize_name(&name),
        &normalize_value(&value),
        AssignmentType::Element,
        self.source_context,
        || scalar_span(self, value_mark, value_style, value.len()),
      ) {
        self.source_context.emit_diagnostic(d);
      }
      embedded_scan(self, &value, value_mark);
    }
  }
}

fn embedded_scan(handler: &YamlHandler, value: &str, mark: Marker) {
  if handler.embedded || value.trim().is_empty() {
    return;
  }

  let inner_context = SourceContext {
    run: handler.source_context.run,
    file_abs_path: handler.source_context.file_abs_path,
    file_extension: None,
    body: Some(value),
    file_type: handler.source_context.file_type,
    #[cfg(feature = "services")]
    file_services: handler.source_context.file_services.clone(),
    parent_line: handler.source_context.parent_line
      + mark.line().saturating_sub(1),
    parent_col: handler.source_context.parent_col + mark.col(),
    directives: std::cell::OnceCell::new(),
  };

  let multi_line = value.contains('\n');
  let yaml_mapping_shape = multi_line && value.contains(": ");

  #[cfg(feature = "lang-yaml")]
  if yaml_mapping_shape {
    parse_with_options(
      &inner_context,
      &YamlOptions {
        on_value: None,
        embedded: true,
      },
    );
  }

  #[cfg(feature = "lang-config")]
  if !yaml_mapping_shape {
    crate::languages::config::parse(&inner_context);
  }
}

pub fn parse(context: &SourceContext) -> bool {
  parse_with_options(
    context,
    &YamlOptions {
      on_value: None,
      embedded: false,
    },
  )
}

pub fn parse_with_options(
  context: &SourceContext,
  options: &YamlOptions,
) -> bool {
  let Some(source) = context.body else {
    return false;
  };

  let mut handler = YamlHandler {
    source,
    source_context: context,
    stack: Vec::new(),
    pending_key: None,
    on_value: options.on_value,
    embedded: options.embedded,
  };

  let mut parser = Parser::new_from_str(source);
  let _ = parser.load(&mut handler, true);

  true
}

fn compute_span(
  handler: &YamlHandler,
  start: usize,
  end: usize,
) -> SourceFileSpan {
  compute_file_span(handler.source_context, handler.source, start, end)
}

fn char_index_to_byte(source: &str, char_index: usize) -> usize {
  source
    .char_indices()
    .nth(char_index)
    .map_or(source.len(), |(byte, _)| byte)
}

fn scalar_span(
  handler: &YamlHandler,
  mark: Marker,
  style: TScalarStyle,
  value_len: usize,
) -> SourceFileSpan {
  let start = char_index_to_byte(handler.source, mark.index());
  let end = scalar_source_end(handler.source, start, style, value_len);
  compute_span(handler, start, end)
}

fn scalar_source_end(
  source: &str,
  start: usize,
  style: TScalarStyle,
  value_len: usize,
) -> usize {
  match style {
    TScalarStyle::DoubleQuoted => find_quoted_end(source, start, b'"', true),
    TScalarStyle::SingleQuoted => find_quoted_end(source, start, b'\'', false),
    TScalarStyle::Plain | TScalarStyle::Literal | TScalarStyle::Folded => {
      start + value_len
    }
  }
}

fn find_quoted_end(
  source: &str,
  start: usize,
  quote: u8,
  backslash_escapes: bool,
) -> usize {
  let bytes = source.as_bytes();
  if bytes.get(start) != Some(&quote) {
    return start + 1;
  }

  let mut i = start + 1;
  while i < bytes.len() {
    let b = bytes.get(i).copied().unwrap_or(0);

    if backslash_escapes && b == b'\\' {
      i += 2;
      continue;
    }

    if b == quote {
      if !backslash_escapes && bytes.get(i + 1) == Some(&quote) {
        i += 2;
        continue;
      }
      return i + 1;
    }

    i += 1;
  }

  bytes.len()
}
