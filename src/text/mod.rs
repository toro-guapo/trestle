pub mod markdown;
pub mod plain;

pub type RichText = Vec<TextSpan>;

#[derive(Clone)]
pub enum Text {
  Plain(String),
  Rich(RichText),
}

#[derive(Clone)]
pub enum TextSpan {
  Plain(String),
  Code(String),
  Filename(String),
  Heading(String),
  Link { url: String, text: Option<Text> },
  Paragraph(Vec<TextSpan>),
  UnorderedList(Vec<Text>),
  OrderedList(Vec<Text>),
}
