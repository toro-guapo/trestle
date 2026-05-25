use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use icu_time::zone::{IanaParser, IanaParserBorrowed, TimeZone};

#[cfg(feature = "services")]
use crate::scanning::Service;
#[cfg(feature = "signatures")]
use crate::scanning::{Signature, signatures};
#[cfg(feature = "pem")]
use crate::secrets::pem;
#[cfg(feature = "putty")]
use crate::secrets::putty;
#[cfg(feature = "url")]
use crate::secrets::urls::{UrlSecret, classify_url};
use crate::{
  formatting::normalize_camel_case_and_lower,
  processing::SourceContext,
  scanning::{COMMON_ENGLISH_WORDS, KNOWN_WORDS},
  secrets::{
    names::classify::{NameClass, NameKind},
    values::normalize::NormalizedValue,
  },
};

#[derive(Debug)]
pub enum NamedSecret {
  Mnemonic,
  Header,
  CreditCard,
  #[cfg(feature = "pem")]
  PrivateKey(pem::PrivateKey),
  #[cfg(feature = "putty")]
  PuttyKey(putty::PuttyKey),
  #[cfg(feature = "signatures")]
  Signature(&'static Signature),
  #[cfg(feature = "services")]
  Service(&'static Service),
  #[cfg(feature = "url")]
  Url(UrlSecret),
}

impl std::fmt::Display for NamedSecret {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      NamedSecret::Mnemonic => write!(f, "mnemonic"),
      NamedSecret::Header => write!(f, "possible header secret"),
      NamedSecret::CreditCard => write!(f, "credit card number"),
      #[cfg(feature = "pem")]
      NamedSecret::PrivateKey(key) => write!(f, "{key}"),
      #[cfg(feature = "putty")]
      NamedSecret::PuttyKey(key) => write!(f, "{key}"),
      #[cfg(feature = "signatures")]
      NamedSecret::Signature(sig) => write!(f, "{}", sig.name),
      #[cfg(feature = "services")]
      NamedSecret::Service(service) => {
        write!(f, "possible {} secret", service.display_name)
      }
      #[cfg(feature = "url")]
      NamedSecret::Url(url) => {
        write!(f, "possible {} URL secret", url.kind.display_name())
      }
    }
  }
}

#[derive(Debug)]
pub enum ValueClass {
  Secret(NamedSecret),
  PossibleSecret,
  Public,
}

impl std::fmt::Display for ValueClass {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      ValueClass::PossibleSecret => write!(f, "possible secret"),
      ValueClass::Secret(secret) => write!(f, "{}", secret),
      ValueClass::Public => write!(f, "public credential"),
    }
  }
}

pub fn classify_named_value(
  name_class: &NameClass,
  value: &NormalizedValue,
  context: &SourceContext,
) -> Option<ValueClass> {
  if is_template_expression(value) {
    return None;
  }

  if let Some(vc) = classify_value_with_spaces(value) {
    return Some(vc);
  }

  #[cfg(feature = "services")]
  if let Some(service) = name_class.service {
    if service.matches(value.as_str()) {
      return Some(ValueClass::Secret(NamedSecret::Service(service)));
    }
  }

  if let Some(vc) = classify_value_evidence(value, context) {
    return Some(vc);
  }

  // Unqualified ("weak") key/token names: require entropy, not just a
  // non-dictionary value.
  #[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
  if matches!(
    name_class.kind,
    NameKind::Key { weak: true } | NameKind::Token { weak: true }
  ) {
    return (has_sufficient_entropy(value) && value_could_be_secret(value))
      .then_some(ValueClass::PossibleSecret);
  }

  if value_could_be_secret(value) {
    Some(ValueClass::PossibleSecret)
  } else {
    None
  }
}

pub fn classify_value(
  value: &NormalizedValue,
  context: &SourceContext,
) -> Option<ValueClass> {
  if is_template_expression(value) {
    return None;
  }

  if let Some(vc) = classify_value_with_spaces(value) {
    return Some(vc);
  }

  if contains_spaces(value) {
    return None;
  }

  classify_value_body(value, context)
}

#[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
pub fn calculate_shannon_entropy(value: &str) -> f64 {
  shannon_entropy_and_unique(value).0
}

#[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
fn shannon_entropy_and_unique(value: &str) -> (f64, usize) {
  if value.is_empty() {
    return (0.0, 0);
  }

  let len = value.len() as f64;
  let mut counts = [0u32; 256];

  for byte in value.as_bytes() {
    counts[*byte as usize] += 1;
  }

  let mut entropy = 0.0;
  let mut unique = 0usize;
  for count in counts.iter() {
    if *count > 0 {
      unique += 1;
      let p = *count as f64 / len;
      entropy -= p * p.log2();
    }
  }

  (entropy, unique)
}

#[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
pub fn has_sufficient_entropy(value: &NormalizedValue) -> bool {
  const MIN_LENGTH: usize = 8;
  const MIN_TOTAL_BITS: f64 = 40.0;
  const ABSOLUTE_THRESHOLD: f64 = 3.5;
  const NORMALIZED_THRESHOLD: f64 = 0.85;

  let s = value.as_str();
  if s.len() < MIN_LENGTH {
    return false;
  }

  let (entropy, _) = shannon_entropy_and_unique(s);
  if entropy * (s.len() as f64) < MIN_TOTAL_BITS {
    return false;
  }

  if is_pure_hex_token(s) {
    return true;
  }

  let max_entropy = (alphabet_size(s) as f64).log2();
  let absolute_pass = entropy >= ABSOLUTE_THRESHOLD;
  let normalized_pass =
    max_entropy > 0.0 && entropy / max_entropy >= NORMALIZED_THRESHOLD;

  if !absolute_pass && !normalized_pass {
    return false;
  }

  if appears_language_like(s) {
    return false;
  }

  if contains_alphabet_sequence(s) || contains_keyboard_walk(s) {
    return false;
  }

  true
}

#[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
fn is_pure_hex_token(value: &str) -> bool {
  const MIN_HEX_TOKEN_LEN: usize = 40;
  value.len() >= MIN_HEX_TOKEN_LEN
    && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
fn alphabet_size(value: &str) -> usize {
  let bytes = value.as_bytes();
  let mut size = 0;

  if bytes.iter().any(|b| b.is_ascii_lowercase()) {
    size += 26;
  }

  if bytes.iter().any(|b| b.is_ascii_digit()) {
    size += 10;
  }

  let mut symbols = [false; 128];

  for &b in bytes {
    if b.is_ascii() && !b.is_ascii_alphanumeric() {
      symbols[b as usize] = true;
    }
  }

  size + symbols.iter().filter(|s| **s).count()
}

#[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
thread_local! {
  static COMMON_BIGRAMS: HashSet<[u8; 2]> = [
    // Top 50 - cover ~47% of all bigram occurrences in English.
    *b"th", *b"he", *b"in", *b"er", *b"an", *b"re", *b"on", *b"at", *b"en",
    *b"nd", *b"ti", *b"es", *b"or", *b"te", *b"of", *b"ed", *b"is", *b"it",
    *b"al", *b"ar", *b"st", *b"to", *b"nt", *b"ng", *b"se", *b"ha", *b"as",
    *b"ou", *b"io", *b"le", *b"ve", *b"co", *b"me", *b"de", *b"hi", *b"ri",
    *b"ro", *b"ic", *b"ne", *b"ea", *b"ra", *b"ce", *b"li", *b"ch", *b"ll",
    *b"be", *b"ma", *b"si", *b"om", *b"ur",
    // Positions ~51-100 by frequency.
    *b"ca", *b"el", *b"ta", *b"la", *b"ns", *b"di", *b"fo", *b"ho", *b"pe",
    *b"ec", *b"pr", *b"no", *b"ct", *b"us", *b"ac", *b"ot", *b"il", *b"tr",
    *b"ly", *b"nc", *b"et", *b"ut", *b"ss", *b"so", *b"rs", *b"un", *b"lo",
    *b"wa", *b"ge", *b"ie", *b"wh", *b"ee", *b"wi", *b"em", *b"ad", *b"ol",
    *b"rt", *b"po", *b"we", *b"na", *b"ul", *b"ni", *b"ts", *b"mo", *b"ow",
    *b"pa", *b"im", *b"mi", *b"ai", *b"sh",
    // High-confidence English signals not in the top 100 but very
    // characteristic: "qu" (Q is essentially always followed by U),
    // "ck" (common consonant cluster), "ju" / "um" / "mp" / "br" /
    // "og" / "do" - present in any pangram-style compressed prose.
    *b"qu", *b"ck", *b"ju", *b"um", *b"mp", *b"br", *b"og", *b"do",
  ].into_iter().collect();
}

#[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
fn appears_language_like(value: &str) -> bool {
  let bytes = value.as_bytes();
  if !bytes.iter().all(|b| b.is_ascii_alphabetic()) {
    return false;
  }

  const MIN_BIGRAMS: usize = 6;
  const COMMON_FRACTION_NUM: usize = 1;
  const COMMON_FRACTION_DEN: usize = 4;

  let mut total = 0usize;
  let mut common = 0usize;

  COMMON_BIGRAMS.with(|set| {
    let mut prev: Option<u8> = None;
    for &b in bytes {
      if let Some(p) = prev {
        total += 1;
        if set.contains(&[p, b]) {
          common += 1;
        }
      }
      prev = Some(b);
    }
  });

  if total < MIN_BIGRAMS {
    return false;
  }

  common * COMMON_FRACTION_DEN >= total * COMMON_FRACTION_NUM
}

#[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
fn contains_alphabet_sequence(value: &str) -> bool {
  const MIN_RUN: usize = 8;

  let mut prev: Option<u8> = None;
  let mut ascending = 1usize;
  let mut descending = 1usize;

  for &b in value.as_bytes() {
    if !b.is_ascii_alphabetic() {
      prev = None;
      ascending = 1;
      descending = 1;
      continue;
    }
    let curr = b.to_ascii_lowercase();
    if let Some(p) = prev {
      if curr == p + 1 {
        ascending += 1;
        descending = 1;
      } else if p == curr + 1 {
        descending += 1;
        ascending = 1;
      } else {
        ascending = 1;
        descending = 1;
      }
      if ascending >= MIN_RUN || descending >= MIN_RUN {
        return true;
      }
    }
    prev = Some(curr);
  }

  false
}

#[cfg(any(feature = "entropy-key", feature = "entropy-token"))]
fn contains_keyboard_walk(value: &str) -> bool {
  const MIN_RUN: usize = 8;
  const ROWS: &[&str] = &[
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "azertyuiop",
    "qsdfghjklm",
    "wxcvbn",
    "qwertzuiop",
    "yxcvbnm",
    "qzertyuiop",
  ];

  let lower = value.to_ascii_lowercase();
  for row in ROWS {
    if row.len() < MIN_RUN {
      continue;
    }

    // Forward walk: contiguous substring of the row, length MIN_RUN+.
    for start in 0..=row.len() - MIN_RUN {
      if lower.contains(&row[start..start + MIN_RUN]) {
        return true;
      }
    }

    // Backward walk: reverse the row and look for substrings.
    let reversed: String = row.chars().rev().collect();
    for start in 0..=reversed.len() - MIN_RUN {
      if lower.contains(&reversed[start..start + MIN_RUN]) {
        return true;
      }
    }
  }

  false
}

fn classify_value_evidence(
  value: &NormalizedValue,
  context: &SourceContext,
) -> Option<ValueClass> {
  #[cfg(feature = "signatures")]
  if let Some(vc) = classify_signature(value) {
    return Some(vc);
  }

  #[cfg(feature = "services")]
  for service in &context.file_services {
    if service.matches(value.as_str()) {
      return Some(ValueClass::Secret(NamedSecret::Service(service)));
    }
  }

  #[cfg(feature = "url")]
  if let Some(vc) = classify_url(value, context) {
    return Some(vc);
  }

  if is_credit_card_number(value) {
    return Some(ValueClass::Secret(NamedSecret::CreditCard));
  }

  None
}

/// Canonical sandbox / test card numbers from major payment processors
/// and card networks. Numeric digits only, no separators. These pass
/// Luhn validation but are not real accounts and should not be flagged.
///   Stripe: https://docs.stripe.com/testing
///   PayPal: https://developer.paypal.com/api/rest/sandbox/card-testing/
///   Adyen:  https://docs.adyen.com/development-resources/testing/test-card-numbers/
const TEST_CARD_NUMBERS: &[&str] = &[
  // Visa
  "4000000000000002",
  "4000000000000069",
  "4000000000000101",
  "4000000000000119",
  "4000000000000127",
  "4000000000000341",
  "4000000000003220",
  "4000000000005126",
  "4000000000009979",
  "4000000000009987",
  "4000000000009995",
  "4000002500003155",
  "4000002760003184",
  "4000008260003178",
  "4000020000000000",
  "4000033033003335",
  "4000056655665556",
  "4000060000000006",
  "4000160000000004",
  "4000180000000002",
  "4000620000000007",
  "4000640000000005",
  "4000760000000001",
  "4001020000000009",
  "4001590000000001",
  "4002690000000008",
  "4003550000000003",
  "4005519000000006",
  "4012888888881881",
  "4013250000000000006",
  "4017340000000003",
  "4111111111111111",
  "4111111145551142",
  "4111112014267661",
  "4131840000000003",
  "4151500000000008",
  "4166676766766746",
  "4199350000000002",
  "4222222222222",
  "4242424242424242",
  "4293189100000008",
  "4400000000000008",
  "4400002000000004",
  "4444333322221111",
  "4484600000000004",
  "4607000000000009",
  "4646464646464644",
  "4917610000000000",
  "4977949494949497",
  "4988080000000000",
  "4988438843884305",
  // Mastercard
  "2222400010000008",
  "2222400030000004",
  "2222400050000009",
  "2222400060000007",
  "2222400070000005",
  "2222410700000002",
  "2222410740360010",
  "2223000048400011",
  "2223000048410010",
  "2223003122003222",
  "2223520443560010",
  "5002510000000013",
  "5100060000000002",
  "5103221911199245",
  "5105105105105100",
  "5127880999999990",
  "5130290000000009",
  "5200828282828210",
  "5413330033003303",
  "5454545454545454",
  "5554444333311111",
  "5555341244441115",
  "5555555555554444",
  "5577000055770004",
  // Maestro
  "6304000000000000",
  "6703444444444449",
  "6771798021000008",
  "6771798021000016",
  // American Express
  "371449635398431",
  "3700000000000002",
  "3700000001000018",
  "3714496353984310",
  "376680816376961",
  "378282246310005",
  "378734493671000",
  // Discover
  "6011000990139424",
  "6011111111111117",
  "6011601160116611",
  "6011609900000003",
  "6011981111111113",
  "6445644564456445",
  "6445645000000002",
  // Diners Club
  "3056930009020004",
  "30569309025904",
  "36227206271667",
  "3600666633334400",
  "3607050000001020",
  "36461510000013",
  "36461510000039",
  "38520000023237",
  // JCB
  "3530111333300000",
  "3566002020360505",
  "3569990010095841",
  // UnionPay
  "6200000000000005",
  "6200000000000047",
  "6205500000000000004",
  "6243030000000001",
  // BCcard and DinaCard
  "6555900000604105",
  // Dankort
  "4571000000000001",
  "5019555544445555",
  // Cartes Bancaires
  "4035501000000008",
  "4035501428146300",
  "4360000001000005",
  // Bancontact
  "4871049999999910",
  // Elo
  "4089670000000014",
  "4687380100010006",
  "5066991111111118",
  // Hipercard
  "6062828888666688",
];

/// True when `value` is a Luhn-valid 13-19 digit number whose leading
/// digit corresponds to a real card-issuer network. Permits spaces and
/// hyphens as group separators. Excludes canonical sandbox/test card
/// numbers published by payment processors.
fn is_credit_card_number(value: &NormalizedValue) -> bool {
  let original = value.original();

  // Permitted characters: digits and group separators only.
  if !original
    .bytes()
    .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b' '))
  {
    return false;
  }

  let digit_str: String = original
    .bytes()
    .filter(|b| b.is_ascii_digit())
    .map(char::from)
    .collect();

  if digit_str.len() < 13 || digit_str.len() > 19 {
    return false;
  }

  // BIN-range check: real card networks start with 2 (Mastercard
  // 2-series, BIN range 2221-2720), 3 (Amex/Diners/JCB), 4 (Visa),
  // 5 (Mastercard 5-series), or 6 (Discover, UnionPay, etc.).
  if !matches!(digit_str.as_bytes()[0], b'2' | b'3' | b'4' | b'5' | b'6') {
    return false;
  }

  if TEST_CARD_NUMBERS.contains(&digit_str.as_str()) {
    return false;
  }

  // Luhn: from rightmost digit, double every second digit; if doubling
  // produces a two-digit value, add the digits. Sum must be a multiple
  // of 10.
  let mut sum: u32 = 0;
  let mut double = false;
  for d in digit_str.bytes().rev() {
    let mut x = u32::from(d - b'0');
    if double {
      x *= 2;
      if x >= 10 {
        x -= 9;
      }
    }
    sum += x;
    double = !double;
  }
  sum % 10 == 0
}

fn classify_value_body(
  value: &NormalizedValue,
  context: &SourceContext,
) -> Option<ValueClass> {
  if let Some(vc) = classify_value_evidence(value, context) {
    return Some(vc);
  }

  if value_could_be_secret(value) {
    Some(ValueClass::PossibleSecret)
  } else {
    None
  }
}

fn classify_value_with_spaces(value: &NormalizedValue) -> Option<ValueClass> {
  if is_value_mnemonic(value) {
    return Some(ValueClass::Secret(NamedSecret::Mnemonic));
  }

  #[cfg(feature = "pem")]
  if let Some(vc) = classify_pem(value) {
    return Some(vc);
  }

  #[cfg(feature = "putty")]
  if let Some(vc) = classify_putty(value) {
    return Some(vc);
  }

  #[cfg(feature = "signatures")]
  if let Some(vc) = classify_signature(value) {
    return Some(vc);
  }

  if is_credit_card_number(value) {
    return Some(ValueClass::Secret(NamedSecret::CreditCard));
  }

  None
}

fn contains_spaces(value: &NormalizedValue) -> bool {
  value.as_str().contains(' ')
}

#[cfg(feature = "pem")]
fn classify_pem(value: &NormalizedValue) -> Option<ValueClass> {
  let finding = pem::scan(value.original()).into_iter().next()?;
  Some(ValueClass::Secret(NamedSecret::PrivateKey(
    finding.key_type,
  )))
}

#[cfg(feature = "putty")]
fn classify_putty(value: &NormalizedValue) -> Option<ValueClass> {
  let finding = putty::scan(value.original()).into_iter().next()?;
  Some(ValueClass::Secret(NamedSecret::PuttyKey(finding.key_type)))
}

#[cfg(feature = "signatures")]
fn classify_signature(value: &NormalizedValue) -> Option<ValueClass> {
  let sig = signatures::scan(value.original())?;
  let lower = value.as_str();
  let suppresses = PLACEHOLDER_SUBSTRINGS
    .iter()
    .any(|marker| lower.contains(marker) && !sig.pattern.contains(marker));

  if suppresses {
    return None;
  }

  if sig.is_public() {
    return Some(ValueClass::Public);
  }

  Some(ValueClass::Secret(NamedSecret::Signature(sig)))
}

fn is_value_mnemonic(value: &NormalizedValue) -> bool {
  is_bip39_mnemonic(value.as_str())
}

fn value_could_be_secret(value: &NormalizedValue) -> bool {
  if value.len() < 8 {
    return false;
  }

  !is_known_words(value)
    && !is_multi_segment_word_identifier(value)
    && !contains_non_ascii_letter(value.as_str())
    && !is_file_path(value)
    && !is_placeholder(value)
    && !contains_long_known_word(value.as_str())
    && !is_markup(value)
    && !is_sentinel(value)
    && !is_integrity_hash(value)
    && !is_repeated_char(value)
    && !is_version(value)
    && !is_email(value)
    && !is_color(value)
    && !is_css_variable(value)
    && !is_cron(value)
    && !is_locale_or_timezone(value)
    && !is_mime_type(value)
    && !is_datetime(value)
    && !is_aws_arn(value)
}

fn contains_non_ascii_letter(value: &str) -> bool {
  value.chars().any(|c| c.is_alphabetic() && !c.is_ascii())
}

const SENTINELS: &[&str] = &[
  "false",
  "n/a",
  "na",
  "nil",
  "no",
  "none",
  "null",
  "off",
  "on",
  "true",
  "undefined",
  "yes",
];

fn is_sentinel(value: &NormalizedValue) -> bool {
  SENTINELS.contains(&value.as_str())
}

const PLACEHOLDER_SUBSTRINGS: &[&str] = &[
  "changeme",
  "change_me",
  "change-me",
  "dummy",
  "example",
  "expired",
  "fake",
  "fixme",
  "invalid",
  "masked",
  "mock",
  "obsolete",
  "placeholder",
  "redacted",
  "replace",
  "revoked",
  "sample",
  "test",
  "todo",
  "xxx",
  "your_",
];

pub(crate) fn is_placeholder(value: &NormalizedValue) -> bool {
  let lower = value.as_str();
  PLACEHOLDER_SUBSTRINGS.iter().any(|s| lower.contains(s))
}

const MIN_PLACEHOLDER_WORD_LEN: usize = 7;

const PLACEHOLDER_WORD_FRACTION_NUM: usize = 2;
const PLACEHOLDER_WORD_FRACTION_DEN: usize = 5;

pub fn contains_long_known_word(lower: &str) -> bool {
  let total = lower.len();
  if total == 0 {
    return false;
  }

  KNOWN_WORD_MATCHER.with(|m| {
    let Some(matcher) = m else {
      return false;
    };

    matcher.find_overlapping_iter(lower).any(|mat| {
      mat.len() >= MIN_PLACEHOLDER_WORD_LEN
        && mat.len() * PLACEHOLDER_WORD_FRACTION_DEN
          >= total * PLACEHOLDER_WORD_FRACTION_NUM
    })
  })
}

fn is_repeated_char(value: &NormalizedValue) -> bool {
  let mut chars = value.as_str().chars();
  let Some(first) = chars.next() else {
    return false;
  };
  chars.all(|c| c == first)
}

fn is_file_path(value: &NormalizedValue) -> bool {
  let lower = value.as_str();
  lower.starts_with('/')
    || lower.starts_with("./")
    || lower.starts_with("../")
    || lower.starts_with("~/")
    || (lower.len() >= 3
      && lower.as_bytes().get(1) == Some(&b':')
      && lower.as_bytes().get(2) == Some(&b'\\'))
}

fn is_integrity_hash(value: &NormalizedValue) -> bool {
  let lower = value.as_str();
  lower.starts_with("sha1-")
    || lower.starts_with("sha256-")
    || lower.starts_with("sha384-")
    || lower.starts_with("sha512-")
}

fn is_version(value: &NormalizedValue) -> bool {
  let s = value.as_str();
  let s = s.strip_prefix('v').unwrap_or(s);
  let mut parts = s.split('.');
  let Some(first) = parts.next() else {
    return false;
  };
  if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
    return false;
  }
  let Some(second) = parts.next() else {
    return false;
  };
  second
    .as_bytes()
    .first()
    .is_some_and(|b| b.is_ascii_digit())
}

fn is_email(value: &NormalizedValue) -> bool {
  let s = value.as_str();
  let Some(at_pos) = s.find('@') else {
    return false;
  };

  let domain = s.get(at_pos + 1..).unwrap_or("");
  if !domain.contains('.') {
    return false;
  }

  email_address::EmailAddress::is_valid(s)
}

fn is_color(value: &NormalizedValue) -> bool {
  csscolorparser::parse(value.as_str()).is_ok()
}

fn is_css_variable(value: &NormalizedValue) -> bool {
  let b = value.as_str().as_bytes();
  let Some(pos) = value.as_str().find("var(") else {
    return false;
  };
  let mut i = pos + 4; // skip "var("

  // Skip whitespace after '('
  while b.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
    i += 1;
  }

  // Expect "--" followed by a valid CSS identifier start character
  b.get(i).copied() == Some(b'-')
    && b.get(i + 1).copied() == Some(b'-')
    && b
      .get(i + 2)
      .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
}

fn is_cron(value: &NormalizedValue) -> bool {
  value.original().parse::<croner::Cron>().is_ok()
}

fn is_locale_or_timezone(value: &NormalizedValue) -> bool {
  let s = value.as_str();
  is_locale(s) || is_timezone(s)
}

fn is_locale(s: &str) -> bool {
  // BCP 47: en-US, zh-Hans-CN, etc.
  if s.parse::<icu_locale_core::Locale>().is_ok() {
    return true;
  }

  // POSIX locale with encoding: en_us.utf-8, de_de.iso-8859-1
  let b = s.as_bytes();
  b.len() >= 8
    && b.first().is_some_and(|c| c.is_ascii_lowercase())
    && b.get(1).is_some_and(|c| c.is_ascii_lowercase())
    && b.get(2).copied() == Some(b'_')
    && b.get(3).is_some_and(|c| c.is_ascii_lowercase())
    && b.get(4).is_some_and(|c| c.is_ascii_lowercase())
    && b.get(5).copied() == Some(b'.')
    && b.get(6).is_some_and(|c| c.is_ascii_lowercase())
    && b.get(7).is_some_and(|c| c.is_ascii_lowercase())
}

thread_local! {
  static IANA_PARSER: IanaParserBorrowed<'static> = IanaParser::new();
}

fn is_timezone(s: &str) -> bool {
  IANA_PARSER.with(|p| p.parse(s) != TimeZone::UNKNOWN)
}

fn is_mime_type(value: &NormalizedValue) -> bool {
  value.as_str().parse::<mime::Mime>().is_ok()
}

fn is_datetime(value: &NormalizedValue) -> bool {
  ixdtf::parsers::IxdtfParser::from_str(value.original())
    .parse()
    .is_ok()
}

fn starts_with_html_entity(value: &str) -> bool {
  let b = value.as_bytes();
  if b.first().copied() != Some(b'&') || b.get(1).copied() != Some(b'#') {
    return false;
  }

  let is_hex = b.get(2).copied() == Some(b'x');
  let digits = if is_hex {
    b.get(3..).unwrap_or(&[])
  } else {
    b.get(2..).unwrap_or(&[])
  };

  let mut found_digits = false;
  for &c in digits {
    if c == b';' || c.is_ascii_whitespace() {
      return found_digits;
    }

    let valid = if is_hex {
      c.is_ascii_hexdigit()
    } else {
      c.is_ascii_digit()
    };

    if !valid {
      return false;
    }

    found_digits = true;
  }

  found_digits
}

fn is_aws_arn(value: &NormalizedValue) -> bool {
  let s = value.as_str();
  s.starts_with("arn:aws:")
    || s.starts_with("arn:aws-cn:")
    || s.starts_with("arn:aws-us-gov:")
}

fn is_template_expression(value: &NormalizedValue) -> bool {
  let s = value.as_str();

  let Some(rest) = s.strip_prefix("${{") else {
    return false;
  };

  let Some(inner) = rest.strip_suffix("}}") else {
    return false;
  };

  !inner.contains("}}")
}

fn is_markup(value: &NormalizedValue) -> bool {
  let lower = value.as_str();
  if starts_with_html_entity(lower) {
    return true;
  }

  let b = lower.as_bytes();
  if b.first().copied() != Some(b'<') {
    return false;
  }

  match b.get(1).copied() {
    Some(b'?') => {
      // <?xml - at least 3 alphabetic after ?
      b.get(2).is_some_and(|c| c.is_ascii_alphabetic())
        && b.get(3).is_some_and(|c| c.is_ascii_alphabetic())
        && b.get(4).is_some_and(|c| c.is_ascii_alphabetic())
    }
    Some(b'!') => {
      if b.get(2).copied() == Some(b'-') && b.get(3).copied() == Some(b'-') {
        // <!-- comment -->
        return true;
      }
      // <!DOCTYPE - at least 3 alphabetic after !
      b.get(2).is_some_and(|c| c.is_ascii_alphabetic())
        && b.get(3).is_some_and(|c| c.is_ascii_alphabetic())
        && b.get(4).is_some_and(|c| c.is_ascii_alphabetic())
    }
    Some(c) if c.is_ascii_alphabetic() => {
      // <tag - second char must be alphabetic, space, or end of string
      b.len() == 2
        || b
          .get(2)
          .is_some_and(|c| c.is_ascii_alphabetic() || *c == b' ' || *c == b'>')
    }
    _ => false,
  }
}

fn is_bip39_mnemonic(value: &str) -> bool {
  let word_count = value.split_ascii_whitespace().count();

  if word_count != 12
    && word_count != 15
    && word_count != 18
    && word_count != 21
    && word_count != 24
  {
    return false;
  }

  bip39::Mnemonic::parse_in_normalized(bip39::Language::English, value).is_ok()
}

const MIN_COVERAGE_WORD_LEN: usize = 3;

thread_local! {
  static KNOWN_WORD_SET: HashSet<&'static str> = KNOWN_WORDS
    .iter()
    .chain(COMMON_ENGLISH_WORDS.iter())
    .copied()
    .collect();

  static KNOWN_WORD_MATCHER: Option<AhoCorasick> = AhoCorasick::builder()
    .ascii_case_insensitive(false)
    .build(
      KNOWN_WORDS
        .iter()
        .chain(COMMON_ENGLISH_WORDS.iter())
        .copied()
        .filter(|w| w.len() >= MIN_COVERAGE_WORD_LEN)
        .collect::<Vec<_>>(),
    )
    .ok();
}

fn segment_value(value: &str) -> Vec<String> {
  let mut out = Vec::new();

  for part in value
    .split(|c: char| !c.is_ascii_alphanumeric())
    .filter(|s| !s.is_empty())
  {
    out.extend(normalize_camel_case_and_lower(part));
  }

  out
}

const KNOWN_WORD_THRESHOLD: usize = 3;
const KNOWN_WORD_COVERAGE: f64 = 0.6;
const MULTI_SEGMENT_IDENTIFIER_CHAR_COVERAGE: f64 = 0.45;

pub fn is_known_words(value: &NormalizedValue) -> bool {
  KNOWN_WORD_SET.with(|set| {
    let segments = segment_value(value.original());
    if segments.is_empty() {
      return false;
    }

    let matched = segments.iter().filter(|s| set.contains(s.as_str())).count();
    if matched >= segments.len() || matched >= KNOWN_WORD_THRESHOLD {
      return true;
    }

    if segments.len() == 1 {
      return is_concatenated_known_words(&segments[0]);
    }

    false
  })
}

fn is_concatenated_known_words(segment: &str) -> bool {
  KNOWN_WORD_MATCHER.with(|m| {
    let Some(matcher) = m else {
      return false;
    };

    let bytes = segment.as_bytes();
    if bytes.is_empty() {
      return false;
    }

    let mut covered = vec![false; bytes.len()];
    for mat in matcher.find_overlapping_iter(segment) {
      for slot in &mut covered[mat.start()..mat.end()] {
        *slot = true;
      }
    }

    let uncovered_digit_count = bytes
      .iter()
      .zip(covered.iter())
      .filter(|(_, c)| !**c)
      .filter(|(b, _)| b.is_ascii_digit())
      .count();

    let uncovered_total = covered.iter().filter(|c| !**c).count();
    if uncovered_total > 0 && uncovered_digit_count * 2 > uncovered_total {
      return false;
    }

    let covered_count = covered.iter().filter(|c| **c).count();
    covered_count as f64 / bytes.len() as f64 >= KNOWN_WORD_COVERAGE
  })
}

fn is_multi_segment_word_identifier(value: &NormalizedValue) -> bool {
  if !value.original().chars().any(|c| {
    matches!(
      c,
      '_'
        | '-'
        | '.'
        | '/'
        | '\\'
        | '%'
        | '('
        | ')'
        | '{'
        | '}'
        | '['
        | ']'
        | ':'
    )
  }) {
    return false;
  }

  KNOWN_WORD_MATCHER.with(|m| {
    let Some(matcher) = m else {
      return false;
    };

    let lower = value.as_str();

    let alphabetic_chars =
      lower.chars().filter(|c| c.is_ascii_alphabetic()).count();

    if alphabetic_chars == 0 {
      return false;
    }

    let mut covered = vec![false; lower.len()];
    for mat in matcher.find_overlapping_iter(lower) {
      for slot in &mut covered[mat.start()..mat.end()] {
        *slot = true;
      }
    }

    let covered_chars = covered.iter().filter(|c| **c).count();
    covered_chars as f64 / alphabetic_chars as f64
      >= MULTI_SEGMENT_IDENTIFIER_CHAR_COVERAGE
  })
}
