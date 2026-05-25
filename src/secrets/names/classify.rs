#[cfg(feature = "services")]
use crate::scanning::{SERVICE_KEYWORDS, Service};
use crate::{
  scanning::{
    DISQUALIFIERS, EXCLUSIONS, KEY_DISQUALIFIERS, KEY_QUALIFIER_PHRASES,
    KEY_QUALIFIERS, STRONG_KEYWORD_PHRASES, STRONG_KEYWORDS,
    TOKEN_DISQUALIFIERS, TOKEN_QUALIFIERS,
  },
  secrets::names::normalize::NormalizedName,
};

#[derive(Debug, Eq, PartialEq)]
pub enum NameKind {
  Sensitive,
  Key { weak: bool },
  Token { weak: bool },
  Mnemonic,
}

#[derive(Debug)]
pub struct NameClass {
  #[cfg(feature = "services")]
  pub service: Option<&'static Service>,
  pub kind: NameKind,
}

pub fn classify_normalized_name(
  normalized: &NormalizedName,
) -> Option<NameClass> {
  let segments_owned: Vec<String> = normalized
    .segments()
    .iter()
    .flat_map(|s| split_compound_credential(s.as_str()))
    .collect();

  let segments = &segments_owned;

  if segments.iter().any(|s| DISQUALIFIERS.contains(&s.as_str())) {
    return None;
  }

  let mut could_be_key = false;
  let mut could_be_token = false;
  let mut is_mnemonic = false;
  #[cfg(feature = "services")]
  let mut found_service = None;

  for segment in segments {
    let segment = segment.as_str();

    match segment {
      "key" => could_be_key = true,
      "token" => could_be_token = true,
      "mnemonic" => is_mnemonic = true,
      #[cfg(feature = "services")]
      service_keyword if SERVICE_KEYWORDS.contains(&service_keyword) => {
        if let Some(service) = Service::by_keyword(service_keyword) {
          found_service = Some(service);
        }
      }
      exclusion if EXCLUSIONS.contains(&exclusion) => {
        return None;
      }
      _ => {}
    }
  }

  if could_be_key {
    for segment in segments {
      if KEY_DISQUALIFIERS.contains(&segment.as_str()) {
        could_be_key = false;
        break;
      }
    }
  }

  if could_be_token {
    for segment in segments {
      if TOKEN_DISQUALIFIERS.contains(&segment.as_str()) {
        could_be_token = false;
        break;
      }
    }
  }

  if is_mnemonic {
    return Some(NameClass {
      #[cfg(feature = "services")]
      service: found_service,
      kind: NameKind::Mnemonic,
    });
  }

  let mut kind = 'kind: {
    let joined = segments.join("_");
    for phrase in STRONG_KEYWORD_PHRASES {
      if joined.contains(phrase) {
        break 'kind NameKind::Sensitive;
      }
    }

    for segment in segments {
      let segment = segment.as_str();

      if STRONG_KEYWORDS.contains(&segment) {
        break 'kind NameKind::Sensitive;
      } else if could_be_key && KEY_QUALIFIERS.contains(&segment) {
        break 'kind NameKind::Key { weak: false };
      } else if could_be_token && TOKEN_QUALIFIERS.contains(&segment) {
        break 'kind NameKind::Token { weak: false };
      }
    }

    if could_be_key {
      for phrase in KEY_QUALIFIER_PHRASES {
        if joined.contains(phrase) {
          break 'kind NameKind::Key { weak: false };
        }
      }
    }

    // A service keyword in the name acts as a strong qualifier: the service
    // is what makes "algolia_admin_key" a credential-shaped name, even if
    // no other segment is in KEY_QUALIFIERS.
    #[cfg(feature = "services")]
    {
      let is_end_key = segments.last().map(|s| s.as_str()) == Some("key");
      let is_end_token = segments.last().map(|s| s.as_str()) == Some("token");

      if found_service.is_some() && is_end_key {
        break 'kind NameKind::Key { weak: false };
      }
      if found_service.is_some() && is_end_token {
        break 'kind NameKind::Token { weak: false };
      }
    }

    // Only allow unqualified "key" or "token" names with entropy features,
    // and only if there's no service keyword either
    #[cfg(feature = "entropy-key")]
    {
      let is_end_key = segments.last().map(|s| s.as_str()) == Some("key");

      if could_be_key && found_service.is_none() && is_end_key {
        break 'kind NameKind::Key { weak: false };
      }
    }

    #[cfg(feature = "entropy-token")]
    {
      let is_end_token = segments.last().map(|s| s.as_str()) == Some("token");

      if could_be_token && found_service.is_none() && is_end_token {
        break 'kind NameKind::Token { weak: false };
      }
    }

    return None;
  };

  #[cfg(feature = "entropy-key")]
  {
    let weak_key = {
      let is_end_key = segments.last().map(|s| s.as_str()) == Some("key");
      could_be_key
        && matches!(kind, NameKind::Key { .. })
        && found_service.is_none()
        && is_end_key
        && !segments
          .iter()
          .any(|s| KEY_QUALIFIERS.contains(&s.as_str()))
    };

    if weak_key {
      kind = NameKind::Key { weak: true };
    }
  }

  #[cfg(feature = "entropy-token")]
  {
    let weak_token = {
      let is_end_token = segments.last().map(|s| s.as_str()) == Some("token");
      could_be_token
        && matches!(kind, NameKind::Token { .. })
        && found_service.is_none()
        && is_end_token
        && !segments
          .iter()
          .any(|s| TOKEN_QUALIFIERS.contains(&s.as_str()))
    };

    if weak_token {
      kind = NameKind::Token { weak: true };
    }
  }

  Some(NameClass {
    #[cfg(feature = "services")]
    service: found_service,
    kind,
  })
}

fn split_compound_credential(segment: &str) -> Vec<String> {
  for suffix in STRONG_KEYWORDS.iter().chain(&["key", "token"]) {
    if segment.len() > suffix.len()
      && segment.ends_with(suffix)
      && let Some(prefix) = segment.get(..segment.len() - suffix.len())
      && (KEY_QUALIFIERS.contains(&prefix)
        || TOKEN_QUALIFIERS.contains(&prefix)
        || STRONG_KEYWORDS.contains(&prefix))
    {
      return vec![prefix.to_string(), (*suffix).to_string()];
    }
  }
  vec![segment.to_string()]
}
