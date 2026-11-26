//! Shared XML local-name and entity/text/CDATA decoding helpers for S3 and WebDAV parsers.

use quick_xml::events::{BytesRef, Event};
use quick_xml::name::QName;
use rship_core::{Error, Result};
use std::borrow::Cow;

/// Strip an optional XML namespace prefix from a `quick-xml` `QName` (`d:href` -> `href`),
/// preserving the underlying event lifetime without extra temporary bindings.
pub fn local_name<'a>(q: QName<'a>) -> &'a str {
    let s = q.into_inner();
    match s.rsplit_once(':') {
        Some((_, local)) => local,
        None => s,
    }
}

/// Resolve a `quick-xml` `Event::GeneralRef` (`&amp;`, `&quot;`, `&#xNN;`, etc.) into UTF-8 text.
/// Unknown named XML entities return a protocol error rather than passing through unexpanded.
pub fn resolve_general_ref(r: &BytesRef<'_>) -> Result<Cow<'static, str>> {
    if let Some(ch) = r
        .resolve_char_ref()
        .map_err(|e| Error::protocol(format!("XML char ref error: {e}")))?
    {
        return Ok(Cow::Owned(ch.to_string()));
    }
    match r.as_ref() {
        "amp" => Ok(Cow::Borrowed("&")),
        "lt" => Ok(Cow::Borrowed("<")),
        "gt" => Ok(Cow::Borrowed(">")),
        "quot" => Ok(Cow::Borrowed("\"")),
        "apos" => Ok(Cow::Borrowed("'")),
        other => Err(Error::protocol(format!("unknown XML entity `&{other};`"))),
    }
}

/// Escape XML special characters (`&`, `<`, `>`, `"`, `'`) in text or attribute values.
pub fn escape_xml_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Extract decoded text from `Event::Text`, `Event::CData`, or `Event::GeneralRef`,
/// returning `Ok(None)` for all other XML events so callers handle text/CDATA/entity
/// references in one match arm.
pub fn event_text<'a>(ev: &'a Event<'a>) -> Result<Option<Cow<'a, str>>> {
    match ev {
        Event::Text(t) => Ok(Some(t.xml10_content())),
        Event::CData(c) => Ok(Some(Cow::Borrowed(c.as_ref()))),
        Event::GeneralRef(r) => Ok(Some(resolve_general_ref(r)?)),
        _ => Ok(None),
    }
}
