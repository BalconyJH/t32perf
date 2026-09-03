//! Strict JSON decoding for trusted and control-plane documents.
//!
//! Standard JSON object decoding can accept duplicate member names and retain
//! either the first or last value. That behavior is unsafe across signatures,
//! languages, and control-plane boundaries because two implementations can
//! assign different meanings to the same bytes. These helpers reject duplicate
//! names recursively before decoding the original bytes into the requested
//! type. Streaming callers that already need an untyped tree can retain the
//! checked [`Value`] and deserialize it without reparsing valid input.

use std::fmt;

use serde::{
    Deserialize, Deserializer, de::DeserializeOwned, de::Error as _, de::MapAccess, de::SeqAccess,
    de::Visitor,
};
use serde_json::{Map, Number, Value};

/// Decodes one JSON value while rejecting duplicate object names at every depth.
///
/// Callers remain responsible for bounding `input` before invoking this
/// function. The document is validated and decoded in two passes. The second
/// pass uses the original bytes so typed decoding errors retain the same line
/// and column information as [`serde_json::from_slice`].
pub fn from_slice<T: DeserializeOwned>(input: &[u8]) -> serde_json::Result<T> {
    value_from_slice(input)?;
    serde_json::from_slice(input)
}

/// Decodes one JSON string while rejecting duplicate object names at every depth.
///
/// Callers remain responsible for bounding `input` before invoking this
/// function.
pub fn from_str<T: DeserializeOwned>(input: &str) -> serde_json::Result<T> {
    from_slice(input.as_bytes())
}

/// Decodes one JSON value while rejecting duplicate object names at every depth.
///
/// Unlike [`from_slice`], this function returns the recursively checked
/// untyped tree produced by the validation pass. Callers that inspect fields
/// before typed decoding can consume this value with [`serde_json::from_value`]
/// and avoid parsing valid input a second time.
///
/// Callers remain responsible for bounding `input` before invoking this
/// function.
pub fn value_from_slice(input: &[u8]) -> serde_json::Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value.0)
}

/// Decodes one JSON string into a recursively duplicate-checked value.
///
/// Callers remain responsible for bounding `input` before invoking this
/// function.
pub fn value_from_str(input: &str) -> serde_json::Result<Value> {
    value_from_slice(input.as_bytes())
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object member names")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_i128(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("JSON integer is outside the supported range"))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_u128(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("JSON integer is outside the supported range"))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::with_capacity(object.size_hint().unwrap_or(0));
        while let Some(name) = object.next_key::<String>()? {
            if values.contains_key(&name) {
                return Err(A::Error::custom(format_args!(
                    "duplicate JSON object member name `{name}`"
                )));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(name, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::Value;

    use super::{from_slice, from_str, value_from_slice, value_from_str};

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Document {
        name: String,
        properties: Value,
    }

    #[test]
    fn decodes_valid_typed_document() {
        let document: Document =
            from_str(r#"{"name":"capture","properties":{"nested":[{"enabled":true}]}}"#)
                .expect("strict document");

        assert_eq!(document.name, "capture");
        assert_eq!(document.properties["nested"][0]["enabled"], true);
    }

    #[test]
    fn returns_the_recursively_checked_value_without_a_second_decode() {
        let value =
            value_from_str(r#"{"name":"capture","properties":{"nested":[{"enabled":true}]}}"#)
                .expect("strict value");

        assert_eq!(value["name"], "capture");
        assert_eq!(value["properties"]["nested"][0]["enabled"], true);
    }

    #[test]
    fn value_decode_retains_duplicate_location() {
        let input =
            b"{\n  \"properties\": {\n    \"mode\": \"first\",\n    \"mode\": \"last\"\n  }\n}";
        let error = value_from_slice(input).expect_err("duplicate member");

        assert!(
            error
                .to_string()
                .contains("duplicate JSON object member name `mode`")
        );
        assert_eq!(error.line(), 4);
        assert!(error.column() > 0);
    }

    #[test]
    fn rejects_duplicate_top_level_member() {
        let error =
            from_str::<Value>(r#"{"name":"first","name":"last"}"#).expect_err("duplicate member");

        assert!(
            error
                .to_string()
                .contains("duplicate JSON object member name `name`")
        );
        assert_eq!(error.line(), 1);
        assert!(error.column() > 0);
    }

    #[test]
    fn rejects_names_that_are_equal_after_json_unescaping() {
        let error = from_str::<Value>(r#"{"mode":"first","m\u006fde":"last"}"#)
            .expect_err("escaped duplicate member");

        assert!(
            error
                .to_string()
                .contains("duplicate JSON object member name `mode`")
        );
    }

    #[test]
    fn rejects_duplicate_member_nested_in_array_and_properties() {
        let error = from_str::<Document>(
            r#"{"name":"capture","properties":{"nested":[{"mode":"first","mode":"last"}]}}"#,
        )
        .expect_err("nested duplicate member");

        assert!(
            error
                .to_string()
                .contains("duplicate JSON object member name `mode`")
        );
    }

    #[test]
    fn typed_error_retains_original_line_and_column() {
        let input = b"{\n  \"name\": 42,\n  \"properties\": {}\n}";
        let expected = serde_json::from_slice::<Document>(input).expect_err("type error");
        let actual = from_slice::<Document>(input).expect_err("type error");

        assert_eq!(actual.line(), expected.line());
        assert_eq!(actual.column(), expected.column());
        assert_eq!(actual.to_string(), expected.to_string());
    }

    #[test]
    fn rejects_trailing_json_value() {
        let error = from_str::<Value>("{} {} ").expect_err("trailing value");

        assert_eq!(error.classify(), serde_json::error::Category::Syntax);
    }
}
