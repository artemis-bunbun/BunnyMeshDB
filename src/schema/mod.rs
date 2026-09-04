//! Minimal JSON-Schema validation for per-namespace payload schemas.
//!
//! Subset (draft-07/2020-12 surface): `type`, `enum`, `const`, `properties`,
//! `required`, `additionalProperties`, `items`, `minItems`/`maxItems`/
//! `uniqueItems`, `minLength`/`maxLength`, `minProperties`/`maxProperties`,
//! `minimum`/`maximum`, `exclusiveMinimum`/`exclusiveMaximum`, `multipleOf`,
//! `oneOf`/`anyOf`/`allOf`, `not`, plus the annotation keywords `title`,
//! `description`, `default`, `examples`, `$comment`.
//!
//! Deliberately NOT supported: `pattern`, `format`, `$ref`/`$schema`/`$id`/
//! `$defs`. There is no audited regex engine in-tree, so `pattern`/`format`
//! cannot be enforced — rather than silently skip them, `check_supported`
//! rejects a schema that uses them at set time. Add an audited regex engine
//! before accepting those keywords.

use serde_json::{Value as JValue};

fn type_names() -> std::collections::BTreeSet<String> {
    let mut s = std::collections::BTreeSet::new();
    for n in vec!["null", "boolean", "object", "array", "string", "integer", "number"] {
        s.insert(n.to_string());
    }
    s
}

fn supported_kws() -> std::collections::BTreeSet<String> {
    let mut s = std::collections::BTreeSet::new();
    for kw in vec!["type", "enum", "const", "properties", "required", "additionalProperties",
                   "items", "prefixItems", "minItems", "maxItems", "uniqueItems",
                   "minLength", "maxLength", "minProperties", "maxProperties",
                   "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
                   "multipleOf", "oneOf", "anyOf", "allOf", "not",
                   "title", "description", "default", "examples", "$comment"] {
        s.insert(kw.to_string());
    }
    s
}

fn is_number(v: &JValue) -> bool {
    v.as_i64().is_some() || v.as_f64().is_some()
}

fn matches_type(name: &str, v: &JValue) -> bool {
    match name {
        "null" => v.is_null(),
        "boolean" => v.is_boolean(),
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "integer" => v.as_i64().is_some(),
        "number" => is_number(v),
        _ => false,
    }
}

/// Validate `value` against one subschema. `schema` must be an Object node
/// (booleans are handled by the caller walking a schema, not here).
fn validate_at(schema: &JValue, value: &JValue, path: &str) -> Result<(), String> {
    match schema {
        JValue::Object(map) => {
            // `type`: string or array of type names.
            if let Some(t) = map.get("type") {
                if let Some(s) = t.as_str() {
                    if !matches_type(s, value) {
                        return Err(format!("{path}: expected type {s:?}"));
                    }
                } else if let Some(arr) = t.as_array() {
                    let mut hit = false;
                    for n in arr {
                        let name = n.as_str();
                        if name.is_some() && matches_type(name.unwrap(), value) {
                            hit = true;
                        }
                    }
                    if !hit {
                        return Err(format!("{path}: value matches none of the allowed types"));
                    }
                }
            }
            // enum / const.
            if let Some(members) = map.get("enum").and_then(|e| e.as_array()) {
                let mut hit = false;
                for m in members {
                    if *m == *value {
                        hit = true;
                    }
                }
                if !hit {
                    return Err(format!("{path}: value not in enum"));
                }
            }
            if let Some(expected) = map.get("const") {
                if *expected != *value {
                    return Err(format!("{path}: value does not match const"));
                }
            }
            // String length.
            if value.is_string() {
                let s = value.as_str().unwrap();
                if let Some(min) = map.get("minLength").and_then(|v| v.as_i64()) {
                    if s.len() < min as usize {
                        return Err(format!("{path}: string length {} < minLength {min}", s.len()));
                    }
                }
                if let Some(max) = map.get("maxLength").and_then(|v| v.as_i64()) {
                    if s.len() > max as usize {
                        return Err(format!("{path}: string length {} > maxLength {max}", s.len()));
                    }
                }
            }
            // Numeric bounds.
            if let Some(n) = value.as_f64() {
                if let Some(m) = map.get("minimum").and_then(|v| v.as_f64()) {
                    if n < m { return Err(format!("{path}: {n} < minimum {m}")); }
                }
                if let Some(m) = map.get("maximum").and_then(|v| v.as_f64()) {
                    if n > m { return Err(format!("{path}: {n} > maximum {m}")); }
                }
                if let Some(m) = map.get("exclusiveMinimum").and_then(|v| v.as_f64()) {
                    if !(n > m) { return Err(format!("{path}: {n} <= exclusiveMinimum {m}")); }
                }
                if let Some(m) = map.get("exclusiveMaximum").and_then(|v| v.as_f64()) {
                    if !(n < m) { return Err(format!("{path}: {n} >= exclusiveMaximum {m}")); }
                }
                if let Some(m) = map.get("multipleOf").and_then(|v| v.as_f64()) {
                    if m != 0.0 {
                        let q = n / m;
                        if q.fract().abs() > 1e-9 {
                            return Err(format!("{path}: {n} is not a multiple of {m}"));
                        }
                    }
                }
            }
            // Object shape.
            if let Some(obj) = value.as_object() {
                let props = map.get("properties").and_then(|m| m.as_object());
                if let Some(max) = map.get("maxProperties").and_then(|v| v.as_i64()) {
                    if obj.len() > max as usize { return Err(format!("{path}: too many properties")); }
                }
                if let Some(min) = map.get("minProperties").and_then(|v| v.as_i64()) {
                    if obj.len() < min as usize { return Err(format!("{path}: too few properties")); }
                }
                if let Some(required) = map.get("required").and_then(|r| r.as_array()) {
                    for item in required {
                        let name = item.as_str();
                        if name.is_none() {
                            return Err(format!("{path}: `required` entry is not a string"));
                        }
                        let name = name.unwrap();
                        if !obj.contains_key(name) {
                            return Err(format!("{path}: missing required property {name:?}"));
                        }
                    }
                }
                let extra_schema: Option<&JValue> = {
                    let ap = map.get("additionalProperties");
                    if let Some(v) = ap {
                        if v.is_object() {
                            Some(v)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };
                let mut extra_allowed = true;
                if let Some(ap) = map.get("additionalProperties") {
                    if let Some(b) = ap.as_bool() {
                        extra_allowed = b;
                    }
                }
                for (k, v) in obj.iter() {
                    let declared: Option<&JValue> = props.and_then(|p| p.get(k));
                    if let Some(sub) = declared {
                        validate_at(sub, v, format!("{path}/{k}").as_str())?;
                    } else if let Some(sub) = extra_schema {
                        validate_at(sub, v, format!("{path}/{k}").as_str())?;
                    } else if !extra_allowed {
                        return Err(format!("{path}: unexpected property {k:?}"));
                    }
                }
            }
            // Array shape.
            if let Some(arr) = value.as_array() {
                if let Some(max) = map.get("maxItems").and_then(|v| v.as_i64()) {
                    if arr.len() > max as usize { return Err(format!("{path}: too many items")); }
                }
                if let Some(min) = map.get("minItems").and_then(|v| v.as_i64()) {
                    if arr.len() < min as usize { return Err(format!("{path}: too few items")); }
                }
                if map.get("uniqueItems").and_then(|v| v.as_bool()).unwrap_or(false) {
                    for i in 0..arr.len() {
                        for j in (i + 1)..arr.len() {
                            if arr[i] == arr[j] {
                                return Err(format!("{path}: duplicate item"));
                            }
                        }
                    }
                }
                if let Some(items) = map.get("items") {
                    if items.is_object() || items.is_boolean() {
                        for item in arr {
                            validate_at(items, item, format!("{path}[]").as_str())?;
                        }
                    }
                }
            }
            // Combinators.
            if let Some(members) = map.get("oneOf").and_then(|v| v.as_array()) {
                if count_ok(members, value, path) != 1 {
                    return Err(format!("{path}: does not match exactly one of `oneOf`"));
                }
            }
            if let Some(members) = map.get("anyOf").and_then(|v| v.as_array()) {
                if count_ok(members, value, path) == 0 {
                    return Err(format!("{path}: matches none of `anyOf`"));
                }
            }
            if let Some(members) = map.get("allOf").and_then(|v| v.as_array()) {
                for m in members {
                    validate_at(m, value, path)?;
                }
            }
            if let Some(neg) = map.get("not") {
                if validate_at(neg, value, path).is_ok() {
                    return Err(format!("{path}: matched the `not` schema"));
                }
            }
            Ok(())
        }
        JValue::Bool(allowed) => {
            if *allowed { Ok(()) } else { Err(format!("{path}: value prohibited by `false`")) }
        }
        _ => Err(format!("{path}: schema node is not an object or boolean")),
    }
}

fn count_ok(members: &Vec<JValue>, value: &JValue, path: &str) -> usize {
    let mut n = 0usize;
    for m in members {
        if validate_at(m, value, path).is_ok() {
            n += 1;
        }
    }
    n
}

/// Validate `value` against `schema` (object, boolean, or combinator), the
/// public entry point used per-write.
pub fn validate_schema(schema: &JValue, value: &JValue) -> Result<(), String> {
    validate_at(schema, value, "$")
}

/// Recursively reject unsupported/non-object schemas so validation is honest.
pub fn check_supported(schema: &JValue) -> Result<(), String> {
    // Booleans are valid JSON-Schema (true = anything, false = nothing).
    if schema.is_boolean() {
        return Ok(());
    }
    if !schema.is_object() {
        return Err("schema must be an object or boolean".into());
    }
    let kws = supported_kws();
    let types = type_names();
    let map = schema.as_object().unwrap();
    for (kw, sub) in map.iter() {
        if !kws.contains(kw) {
            return Err(format!("unsupported schema keyword: {kw:?}"));
        }
        if kw == "properties" {
            if let Some(props) = sub.as_object() {
                for (_, subschema) in props.iter() {
                    check_supported(subschema)?;
                }
            }
        } else if kw == "additionalProperties" || kw == "items" {
            if sub.is_object() {
                check_supported(sub)?;
            }
        } else if kw == "not" {
            if sub.is_object() || sub.is_boolean() {
                check_supported(sub)?;
            }
        } else if kw == "prefixItems" || kw == "oneOf" || kw == "anyOf" || kw == "allOf" {
            if let Some(arr) = sub.as_array() {
                for m in arr {
                    if m.is_object() || m.is_boolean() {
                        check_supported(m)?;
                    }
                }
            }
        } else if kw == "type" {
            if let Some(s) = sub.as_str() {
                if !types.contains(s) {
                    return Err(format!("unsupported type {s:?}"));
                }
            } else if let Some(arr) = sub.as_array() {
                for n in arr {
                    let name = n.as_str();
                    if name.is_none() || !types.contains(name.unwrap()) {
                        return Err("unsupported `type` entry".into());
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> JValue {
        serde_json::from_str::<JValue>(s).unwrap()
    }

    #[test]
    fn rejects_unsupported_keywords() {
        assert!(check_supported(&v(r##"{"pattern":"^a"}"##)).is_err());
        assert!(check_supported(&v(r##"{"$ref":"#"}"##)).is_err());
    }

    #[test]
    fn object_shape_enforced() {
        let schema = v(r#"{"type":"object","properties":{"title":{"type":"string","minLength":1}},"required":["title"],"additionalProperties":false}"#);
        assert!(validate_schema(&schema, &v(r#"{"title":"hi"}"#)).is_ok());
        assert!(validate_schema(&schema, &v(r#"{"title":""}"#)).is_err());
        assert!(validate_schema(&schema, &v(r#"{"title":"ok","extra":1}"#)).is_err());
        assert!(validate_schema(&schema, &v(r#"{"other":1}"#)).is_err());
        assert!(validate_schema(&schema, &v("[1,2]")).is_err());
    }

    #[test]
    fn arrays_and_numbers() {
        let schema = v(r#"{"type":"array","items":{"type":"integer"},"minItems":1,"uniqueItems":true}"#);
        assert!(validate_schema(&schema, &v("[1,2,3]")).is_ok());
        assert!(validate_schema(&schema, &v("[]")).is_err());
        assert!(validate_schema(&schema, &v("[1,1]")).is_err());
        assert!(validate_schema(&schema, &v("[1,2.5]")).is_err());

        let n = v(r#"{"type":"number","minimum":0,"exclusiveMaximum":100,"multipleOf":5}"#);
        assert!(validate_schema(&n, &v("50")).is_ok());
        assert!(validate_schema(&n, &v("3")).is_err());
        assert!(validate_schema(&n, &v("-1")).is_err());
        assert!(validate_schema(&n, &v("100")).is_err());
    }

    #[test]
    fn enum_and_const() {
        let e = v(r#"{"enum":["a","b",5]}"#);
        assert!(validate_schema(&e, &v(r#""a""#)).is_ok());
        assert!(validate_schema(&e, &v("5")).is_ok());
        assert!(validate_schema(&e, &v(r#""c""#)).is_err());
    }

    #[test]
    fn combinators() {
        let s = v(r#"{"anyOf":[{"type":"string"},{"type":"integer"}]}"#);
        assert!(validate_schema(&s, &v(r#""x""#)).is_ok());
        assert!(validate_schema(&s, &v("5")).is_ok());
        assert!(validate_schema(&s, &v("true")).is_err());

        let n = v(r#"{"type":"string","not":{"enum":["blocked"]}}"#);
        assert!(validate_schema(&n, &v(r#""ok""#)).is_ok());
        assert!(validate_schema(&n, &v(r#""blocked""#)).is_err());
    }
}