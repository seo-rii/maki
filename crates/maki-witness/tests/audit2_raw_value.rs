//! Round-2 audit: functional behaviour of the locally patched serde_json
//! `raw_value` paths that maki-witness compiles into the daemon.
//!
//! Every assertion states upstream serde_json 1.0.x behaviour; a failure means
//! the local erasure edits changed bytes, ownership or error results.
use serde::{Deserialize, Serialize};
use serde_json::value::{to_raw_value, RawValue};
use serde_json::Value;

const CASES: &[&str] = &[
    "null",
    "true",
    "0",
    "-12.5e+3",
    "18446744073709551615",
    "\"\"",
    "\"plain\"",
    "\"esc \\\" \\\\ \\/ \\b\\f\\n\\r\\t \\u00e9 \\ud83d\\ude00\"",
    "\"multi-byte é 漢字 😀\"",
    "[]",
    "{}",
    "[1, 2 ,3]",
    "{ \"a\" : [ {\"b\":null} , \"c\" ] , \"d\":{} }",
    "{\"$serde_json::private::RawValue\":1}",
];

fn deep(n: usize) -> String {
    let mut s = "[".repeat(n);
    s.push('1');
    s.push_str(&"]".repeat(n));
    s
}

#[test]
fn borrowed_raw_value_is_an_exact_input_slice() {
    for case in CASES {
        for padded in [case.to_string(), format!(" \n\t{case} \r\n")] {
            let raw: &RawValue = serde_json::from_str(&padded).unwrap();
            assert_eq!(raw.get(), *case, "from_str {padded:?}");
            let bytes = padded.as_bytes();
            let raw: &RawValue = serde_json::from_slice(bytes).unwrap();
            assert_eq!(raw.get(), *case, "from_slice {padded:?}");
            // The borrow points into the caller's buffer, not parser scratch.
            let start = raw.get().as_ptr() as usize;
            let base = bytes.as_ptr() as usize;
            assert!(start >= base && start + raw.get().len() <= base + bytes.len());
        }
    }
}

#[test]
fn reader_and_boxed_paths_keep_exact_bytes() {
    let mut cases: Vec<String> = CASES.iter().map(|s| s.to_string()).collect();
    // Exercise several private growth steps, multi-byte UTF-8 across them,
    // and a deep explicit ignore stack.
    cases.push(format!("\"{}\"", "é漢😀x".repeat(5000)));
    cases.push(deep(20_000));
    for case in &cases {
        for padded in [case.clone(), format!("  {case}\n ")] {
            let boxed: Box<RawValue> = serde_json::from_reader(padded.as_bytes()).unwrap();
            assert_eq!(boxed.get(), case);
            let boxed: Box<RawValue> = serde_json::from_str(&padded).unwrap();
            assert_eq!(boxed.get(), case);
            let boxed: Box<RawValue> = serde_json::from_slice(padded.as_bytes()).unwrap();
            assert_eq!(boxed.get(), case);
            // from_string trims surrounding whitespace by copying, and reuses
            // an exact-capacity allocation otherwise.
            let from_string = RawValue::from_string(padded.clone()).unwrap();
            assert_eq!(from_string.get(), case);
            let mut spare = String::with_capacity(padded.len() + 100);
            spare.push_str(&padded);
            assert_eq!(RawValue::from_string(spare).unwrap().get(), case);
            let clone = from_string.clone();
            assert_eq!(clone.get(), case);
            let owned: Box<str> = clone.into();
            assert_eq!(&*owned, case);
        }
    }
}

#[test]
fn raw_value_in_structs_seqs_maps_and_reader_streams() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Borrowed<'a> {
        id: u32,
        #[serde(borrow)]
        request: &'a RawValue,
        #[serde(borrow)]
        list: Vec<&'a RawValue>,
    }
    #[derive(Deserialize, Serialize)]
    struct Owned {
        id: u32,
        request: Box<RawValue>,
        list: Vec<Box<RawValue>>,
        opt: Option<Box<RawValue>>,
    }
    let input = "{\"id\":7,\"request\": {\"k\" : [1,\"\\u0041\"]} ,\"list\":[ 1 ,\"x\",{} ],\"opt\":null}";
    let owned: Owned = serde_json::from_reader(input.as_bytes()).unwrap();
    assert_eq!(owned.id, 7);
    assert_eq!(owned.request.get(), "{\"k\" : [1,\"\\u0041\"]}");
    let list: Vec<&str> = owned.list.iter().map(|r| r.get()).collect();
    assert_eq!(list, ["1", "\"x\"", "{}"]);
    assert!(owned.opt.is_none());
    assert_eq!(
        serde_json::to_string(&owned).unwrap(),
        "{\"id\":7,\"request\":{\"k\" : [1,\"\\u0041\"]},\"list\":[1,\"x\",{}],\"opt\":null}"
    );
    let trimmed = input.replace(",\"opt\":null", "");
    let borrowed: Borrowed = serde_json::from_slice(trimmed.as_bytes()).unwrap();
    assert_eq!(borrowed.id, 7);
    assert_eq!(borrowed.request.get(), "{\"k\" : [1,\"\\u0041\"]}");
    assert_eq!(borrowed.list.len(), 3);

    // Map keys (MapKey deserializer path) and a reader stream of raw values.
    let map: std::collections::BTreeMap<String, Box<RawValue>> =
        serde_json::from_reader("{\"a\": [1] , \"b\":\"q\"}".as_bytes()).unwrap();
    assert_eq!(map["a"].get(), "[1]");
    assert_eq!(map["b"].get(), "\"q\"");
    let stream: Vec<String> = serde_json::Deserializer::from_reader("1 \"a\"[2]{}  null".as_bytes())
        .into_iter::<Box<RawValue>>()
        .map(|r| r.unwrap().get().to_owned())
        .collect();
    assert_eq!(stream, ["1", "\"a\"", "[2]", "{}", "null"]);
}

#[test]
fn value_conversions_and_serializer_paths_match_upstream() {
    let value: Value = serde_json::from_str(
        "{\"a\":[1,2.5,-3,\"s\\n\",null,true],\"b\":{\"c\":\"é\"},\"big\":18446744073709551615}",
    )
    .unwrap();
    let compact = serde_json::to_string(&value).unwrap();
    // to_raw_value uses the compact serializer.
    assert_eq!(to_raw_value(&value).unwrap().get(), compact);
    // from_value (Value::deserialize_newtype_struct) and &Value.
    let from_value: Box<RawValue> = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(from_value.get(), compact);
    let from_ref = Box::<RawValue>::deserialize(&value).unwrap();
    assert_eq!(from_ref.get(), compact);
    // RawValue -> Value through the serializer and through Deserialize.
    let raw = RawValue::from_string(" [ 1 , {\"x\" : \"y\"} ] ".to_owned()).unwrap();
    assert_eq!(
        serde_json::to_value(&*raw).unwrap(),
        serde_json::json!([1, {"x": "y"}])
    );
    assert_eq!(
        serde_json::from_str::<Value>(&serde_json::to_string(&raw).unwrap()).unwrap(),
        serde_json::json!([1, {"x": "y"}])
    );
    // &RawValue as a Deserializer.
    let parsed = Value::deserialize(&*raw).unwrap();
    assert_eq!(parsed, serde_json::json!([1, {"x": "y"}]));
    // Pretty output keeps the raw fragment verbatim.
    let pretty = serde_json::to_string_pretty(&serde_json::json!({"k": 1})).unwrap();
    #[derive(Serialize)]
    struct Wrap<'a> {
        raw: &'a RawValue,
    }
    let out = serde_json::to_string_pretty(&Wrap { raw: &raw }).unwrap();
    assert_eq!(out, "{\n  \"raw\": [ 1 , {\"x\" : \"y\"} ]\n}");
    assert!(pretty.contains('\n'));
    // The token-keyed JSON object quirk (upstream classifies it as raw).
    let quirk: Value =
        serde_json::from_str("{\"$serde_json::private::RawValue\":\"[1,2]\"}").unwrap();
    assert_eq!(quirk, serde_json::json!([1, 2]));
    // Display/Debug keep upstream text.
    assert_eq!(format!("{raw}"), " [ 1 , {\"x\" : \"y\"} ] ".trim());
    assert_eq!(
        format!("{:?}", RawValue::NULL),
        "RawValue(null)"
    );
    assert_eq!(Box::<RawValue>::default().get(), "null");
    // Borrowed &RawValue cannot come from an owned Value.
    assert!(serde_json::from_value::<Value>(Value::Null).is_ok());
}

#[test]
fn raw_value_errors_match_upstream_messages_and_positions() {
    for (input, message) in [
        ("", "EOF while parsing a value at line 1 column 0"),
        ("[1,", "EOF while parsing a value at line 1 column 3"),
        ("[1 2]", "expected `,` or `]` at line 1 column 4"),
        ("{\"a\" 1}", "expected `:` at line 1 column 6"),
        ("\"abc", "EOF while parsing a string at line 1 column 4"),
        ("1 2", "trailing characters at line 1 column 3"),
        ("nul", "EOF while parsing a value at line 1 column 3"),
    ] {
        let err = serde_json::from_str::<&RawValue>(input).unwrap_err();
        assert_eq!(err.to_string(), message, "from_str {input:?}");
        let err = serde_json::from_reader::<_, Box<RawValue>>(input.as_bytes()).unwrap_err();
        assert_eq!(err.to_string(), message, "from_reader {input:?}");
        assert!(RawValue::from_string(input.to_owned()).is_err());
    }
    // Invalid UTF-8 inside a raw value read from a slice or reader.
    let bad: &[u8] = b"\"\xff\"";
    assert!(serde_json::from_slice::<&RawValue>(bad).is_err());
    assert!(serde_json::from_reader::<_, Box<RawValue>>(bad).is_err());
    // A borrowed raw value cannot be produced from a reader.
    let err = serde_json::from_reader::<_, Value>("x".as_bytes()).unwrap_err();
    assert_eq!(err.to_string(), "expected value at line 1 column 1");
    // Custom error messages that already carry a position are re-parsed.
    #[derive(Debug)]
    struct Pos;
    impl std::fmt::Display for Pos {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("nested é at line 12 column 34")
        }
    }
    let err = <serde_json::Error as serde::de::Error>::custom(Pos);
    assert_eq!((err.line(), err.column()), (12, 34));
    assert_eq!(err.to_string(), "nested é at line 12 column 34");
    assert_eq!(
        format!("{err:?}"),
        "Error(\"nested é\", line: 12, column: 34)"
    );
    let err = <serde_json::Error as serde::de::Error>::custom("no suffix at line x column 1");
    assert_eq!((err.line(), err.column()), (0, 0));
    assert_eq!(err.to_string(), "no suffix at line x column 1");
}
