//! Audit probe (round 2, #161): RFC 6901 overlap detection edge cases.
//! Expected outcomes follow the request builder (maki-crypto-http
//! `request.rs`: decoded keys, objects only, replace semantics).

use maki_format::config::parse_config;

fn config(body: &str, response: &str) -> String {
    let mut ops = String::new();
    for op in ["encrypt", "decrypt"] {
        ops += &format!(
            "[crypto.http.{op}]\npath = \"/{op}\"\n{}\n[crypto.http.{op}.response]\n{response}\n",
            body.replace("{op}", op)
        );
    }
    format!(
        r#"
config_schema_version = 1
[volume]
name = "t"
max_virtual_size = "1GiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
context_binding = "none"
[[crypto.http.endpoint]]
name = "a"
url = "https://crypto.internal"
{ops}
[backing]
root = "/x"
"#
    )
}

fn single(fields: &str) -> Result<(), String> {
    let text = config(
        &format!("[crypto.http.{{op}}.body]\ntype = \"json\"\n[crypto.http.{{op}}.body.fields]\n{fields}\n"),
        "data_path = \"/data\"\nencoding = \"base64\"\n",
    );
    parse_config(&text)
        .map_err(|e| e.to_string())?
        .validate()
        .map_err(|e| e.to_string())
}

fn batch(items_path: &str, fields: &str) -> Result<(), String> {
    let text = config(
        &format!(
            "[crypto.http.{{op}}.body]\ntype = \"json\"\nitems_path = {items_path:?}\n\
             [crypto.http.{{op}}.body.fields]\n{fields}\n\
             [crypto.http.{{op}}.body.item_fields]\n\"/data\" = {{ source = \"payload\" }}\n\"/unit\" = {{ source = \"unit_index\" }}\n"
        ),
        "items_path = \"/items\"\nitem_index_path = \"/unit\"\ndata_path = \"/data\"\nencoding = \"base64\"\n",
    );
    parse_config(&text)
        .map_err(|e| e.to_string())?
        .validate()
        .map_err(|e| e.to_string())
}

#[test]
fn distinct_keys_are_accepted() {
    for fields in [
        "\"/a\" = { source = \"payload\" }\n\"/ab\" = { source = \"unit_index\" }",
        "\"/a~1b\" = { source = \"payload\" }\n\"/a/b\" = { source = \"unit_index\" }",
        "\"/\" = { source = \"payload\" }\n\"/x\" = { source = \"unit_index\" }",
        "\"/a/b\" = { source = \"payload\" }\n\"/a/c\" = { source = \"unit_index\" }",
        "\"/a\" = { source = \"payload\" }\n\"/a\\u0000\" = { source = \"unit_index\" }\n\"/a!\" = { source = \"batch_index\" }",
    ] {
        assert_eq!(single(fields), Ok(()), "{fields}");
    }
    assert_eq!(
        batch("/items", "\"/items~1x\" = { source = \"volume_id\" }"),
        Ok(())
    );
}

#[test]
fn overlapping_keys_are_refused() {
    for fields in [
        // a trailing slash addresses the empty key inside "a"
        "\"/a\" = { source = \"payload\" }\n\"/a/\" = { source = \"unit_index\" }",
        // "~" and "~0" decode to the same key
        "\"/~\" = { source = \"payload\" }\n\"/~0\" = { source = \"unit_index\" }",
        // separated in raw sort order by "/a!" and "/a/0": still overlap
        "\"/a\" = { source = \"payload\" }\n\"/a!\" = { source = \"batch_index\" }\n\"/a/z/q\" = { source = \"unit_index\" }",
        "\"/\" = { source = \"payload\" }\n\"//\" = { source = \"unit_index\" }",
    ] {
        assert!(single(fields).is_err(), "accepted overlapping {fields}");
    }
    assert!(batch("/items", "\"/items/0\" = { source = \"volume_id\" }").is_err());
    assert!(batch("/items/x", "\"/items\" = { source = \"volume_id\" }").is_err());
    assert!(batch("/", "\"/\" = { source = \"volume_id\" }").is_err());
}
