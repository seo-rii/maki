//! Configuration must reserve room for the largest framed journal record.
use maki_format::config::{parse_config, ByteSize};
use maki_format::journal::{encode_record, JournalRecord};

#[test]
fn pending_limit_must_hold_one_maximum_encoded_record() {
    let mut cfg = parse_config(include_str!("data/full_config.toml")).unwrap();
    let required = encode_record(&JournalRecord {
        sequence: 1,
        unit_index: 0,
        payload: vec![0; cfg.crypto.capabilities.max_ciphertext_size as usize],
    })
    .len() as u64;
    for limit in [0, required - 1] {
        cfg.limits.max_journal_pending_bytes = ByteSize(limit);
        let error = cfg
            .validate()
            .expect_err("pending budget cannot fit a record");
        assert!(error.to_string().contains("max_journal_pending_bytes"));
    }
    for limit in [required, required + 1] {
        cfg.limits.max_journal_pending_bytes = ByteSize(limit);
        cfg.validate()
            .expect("a whole record fits exactly at the boundary");
    }
}
