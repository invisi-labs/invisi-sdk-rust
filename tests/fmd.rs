use invisi_sdk::fmd::*;
#[test]
fn matches_pinned_ts_go_fmd_vectors() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/current-fmd.json")).unwrap();
    for row in v["vectors"].as_array().unwrap() {
        let bytes = |name: &str| hex::decode(row[name].as_str().unwrap()).unwrap();
        let key = bytes("detectionKey");
        let clue_key = bytes("clueKey");
        let clue = bytes("clue");
        assert_eq!(derive_clue_key(&key).unwrap().as_slice(), clue_key);
        assert_eq!(
            create_clue_from_seed(&clue_key, &bytes("seedHex")).unwrap(),
            clue
        );
        assert!(detect_clue(&key, &clue).unwrap());
        assert!(!detect_clue(&bytes("otherDetectionKey"), &clue).unwrap());
    }
}
#[test]
fn rejects_bad_keys_lengths_and_treats_malformed_clues_as_nonmatches() {
    assert!(derive_clue_key(&[0; 32]).is_err());
    assert!(validate_clue_key(&[0; 32]).is_err());
    assert!(create_clue_from_seed(&[0; 32], &[0; 32]).is_err());
    let mut key = [0; 32];
    key[0] = 1;
    assert!(detect_clue(&key, &[0; 67]).is_err());
    let mut clue = [0; 68];
    clue[64] = 24;
    assert!(!detect_clue(&key, &clue).unwrap());
    clue[64] = 0;
    assert!(!detect_clue(&key, &clue).unwrap());
    let clue_key = derive_clue_key(&key).unwrap();
    let fresh = create_clue(&clue_key).unwrap();
    assert!(detect_clue(&key, &fresh).unwrap());
    assert!(create_clue_from_seed(&clue_key, &[0; 31]).is_err());
}
