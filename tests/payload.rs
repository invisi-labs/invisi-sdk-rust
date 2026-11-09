use invisi_sdk::payload::*;
#[test]
fn memo_application_codecs_preserve_bytes_and_enforce_version() {
    assert_eq!(encode_funds_v1(&FundsDataV1::default()).unwrap(), vec![1]);
    let data = FundsDataV1 {
        memo: encode_memo(Some(Memo::Text("hello 🌍"))).unwrap(),
    };
    let encoded = encode_funds_v1(&data).unwrap();
    assert_eq!(decode_funds_v1(&encoded).unwrap(), data);
    assert_eq!(decode_credit_v1(&encoded).unwrap(), data);
    let opaque = vec![255, 0, 1];
    assert_eq!(encode_memo(Some(Memo::Bytes(&opaque))).unwrap(), opaque);
    assert!(decode_memo_text(&opaque).is_err());
    assert!(encode_memo(Some(Memo::Bytes(&[0; 257]))).is_err());
    assert!(decode_funds_v1(&[]).is_err());
    assert!(decode_funds_v1(&[2]).is_err());
    assert!(decode_credit_v1(&[1; 258]).is_err());
    assert_eq!(decode_memo_text(&[239, 187, 191, 65]).unwrap(), "\u{feff}A");
}
