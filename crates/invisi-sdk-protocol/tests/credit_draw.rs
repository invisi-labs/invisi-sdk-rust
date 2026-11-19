use invisi_sdk_protocol::interfaces::{CreditTransition, IndexedCreditState};
use serde_json::{json, Value};

fn draw() -> Value {
    let hash = format!("0x{}", "01".repeat(32));
    let delivery = json!({"ciphertext":"0x81", "clue": format!("0x{}", "02".repeat(68))});
    json!({"block":{"number":10,"hash":hash,"parentHash":hash,"timestamp":123},
        "treeId":1,"leafIndex":0,"commitment":hash,"token":format!("0x{}", "11".repeat(20)),
        "transactionHash":hash,"logIndex":1,"kind":"CreditDraw","name":"CreditDraw",
        "data":{"totalAmount":"10000000000000000"},"deliveries":[delivery,delivery]})
}

#[test]
fn accepts_draw_state_and_transition_without_relaxing_validation() {
    let value = draw();
    assert_eq!(
        IndexedCreditState::parse(&value).unwrap().leaf.kind,
        "CreditDraw"
    );
    assert_eq!(CreditTransition::parse(&value).unwrap().name, "CreditDraw");
    for kind in ["NoteOutputs", "UnknownEvent"] {
        let mut bad = value.clone();
        bad["kind"] = json!(kind);
        assert!(IndexedCreditState::parse(&bad).is_err());
    }
    let mut bad = value.clone();
    bad["deliveries"] = json!([]);
    assert!(IndexedCreditState::parse(&bad).is_err());
    let mut bad = value;
    bad["name"] = json!("UnknownEvent");
    assert!(CreditTransition::parse(&bad).is_err());
}
