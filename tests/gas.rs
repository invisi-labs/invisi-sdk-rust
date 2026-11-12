use invisi_sdk::gas::*;
use serde_json::json;
#[test]
fn legal_unmeasured_shapes_have_calibrated_estimates() {
    let estimate = estimate_gas(
        json!({"kind":"transact","noteInputs":17,"noteOutputs":4,"sourceTrees":3})
            .as_object()
            .unwrap(),
    )
    .unwrap();
    assert!(estimate.gas_units().unwrap() > alloy_primitives::U256::ZERO);
    assert_eq!(
        serde_json::to_value(estimate).unwrap()["statistic"],
        "estimate"
    );
}
#[test]
fn typescript_model_parity_vectors() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/gas-model-parity.json")).unwrap();
    for (i, v) in fixture["vectors"].as_array().unwrap().iter().enumerate() {
        let actual =
            serde_json::to_value(estimate_gas(v["query"].as_object().unwrap()).unwrap()).unwrap();
        let mut expected = if v["result"]["available"] == true {
            fixture["availableDefaults"].clone()
        } else {
            json!({})
        };
        expected
            .as_object_mut()
            .unwrap()
            .extend(v["result"].as_object().unwrap().clone());
        assert_eq!(actual, expected, "vector {i}: {}", v["query"]);
    }
}
#[test]
fn held_out_measurements_remain_within_calibrated_error() {
    let validation: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/model-validation.json")).unwrap();
    assert_eq!(validation["cases"].as_array().unwrap().len(), 12);
    for case in validation["cases"].as_array().unwrap() {
        let mut query = case["shape"].as_object().unwrap().clone();
        query.insert("extraDeliveryBytes".into(), json!(1));
        let estimate = estimate_gas(&query).unwrap();
        assert_eq!(
            serde_json::to_value(&estimate).unwrap()["statistic"],
            "estimate"
        );
        let units = estimate
            .gas_units()
            .unwrap()
            .to_string()
            .parse::<f64>()
            .unwrap();
        let measured = case["measuredGas"].as_f64().unwrap();
        assert!(((units - 32.0) / measured - 1.0).abs() < 0.15, "{case}");
    }
}
#[test]
fn all_legal_direct_counts_and_grouping_ranges_have_positive_gas() {
    for outputs in 1..=10 {
        for fee in [false, true] {
            assert!(
                estimate_gas(
                    json!({"kind":"shield","noteOutputs":outputs,"fee":fee})
                        .as_object()
                        .unwrap()
                )
                .unwrap()
                .gas_units()
                .unwrap()
                    > alloy_primitives::U256::ZERO
            );
        }
    }
    for inputs in 1..=190 {
        for source_trees in 1..=inputs {
            assert!(estimate_gas(json!({"kind":"transact","noteInputs":inputs,"noteOutputs":0,"withdrawal":true,"sourceTrees":source_trees}).as_object().unwrap()).unwrap().gas_units().unwrap() > alloy_primitives::U256::ZERO);
        }
    }
    for inputs in 0..=190 {
        for outputs in 0..=190 - inputs {
            if inputs + outputs == 0 || (inputs == 0 && outputs < 2) {
                continue;
            }
            for deposit in [false, true] {
                for withdrawal in [false, true] {
                    for fee in [false, true] {
                        if (inputs == 0 && !deposit) || (outputs == 0 && !withdrawal && !fee) {
                            continue;
                        }
                        let q = json!({"kind":"transact","noteInputs":inputs,"noteOutputs":outputs,"deposit":deposit,"withdrawal":withdrawal,"fee":fee});
                        assert!(
                            estimate_gas(q.as_object().unwrap())
                                .unwrap()
                                .gas_units()
                                .unwrap()
                                > alloy_primitives::U256::ZERO
                        );
                    }
                }
            }
        }
    }
    for n in 1..=80 {
        for payers in 1..=n {
            for trees in 1..=n {
                for fee in [false, true] {
                    let q = json!({"kind":"draw-credit","creditInputs":n,"distinctPayers":payers,"sourceTrees":trees,"fee":fee});
                    assert!(
                        estimate_gas(q.as_object().unwrap())
                            .unwrap()
                            .gas_units()
                            .unwrap()
                            > alloy_primitives::U256::ZERO
                    );
                }
            }
        }
    }
}
#[test]
fn pinned_typescript_assets_are_byte_exact() {
    use sha2::{Digest, Sha256};
    for (bytes, hash) in [
        (
            &include_bytes!("fixtures/measured-model.json")[..],
            "c028b0d193e0b7c5a9eb549f0fd3be61fede5b33e2078e51675663049a9789bc",
        ),
        (
            &include_bytes!("fixtures/model-validation.json")[..],
            "82cfc194f1bd5bc0d00c4e3b97d6a350eabb4bb4f05540e7007296cba5d0d28d",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(bytes)), hash);
    }
}
#[test]
fn invalid_shapes_and_unsupported_execution_are_distinct() {
    for query in [
        json!({"kind":"shield","noteOutputs":0}),
        json!({"kind":"shield","noteOutputs":11}),
        json!({"kind":"transact","noteInputs":1,"noteOutputs":1,"capacity":3}),
        json!({"kind":"transact","noteInputs":0,"noteOutputs":1,"deposit":true}),
        json!({"kind":"transact","noteInputs":1,"noteOutputs":1,"sourceTrees":2}),
        json!({"kind":"transact","noteInputs":1,"noteOutputs":0}),
        json!({"kind":"draw-credit","creditInputs":81}),
        json!({"kind":"draw-credit","creditInputs":2,"distinctPayers":3}),
        json!({"kind":"draw-credit","creditInputs":2,"sourceTrees":0}),
        json!({"kind":"shield","noteOutputs":1,"extraDeliveryBytes":-1}),
    ] {
        assert!(estimate_gas(query.as_object().unwrap()).is_err(), "{query}");
    }
    for kind in ["aggregate", "noir-recursive", "unknown"] {
        assert_eq!(
            serde_json::to_value(estimate_gas(json!({"kind":kind}).as_object().unwrap()).unwrap())
                .unwrap(),
            json!({"source":"benchmark","available":false,"reason":"shape-not-covered"})
        );
    }
}
