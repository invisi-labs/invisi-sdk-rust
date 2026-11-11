use alloy_primitives::{Address, B256};
use invisi_sdk_session::rpc::CanonicalBlock;
use invisi_sdk_session::{public_history::*, session::scan_status, session::WalletState};
fn block(n: u64) -> CanonicalBlock {
    CanonicalBlock {
        number: n,
        hash: B256::from(alloy_primitives::U256::from(n).to_be_bytes::<32>()),
        parent_hash: B256::from(
            alloy_primitives::U256::from(n.saturating_sub(1)).to_be_bytes::<32>(),
        ),
        timestamp: n,
    }
}
#[test]
fn actual_typescript_status_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/history-status.json")).unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let input = &case["input"];
        let expected = &case["expected"];
        let number = |name: &str| input[name].as_str().unwrap().parse::<u64>().unwrap();
        let scope = PublicHistoryScope {
            chain_id: 1,
            protocol_address: Address::with_last_byte(1),
            runtime_code_hash: B256::with_last_byte(1),
            deployment_block: 100,
        };
        let mut state = WalletState::default();
        state.discovery_ranges = input["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| CoverageRange {
                from_block: r[0].as_str().unwrap().parse().unwrap(),
                block: block(r[1].as_str().unwrap().parse().unwrap()),
            })
            .collect();
        state.discovery_through = Some(block(number("fully")));
        state.recovery_boundary = Some(number("boundary"));
        state.invalidated = input["invalidated"].as_bool().unwrap_or(false);
        state.credit_replay_from = input["replay"].as_str().map(|n| n.parse().unwrap());
        let history = PublicHistorySnapshot {
            revision: 0,
            generation: 1,
            scope_key: scope.key().unwrap(),
            coverage: vec![],
            pages: vec![],
            through: None,
            indexed_head: Some(block(number("indexed"))),
            known_head: Some(block(number("head"))),
            reorg_from: None,
        };
        let status = scan_status(
            &state,
            &history,
            &scope,
            input["unresolved"].as_u64().unwrap_or(0) as usize,
        );
        assert_eq!(
            status.scan_complete,
            expected["scanComplete"].as_bool().unwrap(),
            "{}",
            input["name"]
        );
        assert_eq!(status.is_synced, expected["isSynced"].as_bool().unwrap());
        assert_eq!(status.next_action, expected["nextAction"].as_str().unwrap());
        assert_eq!(
            status.asset_completeness,
            expected["assetCompleteness"].as_str().unwrap()
        );
        let progress = status.progress.unwrap();
        for (part, actual) in [
            ("recent", progress.recent),
            ("recovery", progress.recovery),
            ("overall", progress.overall),
        ] {
            let e = &expected["progress"][part];
            assert_eq!(
                actual.total_blocks,
                e["totalBlocks"].as_str().unwrap().parse::<u64>().unwrap()
            );
            assert_eq!(
                actual.scanned_blocks,
                e["scannedBlocks"].as_str().unwrap().parse::<u64>().unwrap()
            );
            assert_eq!(actual.ratio, e["ratio"].as_f64());
        }
    }
}
