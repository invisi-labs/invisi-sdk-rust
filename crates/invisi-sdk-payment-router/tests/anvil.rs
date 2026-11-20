//! Opt-in integration against an isolated Anvil fixture produced from the reviewed contracts.
//! Only this test host uses unlocked-account broadcasting; the SDK never signs or sends.
use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolCall, SolValue};
use invisi_sdk_payment_router::*;
use invisi_sdk_protocol::protocol::TransactionCall;
use serde_json::{json, Value};
use std::sync::Arc;
fn address(v: &Value) -> Address {
    v.as_str().unwrap().parse().unwrap()
}
fn number(v: &Value) -> U256 {
    U256::from_str_radix(v.as_str().unwrap(), 10).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}
fn quantity(v: &Value) -> U256 {
    U256::from_str_radix(v.as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}
async fn rpc(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Value {
    let v: Value = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(v.get("error").is_none(), "{method}: {v}");
    v["result"].clone()
}
async fn read(client: &reqwest::Client, url: &str, to: Address, data: Vec<u8>) -> U256 {
    quantity(
        &rpc(
            client,
            url,
            "eth_call",
            json!([{"to":to,"data":format!("0x{}",hex::encode(data))},"latest"]),
        )
        .await,
    )
}
fn balance_data(owner: Address) -> Vec<u8> {
    let mut data = alloy_primitives::keccak256("balanceOf(address)")[..4].to_vec();
    data.extend((owner,).abi_encode_params());
    data
}
fn allowance_data(owner: Address, spender: Address) -> Vec<u8> {
    let mut data = alloy_primitives::keccak256("allowance(address,address)")[..4].to_vec();
    data.extend((owner, spender).abi_encode_params());
    data
}
async fn send(
    client: &reqwest::Client,
    url: &str,
    from: Address,
    to: Address,
    data: Vec<u8>,
    value: U256,
) -> Value {
    let hash=rpc(client,url,"eth_sendTransaction",json!([{"from":from,"to":to,"data":format!("0x{}",hex::encode(data)),"value":format!("{value:#x}"),"gas":"0x1e8480"}])).await;
    for _ in 0..200 {
        let receipt = rpc(client, url, "eth_getTransactionReceipt", json!([hash])).await;
        if !receipt.is_null() {
            return receipt;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("Anvil transaction receipt timeout");
}
#[tokio::test]
async fn native_build_and_simulation_execute_v3_direct_and_holder_on_anvil() {
    let Ok(path) = std::env::var("INVISI_PAYMENT_ROUTER_FIXTURE") else {
        eprintln!("Skipped: set INVISI_PAYMENT_ROUTER_FIXTURE for isolated local Anvil execution");
        return;
    };
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let url = v["rpcUrl"].as_str().unwrap();
    let parsed = reqwest::Url::parse(url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    let d = &v["deployment"];
    let z = &d["zeroEx"];
    let deployment = PaymentRouterDeployment {
        chain_id: d["chainId"].as_str().unwrap().parse().unwrap(),
        router_address: address(&d["routerAddress"]),
        core_address: address(&d["coreAddress"]),
        weth_address: address(&d["wethAddress"]),
        uniswap_router_address: address(&d["uniswapRouterAddress"]),
        runtime_code_hash: d
            .get("runtimeCodeHash")
            .map(|h| h.as_str().unwrap().parse().unwrap()),
        zero_ex: Some(ZeroExDeployment {
            allowance_holder_address: address(&z["allowanceHolderAddress"]),
            settler_registry_address: address(&z["settlerRegistryAddress"]),
        }),
    };
    let provider = Arc::new(HttpRouterProvider::new(url).unwrap());
    let c = PaymentRouterClient::new(deployment.clone(), provider).unwrap();
    let http = reqwest::Client::new();
    let player = address(&v["player"]);
    let token = address(&v["tokenOut"]);
    let core = &v["corePayment"];
    let payment = TransactionCall {
        to: address(&core["to"]),
        data: bytes(&core["data"]),
        value: number(&core["value"]),
    };
    let proof = invisi_sdk_protocol::protocol::InvisiCore::transact_0Call::abi_decode_validate(
        &payment.data,
    )
    .unwrap()
    ._0;
    for q in v["quotes"].as_array().unwrap() {
        let quote = SwapQuote {
            chain_id: deployment.chain_id,
            router_address: deployment.router_address,
            token_out: token,
            amount_out: number(&q["amountOut"]),
            estimated_input: number(&q["estimatedInput"]),
            max_input: number(&q["maxInput"]),
            deadline: q["deadline"].as_str().unwrap().parse().unwrap(),
            route: if q["channel"] == "uniswap-v3" {
                SwapRoute::UniswapV3 {
                    reverse_path: bytes(&q["reversePath"]),
                }
            } else {
                SwapRoute::ZeroEx {
                    target: address(&q["target"]),
                    data: bytes(&q["data"]),
                    settler_address: address(&q["settlerAddress"]),
                }
            },
        };
        let call = c
            .build_payment_transaction(payment.clone(), quote, player)
            .await
            .unwrap();
        let simulation = c.simulate_payment(call.clone(), player).await.unwrap();
        assert_eq!(simulation.eth_spent, number(&v["expected"]["ethSpent"]));
        assert_eq!(
            simulation.eth_refunded,
            number(&v["expected"]["ethRefunded"])
        );
        let core_before = read(&http, url, token, balance_data(deployment.core_address)).await;
        let player_before =
            quantity(&rpc(&http, url, "eth_getBalance", json!([player, "latest"])).await);
        let receipt = send(&http, url, player, call.to, call.data.clone(), call.value).await;
        assert_eq!(quantity(&receipt["status"]), U256::from(1));
        let player_after =
            quantity(&rpc(&http, url, "eth_getBalance", json!([player, "latest"])).await);
        let gas = quantity(&receipt["gasUsed"]) * quantity(&receipt["effectiveGasPrice"]);
        assert_eq!(player_before - player_after - gas, simulation.eth_spent);
        assert_eq!(
            read(&http, url, token, balance_data(deployment.core_address)).await - core_before,
            number(&v["expected"]["fundingAmount"])
        );
        assert_eq!(
            quantity(
                &rpc(
                    &http,
                    url,
                    "eth_getBalance",
                    json!([deployment.router_address, "latest"])
                )
                .await
            ),
            U256::ZERO
        );
        for asset in [token, deployment.weth_address] {
            assert_eq!(
                read(&http, url, asset, balance_data(deployment.router_address)).await,
                U256::ZERO
            );
            for spender in [deployment.core_address, deployment.uniswap_router_address] {
                assert_eq!(
                    read(
                        &http,
                        url,
                        asset,
                        allowance_data(deployment.router_address, spender)
                    )
                    .await,
                    U256::ZERO
                );
            }
        }
        let event = receipt["logs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| {
                address(&l["address"]) == deployment.router_address
                    && l["topics"][0]
                        == json!(alloy_primitives::keccak256(
                            "Payment(address,address,address,uint256,uint256,uint256,bytes32)"
                        ))
            })
            .expect("Payment event");
        let event_data = bytes(&event["data"]);
        assert_eq!(U256::from_be_slice(&event_data[..32]), U256::from(10));
        assert_eq!(
            U256::from_be_slice(&event_data[32..64]),
            simulation.eth_spent
        );
        assert_eq!(
            U256::from_be_slice(&event_data[64..96]),
            simulation.eth_refunded
        );
        assert_eq!(
            &event_data[96..128],
            alloy_primitives::keccak256(&proof).as_slice()
        );
        // Configure the fixture Core to fail. Both preflight and execution must roll back.
        let mut configure = alloy_primitives::keccak256("configure(bool,bool)")[..4].to_vec();
        configure.extend((true, false).abi_encode_params());
        let configured = send(
            &http,
            url,
            player,
            deployment.core_address,
            configure,
            U256::ZERO,
        )
        .await;
        assert_eq!(quantity(&configured["status"]), U256::from(1));
        assert!(c.simulate_payment(call.clone(), player).await.is_err());
        let before = read(&http, url, token, balance_data(deployment.core_address)).await;
        let failed = send(&http, url, player, call.to, call.data, call.value).await;
        assert_eq!(quantity(&failed["status"]), U256::ZERO);
        assert_eq!(
            read(&http, url, token, balance_data(deployment.core_address)).await,
            before
        );
        assert_eq!(
            quantity(
                &rpc(
                    &http,
                    url,
                    "eth_getBalance",
                    json!([deployment.router_address, "latest"])
                )
                .await
            ),
            U256::ZERO
        );
        let mut reset = alloy_primitives::keccak256("configure(bool,bool)")[..4].to_vec();
        reset.extend((false, false).abi_encode_params());
        send(
            &http,
            url,
            player,
            deployment.core_address,
            reset,
            U256::ZERO,
        )
        .await;
    }
}
