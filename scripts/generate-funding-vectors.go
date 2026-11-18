// Run from the current Go SDK checkout: go run /path/to/this/file /path/to/funding-hashes.json.
// Public fixture calldata is decoded and hashed by the independent Go implementation.
package main

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/invisi-labs/invisi-sdk-go/protocol"
	"math/big"
	"os"
)

func main() {
	raw, _ := os.ReadFile(os.Args[1])
	var root map[string]json.RawMessage
	json.Unmarshal(raw, &root)
	var cases []map[string]any
	json.Unmarshal(root["cases"], &cases)
	a, _ := protocol.ProtocolABI()
	for _, f := range cases {
		data := common.FromHex(f["calldata"].(string))
		m, _ := a.MethodById(data[:4])
		v, _ := m.Inputs.Unpack(data[4:])
		var funding protocol.FundingParams
		primary := "FundTransact"
		if f["name"] == "shield" {
			funding = *abi.ConvertType(v[3], new(protocol.FundingParams)).(*protocol.FundingParams)
			primary = "FundShield"
			params := *abi.ConvertType(v[0], new(protocol.ShieldParams)).(*protocol.ShieldParams)
			outputs := *abi.ConvertType(v[1], new([]protocol.ShieldOutput)).(*[]protocol.ShieldOutput)
			deliveries := *abi.ConvertType(v[2], new([]protocol.Delivery)).(*[]protocol.Delivery)
			hash, e := protocol.ShieldFundingRequestHash(params, outputs, deliveries)
			if e != nil {
				panic(e)
			}
			f["expectedHash"] = hash.Hex()
		} else {
			r := *abi.ConvertType(v[1], new(protocol.TransactRequest)).(*protocol.TransactRequest)
			funding = r.Funding
			{
				hash, e := protocol.TransactFundingRequestHash(v[0].([]byte), r.Params, r.Deliveries)
				if e != nil {
					panic(e)
				}
				f["expectedHash"] = hash.Hex()
			}
		}
		if funding.Amount.Sign() == 0 {
			funding.Amount = big.NewInt(7)
			funding.Payer = common.HexToAddress("0x3333333333333333333333333333333333333333")
		}
		funding.SigNonce = big.NewInt(2)
		funding.Deadline = big.NewInt(2000)
		c := protocol.TransactionContext{ChainID: big.NewInt(31337), ProtocolAddress: common.HexToAddress("0x1111111111111111111111111111111111111111"), TokenAddress: common.HexToAddress("0x2222222222222222222222222222222222222222")}
		td, e := protocol.EncodeFundingTypedData(c, primary, common.HexToHash(f["expectedHash"].(string)), funding)
		if e != nil {
			panic(e)
		}
		digest, _ := protocol.TypedDataHash(td)
		f["fundingTypedData"] = td
		f["fundingDigest"] = digest.Hex()
		f["fundingAmount"] = funding.Amount.String()
		f["fundingPayer"] = funding.Payer.Hex()
	}
	root["cases"], _ = json.Marshal(cases)
	output, _ := json.MarshalIndent(root, "", "  ")
	os.WriteFile(os.Args[1], append(output, '\n'), 0600)
}
