// Run from the current Go SDK module with the current-proving.json path as argument.
// The source C5 witness omits opaque delivery bytes. This adds an explicit omitted-delivery case.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/invisi-lab/invisi-sdk-go/primitives"
	"github.com/invisi-lab/invisi-sdk-go/protocol"
	"math/big"
	"os"
)

func main() {
	path := os.Args[1]
	raw, e := os.ReadFile(path)
	if e != nil {
		panic(e)
	}
	var root map[string]any
	if e = json.Unmarshal(raw, &root); e != nil {
		panic(e)
	}
	cases := root["fixtures"].([]any)
	var source map[string]any
	kept := []any{}
	for _, v := range cases {
		f := v.(map[string]any)
		if f["label"] == "note5" {
			data, _ := json.Marshal(f)
			json.Unmarshal(data, &source)
		}
		if f["label"] != "note5_omitted_deliveries" {
			kept = append(kept, f)
		}
	}
	if source == nil {
		panic("source C5 fixture required")
	}
	w := source["witness"].(map[string]any)
	num := func(key string) *big.Int {
		v, ok := new(big.Int).SetString(w[key].(string), 10)
		if !ok {
			panic(key)
		}
		return v
	}
	row := func(key string) []any { return w[key].([]any) }
	rnum := func(key string, i int) *big.Int {
		v, ok := new(big.Int).SetString(row(key)[i].(string), 10)
		if !ok {
			panic(key)
		}
		return v
	}
	n, m, count := int(num("input_count").Int64()), int(num("output_count").Int64()), int(num("source_count").Int64())
	c := protocol.TransactionContext{ChainID: num("chain_id"), ProtocolAddress: common.BigToAddress(num("protocol_address")), TokenAddress: common.BigToAddress(num("token_address"))}
	p := protocol.CrossTreeTransactParams{Token: c.TokenAddress, WithdrawalAddress: common.BigToAddress(num("withdrawal_address")), WithdrawalAmount: num("withdrawal_amount"), Deadline: num("deadline"), FeeRecipient: common.BigToAddress(num("fee_recipient")), FeeAmount: num("fee_amount")}
	for i := 0; i < count; i++ {
		p.Sources = append(p.Sources, protocol.InputSource{TreeId: rnum("input_tree_ids", i), MerkleRoot: common.BigToHash(rnum("merkle_roots", i))})
	}
	for i := 0; i < n; i++ {
		p.Nullifiers = append(p.Nullifiers, common.BigToHash(rnum("slot_values", i)))
	}
	for i := 0; i < m; i++ {
		p.NoteCommitments = append(p.NoteCommitments, common.BigToHash(rnum("slot_values", n+i)))
	}
	f := protocol.FundingParams{Amount: num("deposit_amount"), Payer: common.BigToAddress(num("deposit_payer"))}
	deliveries := make([]protocol.Delivery, m)
	words, e := protocol.TransactUserPublicInputs(c, p, deliveries, f)
	if e != nil {
		panic(e)
	}
	hash, e := protocol.DeliveriesHash(deliveries)
	if e != nil {
		panic(e)
	}
	w["delivery_hash_high"] = new(big.Int).SetBytes(hash[:16]).String()
	w["delivery_hash_low"] = new(big.Int).SetBytes(hash[16:]).String()
	w["auth_digest_high"] = new(big.Int).SetBytes(words[len(words)-2][:]).String()
	w["auth_digest_low"] = new(big.Int).SetBytes(words[len(words)-1][:]).String()
	req, e := protocol.WalletAuthorizationRequest(c, primitives.WalletTransact, 5, words[:len(words)-2])
	if e != nil {
		panic(e)
	}
	signature, e := primitives.SignWalletAuthorization(common.LeftPadBytes([]byte{1}, 32), req)
	if e != nil {
		panic(e)
	}
	var signed [64]byte
	copy(signed[:], signature)
	w["signature"] = signed
	public := []string{}
	for _, word := range words {
		public = append(public, common.Hash(word).Hex())
	}
	source["publicInputs"] = public
	source["label"] = "note5_omitted_deliveries"
	source["source"] = "Independent current Go protocol: same Note preimages, explicit four omitted deliveries"
	source["deliveries"] = []any{map[string]string{"ciphertext": "0x", "clue": "0x"}, map[string]string{"ciphertext": "0x", "clue": "0x"}, map[string]string{"ciphertext": "0x", "clue": "0x"}, map[string]string{"ciphertext": "0x", "clue": "0x"}}
	root["fixtures"] = append(kept, source)
	out, e := json.MarshalIndent(root, "", "  ")
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(path, append(out, '\n'), 0600); e != nil {
		panic(e)
	}
	fmt.Println("Generated independent omitted-delivery C5 statement and signature")
}
