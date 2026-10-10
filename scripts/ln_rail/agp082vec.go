//go:build ignore

// AGP-082: the generator of crates/xbt-signer/tests/data/bolt12/lightning-fork-17.json. It is a main
// package of Lightning Fork's module, not of this repository: copy it to cmd/agp082vec/main.go in a
// checkout of github.com/paulscode/lightning-fork at v0.21.3-beta-blake2b.17 (cebc10fe) and run, from
// that checkout,
//
//	docker run --rm --cpus=4 -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOWORK=off -e GOCACHE=/cache/build \
//	  -e GOMODCACHE=/cache/mod -e GOFLAGS=-buildvcs=false -v "$PWD:/src:ro" -v "$PWD/../gocache:/cache" \
//	  -w /src golang:1.25.13 go run ./cmd/agp082vec > lightning-fork-17.json
//
// (drop the "go:build ignore" line in the copy). Keys and times are fixed: the output is the same on
// every run. No node runs; this is the fork's bolt12 package alone.
//
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/bolt12"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

const now = 1_790_000_000

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "agp082vec:", err)
		os.Exit(1)
	}
}

func key(b byte) *btcec.PrivateKey {
	k, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{b}, 32))
	return k
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func pub(k *btcec.PublicKey) string { return hx(k.SerializeCompressed()) }

func path(first, last *btcec.PublicKey, hops int) lnwire.BlindedPath {
	intro, err := lnwire.NewPubkeyIntro(first)
	must(err)
	p := lnwire.BlindedPath{IntroductionNode: intro, BlindingPoint: first}
	for i := 0; i < hops; i++ {
		node := first
		if i == hops-1 {
			node = last
		}
		p.Hops = append(p.Hops, lnwire.BlindedHop{BlindedNodeID: node, EncryptedData: []byte{1, 2, 3, 4}})
	}
	return p
}

type offerSpec struct {
	name     string
	chain    *[32]byte
	issuer   *btcec.PublicKey
	amount   uint64
	desc     string
	blake2b  bool
	paths    []lnwire.BlindedPath
	expiry   uint64
	quantity uint64
}

func mkOffer(s offerSpec) *bolt12.Offer {
	o := &bolt12.Offer{}
	if s.chain != nil {
		o.OfferChains = tlv.SomeRecordT(tlv.NewRecordT[tlv.TlvType2](bolt12.ChainsRecord{Chains: [][32]byte{*s.chain}}))
	}
	if s.issuer != nil {
		o.OfferIssuerID = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType22](s.issuer))
	}
	if s.blake2b {
		o.OfferFeatures = tlv.SomeRecordT(tlv.NewRecordT[tlv.TlvType12](*bolt12.Blake2bVector()))
	}
	if s.amount != 0 {
		o.OfferAmount = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType8](bolt12.TUint64(s.amount)))
	}
	if s.desc != "" {
		o.OfferDescription = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType10](tlv.Blob(s.desc)))
	}
	if s.expiry != 0 {
		o.OfferAbsoluteExpiry = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType14](bolt12.TUint64(s.expiry)))
	}
	if len(s.paths) > 0 {
		o.OfferPaths = tlv.SomeRecordT(tlv.NewRecordT[tlv.TlvType16](lnwire.BlindedPaths{Paths: s.paths}))
	}
	if s.quantity != 0 {
		o.OfferQuantityMax = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType20](bolt12.TUint64(s.quantity)))
	}
	return o
}

// verdict is what the fork's payer says of an offer on a chain: its reader checks, then option_blake2b
// (offerpay/client.go buildRequest).
func verdict(o *bolt12.Offer, chain [32]byte) map[string]any {
	err := bolt12.ValidateOfferRead(o, time.Unix(now, 0), chain, bolt12.Blake2bFeatures)
	if err == nil {
		err = bolt12.CheckBlake2b(o.OfferFeatures, "offer")
	}
	if err != nil {
		return map[string]any{"payable": false, "error": err.Error()}
	}
	return map[string]any{"payable": true}
}

type invSpec struct {
	name      string
	offer     string
	chainName string
	payer     byte
	signer    *btcec.PrivateKey
	nodeID    *btcec.PublicKey
	amount    uint64
	blake2b   bool
	preimage  byte
}

func main() {
	regtest := [32]byte(*chaincfg.RegressionNetParams.GenesisHash)
	mainnet := bolt12.BitcoinMainnetChain()
	chains := map[string][32]byte{"regtest": regtest, "mainnet": mainnet}
	alice, mallory := key(0x41), key(0x66)
	hop, last1, last2 := key(0x70), key(0x71), key(0x72)

	offerSpecs := []offerSpec{
		{name: "regtest, 250000 msat, issuer id", chain: &regtest, issuer: alice.PubKey(), amount: 250_000, desc: "coffee", blake2b: true},
		{name: "regtest, any amount", chain: &regtest, issuer: alice.PubKey(), desc: "tips", blake2b: true},
		{name: "regtest, no option_blake2b", chain: &regtest, issuer: alice.PubKey(), amount: 250_000, desc: "coffee"},
		{name: "no chain (mainnet), option_blake2b", issuer: alice.PubKey(), amount: 250_000, desc: "coffee", blake2b: true},
		{name: "no chain, no option_blake2b", issuer: alice.PubKey(), amount: 250_000, desc: "coffee"},
		{name: "mainnet named, option_blake2b", chain: &mainnet, issuer: alice.PubKey(), amount: 250_000, desc: "coffee", blake2b: true},
		{name: "regtest, two blinded paths, no issuer id", chain: &regtest, amount: 250_000, desc: "coffee", blake2b: true,
			paths: []lnwire.BlindedPath{path(hop.PubKey(), last1.PubKey(), 2), path(hop.PubKey(), last2.PubKey(), 3)}},
		{name: "regtest, expired", chain: &regtest, issuer: alice.PubKey(), amount: 250_000, desc: "coffee", blake2b: true, expiry: now - 1},
		{name: "regtest, expires later", chain: &regtest, issuer: alice.PubKey(), amount: 250_000, desc: "coffee", blake2b: true, expiry: now + 600},
	}
	offers := map[string]*bolt12.Offer{}
	var outOffers []map[string]any
	for _, s := range offerSpecs {
		raw, err := mkOffer(s).Encode()
		must(err)
		str, err := bolt12.Encode(bolt12.HRPOffer, raw)
		must(err)
		// read it back as the node reads a string it is given
		hrp, data, err := bolt12.Decode(str)
		must(err)
		o, err := bolt12.DecodeOffer(data)
		must(err)
		id, err := bolt12.OfferID(o)
		must(err)
		offers[s.name] = o
		var named []string
		if o.OfferChains.IsSome() {
			for _, c := range bolt12.OfferChains(o) {
				named = append(named, hx(c[:]))
			}
		}
		rec := map[string]any{"name": s.name, "hrp": hrp, "bolt12": str, "tlv": hx(data), "offer_id": hx(id[:]), "amount_msat": s.amount,
			"description": s.desc, "chains": named, "num_paths": len(s.paths),
			"lightning_fork": map[string]any{"regtest": verdict(o, regtest), "mainnet": verdict(o, mainnet)}}
		if s.issuer != nil {
			rec["issuer_id"] = pub(s.issuer)
		}
		outOffers = append(outOffers, rec)
	}

	invSpecs := []invSpec{
		{name: "for the regtest offer", offer: "regtest, 250000 msat, issuer id", chainName: "regtest", payer: 0x51, signer: alice, amount: 250_000, blake2b: true, preimage: 1},
		{name: "the same offer again: another payer key", offer: "regtest, 250000 msat, issuer id", chainName: "regtest", payer: 0x52, signer: alice, amount: 250_000, blake2b: true, preimage: 2},
		{name: "any-amount offer, 7000 msat asked", offer: "regtest, any amount", chainName: "regtest", payer: 0x53, signer: alice, amount: 7_000, blake2b: true, preimage: 3},
		{name: "chain-less offer on mainnet", offer: "no chain (mainnet), option_blake2b", chainName: "mainnet", payer: 0x54, signer: alice, amount: 250_000, blake2b: true, preimage: 4},
		{name: "blinded offer, signed by the second path's last node", offer: "regtest, two blinded paths, no issuer id", chainName: "regtest", payer: 0x55, signer: last2,
			amount: 250_000, blake2b: true, preimage: 5},
		{name: "invoice without option_blake2b", offer: "regtest, 250000 msat, issuer id", chainName: "regtest", payer: 0x56, signer: alice, amount: 250_000, preimage: 6},
		{name: "signed by a key that is not the issuer", offer: "regtest, 250000 msat, issuer id", chainName: "regtest", payer: 0x57, signer: mallory, amount: 250_000, blake2b: true,
			preimage: 7},
		{name: "invoice_node_id the issuer's, signature another key's", offer: "regtest, 250000 msat, issuer id", chainName: "regtest", payer: 0x58, signer: mallory,
			nodeID: alice.PubKey(), amount: 250_000, blake2b: true, preimage: 8},
	}
	var outInvoices []map[string]any
	for _, s := range invSpecs {
		o, chain := offers[s.offer], chains[s.chainName]
		payer := key(s.payer)
		// the request, as offerpay/client.go buildRequest writes it
		ir, err := bolt12.NewInvoiceRequestFromOffer(o, payer.PubKey(), bytes.Repeat([]byte{s.payer}, 16), chain)
		must(err)
		if !o.OfferAmount.IsSome() {
			ir.InvreqAmount = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType82](bolt12.TUint64(s.amount)))
		}
		rsig, err := bolt12.SignInvoiceRequest(ir, payer)
		must(err)
		ir.Signature = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType240](rsig))
		must(bolt12.ValidateInvoiceRequestWriteOnChain(ir, chain))
		// the invoice, as offerserve/server.go writes it
		node := s.nodeID
		if node == nil {
			node = s.signer.PubKey()
		}
		inv := bolt12.NewInvoiceFromRequest(ir)
		inv.InvoicePaths = tlv.SomeRecordT(tlv.NewRecordT[tlv.TlvType160](lnwire.BlindedPaths{Paths: []lnwire.BlindedPath{path(hop.PubKey(), node, 2)}}))
		inv.InvoiceBlindedPay = tlv.SomeRecordT(tlv.NewRecordT[tlv.TlvType162](bolt12.BlindedPayInfos{Infos: []bolt12.BlindedPayInfo{{
			FeeBaseMsat: 1000, FeeProportionalMillionths: 100, CltvExpiryDelta: 40, HtlcMinimumMsat: 1, HtlcMaximumMsat: 21_000_000_000}}}))
		inv.InvoiceCreatedAt = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType164](bolt12.TUint64(now - 10)))
		inv.InvoiceRelativeExp = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType166](bolt12.TUint32(3600)))
		hash := sha256.Sum256(bytes.Repeat([]byte{s.preimage}, 32))
		inv.InvoicePaymentHash = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType168](hash))
		inv.InvoiceAmount = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType170](bolt12.TUint64(s.amount)))
		feats := lnwire.NewRawFeatureVector(lnwire.MPPOptional)
		if s.blake2b {
			feats = bolt12.Blake2bVector(lnwire.MPPOptional)
		}
		inv.InvoiceFeatures = tlv.SomeRecordT(tlv.NewRecordT[tlv.TlvType174](*feats))
		inv.InvoiceNodeID = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType176](node))
		isig, err := bolt12.SignInvoice(inv, s.signer)
		must(err)
		inv.Signature = tlv.SomeRecordT(tlv.NewPrimitiveRecord[tlv.TlvType240](isig))
		// the records as they are, without the writer's own checks: some of these are invoices an honest
		// issuer would not write, and the question is what the payer's reader says of them
		raw, err := lnwire.EncodeRecords(inv.AllRecords())
		must(err)
		str, err := bolt12.Encode(bolt12.HRPInvoice, raw)
		must(err)
		// the payer's checks (offerpay/client.go checkInvoice and CheckInvoice), on the string read back
		_, data, err := bolt12.Decode(str)
		must(err)
		got, err := bolt12.DecodeInvoice(data)
		must(err)
		check := bolt12.VerifyInvoice(got)
		if check == nil {
			check = bolt12.ValidateInvoiceRead(got, chain, bolt12.InvoiceFeatureCatalogues{Invoice: bolt12.Blake2bFeatures})
		}
		if check == nil {
			check = bolt12.CheckBlake2b(got.InvoiceFeatures, "invoice")
		}
		if check == nil {
			check = bolt12.ValidateInvoiceExpiry(got, time.Unix(now, 0))
		}
		if check == nil {
			check = bolt12.ValidateInvoiceAgainstRequest(got, ir)
		}
		id, err := bolt12.InvoiceOfferID(got)
		must(err)
		rec := map[string]any{"name": s.name, "offer": s.offer, "chain": s.chainName, "bolt12": str, "offer_id": hx(id[:]), "payment_hash": hx(hash[:]),
			"preimage": hx(bytes.Repeat([]byte{s.preimage}, 32)), "amount_msat": s.amount, "node_id": pub(node), "payer_id": pub(payer.PubKey()),
			"created_at": now - 10, "relative_expiry": 3600, "lightning_fork": map[string]any{"payer_accepts": check == nil}}
		if check != nil {
			rec["lightning_fork"].(map[string]any)["error"] = check.Error()
		}
		outInvoices = append(outInvoices, rec)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	must(enc.Encode(map[string]any{
		"source": "Lightning Fork bolt12 package, v0.21.3-beta-blake2b.17 (cebc10fe), by cmd/agp082vec (xbt-rs scripts/ln_rail/agp082vec.go)",
		"now":    now, "chains": map[string]string{"regtest": hx(regtest[:]), "mainnet": hx(mainnet[:])},
		"offers": outOffers, "invoices": outInvoices,
	}))
}
