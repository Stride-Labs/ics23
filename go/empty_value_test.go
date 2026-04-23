package ics23

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// These tests cover the Stride fork's one-line patch to LeafOp.Apply, which
// permits empty-byte values on leaves. The change is motivated by Cosmos SDK
// 0.50+ bank module storing reverse-index entries (DenomAddressPrefix 0x03)
// with []byte{} via collections' WithReversePairUncheckedValue. Upstream
// ics23 rejects these leaves even though IAVL produces valid proofs for
// them, causing intermittent non-membership proof failures when an
// empty-value entry is the neighbor of an absent key. See cosmos/ics23#134.

// TestLeafOpEmptyValueAccepted verifies the core patched behavior: an empty
// (but non-nil) value no longer trips the guard in LeafOp.Apply.
func TestLeafOpEmptyValueAccepted(t *testing.T) {
	op := &LeafOp{
		Hash:         HashOp_SHA256,
		PrehashKey:   HashOp_NO_HASH,
		PrehashValue: HashOp_SHA256,
		Length:       LengthOp_VAR_PROTO,
		Prefix:       []byte{0},
	}

	res, err := op.Apply([]byte("uatom"), []byte{})
	if err != nil {
		t.Fatalf("expected success on empty-byte value, got error: %v", err)
	}
	if len(res) != 32 {
		t.Fatalf("expected 32-byte SHA256 output, got %d bytes", len(res))
	}
}

// TestLeafOpEmptyValueDeterministic confirms that the empty-value hash path
// is pure and repeatable — no accidental entropy from the patch.
func TestLeafOpEmptyValueDeterministic(t *testing.T) {
	op := &LeafOp{
		Hash:         HashOp_SHA256,
		PrehashValue: HashOp_SHA256,
		Length:       LengthOp_VAR_PROTO,
		Prefix:       []byte{0},
	}
	key := []byte("uatom")

	first, err := op.Apply(key, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := op.Apply(key, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("empty-value leaf hash is non-deterministic:\n  first:  %x\n  second: %x", first, second)
	}
}

// TestLeafOpNilValueAccepted pins the behavior required to fix the real-world
// bug: proto3 elides empty-bytes fields on the wire (see ExistenceProof's
// MarshalToSizedBuffer, "if len(m.Value) > 0 { ... }"), so an empty-value leaf
// arrives at the verifier as `nil`, not `[]byte{}`. Accepting nil is therefore
// load-bearing — without it the patch is cosmetic and the original
// non-membership failure still fires in production.
func TestLeafOpNilValueAccepted(t *testing.T) {
	op := &LeafOp{
		Hash:         HashOp_SHA256,
		PrehashValue: HashOp_SHA256,
		Length:       LengthOp_VAR_PROTO,
		Prefix:       []byte{0},
	}

	got, err := op.Apply([]byte("uatom"), nil)
	if err != nil {
		t.Fatalf("expected success on nil value, got error: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32-byte SHA256 output, got %d bytes", len(got))
	}

	// nil and []byte{} should produce identical hashes; they're semantically
	// equivalent at the hashing layer.
	fromEmpty, err := op.Apply([]byte("uatom"), []byte{})
	if err != nil {
		t.Fatalf("unexpected error on []byte{}: %v", err)
	}
	if !bytes.Equal(got, fromEmpty) {
		t.Fatalf("nil and []byte{} produced different hashes:\n  nil:   %x\n  empty: %x", got, fromEmpty)
	}
}

// TestLeafOpEmptyKeyStillRejected confirms the key-length check is unchanged.
// The patch only relaxes value validation; key absence remains an error for
// both nil and []byte{} inputs.
func TestLeafOpEmptyKeyStillRejected(t *testing.T) {
	op := &LeafOp{Hash: HashOp_SHA256}

	cases := map[string][]byte{
		"nil key":   nil,
		"empty key": {},
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := op.Apply(key, []byte("bar"))
			if err == nil {
				t.Fatal("expected error on zero-length key, got nil")
			}
			if err.Error() != "leaf op needs key" {
				t.Fatalf("expected 'leaf op needs key', got: %v", err)
			}
		})
	}
}

// TestLeafOpEmptyValueMatchesManualHash pins the empty-value leaf's output
// format. It independently reconstructs the preimage that IAVL-spec leaves
// hash over and compares against LeafOp.Apply's result. If a future upstream
// change (or an accidental tweak to this fork) alters the leaf encoding, this
// test fires with a specific, diffable mismatch rather than a silent drift.
//
// IAVL leaf hash:
//
//	prefix || varint(len(key))        || key
//	       || varint(len(SHA256("")) ) || SHA256("")
func TestLeafOpEmptyValueMatchesManualHash(t *testing.T) {
	prefix := []byte{0}
	key := []byte("uatom")

	op := &LeafOp{
		Hash:         HashOp_SHA256,
		PrehashKey:   HashOp_NO_HASH,
		PrehashValue: HashOp_SHA256,
		Length:       LengthOp_VAR_PROTO,
		Prefix:       prefix,
	}

	got, err := op.Apply(key, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	emptyValueHash := sha256.Sum256([]byte{})

	var preimage []byte
	preimage = append(preimage, prefix...)
	preimage = append(preimage, encodeVarintProto(len(key))...)
	preimage = append(preimage, key...)
	preimage = append(preimage, encodeVarintProto(len(emptyValueHash))...)
	preimage = append(preimage, emptyValueHash[:]...)

	expected := sha256.Sum256(preimage)

	if !bytes.Equal(got, expected[:]) {
		t.Fatalf("leaf hash mismatch:\n  got:      %x\n  expected: %x", got, expected)
	}
}

// TestLeafOpEmptyValueDistinctFromNonEmpty ensures that the hash of an
// empty-value leaf is distinct from the hash of a leaf with any non-empty
// value. No collision ambiguity is introduced by permitting empty bytes.
func TestLeafOpEmptyValueDistinctFromNonEmpty(t *testing.T) {
	op := &LeafOp{
		Hash:         HashOp_SHA256,
		PrehashValue: HashOp_SHA256,
		Length:       LengthOp_VAR_PROTO,
		Prefix:       []byte{0},
	}
	key := []byte("uatom")

	emptyHash, err := op.Apply(key, []byte{})
	if err != nil {
		t.Fatalf("unexpected error on empty value: %v", err)
	}
	nonEmptyHash, err := op.Apply(key, []byte{0x01})
	if err != nil {
		t.Fatalf("unexpected error on non-empty value: %v", err)
	}

	if bytes.Equal(emptyHash, nonEmptyHash) {
		t.Fatalf("hash collision between empty and non-empty value leaves: %x", emptyHash)
	}
}

// TestExistenceProofEmptyValueCalculate verifies the patch wires all the way
// through ExistenceProof.Calculate — i.e., no other gate in the verification
// chain silently blocks empty-value leaves.
func TestExistenceProofEmptyValueCalculate(t *testing.T) {
	op := &LeafOp{
		Hash:         HashOp_SHA256,
		PrehashValue: HashOp_SHA256,
		Length:       LengthOp_VAR_PROTO,
		Prefix:       []byte{0},
	}
	proof := &ExistenceProof{
		Key:   []byte("bank/denom/uatom/cosmos1abc"),
		Value: []byte{},
		Leaf:  op,
	}

	root, err := proof.Calculate()
	if err != nil {
		t.Fatalf("Calculate failed on empty-value existence proof: %v", err)
	}

	// With no inner ops, the proof root is just the leaf hash.
	expected, err := op.Apply(proof.Key, proof.Value)
	if err != nil {
		t.Fatalf("LeafOp.Apply failed: %v", err)
	}
	if !bytes.Equal(root, expected) {
		t.Fatalf("ExistenceProof root mismatch:\n  got:      %x\n  expected: %x", root, expected)
	}
}

// TestExistenceProofEmptyValueVerifyAcceptsCorrectRoot confirms that a valid
// empty-value existence proof passes end-to-end verification when the claimed
// root matches.
func TestExistenceProofEmptyValueVerifyAcceptsCorrectRoot(t *testing.T) {
	op := &LeafOp{
		Hash:         HashOp_SHA256,
		PrehashValue: HashOp_SHA256,
		Length:       LengthOp_VAR_PROTO,
		Prefix:       []byte{0},
	}
	key := []byte("bank/denom/uatom/cosmos1abc")
	value := []byte{}

	proof := &ExistenceProof{Key: key, Value: value, Leaf: op}
	root, err := proof.Calculate()
	if err != nil {
		t.Fatalf("Calculate failed: %v", err)
	}

	spec := &ProofSpec{
		LeafSpec: op,
		InnerSpec: &InnerSpec{
			ChildOrder:      []int32{0, 1},
			MinPrefixLength: 1,
			MaxPrefixLength: 1,
			ChildSize:       32,
			Hash:            HashOp_SHA256,
		},
	}

	if err := proof.Verify(spec, root, key, value); err != nil {
		t.Fatalf("expected Verify to accept empty-value proof against its own root, got: %v", err)
	}
}

// TestExistenceProofEmptyValueSurvivesProtoRoundTrip is the regression test
// for the real-world bug. An ExistenceProof constructed with Value=[]byte{}
// serializes to a wire form that OMITS the Value field entirely (proto3
// elides empty bytes fields — see ExistenceProof.MarshalToSizedBuffer), so
// on the verifier side the value arrives as nil. The patch must accept this
// round-trip or the production non-membership failures continue to fire.
func TestExistenceProofEmptyValueSurvivesProtoRoundTrip(t *testing.T) {
	op := &LeafOp{
		Hash:         HashOp_SHA256,
		PrehashValue: HashOp_SHA256,
		Length:       LengthOp_VAR_PROTO,
		Prefix:       []byte{0},
	}
	original := &ExistenceProof{
		Key:   []byte("bank/denom/uatom/cosmos1abc"),
		Value: []byte{},
		Leaf:  op,
	}

	wire, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var roundTripped ExistenceProof
	if err := roundTripped.Unmarshal(wire); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Confirm our reading of proto3 semantics: after serialize+deserialize the
	// empty Value has become nil. If this ever changes upstream, this assertion
	// flips from documenting the bug to flagging the regression.
	if roundTripped.Value != nil {
		t.Fatalf("expected Value to deserialize as nil (proto3 omits empty bytes), got %v", roundTripped.Value)
	}

	// The load-bearing property: Calculate must succeed on the round-tripped
	// proof. Under stock ics23 (or our original patch that only accepted
	// []byte{}) this errors with "leaf op needs value".
	root, err := roundTripped.Calculate()
	if err != nil {
		t.Fatalf("Calculate failed on proto-roundtripped empty-value proof: %v", err)
	}

	// And the root must match what the original produces — the patch doesn't
	// change the hash, only whether the hash is allowed to be computed.
	expected, err := original.Calculate()
	if err != nil {
		t.Fatalf("original Calculate failed: %v", err)
	}
	if !bytes.Equal(root, expected) {
		t.Fatalf("round-tripped root differs from original:\n  original:  %x\n  roundtrip: %x", expected, root)
	}
}

// TestExistenceProofEmptyValueVerifyRejectsWrongRoot is the load-bearing
// safety check for the patch: permitting empty-value leaves must not weaken
// the root-hash comparison. A forged proof claiming an empty value but
// paired with a bogus root must still fail.
func TestExistenceProofEmptyValueVerifyRejectsWrongRoot(t *testing.T) {
	op := &LeafOp{
		Hash:         HashOp_SHA256,
		PrehashValue: HashOp_SHA256,
		Length:       LengthOp_VAR_PROTO,
		Prefix:       []byte{0},
	}
	proof := &ExistenceProof{
		Key:   []byte("bank/denom/uatom/cosmos1abc"),
		Value: []byte{},
		Leaf:  op,
	}

	spec := &ProofSpec{
		LeafSpec: op,
		InnerSpec: &InnerSpec{
			ChildOrder:      []int32{0, 1},
			MinPrefixLength: 1,
			MaxPrefixLength: 1,
			ChildSize:       32,
			Hash:            HashOp_SHA256,
		},
	}

	bogusRoot := bytes.Repeat([]byte{0xff}, 32)
	if err := proof.Verify(spec, bogusRoot, proof.Key, proof.Value); err == nil {
		t.Fatal("expected Verify to reject empty-value proof with mismatched root, got nil")
	}
}
