# Non-membership proof failure in ICQ

Working doc for investigating the intermittent `QUERY PROOF VERIFICATION FAILED` we see on Stride's `WITHDRAWALBALANCE` ICQ (and other non-membership queries) after the SDK 0.53 + ibc-go v10 upgrade (PR 1490, branch `sdk53`).

## Symptom

When the withdrawal ICA has zero balance on a host zone, the host returns a non-membership proof. Stride's `interchainquery` module fails to verify it with an error like:

```
QUERY PROOF VERIFICATION FAILED - QueryId: 07e5507e...,
Error: Unable to verify non-membership proof: failed to verify non-membership proof
with key  ...uatom: right proof, error calculating root, leaf, leaf op needs value:
invalid proof: icq query response failed
```

Membership proofs (non-zero result) verify fine. Only non-membership fails, and not every time — **same query, same key, sometimes works, sometimes doesn't**.

Downstream effect on integration tests: `core.test.ts` "Reinvestment" on cosmoshub times out because reinvestment is gated on the withdrawal-balance ICQ succeeding. Osmosis tends to pass because rewards accrue fast enough to get past the zero-balance window before the test's internal 6-min poll (`polling.ts:waitForRedemptionRateChange`, now bumped to ~9 min). Cosmoshub often doesn't.

## Root cause

### 1. SDK 0.50+ bank module stores reverse-index entries with empty values

`cosmos-sdk@v0.53.7/x/bank/types/keys.go:22-35` lays out five prefix spaces in the bank KV store:

```go
SupplyKey           = collections.NewPrefix(0)
DenomMetadataPrefix = collections.NewPrefix(1)
BalancesPrefix      = collections.NewPrefix(2)
DenomAddressPrefix  = collections.NewPrefix(3)  // reverse index
SendEnabledPrefix   = collections.NewPrefix(4)
ParamsKey           = collections.NewPrefix(5)
```

`cosmos-sdk@v0.53.7/x/bank/keeper/view.go:39-47` wires the `DenomAddressPrefix` as a reverse-pair index with `WithReversePairUncheckedValue()`:

```go
func newBalancesIndexes(sb *collections.SchemaBuilder) BalancesIndexes {
    return BalancesIndexes{
        Denom: indexes.NewReversePair[math.Int](
            sb, types.DenomAddressPrefix, "address_by_denom_index",
            collections.PairKeyCodec(...),
            indexes.WithReversePairUncheckedValue(),
            // denom to address indexes were stored as Key: Join(denom, address) Value: []byte{0},
            // this will migrate the value to []byte{} in a lazy way.
        ),
    }
}
```

`collections@v1.2.0/keyset.go:11-22` documents what the option does:

```go
// WithKeySetUncheckedValue changes the behavior of the KeySet when it encounters
// a value different from '[]byte{}', by default the KeySet errors when this happens.
// This option allows to ignore the value and continue with the operation, in turn
// the value will be cleared out and set to '[]byte{}'.
```

So: **on writes the bank module deliberately stores these reverse-index entries with value `[]byte{}`**. By design, for backwards compat with old `[]byte{0}` entries.

### 2. ICS-23 rejects leaves with empty values

`ics23/go@v0.11.0/ops.go:60-67` — the leaf-hash step used when verifying any existence proof:

```go
func (op *LeafOp) Apply(key []byte, value []byte) ([]byte, error) {
    if len(key) == 0 {
        return nil, errors.New("leaf op needs key")
    }
    if len(value) == 0 {
        return nil, errors.New("leaf op needs value")   // <-- our error
    }
    ...
}
```

### 3. Non-membership proofs verify neighbors as _existence_ proofs

`ics23/go@v0.11.0/proof.go:227-277`, `NonExistenceProof.Verify`:

```go
if p.Right != nil {
    if err := p.Right.Verify(spec, root, p.Right.Key, p.Right.Value); err != nil {
        return fmt.Errorf("right proof, %w", err)
    }
    rightKey = p.Right.Key
}
```

The right (and/or left) neighbor is fed through `LeafOp.Apply(key, value)`. If the neighbor happens to be a `0x03` reverse-index entry from the bank module, its `Value` is `[]byte{}`, and `Apply` returns `"leaf op needs value"`. Wrapping gives the observed error: `right proof, error calculating root, leaf, leaf op needs value`.

### 4. Why it's intermittent

The error only fires when the **right (or left) neighbor** of the absent balance key in the iavl tree happens to be one of those empty-value `0x03` entries. That's tree-ordering-dependent:

- Balance keys live under `0x02 | lenPrefix(addr) | denom`
- Reverse-index keys live under `0x03 | denom | addr`

When the queried absent key's right neighbor is another _balance_ entry (0x02), the neighbor value is a non-empty int-encoded amount and the proof verifies. When it's the first `0x03` entry lexicographically after the absent key, verification fails. Which one is the right neighbor depends on what else is in the tree at query time.

### 5. No upstream fix

- `cosmos/ics23/go` is at v0.11.0 (Aug 2024, most recent). No open issue mentions this specific pattern.
- `cosmos-sdk` considers the empty-value storage intentional.
- This is effectively an ICS-23 ↔ SDK-collections incompatibility.

## Where the fix would go in Stride

`x/interchainquery/keeper/msg_server.go`, function `VerifyKeyProof`, the `else` branch for nil `msg.Result`. Relevant existing code:

```go
// If we got a non-nil response, verify inclusion proof
if len(msg.Result) != 0 {
    if err := merkleProof.VerifyMembership(clientStateProof, stateRoot, path, msg.Result); err != nil {
        return errorsmod.Wrapf(types.ErrInvalidICQProof, "Unable to verify membership proof: %s", err.Error())
    }
    k.Logger(ctx).Info(...)
} else {
    // if we got a nil query response, verify non inclusion proof.
    if err := merkleProof.VerifyNonMembership(clientStateProof, stateRoot, path); err != nil {
        return errorsmod.Wrapf(types.ErrInvalidICQProof, "Unable to verify non-membership proof: %s", err.Error())
    }
    k.Logger(ctx).Info(...)
}
```
