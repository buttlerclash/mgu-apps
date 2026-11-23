package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// syntheticStock builds a structurally valid factory stand-in for a profile: the
// correct size, entry prologue and fifth program header, plus the stock modulus
// prefix at the profile's modulus offset so scanBinary classifies it as a stock
// variant. It is not real firmware; the pinned-hash gate still refuses it in
// production (buildDual), which the tests assert separately.
func syntheticStock(p *dualProfile) []byte {
	stock := make([]byte, p.stockSize)
	copy(stock[dualNote:], p.originalNote)
	copy(stock[p.entryOff:], p.prologue)
	copy(stock[p.modulus:], stockPattern)
	return stock
}

func TestProfileRegistryIsConsistent(t *testing.T) {
	if len(dualProfiles) != 2 {
		t.Fatalf("expected 2 audited profiles, got %d", len(dualProfiles))
	}
	seenHash := map[string]bool{}
	seenPatched := map[int]bool{}
	for i := range dualProfiles {
		p := &dualProfiles[i]
		patchedSize := p.file + len(dualPayload) + len(dualMagic)
		// Stock length is deliberately not a uniqueness key: two audited builds
		// share one length. The pinned hash is the only profile identity.
		if seenHash[p.stockHash] || seenPatched[patchedSize] {
			t.Fatalf("profile %s collides with another profile", p.name)
		}
		seenHash[p.stockHash], seenPatched[patchedSize] = true, true
		if profileByStockHash(p.stockHash) != p || profileByPatchedSize(patchedSize) != p {
			t.Fatalf("profile %s is not reachable by its selectors", p.name)
		}
		if p.file%4096 != 0 || p.va%4096 != 0 || uint64(p.file)%4096 != p.va%4096 {
			t.Fatalf("profile %s payload placement is not page congruent", p.name)
		}
		if p.file < p.stockSize {
			t.Fatalf("profile %s payload overlaps the stock image", p.name)
		}
		if profileForStock(syntheticStock(p)) != p {
			t.Fatalf("profile %s is not recoverable from its own stock image", p.name)
		}
		// Names are the image base name plus the stock fingerprint prefix.
		if want := "BAC4x_VSTAR_i386_Eth_Application_" + p.stockHash[:8]; p.name != want {
			t.Fatalf("profile name %s does not match its stock fingerprint, want %s", p.name, want)
		}
	}
}

// Two audited builds share one stock length, so length alone must never select a
// profile, and each build's patched image must stay distinguishable by length.
func TestProfilesWithSharedStockLengthStayDistinct(t *testing.T) {
	var shared []*dualProfile
	for i := range dualProfiles {
		if p := &dualProfiles[i]; p.stockSize == 6515808 {
			shared = append(shared, p)
		}
	}
	if len(shared) != 2 {
		t.Fatalf("expected two builds sharing stock length 6515808, got %d", len(shared))
	}
	for _, p := range shared {
		stock := syntheticStock(p)
		// The production allowlist must refuse a stand-in even though its length
		// matches two registered builds.
		if _, err := buildDual(stock); err == nil {
			t.Fatalf("%s: unaudited stock accepted", p.name)
		}
		patched, err := buildDualProfile(stock, fingerprint(stock))
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range shared {
			if other == p {
				continue
			}
			if len(patched) == other.file+len(dualPayload)+len(dualMagic) {
				t.Fatalf("%s patched length is ambiguous with %s", p.name, other.name)
			}
			if _, ok := dualOriginalProfile(patched, other.stockHash); ok {
				t.Fatalf("%s validated under the %s pinned hash", p.name, other.name)
			}
		}
	}
}

func TestProfileRelinkingMatchesAuditedPayloads(t *testing.T) {
	for i := range dualProfiles {
		p := &dualProfiles[i]
		payload, err := relinkPayload(p)
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		if fingerprint(payload) != p.payloadSHA {
			t.Fatalf("%s: re-linked payload fingerprint mismatch", p.name)
		}
		if p == &dualProfiles[0] && !bytes.Equal(payload, dualPayload) {
			t.Fatal("known profile re-link must reproduce the embedded payload byte-for-byte")
		}
		// The local-key lea is payload-internal and must never be re-targeted.
		if !bytes.Equal(payload[0x75:0x79], dualPayload[0x75:0x79]) {
			t.Fatalf("%s: local-key lea was modified", p.name)
		}
	}
	// A wrong address must fail the audited fingerprint gate.
	bad := dualProfiles[1]
	bad.cal += 4
	if _, err := relinkPayload(&bad); err == nil {
		t.Fatal("re-link accepted an unaudited address")
	}
}

func TestAllProfilesStrictRoundTripAndTamper(t *testing.T) {
	for i := range dualProfiles {
		p := &dualProfiles[i]
		t.Run(p.name, func(t *testing.T) {
			stock := syntheticStock(p)
			hash := fingerprint(stock)
			patched, err := buildDualProfile(stock, hash)
			if err != nil {
				t.Fatal(err)
			}
			if len(patched) != p.file+len(dualPayload)+len(dualMagic) {
				t.Fatal("unexpected patched size")
			}
			if binary.LittleEndian.Uint32(patched[dualNote:]) != 1 || binary.LittleEndian.Uint32(patched[dualNote+4:]) != 5 {
				t.Fatal("payload not mapped PT_LOAD RX")
			}
			if binary.LittleEndian.Uint64(patched[dualNote+8:]) != uint64(p.file) || binary.LittleEndian.Uint64(patched[dualNote+16:]) != p.va {
				t.Fatal("payload segment addresses wrong")
			}
			restored, ok := dualOriginalProfile(patched, hash)
			if !ok || !bytes.Equal(restored, stock) {
				t.Fatal("normalization failed")
			}
			if dualMatchedProfile(stock) != nil {
				t.Fatal("stock image matched a patched profile")
			}
			// The production allowlist pins each profile to its real factory hash,
			// so a synthetic stand-in is never recognized by the pinned path.
			if _, ok := dualOriginalProfile(patched, p.stockHash); ok {
				t.Fatal("synthetic image accepted under the pinned factory hash")
			}
			if dualMatchedProfile(patched) != nil || dualCurrent(patched) {
				t.Fatal("synthetic image recognized by the production allowlist")
			}
			for _, offset := range []int{0, p.entryOff + 1, dualNote + 16, p.file + 55, p.file + dualLocalModulus + 5, len(patched) - 2} {
				data := append([]byte(nil), patched...)
				data[offset] ^= 1
				if _, ok := dualOriginalProfile(data, hash); ok {
					t.Fatalf("accepted tampering at %x", offset)
				}
				if dualMatchedProfile(data) != nil {
					t.Fatalf("matched tampered image at %x", offset)
				}
			}
			// Another profile's pinned hash must not validate this image.
			for j := range dualProfiles {
				if j != i {
					if _, ok := dualOriginalProfile(patched, dualProfiles[j].stockHash); ok {
						t.Fatal("cross-profile hash accepted")
					}
				}
			}
			// Production buildDual refuses any stock whose hash is not pinned.
			if _, err := buildDual(stock); err == nil {
				t.Fatal("unaudited stock accepted by production builder")
			}
		})
	}
}

func TestUnknownBuildsAreRefused(t *testing.T) {
	if _, err := buildDual(make([]byte, 4096)); err == nil {
		t.Fatal("unknown size accepted")
	}
	if _, err := buildDualProfile(make([]byte, 4096), "x"); err == nil {
		t.Fatal("unknown size accepted by profile builder")
	}
	if dualMatchedProfile(make([]byte, 4096)) != nil {
		t.Fatal("unknown image matched")
	}
	if _, ok := dualOriginal(make([]byte, 4096)); ok {
		t.Fatal("unknown image normalized")
	}
	// A known-size image with the wrong entry prologue must be refused.
	p := &dualProfiles[0]
	stock := syntheticStock(p)
	stock[p.entryOff] ^= 0xff
	if _, err := buildDualProfile(stock, fingerprint(stock)); err == nil {
		t.Fatal("wrong prologue accepted")
	}
}