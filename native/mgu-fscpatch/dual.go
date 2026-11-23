package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// Layout shared by every audited build: the file offset of the program header the
// detour reuses, the trailer tags, and the local key's offset inside the payload.
// Everything that differs per build lives in dualProfiles, which is deliberately
// restricted to inspected factory builds; unknown firmware must never receive
// instruction offsets from any profile.
const dualNote = 64 + 5*56
const dualMagic = "MGU-FSC-OEM-LOCAL-v2\n"
const legacyDualMagic = "MGU-FSC-OEM-LOCAL-v1\n"
const dualLocalModulus = 164

func unhex(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}

var dualPrologue = unhex("4883ec0849")
var dualOriginalNote = unhex("04000000040000008c020000000000008c020000000000008c02000000000000440000000000000044000000000000000400000000000000")

// Position-independent SysV x86-64 wrapper. The companion payload/dual.c
// documents the source and ABI. It calls the existing CAL verifier, retaining
// all caller-side VIN, application, validity and certificate parsing checks.
var dualPayload = unhex("f30f1efa41564989c841554989fd415455534889cb4883ec20440fb7721a4889fa4429f64a8d2c374489f1440fb7e64889ef4489e6e8566763ff3df90000007545488d15a81d97ff4839d37539833b087534488b43084c8d4424084489f14c89ea48c7442408080000004489e64889ef4889442410488d05240000004889442418e80a6763ff4883c4205b5d415c415d415ec3000000000000000000000000004000000093173e3232aa6a7fe26707f811206fa614f876881cbac409a1a46ffff3dbcb24b80b1bb06025bce52d647912541514c65501546148efd23bec8de9ea5cbf8230a02d63b60804bfd560e7e784d3ab7ea08a6e491191b815ca1c6e58760cee74755334bb6b6c0a97da2586f073321956e02696751cf89dac8763b33d755bbec45930fb3e320e4e4cabc806ee0b613592f86ddb4ebb52caeabf68c05be422e6faba8858d8d0ecfe252f25217479633c1ad1bd8897110e245d83149f08522498a2bbb253765bb3ad6545d353c56d99a8d86c9c828b40e92fc0d5e2b6547ac7d1ef4fc223ab0dda475d5a7bc294cf4eae8a1580e57335f530a00c39175ba9d4bb8eae")

// dualProfile pins one audited factory verifier build. Every address was recovered
// from the binary and cross-checked by re-linking the shared PIC payload: the
// resulting payload fingerprint must equal payloadSHA before any image is accepted.
// stockSize/entryOff/modulus/file are file offsets; va/cal/oem are load addresses.
// Both supported builds are ET_DYN with their first PT_LOAD at vaddr 0, so entryOff
// doubles as the detour's load address.
type dualProfile struct {
	name         string
	stockHash    string
	stockSize    int
	entryOff     int
	prologue     []byte
	originalNote []byte
	file         int
	va           uint64
	modulus      int
	cal          uint64
	oem          uint64
	payloadSHA   string
}

// dualProfiles is the strict allowlist of supported factory builds. Unknown builds
// are refused; nothing here is discovered heuristically at patch time. Each name is
// the image base name plus the first eight hex digits of its stock fingerprint;
// README.md maps those fingerprints to BMW build versions.
var dualProfiles = []dualProfile{
	{
		// The first entry is load-bearing: its re-linked payload must reproduce
		// dualPayload byte-for-byte, and it is the only build with a v1 image to
		// rotate from (see dualOriginalProfile).
		name: "BAC4x_VSTAR_i386_Eth_Application_b26d1830",
		stockHash: "b26d18308c0f2ca1edd5aff8c373aa3aa659751e940cb6eed8509873670c1231",
		stockSize: 6515808, entryOff: 0x1fa100,
		prologue: dualPrologue, originalNote: dualOriginalNote,
		file: 0x637000, va: 0xbc5000, modulus: 0x27c8c4, cal: 0x1fb790, oem: 0x536df0,
		payloadSHA: "e3b729890e619d1c5e24d069c301facbd4df35699cee48d3f040075ceb0fbe6d",
	},
	{
		// Shares its stock length with 030_016_002 (b26d1830) but is a distinct
		// image: the shared wrapper and CAL both moved +0x20. Its payload takes
		// the next page so a patched image's length still identifies its build.
		// Its own build version is unknown.
		name: "BAC4x_VSTAR_i386_Eth_Application_c221d8dc",
		stockHash: "c221d8dc35dd09e8d2c33688f978548eb15b755778cc58f354045a9956ac5f4c",
		stockSize: 6515808, entryOff: 0x1fa120,
		prologue: dualPrologue, originalNote: dualOriginalNote,
		file: 0x638000, va: 0xbc5000, modulus: 0x27c864, cal: 0x1fb7b0, oem: 0x536df0,
		payloadSHA: "8b878393faee159336c8ca6f3dbd85210c77a84a913ea9cdb4d29b63ca6a3011",
	},
}

// profileForStock returns the single profile whose structural markers match stock,
// or nil when none or more than one does. Stock length alone cannot select a
// profile: two audited builds share one length, so the detour offset and prologue
// decide between them.
func profileForStock(stock []byte) *dualProfile {
	var found *dualProfile
	for i := range dualProfiles {
		p := &dualProfiles[i]
		if len(stock) != p.stockSize ||
			!bytes.Equal(stock[p.entryOff:p.entryOff+len(p.prologue)], p.prologue) ||
			!bytes.Equal(stock[dualNote:dualNote+56], p.originalNote) {
			continue
		}
		if found != nil {
			return nil
		}
		found = p
	}
	return found
}

func profileByPatchedSize(size int) *dualProfile {
	for i := range dualProfiles {
		if dualProfiles[i].file+len(dualPayload)+len(dualMagic) == size {
			return &dualProfiles[i]
		}
	}
	return nil
}

func profileByStockHash(hash string) *dualProfile {
	for i := range dualProfiles {
		if dualProfiles[i].stockHash == hash {
			return &dualProfiles[i]
		}
	}
	return nil
}

// dualMatchedProfile returns the profile whose exact factory-compatible image equals
// data, or nil. It is the single strict gate used by inspection and restore.
func dualMatchedProfile(data []byte) *dualProfile {
	for i := range dualProfiles {
		if _, ok := dualOriginalProfile(data, dualProfiles[i].stockHash); ok {
			return &dualProfiles[i]
		}
	}
	return nil
}

// relinkPayload re-targets the shared PIC payload's three external references (two
// CAL calls and the OEM-key lea) to a profile's addresses and verifies the result
// against the audited payload fingerprint. The local-key lea is payload-internal and
// is never modified.
func relinkPayload(p *dualProfile) ([]byte, error) {
	payload := append([]byte(nil), dualPayload...)
	// Each call's rel32 is relative to its own next instruction, so the two CAL
	// calls (at payload offsets 0x35 and 0x81) need distinct displacements.
	binary.LittleEndian.PutUint32(payload[0x36:], uint32(int64(p.cal)-int64(p.va)-0x35-5))
	binary.LittleEndian.PutUint32(payload[0x82:], uint32(int64(p.cal)-int64(p.va)-0x81-5))
	binary.LittleEndian.PutUint32(payload[0x44:], uint32(int64(p.oem)-int64(p.va)-0x41-7))
	if fingerprint(payload) != p.payloadSHA {
		return nil, errors.New("re-linked payload does not match the audited profile")
	}
	return payload, nil
}

func buildDual(stock []byte) ([]byte, error) {
	p := profileByStockHash(fingerprint(stock))
	if p == nil {
		return nil, errors.New("factory-compatible patch is not validated for this firmware build; no files changed")
	}
	return buildDualProfile(stock, p.stockHash)
}

func buildDualProfile(stock []byte, expected string) ([]byte, error) {
	p := profileForStock(stock)
	if p == nil || fingerprint(stock) != expected ||
		!bytes.Equal(stock[p.entryOff:p.entryOff+len(p.prologue)], p.prologue) ||
		!bytes.Equal(stock[dualNote:dualNote+56], p.originalNote) {
		return nil, errors.New("factory-compatible patch is not validated for this firmware build; no files changed")
	}
	payload, err := relinkPayload(p)
	if err != nil {
		return nil, err
	}
	out := make([]byte, p.file+len(payload)+len(dualMagic))
	copy(out, stock)
	note := out[dualNote : dualNote+56]
	binary.LittleEndian.PutUint32(note, 1)     // PT_LOAD
	binary.LittleEndian.PutUint32(note[4:], 5) // RX, never writable
	for i, v := range []uint64{uint64(p.file), p.va, p.va, uint64(len(payload)), uint64(len(payload)), 4096} {
		binary.LittleEndian.PutUint64(note[8+i*8:], v)
	}
	out[p.entryOff] = 0xe9
	// Both supported builds are ET_DYN with their first PT_LOAD at vaddr 0, so the
	// detour's load address equals its file offset.
	binary.LittleEndian.PutUint32(out[p.entryOff+1:], uint32(int64(p.va)-int64(p.entryOff)-5))
	copy(out[p.file:], payload)
	copy(out[p.file+len(payload):], dualMagic)
	return out, nil
}

func dualOriginal(data []byte) ([]byte, bool) {
	if p := dualMatchedProfile(data); p != nil {
		return dualOriginalProfile(data, p.stockHash)
	}
	return nil, false
}

func dualOriginalProfile(data []byte, expected string) ([]byte, bool) {
	p := profileByPatchedSize(len(data))
	if p == nil ||
		!(bytes.HasSuffix(data, []byte(dualMagic)) || bytes.HasSuffix(data, []byte(legacyDualMagic))) {
		return nil, false
	}
	stock := append([]byte(nil), data[:p.stockSize]...)
	copy(stock[p.entryOff:], p.prologue)
	copy(stock[dualNote:], p.originalNote)
	rebuilt, err := buildDualProfile(stock, expected)
	if err != nil {
		return nil, false
	}
	if bytes.Equal(data, rebuilt) {
		return stock, true
	}
	// The legacy v1 key/tag rotation is defined only for the first profile, the
	// original 030_016_002 build; newer builds have no previous dual profile to
	// rotate from.
	if p != &dualProfiles[0] {
		return nil, false
	}
	start := p.file + dualLocalModulus
	if !bytes.HasSuffix(data, []byte(legacyDualMagic)) || fingerprint(data[start:start+256]) != legacyModulusSHA256 {
		return nil, false
	}
	normalized := append([]byte(nil), data...)
	copy(normalized[start:], patchedModulus)
	copy(normalized[p.file+len(dualPayload):], dualMagic)
	return stock, bytes.Equal(normalized, rebuilt)
}

func dualCurrent(data []byte) bool {
	_, ok := dualOriginal(data)
	return ok && bytes.HasSuffix(data, []byte(dualMagic))
}
