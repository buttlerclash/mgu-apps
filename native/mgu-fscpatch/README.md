# FSC patch service

Version 1.1.0 supports two inspected `BAC4x_VSTAR_i386_Eth_Application.out`
verifier builds (version suffixes ignored). Each build is pinned by its stock
SHA-256 in a strict allowlist; unknown or modified builds are refused before
live changes. A matching stock binary backup is required to repair an
incomplete patch.

| Build | Stock SHA-256 | Validation |
|---|---|---|
| `030_016_002` | `b26d18308c0f2ca1edd5aff8c373aa3aa659751e940cb6eed8509873670c1231` | Round trip executed; reconstruction gate passed; CAL fallback executed in an MGU userspace guest; physical pending |
| unknown, profile `c221d8dc` | `c221d8dc35dd09e8d2c33688f978548eb15b755778cc58f354045a9956ac5f4c` | Profile derived, re-link verified; reconstruction gate passed; CAL fallback executed in an MGU userspace guest; physical pending |

Both share the identical factory OEM modulus and are ET_DYN images whose first
`PT_LOAD` maps at vaddr 0. `c221d8dc` is the `030_016_002` codegen with the
shared verifier wrapper and CAL both moved `+0x20`; the two builds share one
stock length, so the detour offset and prologue distinguish them and `c221d8dc`
places its payload one page higher to keep patched lengths unique.

The `036_010_004`, `001_032_079` and `001_034_044` profiles registered by the
released 1.1.0 are no longer in the allowlist and are now refused before any
live change. The ET_EXEC frame-pointer support they needed has been removed.

The factory modulus stays intact. A position-independent x86-64 wrapper calls
the original CAL signature verifier with the factory key first. Only an invalid
signature (`0xf9`) for the FSC key descriptor permits a second call with the
local public key. The original caller retains parsing, VIN, application,
upgrade and validity policy. Other key descriptors do not use the fallback.
The entire patched image must match the reconstructed audited profile for that
build, including the payload, program header, detour, padding and trailer.

Support configuration is merged into the 30-record NVM block. Existing FSC
records are preserved byte-for-byte; missing originals can be recovered from
the retained support-block backup. Current certificates take priority over
backups of the same software identifier. A malformed block or insufficient
space aborts the operation. Deleted certificates cannot be recreated without
an original record or backup.

The service writes a one-time, root-owned pending job tied to the installed
binary's SHA-256. An autosaronlinux.service ExecStartPre drop-in commits it
after persistence mounts and before NVM is loaded. It merges certificates
flushed by the old running verifier during shutdown. Restore stages the
original block instead. Completed jobs are removed, firmware mismatches leave
the job for inspection, and a hook failure never prevents AUTOSAR startup.
`blockPending` and `restartRequired` expose the staged state to the app.

The app's Restart head unit action needs a second press within eight seconds.
POST /restart requests `/usr/bin/nsm_control --requestRestart 7 --normal`, using
the same unit restart mechanism as the Store. NSM refusal and timeout are
reported. Restart shares the operation mutex and root/method/body checks.

Validation: the native suite runs under Linux 4.14.328 in QEMU with a temporary
ext4 disk, read-only tmpfs mounts and executing ELF fixtures. A production-code
round trip patches a captured registered build and restores it byte-for-byte.
An offline harness rejects altered copies of a patched image and, as recorded
for 1.0.0, executes the patched image's original CAL routines with four
captured factory FSCs. A QEMU guest running an original MGU head-unit userspace
executes the fallback path against both audited builds; see the measurement
below. A disposable RSA test key exercises the same fallback instructions with
its public modulus substituted only in the test image. No private key or vehicle
file is packaged in the app or service. The separate offline generator
intentionally publishes the matching local signing key under
`scripts/fsc_generator/`.

The `030_016_002` profile is the executed 1.0.0 build. The `c221d8dc` profile
is registered from derived addresses whose re-linked payload matches its audited
fingerprint.

Measured on 2026-11-20 with the offline harness against both real images: its
strict reconstruction gate **passes** for both builds - the harness re-derives
each patched image byte-for-byte in C from the same profile table and confirms
the recovered stock hashes to the pinned SHA-256 - and a single flipped byte in
the stock portion or near the payload is rejected. Its own execution path does
**not** work for these builds: they are `ET_DYN` with 16261 dynamic relocations
and 554 symbols imported from roughly 95 shared libraries, and the harness maps
`PT_LOAD`s without acting as a dynamic linker, so the first indirect call
faults. The 1.0.0 "CAL harness executed" entry predates that measurement and was
not reproducible with the static harness, which still needs to run on the head
unit where the `NEEDED` libraries exist.

CAL `0xf9` fallback execution has since been demonstrated off-device for both
builds, in a QEMU guest running an original MGU head-unit userspace (Linux
4.14.300-apl, glibc 2.27) assembled from BMW firmware packages. A preload probe
lets the guest's own loader do relocation and symbol resolution, then runs the
same oracle the offline harness defines. For an FSC signed by the published local
key, `cal_check` with the factory key returns `0xf9`, a direct `cal_check` with
the local key returns `0`, and the wrapper returns `0`. Both negative controls -
a descriptor copied to another address, and a descriptor with a non-FSC key type
- return `0xf9`, so the retry stays gated on descriptor identity and key type
rather than on the signature merely failing. A corrupted copy of the same FSC
returns `0xf9` from both keys, so the result is real RSA verification and not a
constant. Each patched image also resolves all 96 of its dependencies with none
missing, runs as a program and is still alive 20 s into its own startup, and
reports the factory modulus fingerprint unchanged in a live process. The stock
donor for `030_016_002`, taken from the matching firmware package, hashes to the
pinned SHA-256 and reaches the same `cal_check` results with no wrapper present.

That guest is not a car. It has no vehicle network, no NVM partitions and no
SOME/IP peers, and no captured factory FSC has been driven through it, so the
factory-accepts path in which the fallback must **not** fire remains
unexercised. Physical head-unit restart/persistence validation remains pending
for every build.

The custom wrapper source is in payload/dual.c and payload/dual.ld. It was
built with GCC 11 (`-Os -fPIC -fno-stack-protector
-fno-asynchronous-unwind-tables -ffreestanding -fno-builtin`), linked with GNU
ld using dual.ld, and extracted using objcopy -O binary. The embedded template
payload SHA-256 is `e3b729890e619d1c5e24d069c301facbd4df35699cee48d3f040075ceb0fbe6d`
(the `030_016_002` link). For every build the service re-links the template's
three external references — two CAL calls and the OEM-key lea — to that build's
audited addresses, then requires the result to match the profile's recorded
payload SHA-256 before writing anything. The payload-internal local-key lea is
never modified. Re-linking `030_016_002` reproduces the embedded template
byte-for-byte.

The local key's little-endian modulus SHA-256 is
`d4f1ebaece4e4dbc1536a28eaa15b6b9f80f50213bd485ba01495fb2c6c469e0`.
The installed verifier accepts OEM and local signatures; factory FSCs keep the
OEM verification path.
