# Copilot Instructions for SPMBlockCipher

## Build, Test, and Run

The .NET projects target **net10.0**. Tests use **MSTest**.

```powershell
# Build
dotnet build SpmCryptNet/SpmBlockCipherNet.csproj --configuration Release

# Run all tests
dotnet test SpmCryptNetTests/SpmBlockCipherNetTests.csproj --configuration Release

# Run a single test by fully qualified name
dotnet test SpmCryptNetTests/SpmBlockCipherNetTests.csproj --filter "FullyQualifiedName~SpmBlockCipherTests.TestEncryptDecrypt"

# Run all tests in one class
dotnet test SpmCryptNetTests/SpmBlockCipherNetTests.csproj --filter "ClassName~SimplePrngTests"

# Publish self-contained binary
dotnet publish SpmCryptNet/SpmBlockCipherNet.csproj --configuration Release --runtime win-x64 --self-contained true
```

The C++ project (`SpmCrypt64/SpmCrypt64.vcxproj`) builds with Visual Studio 2019 toolset (v142) for Win32 and x64. It has its own unit tests invoked via the `T` command-line mode.

## Architecture

This is a **block cipher** implementation using a Substitution-Permutation-Mask (SPM) algorithm, implemented in three languages: C# (.NET), C++ (Win32), and PowerShell.

### Core algorithm (128-byte blocks, 32-byte keys, 3 rounds per block)

Each round performs:
1. **Forward pass** (byte 0→127): apply 16-bit S-box substitution + XOR mask on overlapping 2-byte windows, stepping 1 byte at a time
2. **Reverse pass** (byte 126→0): same operation in reverse for diffusion
3. **Block permutation** (optional): shuffle all 128 bytes via a codebook

### Dual PRNG design

Each `SpmBlockCipher` instance holds two `SimplePrng` instances (`_sboxPrng` for S-box shuffling, `_maskPrng` for XOR masks), both derived from the same 32-byte key at different offsets. The PRNG is a 64-bit linear congruential generator with a guaranteed period of 2^64.

### Static codebook pattern

The S-box (`CodeBook`, 65536 entries) and permutation table (`PermutationCodeBook`, 128 entries) are **static** and shared across all cipher instances. They are initialized once via `SpmBlockCipher.InitCodebook()`.

### File encryption format

Encrypted files have the structure: `Nonce (16 bytes) | FileSize (8 bytes) | Ciphertext`. A random nonce is generated per encryption and used to derive a session key from the master key.

### CLI usage

```
SpmBlockCipherNet E|EP|D|DP <filein> <fileout> <key|password> <codebook>
```
`E`/`D` = encrypt/decrypt without permutation; `EP`/`DP` = with permutation.

## Key Conventions

### Type aliases

Both C# and C++ use type aliases to document word widths. In C#:
```csharp
using SPM_WORD = System.UInt64;
using SPM_SBOX_WORD = System.UInt16;
using SPM_PRNG = Spm.SimplePrng;
using FBC_PRNG = Spm.SimplePrng;
```

### Naming prefixes

- `s_` — static members (`s_blockMode`, `s_ConstructCodebook`)
- `_` — private instance fields (`_sbox`, `_maskPrng`)
- `m_` — C++ private members (`m_wState`, `m_prngSBox`)
- `k_c` — C++ constants (`k_cSpmBlockSizeBytes`)
- `Fbc` — file-level operations (`FbcEncryptFile`, `FbcDecryptFile`)

### C#/C++ parity

The C# and C++ implementations are intentionally parallel — same method names (`SetKeys`, `Encrypt`, `Decrypt`), same algorithm, same constants. Changes to one should be mirrored in the other.

### Namespace

All C# code lives in the `Spm` namespace.

### Constants

| Name | Value | Meaning |
|------|-------|---------|
| `BlockSizeBytes` | 128 | Block size |
| `SpmSBoxWidthBits` | 16 | S-box entry width |
| `SPM_SBOX_WIDTH` | 65536 | S-box table size |
| `FBC_PRNG_NUM_KEYS` | 2 | PRNGs per cipher instance |
| `GetKeyWidth()` | 32 | Total key size in bytes |

### Test patterns

Tests use MSTest with `[TestClass]`/`[TestMethod]` attributes and fixed test vectors. Tests validate encrypt/decrypt round-trips, PRNG determinism, S-box bijectivity, and static utility methods.
