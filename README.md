# inno7-unpack

Unpack Inno Setup **7** installers, which `innounp` and `innoextract` cannot read.

Both established tools stop below Inno Setup 7:

| Tool | Highest supported | Symptom on an Inno 7 installer |
|------|-------------------|--------------------------------|
| [innounp](https://innounp.sourceforge.net/) | 6.x | `*** This is not a supported version` |
| [innoextract](https://constexpr.org/innoextract/) | 6.3.3 | `Unexpected setup loader revision: 2`, `Could not determine setup data version!` |

Inno Setup 7 bumped the `SetupLdrOffsetTable` to **revision 2**, whose fields are
64-bit. Both tools read the old 32-bit layout, get nonsense offsets, and give up.

This recovers the parts that matter for analysis: the setup-data header, the
compiled `[Code]` section as IFPS bytecode, and the string table.

## Requirements

**Python 3.10 or newer, and you must invoke it as `python3`.** No third-party
packages, no build step - the standard library only.

On macOS and many Linux boxes `python` is still Python 2. Running this under 2.7
fails at parse time with a misleading error, because `rb"..."` is a Python 3
literal:

```
    SETUP_DATA_ID = re.compile(rb"Inno Setup Setup Data \(([\d.]+)\)")
                                                                    ^
SyntaxError: invalid syntax
```

That is not a bug in the script. Use `python3 inno7_unpack.py ...`, or `./inno7_unpack.py`
so the shebang selects the right interpreter.

## Usage

```
./inno7_unpack.py <installer.exe> [-o OUTDIR] [-q]
```

Output defaults to `<installer>.unpacked/`.

```
$ ./inno7_unpack.py setup.exe -o out

setup.exe  (2,100,183 bytes)
  Inno Setup Setup Data (7.0.0.3) at 890,880 (0xD9800)
  SetupLdr offset table at 886,868 (0xD8854), revision 2
    Offset0=890,880  Offset1=890,880  OffsetEXE=913,726
    Offset0 == Offset1: the installer bundles NO files

  block 0 at 890,997: 22,660 stored -> 62,638 bytes  [setup0_header.bin]
    IFPS [Code] at +2,215: 17,691 bytes, 22 procedures  [CompiledCode.bin]
    403 UTF-16 literals  [strings.txt]
  block 1 at 913,694: 15 stored -> 0 bytes  [setup0_block1.bin]
  engine: 4,455,424 bytes, CRC 0xE0956D3D != 0xE13E9454  [setup.e32.raw]

  5 file(s) written to out
```

### What you get

| File | Contents |
|------|----------|
| `setup0_header.bin` | Decompressed setup-data header: Inno's header fields plus the compiled `[Code]` section |
| `CompiledCode.bin` | The IFPS bytecode carved out of that header |
| `setup0_block<N>.bin` | Every other decompressed setup-data block |
| `strings.txt` | Every printable UTF-16LE literal in the header, in file order |
| `setup.e32` | The setup engine, when it verifies against the table CRC (otherwise `setup.e32.raw`, see below) |

`strings.txt` is usually where the interesting content is: an installer's URLs,
paths, registry keys and command lines are string constants in the compiled
script, and they are invisible to `strings(1)` on the original file because the
whole block is LZMA-compressed.

### Disassembling the `[Code]` section

`CompiledCode.bin` is RemObjects PascalScript (IFPS) bytecode. Disassemble it
with [IFPSTools.NET](https://github.com/Wack0/IFPSTools.NET):

```
dotnet ifpsdasm.dll CompiledCode.bin      # writes CompiledCode.txt
```

Note that `ifpsdasm` **disassembles**; it does not decompile back to Pascal. No
public tool reconstructs `[Code]` as readable Pascal source today.

## What this does not do

Three limits, stated plainly because the tool reports them rather than hiding
them:

1. **It does not extract bundled application files.** That needs Inno's
   per-version file-entry structures, which are not implemented here. The layout
   report does tell you whether an installer carries any: `Offset0 == Offset1`
   means it bundles nothing.
2. **It does not reconstruct the `.iss` script.** Inno does not store the source.
   `innounp` *approximates* one from the header entries, which is a separate job
   from anything here.
3. **The extracted engine is not byte-exact.** Inno applies a call/jmp address
   transform to `setup.e32` before compressing it. The LZMA SDK's `Bra86`, xz's
   `FILTER_X86` and several simpler rules were all tested against the `CRCEXE`
   field in the offset table; the closest leaves roughly 3,500 bytes of a 4.4 MB
   image wrong, every one of them inside an `e8`/`e9` operand. So the output is
   written as `setup.e32.raw` with the CRC mismatch reported. Strings, resources,
   imports and overall structure are intact - only branch targets are wrong. If
   you need it byte-exact, the `.tmp` an Inno installer drops into
   `%TEMP%\is-*.tmp\` at run time is the genuine article.

For Inno **6.3.3 and below**, use `innounp` or `innoextract`. They support those
versions, extract the bundled files, and reconstruct an approximate script. This
tool exists for the gap above them, and it says so when handed an older
installer.

## Format notes

Collected while writing this, since none of it is documented in one place.

### Revision-2 offset table

Found by Inno's own `SetupLdrOffsetTableID`,
`72 44 6C 50 74 53 CD E6 D7 7B 0B 2A`, and also stored as `RT_RCDATA` resource
`11111`:

| Offset | Type | Field |
|--------|------|-------|
| +0 | `byte[12]` | ID |
| +12 | `u32` | `Version` (2 for Inno 7) |
| +16 | `i64` | `TotalSize` - equals the file size |
| +24 | `i64` | `OffsetEXE` - the compressed setup engine |
| +32 | `u32` | `UncompressedSizeEXE` |
| +36 | `u32` | `CRCEXE` - crc32 of the extracted engine |
| +40 | `i64` | `Offset0` - the setup data |
| +48 | `i64` | `Offset1` - the bundled file data |

`Offset0 == Offset1` means zero bytes of file data were written between the
loader stub and the setup data, i.e. the installer installs nothing of its own.

### Block framing

A setup-data block is `u32 headerCRC`, `i64 StoredSize`, `u8 Compressed`, then
the stream in chunks of `u32 crc32(chunk)` plus up to 4096 payload bytes.

**`StoredSize` counts the CRC words as well as the payload.** Missing that reads
past the end of the block.

The payload is raw LZMA1 beginning with the usual five property bytes. Decode
them yourself rather than calling the private `lzma._decode_filter_properties`:

```python
lc = props[0] % 9
lp = (props[0] // 9) % 5
pb = (props[0] // 9) // 5
dict_size = int.from_bytes(props[1:5], "little")
```

### Locating the setup data

Two traps here, both of which this tool handles:

- The identifier string `Inno Setup Setup Data (x.y.z)` appears **twice** - once
  as a compiler literal inside the SetupLdr stub, once at the real data. Taking
  the first match in the file gives you the wrong one. This picks the occurrence
  that is actually followed by a block whose chunk CRCs validate, and flags
  `[UNCONFIRMED]` when none is.
- A small fixed-size record sits between the 64-byte identifier and the first
  block header (53 bytes in the builds examined, itself CRC-protected). Its
  layout is undocumented, so the block header is found by probing candidate
  offsets and requiring every chunk CRC to check out, which makes a false
  positive effectively impossible.

### String extraction

Inno writes a 32-bit length immediately before each string: a **byte** count in
the header-field region, a **character** count in the compiled-script region.
When that length's low byte happens to be printable, the pair
`(length_low, 0x00)` looks like another UTF-16LE character and the *preceding*
string absorbs a character it does not own. `strings.txt` is trimmed against
each run's own prefix, so the literals come out byte-exact.

## Known gaps

Contributions welcome on any of these:

- Revision-1 (Inno ≤ 6) offset-table layout, so the engine can be extracted from
  older installers too.
- Per-file extraction of bundled application files.
- The exact call/jmp transform Inno applies to the engine. If you know which
  variant Inno bundles, the `CRCEXE` field makes verification a one-liner.

## License

MIT - see [LICENSE](LICENSE).
