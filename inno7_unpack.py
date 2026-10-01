#!/usr/bin/env python3
"""Unpack an Inno Setup installer that innounp and innoextract cannot read.

Both bundled tools stop below Inno Setup 7: innounp answers "This is not a
supported version" and innoextract supports up to 6.3.3, because Inno 7 bumped
the SetupLdr offset table to revision 2 with 64-bit fields. This walks the
container directly and recovers, for any version it can reach:

  setup0_header.bin   the decompressed setup-data header: Inno's header fields
                      plus the compiled [Code] section
  CompiledCode.bin    the IFPS bytecode carved out of that header, ready for
                      ifpsdasm (https://github.com/Wack0/IFPSTools.NET)
  setup0_block<N>.bin every other decompressed setup-data block
  setup.e32           the setup engine, when it verifies against the table CRC
  strings.txt         every printable UTF-16LE literal in the header, in order

It does NOT reconstruct the .iss source (Inno does not store it) and does not
extract bundled application files: those need Inno's per-version file-entry
structures, which are not implemented here. The layout report says whether a
given installer carries any.

Locating is deliberately version-agnostic. The setup data is found by Inno's own
"Inno Setup Setup Data (x.y.z)" identifier rather than by trusting a table
layout, and each compressed block is found by validating candidate offsets
against their per-chunk CRC-32 words, so an undocumented preamble between the
identifier and the first block costs nothing.

Usage:
    uv run python scripts/inno_unpack.py <installer.exe> [-o OUTDIR] [-q]
"""

from __future__ import annotations

import argparse
import lzma
import re
import struct
import sys
import zlib
from pathlib import Path

# Inno's SetupLdrOffsetTableID, shared by every revision.
OFFSET_TABLE_ID = bytes.fromhex("72446c507453cde6d77b0b2a")
SETUP_DATA_ID = re.compile(rb"Inno Setup Setup Data \(([\d.]+)\)")
SETUP_DATA_ID_LEN = 64

# TCompressedBlockHeader: CRC-32 of the record, StoredSize, Compressed flag.
BLOCK_HEADER = struct.Struct("<IqB")
BLOCK_CHUNK = 4096
BLOCK_SEARCH_WINDOW = 512
LZMA_PROPS_LEN = 5
MAX_BLOCK_OUTPUT = 256 << 20

UTF16_RUN = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){4,}")


def log(quiet: bool, message: str = "") -> None:
    if not quiet:
        print(message)


# --------------------------------------------------------------- offset table

def parse_offset_table(data: bytes) -> dict | None:
    """Read the SetupLdr offset table. Revision 2 (Inno 7) is parsed in full.

    Revision 1's field layout is not implemented: it could not be verified
    against a real installer, and a guessed layout would silently report wrong
    offsets. The setup data is located by its identifier anyway, so a revision-1
    installer still unpacks - only the engine is skipped.
    """
    at = data.find(OFFSET_TABLE_ID)
    if at < 0:
        return None
    version = struct.unpack_from("<I", data, at + 12)[0]
    table = {"at": at, "version": version}
    if version != 2:
        return table
    table.update(
        total_size=struct.unpack_from("<q", data, at + 16)[0],
        offset_exe=struct.unpack_from("<q", data, at + 24)[0],
        uncompressed_exe=struct.unpack_from("<I", data, at + 32)[0],
        crc_exe=struct.unpack_from("<I", data, at + 36)[0],
        offset0=struct.unpack_from("<q", data, at + 40)[0],
        offset1=struct.unpack_from("<q", data, at + 48)[0],
    )
    return table


# -------------------------------------------------------------- block reading

def locate_setup_data(data: bytes, table: dict | None) -> tuple[int, str, bool] | None:
    """Offset of the real setup data, and the version it declares.

    The identifier also appears as a compiler literal inside the SetupLdr stub,
    so the first match in the file is routinely the wrong one. Prefer the
    table's Offset0, and otherwise take the first occurrence that is actually
    followed by a block whose chunk CRCs validate. The third element says
    whether the offset was confirmed that way.
    """
    hits = [(m.start(), m.group(1).decode()) for m in SETUP_DATA_ID.finditer(data)]
    if not hits:
        return None
    if table and table.get("offset0"):
        declared = table["offset0"]
        for at, version in hits:
            if at == declared:
                return at, version, True
    for at, version in hits:
        if find_block(data, at + SETUP_DATA_ID_LEN) is not None:
            return at, version, True
    at, version = hits[0]
    return at, version, False


def read_block(data: bytes, offset: int) -> tuple[bytes, bool, int] | None:
    """Reassemble one TCompressedBlockReader stream.

    StoredSize counts the per-chunk CRC-32 words as well as the payload, and
    every one of them must check out, which is what makes a candidate offset
    safe to probe. Returns (stream, compressed, end_offset).
    """
    if offset + BLOCK_HEADER.size > len(data):
        return None
    _crc, stored, compressed = BLOCK_HEADER.unpack_from(data, offset)
    body = offset + BLOCK_HEADER.size
    if compressed not in (0, 1) or not 0 < stored <= len(data) - body:
        return None
    end = body + stored
    out = bytearray()
    position = body
    while position + 4 <= end:
        want = struct.unpack_from("<I", data, position)[0]
        position += 4
        chunk = data[position:position + min(BLOCK_CHUNK, end - position)]
        position += len(chunk)
        if zlib.crc32(chunk) & 0xFFFFFFFF != want:
            return None
        out += chunk
    if position != end or not out:
        return None
    return bytes(out), bool(compressed), end


def lzma1_filter(props: bytes) -> dict[str, int]:
    """Decode the 5-byte LZMA1 property header an Inno stream starts with."""
    packed = props[0]
    if packed > 0xE0:
        raise ValueError("not LZMA1 properties")
    remainder = packed // 9
    return {
        "id": lzma.FILTER_LZMA1,
        "lc": packed % 9,
        "lp": remainder % 5,
        "pb": remainder // 5,
        "dict_size": struct.unpack_from("<I", props, 1)[0],
    }


def inflate(stream: bytes, compressed: bool, limit: int = MAX_BLOCK_OUTPUT):
    if not compressed:
        return stream
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW, filters=[lzma1_filter(stream[:LZMA_PROPS_LEN])]
    )
    out = decoder.decompress(stream[LZMA_PROPS_LEN:], limit)
    # needs_input means the stream ended early: draining further returns
    # b"" forever, so stop and let the eof check below reject it.
    while not decoder.eof and not decoder.needs_input and len(out) < limit:
        out += decoder.decompress(b"", limit - len(out))
    if not decoder.eof:
        raise ValueError("stream exceeds the output limit")
    return out


def find_block(data: bytes, start: int) -> tuple[int, bytes, bool, int] | None:
    """First validating block header at or after `start`."""
    for candidate in range(start, min(start + BLOCK_SEARCH_WINDOW, len(data))):
        found = read_block(data, candidate)
        if found is None:
            continue
        stream, compressed, end = found
        if compressed and stream[0] > 0xE0:
            continue
        return candidate, stream, compressed, end
    return None


# ------------------------------------------------------------------ artifacts

def carve_compiled_code(header: bytes) -> bytes | None:
    """The IFPS blob, sized by the length prefix Inno writes before it."""
    at = header.find(b"IFPS")
    if at < 4:
        return None
    declared = struct.unpack_from("<I", header, at - 4)[0]
    if not 0 < declared <= len(header) - at:
        return None
    return header[at:at + declared]


def literals(header: bytes) -> list[str]:
    """Printable UTF-16LE runs, trimmed against Inno's own length prefixes.

    Inno stores a 32-bit length before each string: a byte count in the header
    fields, a character count in the compiled script. When its low byte is
    printable, the pair (length_low, 0x00) satisfies the run and the PRECEDING
    string absorbs a character it does not own.
    """
    out = []
    for run in UTF16_RUN.finditer(header):
        raw = run.group()
        if run.start() >= 4:
            declared = struct.unpack_from("<I", header, run.start() - 4)[0]
            if declared in (len(raw) - 2, len(raw) // 2 - 1):
                raw = raw[:-2]
        out.append(raw.decode("utf-16-le", "replace"))
    return out


def unpack(path: Path, outdir: Path, quiet: bool = False) -> int:
    data = path.read_bytes()
    table = parse_offset_table(data)
    marker = locate_setup_data(data, table)
    if marker is None:
        print(f"{path.name}: no Inno setup-data identifier found", file=sys.stderr)
        return 2
    offset0, version, confirmed = marker
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"cannot create {outdir}: {exc}", file=sys.stderr)
        return 2

    log(quiet, f"{path.name}  ({len(data):,} bytes)")
    log(quiet, f"  Inno Setup Setup Data ({version}) at {offset0:,} (0x{offset0:X})"
               + ("" if confirmed else "  [UNCONFIRMED]"))
    if not confirmed:
        log(quiet, "    No block validated at this identifier, so it is probably the "
                   "compiler literal inside the stub rather than real setup data.")
    if table:
        log(quiet, f"  SetupLdr offset table at {table['at']:,} "
                   f"(0x{table['at']:X}), revision {table['version']}")
        if table["version"] != 2:
            log(quiet, "    revision 1 layout is not parsed: engine extraction skipped")
        else:
            bundled = table["offset_exe"] - table["offset0"]
            log(quiet, f"    Offset0={table['offset0']:,}  Offset1={table['offset1']:,}"
                       f"  OffsetEXE={table['offset_exe']:,}")
            if table["offset0"] == table["offset1"]:
                log(quiet, "    Offset0 == Offset1: the installer bundles NO files")
            else:
                log(quiet, f"    bundled file data present ({bundled:,} bytes of setup "
                           "data); per-file extraction is not implemented")
    log(quiet)

    # ---- setup-data blocks
    written = []
    position = offset0 + SETUP_DATA_ID_LEN
    limit = table["offset_exe"] if table and table.get("offset_exe") else len(data)
    index = 0
    while position < limit:
        found = find_block(data, position)
        if found is None:
            break
        at, stream, compressed, end = found
        try:
            blob = inflate(stream, compressed)
        except (lzma.LZMAError, ValueError, EOFError) as exc:
            log(quiet, f"  block {index} at {at:,}: cannot inflate ({exc})")
            position = end
            index += 1
            continue
        name = "setup0_header.bin" if index == 0 else f"setup0_block{index}.bin"
        (outdir / name).write_bytes(blob)
        written.append(name)
        log(quiet, f"  block {index} at {at:,}: {len(stream):,} stored -> "
                   f"{len(blob):,} bytes  [{name}]")
        if index == 0:
            code = carve_compiled_code(blob)
            if code:
                (outdir / "CompiledCode.bin").write_bytes(code)
                procs = struct.unpack_from("<I", code, 12)[0]
                written.append("CompiledCode.bin")
                log(quiet, f"    IFPS [Code] at +{blob.find(b'IFPS'):,}: {len(code):,} "
                           f"bytes, {procs} procedures  [CompiledCode.bin]")
            text = literals(blob)
            (outdir / "strings.txt").write_text("\n".join(text), encoding="utf-8")
            written.append("strings.txt")
            log(quiet, f"    {len(text):,} UTF-16 literals  [strings.txt]")
        position = end
        index += 1

    # ---- setup engine
    if table and table.get("offset_exe"):
        found = read_block(data, table["offset_exe"])
        if found is None:
            log(quiet, "  engine block did not validate")
        else:
            stream, compressed, _end = found
            try:
                engine = inflate(stream, compressed, table["uncompressed_exe"] or MAX_BLOCK_OUTPUT)
            except (lzma.LZMAError, ValueError, EOFError) as exc:
                log(quiet, f"  engine: cannot inflate ({exc})")
                engine = None
            if engine is not None:
                actual = zlib.crc32(engine) & 0xFFFFFFFF
                if actual == table["crc_exe"]:
                    (outdir / "setup.e32").write_bytes(engine)
                    written.append("setup.e32")
                    log(quiet, f"  engine: {len(engine):,} bytes, CRC verified  [setup.e32]")
                else:
                    (outdir / "setup.e32.raw").write_bytes(engine)
                    written.append("setup.e32.raw")
                    log(quiet, f"  engine: {len(engine):,} bytes, CRC 0x{actual:08X} != "
                               f"0x{table['crc_exe']:08X}  [setup.e32.raw]")
                    log(quiet, "    Inno applies a call/jmp address transform to the "
                               "engine that is not reversed here, so the image is "
                               "readable but not byte-exact.")

    log(quiet)
    if not written:
        log(quiet, "  Nothing extracted. This tool implements the Inno 7 block framing; "
                   f"for version {version} use innounp or innoextract, which support "
                   "up to 6.3.3 and reconstruct the .iss script as well.")
        return 1
    log(quiet, f"  {len(written)} file(s) written to {outdir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Unpack an Inno Setup installer, including Inno 7."
    )
    parser.add_argument("installer", type=Path, help="the installer to unpack")
    parser.add_argument("-o", "--outdir", type=Path,
                        help="output directory (default: <installer>.unpacked)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only report errors")
    args = parser.parse_args()

    if not args.installer.is_file():
        print(f"{args.installer}: not a file", file=sys.stderr)
        return 2
    outdir = args.outdir or args.installer.with_suffix(args.installer.suffix + ".unpacked")
    return unpack(args.installer, outdir, args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
