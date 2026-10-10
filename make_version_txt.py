#!/usr/bin/env python3
import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_version(text):
    if not re.fullmatch(r"[0-9]+(\.[0-9]+){0,3}", text):
        raise ValueError(f"{text!r} is not a version of one to four dot-separated numbers")
    parts = [int(part) for part in text.split(".")]
    if any(part > 65535 for part in parts):
        raise ValueError(f"{text!r} has a part above 65535, which a Windows version cannot hold")
    return parts + [0] * (4 - len(parts))


def filetime_parts(moment):
    delta = moment.astimezone(timezone.utc) - FILETIME_EPOCH
    ticks = (delta.days * 86400 + delta.seconds) * 10**7 + delta.microseconds * 10
    return f"0x{ticks >> 32:08x}", f"0x{ticks & 0xFFFFFFFF:08x}"


def timestamp_count():
    sys.path.insert(0, str(ROOT))
    from time_decode.time_decode import ts_types

    return len(ts_types)


def description_count(count):
    return f"over {count // 10 * 10}"


def render(version, count, moment):
    numbers = ",".join(str(part) for part in parse_version(version))
    high, low = filetime_parts(moment)
    return f"""# https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({numbers}),
    prodvers=({numbers}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=({high},{low})
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'Digital Sleuth'),
        StringStruct(u'FileDescription', u'Timestamp encode/decode utility for {description_count(count)} timestamps'),
        StringStruct(u'FileVersion', u'{version}'),
        StringStruct(u'InternalName', u'Time Decode'),
        StringStruct(u'LegalCopyright', u'© {moment.astimezone(timezone.utc).year} Digital Sleuth'),
        StringStruct(u'OriginalFilename', u'Time Decode GUI v{version}.exe'),
        StringStruct(u'ProductName', u'Time Decode GUI v{version}'),
        StringStruct(u'ProductVersion', u'{version}')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""


def main():
    parser = argparse.ArgumentParser(description="Generate version.txt for a PyInstaller build")
    parser.add_argument("version", help="Version number, such as 11.0.0")
    parser.add_argument("-o", "--output", type=Path, default=ROOT / "version.txt")
    parser.add_argument(
        "-t",
        "--timestamps",
        type=int,
        help="Number of supported timestamps; read from time_decode when not given",
    )
    args = parser.parse_args()
    try:
        parse_version(args.version)
    except ValueError as error:
        parser.error(str(error))
    count = args.timestamps if args.timestamps is not None else timestamp_count()
    content = render(args.version, count, datetime.now(timezone.utc))
    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    print(f"Wrote {args.output} for version {args.version}")


if __name__ == "__main__":
    main()
