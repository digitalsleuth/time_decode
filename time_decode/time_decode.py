#!/usr/bin/env python3
"""
This application is designed to decode timestamps into human-readable date/times and vice-versa
Additional information regarding the source of the timestamp formats and associated equations
will be provided in the docstrings below.

GPS Ref:
    http://www.leapsecond.com/java/gpsclock.htm
Leap Seconds:
    https://www.nist.gov/pml/time-and-frequency-division/leap-seconds-faqs
    http://hpiers.obspm.fr/eop-pc/index.php?index=TAI-UTC_tab&lang=en
Microsoft DateTime:
    https://docs.microsoft.com/en-us/dotnet/api/system.datetime?view=netframework-4.8
Microsoft Time:
    https://docs.microsoft.com/en-ca/windows/win32/sysinfo/time
Microsoft 1904 Timestamp:
    https://docs.microsoft.com/en-us/office/troubleshoot/excel/1900-and-1904-date-system
Microsoft OLE Automation Date (OADate):
    https://docs.microsoft.com/en-us/dotnet/api/system.datetime.tooadate?view=netframework-4.8
MSDOS wFatDate wFatTime DosDate:
    https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime
Microsoft FILETIME:
    https://support.microsoft.com/en-ca/help/188768/info-working-with-the-filetime-structure
Microsoft Active Directory/LDAP Timestamp:
    https://docs.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp
bplist timestamp / Mac Absolute / iOS / Cocoa
    https://developer.apple.com/documentation/corefoundation/cfabsolutetime
    https://developer.apple.com/documentation/foundation/nsdate
GSM Timestamps:
    https://en.wikipedia.org/wiki/GSM_03.40
    http://seven-bit-forensics.blogspot.com/2014/02/decoding-gsmsms-timestamps.html
Symantec AV Timestamp:
    https://knowledge.broadcom.com/external/article/151245/interpreting-endpoint-protection-av-log.html
VMWare Snapshot timestamp:
    https://stuffphilwrites.com/2013/03/vmware-snapshot-forensics/
TikTok and Twitter Timestamps:
    https://dfir.blog/tinkering-with-tiktok-timestamps/
Discord Timestamps:
    https://discord.com/developers/docs/reference#snowflakes
    Discord epoch is 1-1-2015 or 1420070400000
KSUID Timestamp value:
    https://github.com/segmentio/ksuid
    https://github.com/obsidianforensics/unfurl
Mastodon Social value:
    https://github.com/tootsuite/mastodon
Metasploit Payload UUID format:
    https://github.com/rapid7/metasploit-framework/wiki/Payload-UUID
    https://github.com/DidierStevens/Beta/blob/master/metatool.py
DHCPv6 DUID:
    https://tools.ietf.org/html/rfc3315#page-19
Microsoft .NET DateTime Struct (not .NET Framework)
    https://docs.microsoft.com/en-us/dotnet/api/system.datetime?view=net-6.0
GMail Boundary Timestamp
    https://www.metaspike.com/gmail-mime-boundary-delimiter-timestamps/
GMail Message ID Timestamp
    https://www.metaspike.com/dates-gmail-message-id-thread-id-timestamps/
Nokia Timestamp
    http://www.doubleblak.com/m/blogPosts.php?id=7#nokia
Nokia S40 Timestamp
    https://sqliteforensictoolkit.com/a-brief-history-of-time-stamps/
Bitwise Decimal Timestamp
    https://stackoverflow.com/questions/19185106/unknown-timestamp-reference-date/19553622#19553622
    Source of TS unknown, but since it's seemingly rare, it may be useful
BitDate
    https://sqliteforensictoolkit.com/a-brief-history-of-time-stamps/
Apple Biome data
    https://blog.d204n6.com/2022/09/ios-16-now-you-c-it-now-you-dont.html
S32 encoding and decoding - BlueSky Social Network
    https://github.com/bluesky-social/atproto/blob/main/packages/common-web/src/tid.ts
    https://github.com/bluesky-social/atproto/blob/main/packages/common-web/src/util.ts
"""

from datetime import datetime as dt, timedelta
import struct
from string import hexdigits
import argparse
import math
import re
import sys
import base64
import uuid
import traceback
from calendar import monthrange
from dateutil import parser as duparser
from colorama import init

init(autoreset=True)

__author__ = "Corey Forman"
__date__ = "27 Apr 2023"
__version__ = "6.0"
__description__ = "Python 3 CLI Date Time Conversion Tool"
__fmt__ = "%Y-%m-%d %H:%M:%S.%f"
__red__ = "\033[1;31m"
__clr__ = "\033[1;m"

ts_types = {
    "unix_sec": ["Unix Seconds", "Unix seconds timestamp is 10 digits in length"],
    "unix_milli": [
        "Unix Milliseconds",
        "Unix milliseconds timestamp is 13 digits in length",
    ],
    "windows_hex_64": [
        "Windows 64-bit Hex BE",
        "Windows 64-bit Hex Big-Endian timestamp is 16 hex characters (8 bytes)",
    ],
    "windows_hex_64le": [
        "Windows 64-bit Hex LE",
        "Windows 64-bit Hex Little-Endian timestamp is 16 hex characters (8 bytes)",
    ],
    "chrome": ["Google Chrome", "Chrome/Webkit timestamp is 17 digits"],
    "ad": [
        "Active Directory/LDAP dt",
        "Active Directory/LDAP timestamps are 18 digits",
    ],
    "unix_hex_32be": [
        "Unix Hex 32-bit BE",
        "Unix Hex 32-bit Big-Endian timestamps are 8 hex characters (4 bytes)",
    ],
    "unix_hex_32le": [
        "Unix Hex 32-bit LE",
        "Unix Hex 32-bit Little-Endian timestamps are 8 hex characters (4 bytes)",
    ],
    "cookie": [
        "Windows Cookie Date",
        "IE text cookie times consist of 2 ints, enter with a comma between them",
    ],
    "ole_be": [
        "Windows OLE 64-bit double BE",
        "OLE Big-Endian timestamps are 16 hex characters (8 bytes)",
    ],
    "ole_le": [
        "Windows OLE 64-bit double LE",
        "OLE Little-Endian timestamps are 16 hex characters (8 bytes)",
    ],
    "mac": [
        "NSDate - Mac Absolute time",
        "NSDates are either 9, 9.6, or 15-19 digits in length",
    ],
    "hfs_dec": [
        "Mac OS/HFS+ Decimal Time",
        "Mac OS/HFS+ Decimal timestamps are 10 digits",
    ],
    "hfs_be": [
        "HFS/HFS+ 32-bit Hex BE",
        "HFS/HFS+ Big-Endian timestamps are 8 hex characters (4 bytes)",
    ],
    "hfs_le": [
        "HFS/HFS+ 32-bit Hex LE",
        "HFS/HFS+ Little-Endian timestamps are 8 hex characters (4 bytes)",
    ],
    "msdos": [
        "MS-DOS 32-bit Hex Value",
        "MS-DOS wFatDate wFatTime timestamps are 8 hex characters (4 bytes)",
    ],
    "fat": [
        "FAT Date + Time",
        "MS-DOS 32-bit timestamps are 8 hex characters (4 bytes)",
    ],
    "systemtime": [
        "Microsoft 128-bit SYSTEMTIME",
        "Microsoft 128-bit SYSTEMTIME timestamps are 32 hex characters (16 bytes)",
    ],
    "filetime": [
        "Microsoft FILETIME time",
        "FILETIME timestamps are 2 sets of 8 hex chars (4 bytes) separated by a colon",
    ],
    "hotmail": [
        "Microsoft Hotmail time",
        "Hotmail timestamps are 2 sets of 8 hex chars (4 bytes), separated by a colon",
    ],
    "prtime": ["Mozilla PRTime", "Mozilla PRTime timestamps are 16 digits"],
    "ole_auto": [
        "OLE Automation Date",
        "OLE Automation timestamps are 2 ints, separated by a dot",
    ],
    "ms1904": [
        "MS Excel 1904 Date",
        "Excel 1904 timestamps are 2 ints, separated by a dot",
    ],
    "iostime": [
        "NSDate - iOS 11+",
        "NSDates are either 9, 9.6, or 15-19 digits in length",
    ],
    "symtime": [
        "Symantec AV time",
        "Symantec 6-byte hex timestamps are 12 hex characters",
    ],
    "gpstime": ["GPS time", "GPS timestamps are 10 digits"],
    "eitime": [
        "Google EI time",
        "Google ei timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_",
    ],
    "bplist": [
        "NSDate - Binary Plist / Cocoa",
        "NSDates are either 9, 9.6, or 15-19 digits in length",
    ],
    "gsm": ["GSM time", "GSM timestamps are 14 hex characters (7 bytes)"],
    "vm": [
        "VMSD time",
        "VMSD values are a 6-digit value and a signed/unsigned int at least 9 digits",
    ],
    "tiktok": ["TikTok time", "TikTok timestamps are 19 digits long"],
    "twitter": ["Twitter time", "Twitter timestamps are 18 digits or longer"],
    "discord": ["Discord time", "Discord timestamps are 18 digits or longer"],
    "ksuid": ["KSUID time", "KSUID values are 27 characters"],
    "mastodon": ["Mastodon time", "Mastodon timestamps are 18 digits or longer"],
    "metasploit": [
        "Metasploit Payload UUID",
        "Metasploit Payload UUID's are at least 22 chars and base64 urlsafe encoded",
    ],
    "sony": ["Sonyflake time", "Sonyflake values are 15 hex characters"],
    "uuid": [
        "UUID time",
        "UUID's are in the format 00000000-0000-0000-0000-000000000000",
    ],
    "dhcp6": ["DHCP6 DUID time", "DHCPv6 DUID values are at least 14 bytes long"],
    "dotnet": ["Microsoft .NET DateTime", ".NET DateTime values are 18 digits"],
    "gbound": ["GMail Boundary time", "GMail Boundary values are 28 hex chars"],
    "gmsgid": [
        "GMail Message ID time",
        "GMail Message ID values are 16 hex chars or 19 digits (IMAP)",
    ],
    "moto": ["Motorola time", "Motorola 6-byte hex timestamps are 12 hex characters"],
    "nokia": ["Nokia time", "Nokia 4-byte hex timestamps are 8 hex characters"],
    "nokiale": ["Nokia time LE", "Nokia 4-byte hex timestamps are 8 hex characters"],
    "ns40": ["Nokia S40 time", "Nokia 7-byte hex timestamps are 14 hex characters"],
    "ns40le": [
        "Nokia S40 time LE",
        "Nokia 7-byte hex timestamps are 14 hex characters",
    ],
    "bitdec": ["Bitwise Decimal time", "Bitwise Decimal timestamps are 10 digits"],
    "bitdate": ["BitDate time", "Samsung/LG BitDate timestamps are 8 hex characters"],
    "kstime": ["KSUID Decimal", "KSUID decimal timestamps are 9 digits in length"],
    "exfat": ["exFAT time", "exFAT 32-bit timestamps are 8 hex characters (4 bytes)"],
    "biomehex": [
        "Apple Biome hex time",
        "Apple Biome Hex value is 8 bytes (16 chars) long",
    ],
    "biome64": [
        "Apple Biome 64-bit decimal",
        "Apple Biome 64-bit decimal is 19 digits in length",
    ],
    "s32": ["S32 Encoded time", "S32 encoded timestamps are 9 characters long"],
}
__types__ = len(ts_types)

epochs = {
    1: dt(1, 1, 1),
    1601: dt(1601, 1, 1),
    1899: dt(1899, 12, 30),
    1904: dt(1904, 1, 1),
    1970: dt(1970, 1, 1),
    1980: dt(1980, 1, 6),
    2000: dt(2000, 1, 1),
    2001: dt(2001, 1, 1),
    2050: dt(2050, 1, 1),
    "hundreds_nano": 10000000,
    "nano_2001": 1000000000,
    "active": 116444736000000000,
    "hfs_dec_sub": 2082844800,
    "kstime": 1400000000,
}

# There have been no further leapseconds since 2017,1,1 at the __date__ of this script
# which is why the leapseconds end with a dt.now object to valid/relevant timestamp output.
leapseconds = {
    10: [dt(1972, 1, 1), dt(1972, 7, 1)],
    11: [dt(1972, 7, 1), dt(1973, 1, 1)],
    12: [dt(1973, 1, 1), dt(1974, 1, 1)],
    13: [dt(1974, 1, 1), dt(1975, 1, 1)],
    14: [dt(1975, 1, 1), dt(1976, 1, 1)],
    15: [dt(1976, 1, 1), dt(1977, 1, 1)],
    16: [dt(1977, 1, 1), dt(1978, 1, 1)],
    17: [dt(1978, 1, 1), dt(1979, 1, 1)],
    18: [dt(1979, 1, 1), dt(1980, 1, 1)],
    19: [dt(1980, 1, 1), dt(1981, 7, 1)],
    20: [dt(1981, 7, 1), dt(1982, 7, 1)],
    21: [dt(1982, 7, 1), dt(1983, 7, 1)],
    22: [dt(1983, 7, 1), dt(1985, 7, 1)],
    23: [dt(1985, 7, 1), dt(1988, 1, 1)],
    24: [dt(1988, 1, 1), dt(1990, 1, 1)],
    25: [dt(1990, 1, 1), dt(1991, 1, 1)],
    26: [dt(1991, 1, 1), dt(1992, 7, 1)],
    27: [dt(1992, 7, 1), dt(1993, 7, 1)],
    28: [dt(1993, 7, 1), dt(1994, 7, 1)],
    29: [dt(1994, 7, 1), dt(1996, 1, 1)],
    30: [dt(1996, 1, 1), dt(1997, 7, 1)],
    31: [dt(1997, 7, 1), dt(1999, 1, 1)],
    32: [dt(1999, 1, 1), dt(2006, 1, 1)],
    33: [dt(2006, 1, 1), dt(2009, 1, 1)],
    34: [dt(2009, 1, 1), dt(2012, 7, 1)],
    35: [dt(2012, 7, 1), dt(2015, 7, 1)],
    36: [dt(2015, 7, 1), dt(2017, 1, 1)],
    37: [dt(2017, 1, 1), dt.now() - timedelta(seconds=37)],
}

S32_CHARS = "234567abcdefghijklmnopqrstuvwxyz"


def handle(error):
    """Error handling output and formatting to include function causing error"""
    exc_type, exc_obj, _ = error
    error_tb = traceback.extract_stack()[:-3] + traceback.extract_tb(
        exc_obj.__traceback__
    )
    _, line_no, function_name, _ = error_tb[-1]
    print(f"{str(exc_type.__name__)}: {str(exc_obj)} - {function_name} line {line_no}")


def analyze(args):
    """Process arguments and errors"""
    all_args = vars(args)
    try:
        if args.guess:
            full_list = from_all(args.guess)
            if len(full_list) == 0:
                print("[!] No valid dates found. Check your input and try again")
            else:
                print(
                    "[+] Outputs which do NOT result in a date/time value are NOT displayed\r"
                )
                if len(full_list) == 1:
                    dt_text = "date"
                else:
                    dt_text = "dates"
                print(f"[+] Displaying {len(full_list)} potential {dt_text}\r")
                print(
                    f"{__red__}[+] Most likely results (within +/- 5 years) are highlighted\n{__clr__}"
                )
                for _, output in enumerate(full_list):
                    print(f"{full_list[output][1]}")
            print("\r")
            return
        if args.timestamp:
            _, ts_outputs = to_timestamps(args.timestamp)
            print(
                f"\n[+] Converting {args.timestamp} to {len(ts_outputs)} timestamps:\n"
            )
            for ts_val in ts_outputs:
                print(ts_val)
            print("\r")
            return
        for arg_passed in single_funcs:
            if all_args[arg_passed]:
                _, indiv_output, _, reason = single_funcs[arg_passed](
                    all_args[arg_passed]
                )
                if indiv_output is False:
                    print(f"[!] {reason}")
                else:
                    print(indiv_output)
    except Exception:
        handle(sys.exc_info())


def from_unix_sec(timestamp):
    """Convert Unix Seconds value to a date"""
    ts_type, reason = ts_types["unix_sec"]
    try:
        if not len(timestamp) == 10 or not timestamp.isdigit():
            in_unix_sec = indiv_output = combined_output = False
        else:
            in_unix_sec = dt.utcfromtimestamp(float(timestamp)).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_unix_sec} UTC")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_unix_sec} UTC{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_sec = indiv_output = combined_output = False
    return in_unix_sec, indiv_output, combined_output, reason


def to_unix_sec(dt_val):
    """Convert date to a Unix Seconds value"""
    ts_type, _ = ts_types["unix_sec"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_unix_sec = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        ts_output = str(f"{ts_type}:\t\t\t{out_unix_sec}")
    except Exception:
        handle(sys.exc_info())
        out_unix_sec = ts_output = False
    return out_unix_sec, ts_output


def from_unix_milli(timestamp):
    """Convert Unix Millisecond value to a date"""
    ts_type, reason = ts_types["unix_milli"]
    try:
        if not len(timestamp) == 13 or not timestamp.isdigit():
            in_unix_milli = indiv_output = combined_output = False
        else:
            in_unix_milli = dt.utcfromtimestamp(float(timestamp) / 1000.0).strftime(
                __fmt__
            )
            indiv_output = str(f"{ts_type}: {in_unix_milli} UTC")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_unix_milli} UTC{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_milli = indiv_output = combined_output = False
    return in_unix_milli, indiv_output, combined_output, reason


def to_unix_milli(dt_val):
    """Convert date to a Unix Millisecond value"""
    ts_type, _ = ts_types["unix_milli"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_unix_milli = str(
            int(((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000)
        )
        ts_output = str(f"{ts_type}:\t\t{out_unix_milli}")
    except Exception:
        handle(sys.exc_info())
        out_unix_milli = ts_output = False
    return out_unix_milli, ts_output


def from_windows_hex_64(timestamp):
    """Convert a Windows 64 Hex Big-Endian value to a date"""
    ts_type, reason = ts_types["windows_hex_64"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_windows_hex_64 = indiv_output = combined_output = False
        else:
            base10_microseconds = int(timestamp, 16) / 10
            if base10_microseconds >= 1e17:
                in_windows_hex_64 = indiv_output = combined_output = False
            else:
                dt_obj = epochs[1601] + timedelta(microseconds=base10_microseconds)
                in_windows_hex_64 = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_windows_hex_64} UTC")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_windows_hex_64} " f"UTC{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_windows_hex_64 = indiv_output = combined_output = False
    return in_windows_hex_64, indiv_output, combined_output, reason


def to_windows_hex_64(dt_val):
    """Convert a date to a Windows 64 Hex Big-Endian value"""
    ts_type, _ = ts_types["windows_hex_64"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + ((minus_epoch.seconds - int(dt_tz)) * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        out_windows_hex_64 = str(hex(int(calc_time) * 10))[2:].zfill(16)
        ts_output = str(f"{ts_type}:\t\t{out_windows_hex_64}")
    except Exception:
        handle(sys.exc_info())
        out_windows_hex_64 = ts_output = False
    return out_windows_hex_64, ts_output


def from_windows_hex_64le(timestamp):
    """Convert a Windows 64 Hex Little-Endian value to a date"""
    ts_type, reason = ts_types["windows_hex_64le"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_windows_hex_le = indiv_output = combined_output = False
        else:
            indiv_output = combined_output = False
            endianness_change = int.from_bytes(
                struct.pack("<Q", int(timestamp, 16)), "big"
            )
            converted_time = endianness_change / 10
            if converted_time >= 1e17:
                in_windows_hex_le = indiv_output = combined_output = False
            else:
                dt_obj = epochs[1601] + timedelta(microseconds=converted_time)
                in_windows_hex_le = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_windows_hex_le} UTC")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_windows_hex_le} " f"UTC{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_windows_hex_le = indiv_output = combined_output = False
    return in_windows_hex_le, indiv_output, combined_output, reason


def to_windows_hex_64le(dt_val):
    """Convert a date to a Windows 64 Hex Little-Endian value"""
    ts_type, _ = ts_types["windows_hex_64le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + ((minus_epoch.seconds - int(dt_tz)) * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        out_windows_hex_le = str(struct.pack("<Q", int(calc_time * 10)).hex()).zfill(16)
        ts_output = str(f"{ts_type}:\t\t{out_windows_hex_le}")
    except Exception:
        handle(sys.exc_info())
        out_windows_hex_le = ts_output = False
    return out_windows_hex_le, ts_output


def from_chrome(timestamp):
    """Convert a Chrome Timestamp/Webkit Value to a date"""
    ts_type, reason = ts_types["chrome"]
    try:
        if not len(timestamp) == 17 or not timestamp.isdigit():
            in_chrome = indiv_output = combined_output = False
        else:
            delta = timedelta(microseconds=int(timestamp))
            converted_time = epochs[1601] + delta
            in_chrome = converted_time.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_chrome} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_chrome} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_chrome = indiv_output = combined_output = False
    return in_chrome, indiv_output, combined_output, reason


def to_chrome(dt_val):
    """Convert a date to a Chrome Timestamp/Webkit value"""
    ts_type, _ = ts_types["chrome"]
    try:
        dt_obj = duparser.parse(dt_val)
        nano_seconds = ""
        if "." in dt_val:
            nano_seconds = dt_val.split(".")[1].split(" ")[0]
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        micro_seconds = (dt_obj - epochs[1601]).microseconds
        chrome_time = (dt_obj - epochs[1601]).total_seconds() - int(dt_tz)
        chrome_micro = str(chrome_time).split(".")[1]
        if (
            (len(nano_seconds) == 6 and len(chrome_micro) < 6)
            or len(nano_seconds) > 6
            or len(nano_seconds) == 6
        ):
            chrome_time = str(chrome_time).replace(
                str(chrome_time).split(".")[1], str(micro_seconds).zfill(6)
            )
            out_chrome = str(chrome_time).replace(".", "")
        else:
            out_chrome = str(int(chrome_time * 1000000))
        ts_output = str(f"{ts_type}:\t\t\t{out_chrome}")
    except Exception:
        handle(sys.exc_info())
        out_chrome = ts_output = False
    return out_chrome, ts_output


def from_ad(timestamp):
    """Convert an Active Directory/LDAP timestamp to a date"""
    ts_type, reason = ts_types["ad"]
    try:
        if not len(timestamp) == 18 or not timestamp.isdigit():
            in_ad = indiv_output = combined_output = False
        else:
            dt_obj = dt.utcfromtimestamp(
                (float(int(timestamp) - epochs["active"]) / epochs["hundreds_nano"])
            )
            in_ad = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ad} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t{in_ad} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_ad = indiv_output = combined_output = False
    return in_ad, indiv_output, combined_output, reason


def to_ad(dt_val):
    """Convert a date to an Active Directory/LDAP timestamp"""
    ts_type, _ = ts_types["ad"]
    try:
        nano_seconds = ""
        if "." in dt_val:
            nano_seconds = dt_val.split(".")[1].split(" ")[0]
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
            dt_obj = duparser.parse(dt_val, ignoretz=True)
        else:
            dt_tz = 0
            dt_obj = duparser.parse(dt_val, ignoretz=True)
        if len(nano_seconds) == 7:
            dt_obj = dt_obj.replace(microsecond=0)
            nano_seconds = int(nano_seconds)
        elif len(nano_seconds) > 7:
            dt_obj = dt_obj.replace(microsecond=0)
            nano_seconds = int(nano_seconds[: -(len(nano_seconds) - 7)])
        elif len(nano_seconds) == 6 or (
            len(nano_seconds) == 5 and len(str(dt_obj.microsecond)) == 6
        ):
            nano_seconds = dt_obj.microsecond * 10
            dt_obj = dt_obj.replace(microsecond=0)
        else:
            nano_seconds = 0
        tz_shift = (
            int(
                ((dt_obj - epochs[1970]).total_seconds() - int(dt_tz))
                * epochs["hundreds_nano"]
            )
            + nano_seconds
        )
        out_adtime = str(int(tz_shift) + int(epochs["active"]))
        ts_output = str(f"{ts_type}:\t{out_adtime}")
    except Exception:
        handle(sys.exc_info())
        out_adtime = ts_output = False
    return out_adtime, ts_output


def from_unix_hex_32be(timestamp):
    """Convert a Unix Hex 32-bit Big-Endian timestamp to a date"""
    ts_type, reason = ts_types["unix_hex_32be"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_unix_hex_32 = indiv_output = combined_output = False
        else:
            to_dec = int(timestamp, 16)
            in_unix_hex_32 = dt.utcfromtimestamp(float(to_dec)).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_unix_hex_32} UTC")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_unix_hex_32} UTC{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_hex_32 = indiv_output = combined_output = False
    return in_unix_hex_32, indiv_output, combined_output, reason


def to_unix_hex_32be(dt_val):
    """Convert a date to a Unix Hex 32-bit Big-Endian timestamp"""
    ts_type, _ = ts_types["unix_hex_32be"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz))
        out_unix_hex_32 = str(struct.pack(">L", unix_time).hex())
        ts_output = str(f"{ts_type}:\t\t{out_unix_hex_32}")
    except Exception:
        handle(sys.exc_info())
        out_unix_hex_32 = ts_output = False
    return out_unix_hex_32, ts_output


def from_unix_hex_32le(timestamp):
    """Convert a Unix Hex 32-bit Little-Endian timestamp to a date"""
    ts_type, reason = ts_types["unix_hex_32le"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_unix_hex_32le = indiv_output = combined_output = False
        else:
            to_dec = int.from_bytes(struct.pack("<L", int(timestamp, 16)), "big")
            in_unix_hex_32le = dt.utcfromtimestamp(float(to_dec)).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_unix_hex_32le} UTC")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_unix_hex_32le} UTC{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_hex_32le = indiv_output = combined_output = False
    return in_unix_hex_32le, indiv_output, combined_output, reason


def to_unix_hex_32le(dt_val):
    """Convert a date to a Unix Hex 32-bit Little-Endian timestamp"""
    ts_type, _ = ts_types["unix_hex_32le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz))
        out_unix_hex_32le = str(struct.pack("<L", unix_time).hex())
        ts_output = str(f"{ts_type}:\t\t{out_unix_hex_32le}")
    except Exception:
        handle(sys.exc_info())
        out_unix_hex_32le = ts_output = False
    return out_unix_hex_32le, ts_output


def from_cookie(timestamp):
    """Convert an Internet Explorer timestamp to a date"""
    ts_type, reason = ts_types["cookie"]
    try:
        if not ("," in timestamp) or not (
            timestamp.split(",")[0].isdigit() and timestamp.split(",")[1].isdigit()
        ):
            in_cookie = indiv_output = combined_output = False
        else:
            low, high = [int(h, base=10) for h in timestamp.split(",")]
            calc = 10**-7 * (high * 2**32 + low) - 11644473600
            if calc >= 1e11:
                in_cookie = indiv_output = combined_output = False
            else:
                dt_obj = dt.utcfromtimestamp(calc)
                in_cookie = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_cookie} UTC")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_cookie} UTC{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_cookie = indiv_output = combined_output = False
    return in_cookie, indiv_output, combined_output, reason


def to_cookie(dt_val):
    """Convert a date to Internet Explorer timestamp values"""
    ts_type, _ = ts_types["cookie"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz))
        high = int(((unix_time + 11644473600) * 10**7) / 2**32)
        low = int((unix_time + 11644473600) * 10**7) - (high * 2**32)
        out_cookie = f"{str(low)},{str(high)}"
        ts_output = str(f"{ts_type}:\t\t{out_cookie}")
    except Exception:
        handle(sys.exc_info())
        out_cookie = ts_output = False
    return out_cookie, ts_output


def from_ole_be(timestamp):
    """Convert an OLE Big-Endian timestamp to a date"""
    ts_type, reason = ts_types["ole_be"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_ole_be = indiv_output = combined_output = False
        else:
            delta = struct.unpack(">d", struct.pack(">Q", int(timestamp, 16)))[0]
            if delta != delta or int(delta) < 0 or delta > 2e6:
                in_ole_be = indiv_output = combined_output = False
            else:
                dt_obj = epochs[1899] + timedelta(days=delta)
                in_ole_be = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_ole_be} UTC")
                combined_output = str(f"{__red__}{ts_type}:\t{in_ole_be} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_ole_be = indiv_output = combined_output = False
    return in_ole_be, indiv_output, combined_output, reason


def to_ole_be(dt_val):
    """Convert a date to an OLE Big-Endian timestamp"""
    ts_type, _ = ts_types["ole_be"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        delta = ((dt_obj - epochs[1899]).total_seconds() - int(dt_tz)) / 86400
        conv = struct.unpack("<Q", struct.pack("<d", delta))[0]
        out_ole_be = str(struct.pack(">Q", conv).hex())
        ts_output = str(f"{ts_type}:\t{out_ole_be}")
    except Exception:
        handle(sys.exc_info())
        out_ole_be = ts_output = False
    return out_ole_be, ts_output


def from_ole_le(timestamp):
    """Convert an OLE Little-Endian timestamp to a date"""
    ts_type, reason = ts_types["ole_le"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_ole_le = indiv_output = combined_output = False
        else:
            to_le = hex(int.from_bytes(struct.pack("<Q", int(timestamp, 16)), "big"))
            delta = struct.unpack(">d", struct.pack(">Q", int(to_le[2:], 16)))[0]
            if delta != delta or int(delta) < 0 or int(delta) > 99999:
                in_ole_le = indiv_output = combined_output = False
            else:
                dt_obj = epochs[1899] + timedelta(days=delta)
                in_ole_le = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_ole_le} UTC")
                combined_output = str(f"{__red__}{ts_type}:\t{in_ole_le} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_ole_le = indiv_output = combined_output = False
    return in_ole_le, indiv_output, combined_output, reason


def to_ole_le(dt_val):
    """Convert a date to an OLE Little-Endian timestamp"""
    ts_type, _ = ts_types["ole_le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        delta = ((dt_obj - epochs[1899]).total_seconds() - int(dt_tz)) / 86400
        conv = struct.unpack("<Q", struct.pack("<d", delta))[0]
        out_ole_le = str(struct.pack("<Q", conv).hex())
        ts_output = str(f"{ts_type}:\t{out_ole_le}")
    except Exception:
        handle(sys.exc_info())
        out_ole_le = ts_output = False
    return out_ole_le, ts_output


def from_nsdate(timestamp):
    """Convert an Apple NSDate timestamp (Mac Absolute, BPlist, Cocoa, iOS) to a date"""
    val_type = ""
    ts_type, reason = None, None
    try:
        if (
            "." in timestamp
            and (
                (len(timestamp.split(".")[0]) == 9)
                and (len(timestamp.split(".")[1]) in range(0, 7))
            )
            and "".join(timestamp.split(".")).isdigit()
        ):
            ts_type, reason = ts_types["mac"]
            val_type = "mac"
        elif len(timestamp) == 9 and timestamp.isdigit():
            ts_type, reason = ts_types["bplist"]
            val_type = "bplist"
        elif len(timestamp) in range(15, 19) and timestamp.isdigit():
            ts_type, reason = ts_types["iostime"]
            val_type = "iostime"
        else:
            in_nsdate = indiv_output = combined_output = False
            pass
        if val_type in ("mac", "bplist"):
            dt_obj = epochs[2001] + timedelta(seconds=float(timestamp))
            in_nsdate = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_nsdate}")
            combined_output = str(f"{__red__}{ts_type}:\t{in_nsdate} UTC{__clr__}")
        elif val_type == "iostime":
            dt_obj = (int(timestamp) / int(epochs["nano_2001"])) + 978307200
            in_nsdate = dt.utcfromtimestamp(dt_obj).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_nsdate} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_nsdate} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_nsdate = indiv_output = combined_output = False
    return in_nsdate, indiv_output, combined_output, reason


def to_mac(dt_val):
    """Convert a date to a Mac Absolute timestamp"""
    ts_type, _ = ts_types["mac"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        mac_ts = (
            int(
                ((dt_obj - epochs[2001]).total_seconds() - int(dt_tz))
                * epochs["nano_2001"]
            )
            / 1000000000
        )
        if mac_ts < 0:
            out_mac = "[!] Timestamp Boundary Exceeded [!]"
        else:
            out_mac = str(f"{mac_ts:.6f}")
        ts_output = str(f"{ts_type}:\t{out_mac}")
    except Exception:
        handle(sys.exc_info())
        out_mac = ts_output = False
    return out_mac, ts_output


def from_hfs_dec(timestamp):
    """Convert a Mac OS/HFS+ Decimal Timestamp to a date"""
    ts_type, reason = ts_types["hfs_dec"]
    try:
        if len(str(timestamp)) != 10 or not (timestamp).isdigit():
            in_hfs_dec = indiv_output = combined_output = False
        else:
            minus_epoch = float(int(timestamp) - epochs["hfs_dec_sub"])
            if minus_epoch < 0:
                in_hfs_dec = indiv_output = combined_output = False
            else:
                in_hfs_dec = dt.utcfromtimestamp(minus_epoch).strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_hfs_dec} UTC")
                combined_output = str(f"{__red__}{ts_type}:\t{in_hfs_dec} UTC{__clr__}")
    except Exception:
        in_hfs_dec = indiv_output = combined_output = False
        handle(sys.exc_info())
    return in_hfs_dec, indiv_output, combined_output, reason


def to_hfs_dec(dt_val):
    """Convert a date to a Mac OS/HFS+ Decimal Timestamp"""
    ts_type, _ = ts_types["hfs_dec"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_hfs_dec = str(int((dt_obj - epochs[1904]).total_seconds() - int(dt_tz)))
        ts_output = str(f"{ts_type}:\t{out_hfs_dec}")
    except Exception:
        handle(sys.exc_info())
        out_hfs_dec = ts_output = False
    return out_hfs_dec, ts_output


def from_hfs_be(timestamp):
    """Convert an HFS/HFS+ Big-Endian timestamp to a date (HFS+ is in UTC)"""
    ts_type, reason = ts_types["hfs_be"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_hfs_be = indiv_output = combined_output = False
        else:
            dt_obj = epochs[1904] + timedelta(seconds=int(timestamp, 16))
            in_hfs_be = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_hfs_be} HFS Local / HFS+ UTC")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_hfs_be} " f"HFS Local / HFS+ UTC{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_hfs_be = indiv_output = combined_output = False
    return in_hfs_be, indiv_output, combined_output, reason


def to_hfs_be(dt_val):
    """Convert a date to an HFS/HFS+ Big-Endian timestamp"""
    ts_type, _ = ts_types["hfs_be"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        conv = int((dt_obj - epochs[1904]).total_seconds() - int(dt_tz))
        if conv > 4294967295:
            out_hfs_be = "[!] Timestamp Boundary Exceeded [!]"
        else:
            out_hfs_be = f"{conv:08x}"
        ts_output = str(f"{ts_type}:\t\t{out_hfs_be}")
    except Exception:
        handle(sys.exc_info())
        out_hfs_be = ts_output = False
    return out_hfs_be, ts_output


def from_hfs_le(timestamp):
    """Convert an HFS/HFS+ Little-Endian timestamp to a date (HFS+ is in UTC)"""
    ts_type, reason = ts_types["hfs_le"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_hfs_le = indiv_output = combined_output = False
        else:
            to_le = struct.unpack(">I", struct.pack("<I", int(timestamp, 16)))[0]
            dt_obj = epochs[1904] + timedelta(seconds=to_le)
            in_hfs_le = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_hfs_le} HFS Local / HFS+ UTC")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_hfs_le} " f"HFS Local / HFS+ UTC{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_hfs_le = indiv_output = combined_output = False
    return in_hfs_le, indiv_output, combined_output, reason


def to_hfs_le(dt_val):
    """Convert a date to an HFS/HFS+ Little-Endian timestamp"""
    ts_type, _ = ts_types["hfs_le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        conv = int((dt_obj - epochs[1904]).total_seconds() - int(dt_tz))
        if conv > 4294967295:
            out_hfs_le = "[!] Timestamp Boundary Exceeded [!]"
        else:
            out_hfs_le = str(struct.pack("<I", conv).hex())
        ts_output = str(f"{ts_type}:\t\t{out_hfs_le}")
    except Exception:
        handle(sys.exc_info())
        out_hfs_le = ts_output = False
    return out_hfs_le, ts_output


def from_fat(timestamp):
    """Convert an MS-DOS wFatDate wFatTime timestamp to a date"""
    ts_type, reason = ts_types["fat"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_fat = indiv_output = combined_output = False
        else:
            byte_swap = [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)]
            to_le = byte_swap[1] + byte_swap[0] + byte_swap[3] + byte_swap[2]
            binary = f"{int(to_le, 16):032b}"
            stamp = [
                binary[:7],
                binary[7:11],
                binary[11:16],
                binary[16:21],
                binary[21:27],
                binary[27:32],
            ]
            for binary in stamp[:]:
                dec = int(binary, 2)
                stamp.remove(binary)
                stamp.append(dec)
            fat_year = stamp[0] + 1980
            fat_month = stamp[1]
            fat_day = stamp[2]
            fat_hour = stamp[3]
            fat_min = stamp[4]
            fat_sec = stamp[5] * 2
            if (
                fat_year not in range(1970, 2100)
                or fat_month not in range(1, 13)
                or fat_day not in range(1, 32)
                or fat_hour not in range(0, 24)
                or fat_min not in range(0, 60)
                or fat_sec not in range(0, 60)
            ):
                in_fat = indiv_output = combined_output = False
            else:
                dt_obj = dt(fat_year, fat_month, fat_day, fat_hour, fat_min, fat_sec)
                in_fat = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_fat} Local")
                combined_output = str(f"{__red__}{ts_type}:\t\t{in_fat} Local{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_fat = indiv_output = combined_output = False
    return in_fat, indiv_output, combined_output, reason


def to_fat(dt_val):
    """Convert a date to an MS-DOS wFatDate wFatTime timestamp"""
    ts_type, _ = ts_types["fat"]
    try:
        dt_obj = duparser.parse(dt_val)
        year = f"{(dt_obj.year - 1980):07b}"
        month = f"{dt_obj.month:04b}"
        day = f"{dt_obj.day:05b}"
        hour = f"{dt_obj.hour:05b}"
        minute = f"{dt_obj.minute:06b}"
        seconds = f"{int(dt_obj.second / 2):05b}"
        to_hex = str(
            struct.pack(
                ">I", int(year + month + day + hour + minute + seconds, 2)
            ).hex()
        )
        byte_swap = "".join([to_hex[i : i + 2] for i in range(0, len(to_hex), 2)][::-1])
        out_fat = "".join(
            [byte_swap[i : i + 4] for i in range(0, len(byte_swap), 4)][::-1]
        )
        ts_output = str(f"{ts_type}:\t\t{out_fat}")
    except Exception:
        handle(sys.exc_info())
        out_fat = ts_output = False
    return out_fat, ts_output


def from_msdos(timestamp):
    """Convert an MS-DOS timestamp to a date"""
    ts_type, reason = ts_types["msdos"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_msdos = indiv_output = combined_output = False
        else:
            swap = "".join(
                [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)][::-1]
            )
            binary = f"{int(swap, 16):032b}"
            stamp = [
                binary[:7],
                binary[7:11],
                binary[11:16],
                binary[16:21],
                binary[21:27],
                binary[27:32],
            ]
            for val in stamp[:]:
                dec = int(val, 2)
                stamp.remove(val)
                stamp.append(dec)
            dos_year = stamp[0] + 1980
            dos_month = stamp[1]
            dos_day = stamp[2]
            dos_hour = stamp[3]
            dos_min = stamp[4]
            dos_sec = stamp[5] * 2
            if (
                dos_year not in range(1970, 2100)
                or dos_month not in range(1, 13)
                or dos_day not in range(1, 32)
                or dos_hour not in range(0, 24)
                or dos_min not in range(0, 60)
                or dos_sec not in range(0, 60)
                or dos_day not in range(1, monthrange(dos_year, dos_month)[1])
            ):
                in_msdos = indiv_output = combined_output = False
            else:
                dt_obj = dt(dos_year, dos_month, dos_day, dos_hour, dos_min, dos_sec)
                in_msdos = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_msdos} Local")
                combined_output = str(f"{__red__}{ts_type}:\t{in_msdos} Local{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_msdos = indiv_output = combined_output = False
    return in_msdos, indiv_output, combined_output, reason


def to_msdos(dt_val):
    """Convert a date to an MS-DOS timestamp"""
    ts_type, _ = ts_types["msdos"]
    try:
        dt_obj = duparser.parse(dt_val)
        year = f"{(dt_obj.year - 1980):07b}"
        month = f"{dt_obj.month:04b}"
        day = f"{dt_obj.day:05b}"
        hour = f"{dt_obj.hour:05b}"
        minute = f"{dt_obj.minute:06b}"
        seconds = f"{int(dt_obj.second / 2):05b}"
        hexval = str(
            struct.pack(
                ">I", int(year + month + day + hour + minute + seconds, 2)
            ).hex()
        )
        out_msdos = "".join([hexval[i : i + 2] for i in range(0, len(hexval), 2)][::-1])
        ts_output = str(f"{ts_type}:\t{out_msdos}")
    except Exception:
        handle(sys.exc_info())
        out_msdos = ts_output = False
    return out_msdos, ts_output


def from_exfat(timestamp):
    """Convert an exFAT timestamp (LE) to a date"""
    ts_type, reason = ts_types["exfat"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_exfat = indiv_output = combined_output = False
        else:
            binary = f"{int(timestamp, 16):032b}"
            stamp = [
                binary[:7],
                binary[7:11],
                binary[11:16],
                binary[16:21],
                binary[21:27],
                binary[27:32],
            ]
            for val in stamp[:]:
                dec = int(val, 2)
                stamp.remove(val)
                stamp.append(dec)
            exfat_year = stamp[0] + 1980
            exfat_month = stamp[1]
            exfat_day = stamp[2]
            exfat_hour = stamp[3]
            exfat_min = stamp[4]
            exfat_sec = stamp[5] * 2
            if (
                exfat_year not in range(1970, 2100)
                or exfat_month not in range(1, 13)
                or exfat_day not in range(1, 32)
                or exfat_hour not in range(0, 24)
                or exfat_min not in range(0, 60)
                or exfat_sec not in range(0, 60)
                or exfat_day not in range(1, monthrange(exfat_year, exfat_month)[1])
            ):
                in_exfat = indiv_output = combined_output = False
            else:
                dt_obj = dt(
                    exfat_year, exfat_month, exfat_day, exfat_hour, exfat_min, exfat_sec
                )
                in_exfat = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_exfat} Local")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_exfat} Local{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_exfat = indiv_output = combined_output = False
    return in_exfat, indiv_output, combined_output, reason


def to_exfat(dt_val):
    """Convert a date to an exFAT timestamp (LE)"""
    ts_type, _ = ts_types["exfat"]
    try:
        dt_obj = duparser.parse(dt_val)
        year = f"{(dt_obj.year - 1980):07b}"
        month = f"{dt_obj.month:04b}"
        day = f"{dt_obj.day:05b}"
        hour = f"{dt_obj.hour:05b}"
        minute = f"{dt_obj.minute:06b}"
        seconds = f"{int(dt_obj.second / 2):05b}"
        out_exfat = str(
            struct.pack(
                ">I", int(year + month + day + hour + minute + seconds, 2)
            ).hex()
        )
        ts_output = str(f"{ts_type}:\t\t\t{out_exfat}")
    except Exception:
        handle(sys.exc_info())
        out_exfat = ts_output = False
    return out_exfat, ts_output


def from_systemtime(timestamp):
    """Convert a Microsoft 128-bit SYSTEMTIME timestamp to a date"""
    ts_type, reason = ts_types["systemtime"]
    try:
        if not len(timestamp) == 32 or not all(char in hexdigits for char in timestamp):
            in_systemtime = indiv_output = combined_output = False
        else:
            to_le = "".join(
                [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)][::-1]
            )
            converted = [to_le[i : i + 4] for i in range(0, len(to_le), 4)][::-1]
            stamp = []
            for i in converted:
                dec = int(i, 16)
                stamp.append(dec)
            dt_obj = dt(
                stamp[0],
                stamp[1],
                stamp[3],
                stamp[4],
                stamp[5],
                stamp[6],
                stamp[7] * 1000,
            )
            in_systemtime = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_systemtime} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t{in_systemtime} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_systemtime = indiv_output = combined_output = False
    return in_systemtime, indiv_output, combined_output, reason


def to_systemtime(dt_val):
    """Convert a date to a Microsoft 128-bit SYSTEMTIME timestamp"""
    ts_type, _ = ts_types["systemtime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        micro = int(dt_obj.microsecond / 1000)
        tz_shift = dt_obj.timestamp() - int(dt_tz)
        add_micro = (tz_shift * 1000) + micro
        convert_to_seconds = add_micro / 1000
        new_dt_obj = dt.fromtimestamp(convert_to_seconds)
        full_date = new_dt_obj.strftime("%Y, %m, %w, %d, %H, %M, %S, " + str(micro))
        stamp = []
        for val in full_date.split(","):
            to_hex = int(
                hex(int.from_bytes(struct.pack("<H", int(val)), "big"))[2:], 16
            )
            stamp.append(f"{to_hex:04x}")
        out_systemtime = "".join(stamp)
        ts_output = str(f"{ts_type}:\t{out_systemtime}")
    except Exception:
        handle(sys.exc_info())
        out_systemtime = ts_output = False
    return out_systemtime, ts_output


def from_filetime(timestamp):
    """Convert a Microsoft FILETIME timestamp to a date"""
    ts_type, reason = ts_types["filetime"]
    try:
        if not (":" in timestamp) or not (
            all(char in hexdigits for char in timestamp[0:8])
            and all(char in hexdigits for char in timestamp[9:])
        ):
            in_filetime = indiv_output = combined_output = False
        else:
            part2, part1 = [int(h, base=16) for h in timestamp.split(":")]
            converted_time = struct.unpack(">Q", struct.pack(">LL", part1, part2))[0]
            if converted_time >= 1e18:
                in_filetime = indiv_output = combined_output = False
            else:
                dt_obj = dt.utcfromtimestamp(
                    float(converted_time - epochs["active"]) / epochs["hundreds_nano"]
                )
                in_filetime = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_filetime} UTC")
                combined_output = str(
                    f"{__red__}{ts_type}:\t{in_filetime} UTC{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_filetime = indiv_output = combined_output = False
    return in_filetime, indiv_output, combined_output, reason


def to_filetime(dt_val):
    """Convert a date to a Microsoft FILETIME timestamp"""
    ts_type, _ = ts_types["filetime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + ((minus_epoch.seconds - int(dt_tz)) * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        indiv_output = str(struct.pack(">Q", int(calc_time * 10)).hex())
        out_filetime = f"{str(indiv_output[8:])}:{str(indiv_output[:8])}"
        ts_output = str(f"{ts_type}:\t{out_filetime}")
    except Exception:
        handle(sys.exc_info())
        out_filetime = ts_output = False
    return out_filetime, ts_output


def from_hotmail(timestamp):
    """Convert a Microsoft Hotmail timestamp to a date"""
    ts_type, reason = ts_types["hotmail"]
    try:
        if ":" not in timestamp or not (
            all(char in hexdigits for char in timestamp[0:8])
            and all(char in hexdigits for char in timestamp[9:])
        ):
            in_hotmail = indiv_output = combined_output = False
        else:
            hm_repl = timestamp.replace(":", "")
            byte_swap = "".join(
                [hm_repl[i : i + 2] for i in range(0, len(hm_repl), 2)][::-1]
            )
            part2 = int(byte_swap[:8], base=16)
            part1 = int(byte_swap[8:], base=16)
            converted_time = struct.unpack(">Q", struct.pack(">LL", part1, part2))[0]
            if converted_time >= 1e18:
                in_hotmail = indiv_output = combined_output = False
            else:
                dt_obj = dt.utcfromtimestamp(
                    float(converted_time - epochs["active"]) / epochs["hundreds_nano"]
                )
                in_hotmail = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_hotmail} UTC")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_hotmail} UTC{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_hotmail = indiv_output = combined_output = False
    return in_hotmail, indiv_output, combined_output, reason


def to_hotmail(dt_val):
    """Convert a date to a Microsoft Hotmail timestamp"""
    ts_type, _ = ts_types["hotmail"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + ((minus_epoch.seconds - int(dt_tz)) * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        indiv_output = str(struct.pack(">Q", int(calc_time * 10)).hex())
        byte_swap = "".join(
            [indiv_output[i : i + 2] for i in range(0, len(indiv_output), 2)][::-1]
        )
        out_hotmail = f"{str(byte_swap[8:])}:{str(byte_swap[:8])}"
        ts_output = str(f"{ts_type}:\t\t{out_hotmail}")
    except Exception:
        handle(sys.exc_info())
        out_hotmail = ts_output = False
    return out_hotmail, ts_output


def from_prtime(timestamp):
    """Convert a Mozilla PRTime timestamp to a date"""
    ts_type, reason = ts_types["prtime"]
    try:
        if not len(timestamp) == 16 or not timestamp.isdigit():
            in_prtime = indiv_output = combined_output = False
        else:
            dt_obj = epochs[1970] + timedelta(microseconds=int(timestamp))
            in_prtime = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_prtime} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_prtime} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_prtime = indiv_output = combined_output = False
    return in_prtime, indiv_output, combined_output, reason


def to_prtime(dt_val):
    """Convert a date to Mozilla's PRTime timestamp"""
    ts_type, _ = ts_types["prtime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_prtime = str(
            int(((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000000)
        )
        ts_output = str(f"{ts_type}:\t\t\t{out_prtime}")
    except Exception:
        handle(sys.exc_info())
        out_prtime = ts_output = False
    return out_prtime, ts_output


def from_ole_auto(timestamp):
    """Convert an OLE Automation timestamp to a date"""
    ts_type, reason = ts_types["ole_auto"]
    try:
        if (
            "." not in timestamp
            or not (
                (len(timestamp.split(".")[0]) == 5)
                and (len(timestamp.split(".")[1]) in range(9, 13))
            )
            or not "".join(timestamp.split(".")).isdigit()
        ):
            in_ole_auto = indiv_output = combined_output = False
        else:
            dt_obj = epochs[1899] + timedelta(days=float(timestamp))
            in_ole_auto = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ole_auto} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_ole_auto} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_ole_auto = indiv_output = combined_output = False
    return in_ole_auto, indiv_output, combined_output, reason


def to_ole_auto(dt_val):
    """Convert a date to an OLE Automation timestamp"""
    ts_type, _ = ts_types["ole_auto"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        ole_ts = ((dt_obj - epochs[1899]).total_seconds() - int(dt_tz)) / 86400
        out_ole_auto = f"{ole_ts:.12f}"
        ts_output = str(f"{ts_type}:\t\t{out_ole_auto}")
    except Exception:
        handle(sys.exc_info())
        out_ole_auto = ts_output = False
    return out_ole_auto, ts_output


def from_ms1904(timestamp):
    """Convert a Microsoft Excel 1904 timestamp to a date"""
    ts_type, reason = ts_types["ms1904"]
    try:
        if (
            "." not in timestamp
            or not (
                (len(timestamp.split(".")[0]) == 5)
                and (len(timestamp.split(".")[1]) in range(9, 13))
            )
            or not "".join(timestamp.split(".")).isdigit()
        ):
            in_ms1904 = indiv_output = combined_output = False
        else:
            dt_obj = epochs[1904] + timedelta(days=float(timestamp))
            in_ms1904 = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ms1904} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_ms1904} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_ms1904 = indiv_output = combined_output = False
    return in_ms1904, indiv_output, combined_output, reason


def to_ms1904(dt_val):
    """Convert a date to a Microsoft Excel 1904 timestamp"""
    ts_type, _ = ts_types["ms1904"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        ms1904_ts = ((dt_obj - epochs[1904]).total_seconds() - int(dt_tz)) / 86400
        out_ms1904 = f"{ms1904_ts:.12f}"
        ts_output = str(f"{ts_type}:\t\t{out_ms1904}")
    except Exception:
        handle(sys.exc_info())
        out_ms1904 = ts_output = False
    return out_ms1904, ts_output


def to_iostime(dt_val):
    """Convert a date to an iOS 11 timestamp"""
    ts_type, _ = ts_types["iostime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_iostime = str(
            int(
                ((dt_obj - epochs[2001]).total_seconds() - int(dt_tz))
                * epochs["nano_2001"]
            )
        )
        if int(out_iostime) < 0:
            out_iostime = "[!] Timestamp Boundary Exceeded [!]"
        ts_output = str(f"{ts_type}:\t\t{out_iostime}")
    except Exception:
        handle(sys.exc_info())
        out_iostime = ts_output = False
    return out_iostime, ts_output


def from_symtime(timestamp):
    """Convert a Symantec 6-byte hex timestamp to a date"""
    ts_type, reason = ts_types["symtime"]
    try:
        if not len(timestamp) == 12 or not all(char in hexdigits for char in timestamp):
            in_symtime = indiv_output = combined_output = False
        else:
            hex_to_dec = [
                int(timestamp[i : i + 2], 16) for i in range(0, len(timestamp), 2)
            ]
            hex_to_dec[0] = hex_to_dec[0] + 1970
            hex_to_dec[1] = hex_to_dec[1] + 1
            if hex_to_dec[1] not in range(1, 13):
                in_symtime = indiv_output = combined_output = False
            else:
                dt_obj = dt(
                    hex_to_dec[0],
                    hex_to_dec[1],
                    hex_to_dec[2],
                    hex_to_dec[3],
                    hex_to_dec[4],
                    hex_to_dec[5],
                )
                in_symtime = dt_obj.strftime(__fmt__)
        indiv_output = str(f"{ts_type}: {in_symtime}")
        combined_output = str(f"{__red__}{ts_type}:\t\t{in_symtime} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_symtime = indiv_output = combined_output = False
    return in_symtime, indiv_output, combined_output, reason


def to_symtime(dt_val):
    """Convert a date to Symantec's 6-byte hex timestamp"""
    ts_type, _ = ts_types["symtime"]
    try:
        dt_obj = duparser.parse(dt_val)
        sym_year = "{0:x}".format(dt_obj.year - 1970).zfill(2)
        sym_month = "{0:x}".format(dt_obj.month - 1).zfill(2)
        sym_day = "{0:x}".format(dt_obj.day).zfill(2)
        sym_hour = "{0:x}".format(dt_obj.hour).zfill(2)
        sym_minute = "{0:x}".format(dt_obj.minute).zfill(2)
        sym_second = "{0:x}".format(dt_obj.second).zfill(2)
        out_symtime = (
            f"{sym_year}{sym_month}{sym_day}{sym_hour}{sym_minute}{sym_second}"
        )
        ts_output = str(f"{ts_type}:\t\t{out_symtime}")
    except Exception:
        handle(sys.exc_info())
        out_symtime = ts_output = False
    return out_symtime, ts_output


def from_gpstime(timestamp):
    """Convert a GPS timestamp to a date (involves leap seconds)"""
    ts_type, reason = ts_types["gpstime"]
    try:
        if not len(timestamp) == 10 or not timestamp.isdigit():
            in_gpstime = indiv_output = combined_output = False
        else:
            gps_stamp = epochs[1980] + timedelta(seconds=(float(timestamp)))
            tai_convert = gps_stamp + timedelta(seconds=19)
            epoch_convert = (tai_convert - epochs[1970]).total_seconds()
            check_date = dt.utcfromtimestamp(epoch_convert)
            for entry in leapseconds:
                check = date_range(
                    leapseconds.get(entry)[0], leapseconds.get(entry)[1], check_date
                )
                if check is True:
                    variance = entry
                else:
                    variance = 0
            gps_out = check_date - timedelta(seconds=variance)
            in_gpstime = gps_out.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_gpstime}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_gpstime} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_gpstime = indiv_output = combined_output = False
    return in_gpstime, indiv_output, combined_output, reason


def to_gpstime(dt_val):
    """Convert a date to a GPS timestamp (involves leap seconds)"""
    ts_type, _ = ts_types["gpstime"]
    try:
        check_date = duparser.parse(dt_val)
        if hasattr(check_date.tzinfo, "_offset"):
            dt_tz = check_date.tzinfo._offset.total_seconds()
            check_date = duparser.parse(dt_val, ignoretz=True)
        else:
            dt_tz = 0
            check_date = duparser.parse(dt_val, ignoretz=True)
        for entry in leapseconds:
            check = date_range(
                leapseconds.get(entry)[0], leapseconds.get(entry)[1], check_date
            )
            if check is True:
                variance = entry
            else:
                variance = 0
        leap_correction = check_date + timedelta(seconds=variance)
        epoch_shift = leap_correction - epochs[1970]
        gps_stamp = (
            dt.utcfromtimestamp(epoch_shift.total_seconds()) - epochs[1980]
        ).total_seconds() - 19
        gps_stamp = int(gps_stamp) - int(dt_tz)
        out_gpstime = str(gps_stamp)
        ts_output = str(f"{ts_type}:\t\t\t{out_gpstime}")
    except Exception:
        handle(sys.exc_info())
        out_gpstime = ts_output = False
    return out_gpstime, ts_output


def from_eitime(timestamp):
    """Convert a Google ei URL timestamp"""
    ts_type, reason = ts_types["eitime"]
    try:
        urlsafe_chars = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_"
        )
        if not all(char in urlsafe_chars for char in timestamp):
            in_eitime = indiv_output = combined_output = False
        else:
            padding_check = len(timestamp) % 4
            if padding_check != 0:
                padding_reqd = 4 - padding_check
                result_eitime = timestamp + (padding_reqd * "=")
            else:
                result_eitime = timestamp
            try:
                decoded_eitime = base64.urlsafe_b64decode(result_eitime).hex()[:8]
                unix_ts = int.from_bytes(
                    struct.pack("<L", int(decoded_eitime, 16)), "big"
                )
                in_eitime = dt.utcfromtimestamp(unix_ts).strftime(__fmt__)
                indiv_output = str(f"{ts_type}:\t\t\t{in_eitime}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_eitime} UTC{__clr__}"
                )
            except base64.binascii.Error:
                in_eitime = indiv_output = combined_output = False
    except Exception:
        handle(sys.exc_info())
        in_eitime = indiv_output = combined_output = False
    return in_eitime, indiv_output, combined_output, reason


def to_eitime(dt_val):
    """Try to convert a value to an ei URL timestamp"""
    ts_type, _ = ts_types["eitime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[1970]).total_seconds() + int(dt_tz))
        unix_hex = struct.pack("<L", unix_time)
        urlsafe_encode = base64.urlsafe_b64encode(unix_hex)
        out_eitime = urlsafe_encode.decode(encoding="UTF-8").strip("=")
        ts_output = str(f"{ts_type}:\t\t\t{out_eitime}")
    except Exception:
        handle(sys.exc_info())
        out_eitime = ts_output = False
    return out_eitime, ts_output


def to_bplist(dt_val):
    """Convert a date to a Binary Plist timestamp"""
    ts_type, _ = ts_types["bplist"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_bplist = str(int((dt_obj - epochs[2001]).total_seconds()) - int(dt_tz))
        if int(out_bplist) < 0:
            out_bplist = "[!] Timestamp Boundary Exceeded [!]"
        ts_output = str(f"{ts_type}:\t{out_bplist}")
    except Exception:
        handle(sys.exc_info())
        out_bplist = ts_output = False
    return out_bplist, ts_output


def from_gsm(timestamp):
    """Convert a GSM timestamp to a date"""
    ts_type, reason = ts_types["gsm"]
    try:
        # The last byte of the GSM timestamp is a hex representation of the timezone.
        # If the timezone bitwise operation on this byte results in a timezone offset
        # of less than -12 or greater than 12, then the value is incorrect.
        # The values in tz_in_range are hex bytes which return proper timezones.
        tz_in_range = [
            "00",
            "01",
            "02",
            "03",
            "04",
            "05",
            "06",
            "07",
            "08",
            "09",
            "0a",
            "0b",
            "0c",
            "0d",
            "0e",
            "0f",
            "10",
            "11",
            "12",
            "13",
            "14",
            "15",
            "16",
            "17",
            "18",
            "19",
            "20",
            "21",
            "22",
            "23",
            "24",
            "25",
            "26",
            "27",
            "28",
            "29",
            "30",
            "31",
            "32",
            "33",
            "34",
            "35",
            "36",
            "37",
            "38",
            "39",
            "40",
            "41",
            "42",
            "43",
            "44",
            "45",
            "46",
            "47",
            "48",
            "80",
            "81",
            "82",
            "83",
            "84",
            "85",
            "86",
            "87",
            "88",
            "89",
            "8a",
            "8b",
            "8c",
            "8d",
            "8e",
            "8f",
            "90",
            "91",
            "92",
            "93",
            "94",
            "95",
            "96",
            "97",
            "98",
            "99",
            "a0",
            "a1",
            "a2",
            "a3",
            "a4",
            "a5",
            "a6",
            "a7",
            "a8",
            "a9",
            "b0",
            "b1",
            "b2",
            "b3",
            "b4",
            "b5",
            "b6",
            "b7",
            "b8",
            "b9",
            "c0",
            "c1",
            "c2",
            "c3",
            "c4",
            "c5",
            "c6",
            "c7",
            "c8",
        ]
        tz_check = timestamp[12:14][::-1].lower()
        if (
            not len(timestamp) == 14
            or not all(char in hexdigits for char in timestamp)
            or tz_check not in tz_in_range
        ):
            in_gsm = indiv_output = combined_output = False
        else:
            swap = [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)]
            for value in swap[:]:
                l_endian = value[::-1]
                swap.remove(value)
                swap.append(l_endian)
            ts_tz = "{0:08b}".format(int(swap[6], 16))
            if int(ts_tz[0]) == 1:
                utc_offset = (
                    -int(str(int(ts_tz[1:4], 2)) + str(int(ts_tz[4:8], 2))) * 0.25
                )
            elif int(ts_tz[0]) == 0:
                utc_offset = (
                    int(str(int(ts_tz[0:4], 2)) + str(int(ts_tz[4:8], 2))) * 0.25
                )
            swap[6] = utc_offset
            for string in swap[:]:
                swap.remove(string)
                swap.append(int(string))
            dt_year, dt_month, dt_day, dt_hour, dt_min, dt_sec, dt_tz = swap
            if dt_year in range(0, 50):
                dt_year = dt_year + 2000
            if dt_tz == 0:
                dt_tz = " UTC"
            elif dt_tz > 0:
                dt_tz = f" UTC+{str(dt_tz)}"
            else:
                dt_tz = f" UTC{str(dt_tz)}"
            in_gsm = str(
                (
                    dt(dt_year, dt_month, dt_day, dt_hour, dt_min, dt_sec).strftime(
                        __fmt__
                    )
                )
                + dt_tz
            )
            indiv_output = str(f"{ts_type}: {in_gsm}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_gsm}{__clr__}")
    except ValueError:
        in_gsm = indiv_output = combined_output = False
    except Exception:
        handle(sys.exc_info())
        in_gsm = indiv_output = combined_output = False
    return in_gsm, indiv_output, combined_output, reason


def to_gsm(dt_val):
    """Convert a timestamp to a GSM timestamp"""
    ts_type, _ = ts_types["gsm"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        if dt_tz == 0:
            hex_tz = f"{0:02d}"
        elif dt_tz < 0:
            dt_tz = dt_tz / 3600
            conversion = str(f"{(int(abs(dt_tz)) * 4):02d}")
            conv_list = list(conversion)
            high_order = f"{int(conv_list[0]):04b}"
            low_order = f"{int(conv_list[1]):04b}"
            high_order = f"{(int(high_order, 2) + 8):04b}"
            hex_tz = hex(int((high_order + low_order), 2)).lstrip("0x").upper()
        else:
            dt_tz = dt_tz / 3600
            conversion = str(int(dt_tz) * 4).zfill(2)
            conv_list = list(conversion)
            high_order = f"{int(conv_list[0]):04b}"
            low_order = f"{int(conv_list[1]):04b}"
            hex_tz = hex(int((high_order + low_order), 2)).lstrip("0x").upper()
        date_list = [
            f"{(dt_obj.year - 2000):02d}",
            f"{dt_obj.month:02d}",
            f"{dt_obj.day:02d}",
            f"{dt_obj.hour:02d}",
            f"{dt_obj.minute:02d}",
            f"{dt_obj.second:02d}",
            hex_tz,
        ]
        date_value_swap = []
        for value in date_list[:]:
            b_endian = value[::-1]
            date_value_swap.append(b_endian)
        out_gsm = "".join(date_value_swap)
        ts_output = str(f"{ts_type}:\t\t\t{out_gsm}")
    except Exception:
        handle(sys.exc_info())
        out_gsm = ts_output = False
    return out_gsm, ts_output


def from_vm(timestamp):
    """Convert from a .vmsd createTimeHigh/createTimeLow timestamp"""
    ts_type, reason = ts_types["vm"]
    try:
        if "," not in timestamp:
            in_vm = indiv_output = combined_output = False
        else:
            create_time_high = int(timestamp.split(",")[0])
            create_time_low = int(timestamp.split(",")[1])
            vmsd = (
                float(
                    (create_time_high * 2**32)
                    + struct.unpack("I", struct.pack("i", create_time_low))[0]
                )
                / 1000000
            )
            if vmsd >= 1e13:
                in_vm = indiv_output = combined_output = False
            else:
                in_vm = dt.utcfromtimestamp(vmsd).strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_vm}")
                combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_vm} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_vm = indiv_output = combined_output = False
    return in_vm, indiv_output, combined_output, reason


def to_vm(dt_val):
    """Convert date to a .vmsd createTime* value"""
    ts_type, _ = ts_types["vm"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_seconds = (
            int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000000
        )
        create_time_high = int(float(unix_seconds) / 2**32)
        unpacked_int = unix_seconds - (create_time_high * 2**32)
        create_time_low = struct.unpack("i", struct.pack("I", unpacked_int))[0]
        out_vm = f"{str(create_time_high)},{str(create_time_low)}"
        ts_output = str(f"{ts_type}:\t\t\t{out_vm}")
    except Exception:
        handle(sys.exc_info())
        out_vm = ts_output = False
    return out_vm, ts_output


def from_tiktok(timestamp):
    """Convert a TikTok URL value to a date/time"""
    ts_type, reason = ts_types["tiktok"]
    try:
        if len(str(timestamp)) < 19 or not timestamp.isdigit():
            in_tiktok = indiv_output = combined_output = False
        else:
            unix_ts = int(timestamp) >> 32
            in_tiktok = dt.utcfromtimestamp(float(unix_ts)).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_tiktok}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_tiktok} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_tiktok = indiv_output = combined_output = False
    return in_tiktok, indiv_output, combined_output, reason


def from_twitter(timestamp):
    """Convert a Twitter URL value to a date/time"""
    ts_type, reason = ts_types["twitter"]
    try:
        if len(str(timestamp)) < 18 or not timestamp.isdigit():
            in_twitter = indiv_output = combined_output = False
        else:
            unix_ts = (int(timestamp) >> 22) + 1288834974657
            in_twitter = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_twitter}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_twitter} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_twitter = indiv_output = combined_output = False
    return in_twitter, indiv_output, combined_output, reason


def from_discord(timestamp):
    """Convert a Discord URL value to a date/time"""
    ts_type, reason = ts_types["discord"]
    try:
        if len(str(timestamp)) < 18 or not timestamp.isdigit():
            in_discord = indiv_output = combined_output = False
        else:
            unix_ts = (int(timestamp) >> 22) + 1420070400000
            in_discord = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_discord}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_discord} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_discord = indiv_output = combined_output = False
    return in_discord, indiv_output, combined_output, reason


def from_ksuid(timestamp):
    """Extract a timestamp from a KSUID value"""
    ts_type, reason = ts_types["ksuid"]
    try:
        ksuid_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        if len(str(timestamp)) != 27 or not all(
            char in ksuid_chars for char in timestamp
        ):
            in_ksuid = indiv_output = combined_output = False
        else:
            length, i, variation = len(timestamp), 0, 0
            b_array = bytearray()
            for val in timestamp:
                variation += ksuid_chars.index(val) * (62 ** (length - (i + 1)))
                i += 1
            while variation > 0:
                b_array.append(variation & 0xFF)
                variation //= 256
            b_array.reverse()
            ts_bytes = bytes(b_array)[0:4]
            unix_ts = int.from_bytes(ts_bytes, "big", signed=False) + 1400000000
            in_ksuid = dt.utcfromtimestamp(float(unix_ts)).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ksuid}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_ksuid} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_ksuid = indiv_output = combined_output = False
    return in_ksuid, indiv_output, combined_output, reason


def from_mastodon(timestamp):
    """Convert a Mastodon value to a date/time"""
    ts_type, reason = ts_types["mastodon"]
    try:
        if len(str(timestamp)) < 18 or not timestamp.isdigit():
            in_mastodon = indiv_output = combined_output = False
        else:
            ts_conversion = int(timestamp) >> 16
            unix_ts = float(ts_conversion) / 1000.0
            if int(unix_ts) > 32536850399:
                # This is the Windows maximum for parsing a unix TS
                # and is 3001-01-19 21:29:59 UTC
                in_mastodon = indiv_output = combined_output = False
            else:
                in_mastodon = dt.utcfromtimestamp(unix_ts).strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_mastodon}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_mastodon} UTC{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_mastodon = indiv_output = combined_output = False
    return in_mastodon, indiv_output, combined_output, reason


def to_mastodon(dt_val):
    """Convert a date/time to a Mastodon value"""
    ts_type, _ = ts_types["mastodon"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_seconds = int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000
        bit_shift = unix_seconds << 16
        out_mastodon = f"{str(bit_shift)}"
        ts_output = str(f"{ts_type}:\t\t\t{out_mastodon}")
    except Exception:
        handle(sys.exc_info())
        out_mastodon = ts_output = False
    return out_mastodon, ts_output


def from_metasploit(timestamp):
    """Convert a Metasploit Payload UUID value to a date/time"""
    ts_type, reason = ts_types["metasploit"]
    try:
        urlsafe_chars = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_"
        )
        meta_format = "8sBBBBBBBB"
        if len(str(timestamp)) < 22 or not all(
            char in urlsafe_chars for char in timestamp
        ):
            in_metasploit = indiv_output = combined_output = False
        else:
            b64decoded = base64.urlsafe_b64decode(timestamp[0:22] + "==")
            if len(b64decoded) < struct.calcsize(meta_format):
                raise Exception
            (
                _,
                xor1,
                xor2,
                _,
                _,
                ts1_xored,
                ts2_xored,
                ts3_xored,
                ts4_xored,
            ) = struct.unpack(meta_format, b64decoded)
            unix_ts = struct.unpack(
                ">I",
                bytes(
                    [
                        ts1_xored ^ xor1,
                        ts2_xored ^ xor2,
                        ts3_xored ^ xor1,
                        ts4_xored ^ xor2,
                    ]
                ),
            )[0]
            in_metasploit = dt.utcfromtimestamp(float(unix_ts)).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_metasploit}")
            combined_output = str(f"{__red__}{ts_type}:\t{in_metasploit} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_metasploit = indiv_output = combined_output = False
    return in_metasploit, indiv_output, combined_output, reason


def from_sony(timestamp):
    """Convert a Sonyflake value to a date/time"""
    ts_type, reason = ts_types["sony"]
    try:
        if len(str(timestamp)) != 15 or not all(
            char in hexdigits for char in timestamp
        ):
            in_sony = indiv_output = combined_output = False
        else:
            dec_value = int(timestamp, 16)
            ts_value = dec_value >> 24
            unix_ts = (ts_value + 140952960000) * 10
            in_sony = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_sony}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_sony} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_sony = indiv_output = combined_output = False
    return in_sony, indiv_output, combined_output, reason


def from_uuid(timestamp):
    """Convert a UUID value to date/time"""
    ts_type, reason = ts_types["uuid"]
    try:
        uuid_lower = timestamp.lower()
        uuid_regex = re.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        )
        if not bool(uuid_regex.match(uuid_lower)):
            in_uuid = indiv_output = combined_output = False
        else:
            u_data = uuid.UUID(uuid_lower)
            if u_data.version == 1:
                unix_ts = int((u_data.time / 10000) - 12219292800000)
                in_uuid = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime(__fmt__)
            else:
                pass
            indiv_output = str(f"{ts_type}: {in_uuid}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_uuid} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_uuid = indiv_output = combined_output = False
    return in_uuid, indiv_output, combined_output, reason


def from_dhcp6(timestamp):
    """Convert a DHCPv6 DUID value to date/time"""
    ts_type, reason = ts_types["dhcp6"]
    try:
        if len(str(timestamp)) < 28 or not all(char in hexdigits for char in timestamp):
            in_dhcp6 = indiv_output = combined_output = False
        else:
            dhcp6_bytes = timestamp[8:16]
            dhcp6_dec = int(dhcp6_bytes, 16)
            dhcp6_ts = epochs[2000] + timedelta(seconds=int(dhcp6_dec))
            in_dhcp6 = dhcp6_ts.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_dhcp6}")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_dhcp6} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_dhcp6 = indiv_output = combined_output = False
    return in_dhcp6, indiv_output, combined_output, reason


def to_dhcp6(dt_val):
    """Convert a timestamp to a DHCP DUID value"""
    ts_type, _ = ts_types["dhcp6"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[2000]).total_seconds() - int(dt_tz))
        if int(unix_time) < 0:
            out_dhcp6 = "[!] Timestamp Boundary Exceeded [!]"
            ts_output = str(f"{ts_type}:\t\t{out_dhcp6}")
        else:
            out_dhcp6 = str(struct.pack(">L", unix_time).hex())
            ts_output = str(f"{ts_type}:\t\t00010001{out_dhcp6}000000000000")
    except Exception:
        handle(sys.exc_info())
        out_dhcp6 = ts_output = False
    return out_dhcp6, ts_output


def from_dotnet(timestamp):
    """Convert a .NET DateTime value to date/time"""
    ts_type, reason = ts_types["dotnet"]
    try:
        if len(str(timestamp)) != 18 or not (timestamp).isdigit():
            in_dotnet = indiv_output = combined_output = False
        else:
            dotnet_offset = int((epochs[1970] - epochs[1]).total_seconds()) * 10000000
            dotnet_to_umil = (int(timestamp) - dotnet_offset) / 10000000
            in_dotnet = dt.utcfromtimestamp(dotnet_to_umil).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_dotnet} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t{in_dotnet} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_dotnet = indiv_output = combined_output = False
    return in_dotnet, indiv_output, combined_output, reason


def to_dotnet(dt_val):
    """Convert date to a .NET DateTime value"""
    ts_type, _ = ts_types["dotnet"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_dotnet = str(
            int(((dt_obj - epochs[1]).total_seconds() - int(dt_tz)) * 10000000)
        )
        ts_output = str(f"{ts_type}:\t{out_dotnet}")
    except Exception:
        handle(sys.exc_info())
        out_dotnet = ts_output = False
    return out_dotnet, ts_output


def from_gbound(timestamp):
    """Convert a GMail Boundary value to date/time"""
    ts_type, reason = ts_types["gbound"]
    try:
        if len(str(timestamp)) != 28 or not all(
            char in hexdigits for char in timestamp
        ):
            in_gbound = indiv_output = combined_output = False
        else:
            working_value = timestamp[12:26]
            end = working_value[:6]
            begin = working_value[6:14]
            full_dec = int("".join(begin + end), 16)
            in_gbound = dt.utcfromtimestamp(full_dec / 1000000).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_gbound} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_gbound} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_gbound = indiv_output = combined_output = False
    return in_gbound, indiv_output, combined_output, reason


def to_gbound(dt_val):
    """Convert date to a GMail Boundary value"""
    ts_type, _ = ts_types["gbound"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        to_int = int(((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000000)
        if len(f"{to_int:x}") < 14:
            to_int = f"0{to_int:x}"
        begin = to_int[8:]
        end = to_int[:8]
        out_gbound = f"000000000000{begin}{end}00"
        ts_output = str(f"{ts_type}:\t\t{out_gbound}")
    except Exception:
        handle(sys.exc_info())
        out_gbound = ts_output = False
    return out_gbound, ts_output


def from_gmsgid(timestamp):
    """Convert a GMail Message ID to a date/time value"""
    ts_type, reason = ts_types["gmsgid"]
    try:
        gmsgid = timestamp
        if str(gmsgid).isdigit() and len(str(gmsgid)) == 19:
            gmsgid = str(f"{int(gmsgid):x}")
        if len(str(gmsgid)) != 16 or not all(char in hexdigits for char in gmsgid):
            in_gmsgid = indiv_output = combined_output = False
        else:
            working_value = gmsgid[:11]
            to_int = int(working_value, 16)
            in_gmsgid = dt.utcfromtimestamp(to_int / 1000).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_gmsgid} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_gmsgid} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_gmsgid = indiv_output = combined_output = False
    return in_gmsgid, indiv_output, combined_output, reason


def to_gmsgid(dt_val):
    """Convert date to a GMail Message ID value"""
    ts_type, _ = ts_types["gmsgid"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        to_int = int(((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000)
        ts_hex = f"{to_int:x}"
        out_gmsgid = f"{ts_hex}00000"
        ts_output = str(f"{ts_type}:\t\t{out_gmsgid}")
    except Exception:
        handle(sys.exc_info())
        out_gmsgid = ts_output = False
    return out_gmsgid, ts_output


def from_moto(timestamp):
    """Convert a Motorola 6-byte hex timestamp to a date"""
    ts_type, reason = ts_types["moto"]
    try:
        if len(str(timestamp)) != 12 or not all(
            char in hexdigits for char in timestamp
        ):
            in_moto = indiv_output = combined_output = False
        else:
            hex_to_dec = [
                int(timestamp[i : i + 2], 16) for i in range(0, len(timestamp), 2)
            ]
            hex_to_dec[0] = hex_to_dec[0] + 1970
            if hex_to_dec[1] not in range(1, 13):
                in_moto = indiv_output = combined_output = False
            else:
                dt_obj = dt(
                    hex_to_dec[0],
                    hex_to_dec[1],
                    hex_to_dec[2],
                    hex_to_dec[3],
                    hex_to_dec[4],
                    hex_to_dec[5],
                )
                in_moto = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_moto}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_moto} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_moto = indiv_output = combined_output = False
    return in_moto, indiv_output, combined_output, reason


def to_moto(dt_val):
    """Convert a date to Motorola's 6-byte hex timestamp"""
    ts_type, _ = ts_types["moto"]
    try:
        dt_obj = duparser.parse(dt_val)
        moto_year = "{0:x}".format(dt_obj.year - 1970).zfill(2)
        moto_month = "{0:x}".format(dt_obj.month).zfill(2)
        moto_day = "{0:x}".format(dt_obj.day).zfill(2)
        moto_hour = "{0:x}".format(dt_obj.hour).zfill(2)
        moto_minute = "{0:x}".format(dt_obj.minute).zfill(2)
        moto_second = "{0:x}".format(dt_obj.second).zfill(2)
        out_moto = str(
            f"{moto_year}{moto_month}{moto_day}"
            f"{moto_hour}{moto_minute}{moto_second}"
        )
        ts_output = str(f"{ts_type}:\t\t\t{out_moto}")
    except Exception:
        handle(sys.exc_info())
        out_moto = ts_output = False
    return out_moto, ts_output


def from_nokia(timestamp):
    """Convert a Nokia 4-byte value to date/time"""
    ts_type, reason = ts_types["nokia"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_nokia = indiv_output = combined_output = False
        else:
            to_int = int(timestamp, 16)
            int_diff = to_int ^ 4294967295
            int_diff = ~int_diff + 1
            unix_ts = int_diff + (epochs[2050] - epochs[1970]).total_seconds()
            if unix_ts < 0:
                pass
            else:
                in_nokia = dt.utcfromtimestamp(unix_ts).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_nokia}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_nokia} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_nokia = indiv_output = combined_output = False
    return in_nokia, indiv_output, combined_output, reason


def to_nokia(dt_val):
    """Convert a date/time value to a Nokia 4-byte timestamp"""
    ts_type, _ = ts_types["nokia"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_ts = (dt_obj - epochs[1970]).total_seconds() - int(dt_tz)
        int_diff = int(unix_ts - (epochs[2050] - epochs[1970]).total_seconds())
        int_diff = int_diff - 1
        dec_value = ~int_diff ^ 4294967295
        out_nokia = f"{dec_value:x}"
        ts_output = str(f"{ts_type}:\t\t\t{out_nokia}")
    except Exception:
        handle(sys.exc_info())
        out_nokia = ts_output = False
    return out_nokia, ts_output


def from_nokiale(timestamp):
    """Convert a little-endian Nokia 4-byte value to date/time"""
    ts_type, reason = ts_types["nokiale"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_nokiale = indiv_output = combined_output = False
        else:
            to_be = "".join(
                [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)][::-1]
            )
            to_int = int(to_be, 16)
            int_diff = to_int ^ 4294967295
            int_diff = ~int_diff + 1
            unix_ts = int_diff + (epochs[2050] - epochs[1970]).total_seconds()
            if unix_ts < 0:
                pass
            else:
                in_nokiale = dt.utcfromtimestamp(unix_ts).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_nokiale}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_nokiale} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_nokiale = indiv_output = combined_output = False
    return in_nokiale, indiv_output, combined_output, reason


def to_nokiale(dt_val):
    """Convert a date/time value to a little-endian Nokia 4-byte timestamp"""
    ts_type, _ = ts_types["nokiale"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_ts = (dt_obj - epochs[1970]).total_seconds() - int(dt_tz)
        int_diff = int(unix_ts - (epochs[2050] - epochs[1970]).total_seconds())
        int_diff = int_diff - 1
        dec_val = ~int_diff ^ 4294967295
        hex_val = f"{dec_val:x}"
        out_nokiale = "".join(
            [hex_val[i : i + 2] for i in range(0, len(hex_val), 2)][::-1]
        )
        ts_output = str(f"{ts_type}:\t\t\t{out_nokiale}")
    except Exception:
        handle(sys.exc_info())
        out_nokiale = ts_output = False
    return out_nokiale, ts_output


def from_ns40(timestamp):
    """Convert a Nokia S40 7-byte value to a time/time"""
    ts_type, reason = ts_types["ns40"]
    try:
        if not len(timestamp) == 14 or not all(char in hexdigits for char in timestamp):
            in_ns40 = indiv_output = combined_output = False
        else:
            ns40 = timestamp
            ns40_val = {}
            ns40_val["yr"] = ns40[:4]
            ns40_val["mon"] = ns40[4:6]
            ns40_val["day"] = ns40[6:8]
            ns40_val["hr"] = ns40[8:10]
            ns40_val["min"] = ns40[10:12]
            ns40_val["sec"] = ns40[12:]
            for each_key, _ in ns40_val.items():
                ns40_val[str(each_key)] = int(ns40_val[str(each_key)], 16)
            if ns40_val["yr"] > 9999:
                in_ns40 = indiv_output = combined_output = False
            if (int(ns40_val["mon"]) > 12) or (int(ns40_val["mon"] < 1)):
                in_ns40 = indiv_output = combined_output = False
            else:
                in_ns40 = dt(
                    ns40_val["yr"],
                    ns40_val["mon"],
                    ns40_val["day"],
                    ns40_val["hr"],
                    ns40_val["min"],
                    ns40_val["sec"],
                ).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ns40}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_ns40} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_ns40 = indiv_output = combined_output = False
    return in_ns40, indiv_output, combined_output, reason


def to_ns40(dt_val):
    """Convert a date/time value to a Nokia S40 7-byte timestamp"""
    ts_type, _ = ts_types["ns40"]
    try:
        dt_obj = duparser.parse(dt_val)
        dt_tz = 0
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        dt_obj = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        dt_obj = dt.utcfromtimestamp(int(dt_obj))
        hex_vals = []
        hex_vals.append(f"{dt_obj.year:x}".zfill(4))
        hex_vals.append(f"{dt_obj.month:x}".zfill(2))
        hex_vals.append(f"{dt_obj.day:x}".zfill(2))
        hex_vals.append(f"{dt_obj.hour:x}".zfill(2))
        hex_vals.append(f"{dt_obj.minute:x}".zfill(2))
        hex_vals.append(f"{dt_obj.second:x}".zfill(2))
        out_ns40 = "".join(hex_vals)
        ts_output = str(f"{ts_type}:\t\t\t{out_ns40}")
    except Exception:
        handle(sys.exc_info())
        out_ns40 = ts_output = False
    return out_ns40, ts_output


def from_ns40le(timestamp):
    """Convert a little-endian Nokia S40 7-byte value to a date/time"""
    ts_type, reason = ts_types["ns40le"]
    try:
        if len(str(timestamp)) != 14 or not all(
            char in hexdigits for char in timestamp
        ):
            in_ns40le = indiv_output = combined_output = False
        else:
            ns40le = timestamp
            ns40_val = {}
            ns40_val["yr"] = "".join(
                [ns40le[i : i + 2] for i in range(0, len(ns40le[:4]), 2)][::-1]
            )
            ns40_val["mon"] = ns40le[4:6]
            ns40_val["day"] = ns40le[6:8]
            ns40_val["hr"] = ns40le[8:10]
            ns40_val["min"] = ns40le[10:12]
            ns40_val["sec"] = ns40le[12:]
            for each_key, _ in ns40_val.items():
                ns40_val[str(each_key)] = int(ns40_val[str(each_key)], 16)
            if ns40_val["yr"] > 9999:
                in_ns40le = indiv_output = combined_output = False
            else:
                in_ns40le = dt(
                    ns40_val["yr"],
                    ns40_val["mon"],
                    ns40_val["day"],
                    ns40_val["hr"],
                    ns40_val["min"],
                    ns40_val["sec"],
                ).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ns40le}")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_ns40le} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_ns40le = indiv_output = combined_output = False
    return in_ns40le, indiv_output, combined_output, reason


def to_ns40le(dt_val):
    """Convert a date/time value to a little-endian Nokia S40 7-byte timestamp"""
    ts_type, _ = ts_types["ns40le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        dt_obj = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        dt_obj = dt.utcfromtimestamp(int(dt_obj))
        hex_vals = []
        year_le = f"{dt_obj.year:x}".zfill(4)
        year_le = "".join(
            [year_le[i : i + 2] for i in range(0, len(year_le[:4]), 2)][::-1]
        )
        hex_vals.append(f"{year_le}".zfill(4))
        hex_vals.append(f"{dt_obj.month:x}".zfill(2))
        hex_vals.append(f"{dt_obj.day:x}".zfill(2))
        hex_vals.append(f"{dt_obj.hour:x}".zfill(2))
        hex_vals.append(f"{dt_obj.minute:x}".zfill(2))
        hex_vals.append(f"{dt_obj.second:x}".zfill(2))
        out_ns40le = "".join(hex_vals)
        ts_output = str(f"{ts_type}:\t\t{out_ns40le}")
    except Exception:
        handle(sys.exc_info())
        out_ns40le = ts_output = False
    return out_ns40le, ts_output


def from_bitdec(timestamp):
    """Convert a 10-digit Bitwise Decimal value to a date/time"""
    ts_type, reason = ts_types["bitdec"]
    try:
        if len(str(timestamp)) != 10 or not (timestamp).isdigit():
            in_bitdec = indiv_output = combined_output = False
        else:
            full_ts = int(timestamp)
            bd_yr = full_ts >> 20
            bd_mon = (full_ts >> 16) & 15
            bd_day = (full_ts >> 11) & 31
            bd_hr = (full_ts >> 6) & 31
            bd_min = full_ts & 63
            try:
                in_bitdec = dt(bd_yr, bd_mon, bd_day, bd_hr, bd_min).strftime(__fmt__)
            except ValueError:
                in_bitdec = indiv_output = combined_output = False
            indiv_output = str(f"{ts_type}: {in_bitdec}")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_bitdec}  ?{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_bitdec = indiv_output = combined_output = False
    return in_bitdec, indiv_output, combined_output, reason


def to_bitdec(dt_val):
    """Convert a date/time value to a Bitwise Decimal timestamp"""
    ts_type, _ = ts_types["bitdec"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        dt_obj = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        dt_obj = dt.utcfromtimestamp(int(dt_obj))
        out_bitdec = str(
            (dt_obj.year << 20)
            + (dt_obj.month << 16)
            + (dt_obj.day << 11)
            + (dt_obj.hour << 6)
            + (dt_obj.minute)
        )
        ts_output = str(f"{ts_type}:\t\t{out_bitdec}")
    except Exception:
        handle(sys.exc_info())
        out_bitdec = ts_output = False
    return out_bitdec, ts_output


def from_bitdate(timestamp):
    """Convert a Samsung/LG 4-byte hex timestamp to a date/time"""
    ts_type, reason = ts_types["bitdate"]
    try:
        if len(str(timestamp)) != 8 or not all(char in hexdigits for char in timestamp):
            in_bitdate = indiv_output = combined_output = False
        else:
            to_le = "".join(
                [timestamp[i : i + 2] for i in range(0, len(str(timestamp)), 2)][::-1]
            )
            to_binary = f"{int(to_le, 16):032b}"
            bitdate_yr = int(to_binary[:12], 2)
            bitdate_mon = int(to_binary[12:16], 2)
            bitdate_day = int(to_binary[16:21], 2)
            bitdate_hr = int(to_binary[21:26], 2)
            bitdate_min = int(to_binary[26:32], 2)
            try:
                in_bitdate = dt(
                    bitdate_yr, bitdate_mon, bitdate_day, bitdate_hr, bitdate_min
                ).strftime(__fmt__)
            except ValueError:
                pass
            indiv_output = str(f"{ts_type}: {in_bitdate}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_bitdate} Local{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_bitdate = indiv_output = combined_output = False
    return in_bitdate, indiv_output, combined_output, reason


def to_bitdate(dt_val):
    """Convert a date/time value to a Samsung/LG timestamp"""
    ts_type, _ = ts_types["bitdate"]
    try:
        dt_obj = duparser.parse(dt_val)
        bitdate_yr = f"{dt_obj.year:012b}"
        bitdate_mon = f"{dt_obj.month:04b}"
        bitdate_day = f"{dt_obj.day:05b}"
        bitdate_hr = f"{dt_obj.hour:05b}"
        bitdate_min = f"{dt_obj.minute:06b}"
        to_hex = str(
            struct.pack(
                ">I",
                int(
                    bitdate_yr + bitdate_mon + bitdate_day + bitdate_hr + bitdate_min, 2
                ),
            ).hex()
        )
        out_bitdate = "".join(
            [to_hex[i : i + 2] for i in range(0, len(to_hex), 2)][::-1]
        )
        ts_output = str(f"{ts_type}:\t\t\t{out_bitdate}")
    except Exception:
        handle(sys.exc_info())
        out_bitdate = ts_output = False
    return out_bitdate, ts_output


def from_kstime(timestamp):
    """Convert a KSUID decimal value to a date"""
    ts_type, reason = ts_types["kstime"]
    try:
        if len(timestamp) != 9 or not timestamp.isdigit():
            in_kstime = indiv_output = combined_output = False
        else:
            ts_val = int(timestamp) + int(epochs["kstime"])
            in_kstime = dt.utcfromtimestamp(float(ts_val)).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_kstime} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_kstime} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_kstime = indiv_output = combined_output = False
    return in_kstime, indiv_output, combined_output, reason


def to_kstime(dt_val):
    """Convert date to a KSUID decimal value"""
    ts_type, _ = ts_types["kstime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_ts = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        out_kstime = str(int(unix_ts) - int(epochs["kstime"]))
        if int(out_kstime) < 0:
            out_kstime = "[!] Timestamp Boundary Exceeded [!]"
        ts_output = str(f"{ts_type}:\t\t\t{out_kstime}")
    except Exception:
        handle(sys.exc_info())
        out_kstime = ts_output = False
    return out_kstime, ts_output


def from_biomehex(timestamp):
    """Convert an Apple Biome Hex value to a date - from Little Endian"""
    ts_type, reason = ts_types["biomehex"]
    try:
        biomehex = str(timestamp)
        if len(biomehex) != 16 or not all(char in hexdigits for char in biomehex):
            in_biomehex = indiv_output = combined_output = False
        else:
            if biomehex[:2] == "41":
                biomehex = "".join(
                    [biomehex[i : i + 2] for i in range(0, len(biomehex), 2)][::-1]
                )
            byte_val = bytes.fromhex(str(biomehex))
            nsdate_val = struct.unpack("<d", byte_val)[0]
            if nsdate_val >= 1e17:
                in_biomehex = indiv_output = combined_output = False
            else:
                dt_obj = epochs[2001] + timedelta(seconds=float(nsdate_val))
                in_biomehex = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_biomehex} UTC")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_biomehex} UTC{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_biomehex = indiv_output = combined_output = False
    return in_biomehex, indiv_output, combined_output, reason


def to_biomehex(dt_val):
    """Convert a date/time to an Apple Biome Hex value"""
    ts_type, _ = ts_types["biomehex"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        bplist_stamp = str(float((dt_obj - epochs[2001]).total_seconds()) - int(dt_tz))
        byte_biome = struct.pack(">d", float(bplist_stamp))
        out_biomehex = bytes.hex(byte_biome)
        ts_output = str(f"{ts_type}:\t\t{out_biomehex}")
    except Exception:
        handle(sys.exc_info())
        out_biomehex = ts_output = False
    return out_biomehex, ts_output


def from_biome64(timestamp):
    """Convert a 64-bit decimal value to a date/time value"""
    ts_type, reason = ts_types["biome64"]
    try:
        if len(timestamp) != 19 or not timestamp.isdigit():
            in_biome64 = indiv_output = combined_output = False
        else:
            nsdate_unpacked = int(
                struct.unpack("<d", int(timestamp).to_bytes(8, "little"))[0]
            )
            if nsdate_unpacked >= 1e17:
                in_biome64 = indiv_output = combined_output = False
            else:
                dt_obj = epochs[2001] + timedelta(seconds=float(nsdate_unpacked))
                in_biome64 = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_biome64} UTC")
                combined_output = str(f"{__red__}{ts_type}:\t{in_biome64} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_biome64 = indiv_output = combined_output = False
    return in_biome64, indiv_output, combined_output, reason


def to_biome64(dt_val):
    """Convert a date/time value to a"""
    ts_type, _ = ts_types["biome64"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        nsdate_stamp = float((dt_obj - epochs[2001]).total_seconds()) - int(dt_tz)
        out_biome64 = str(int.from_bytes(struct.pack(">d", nsdate_stamp), "big"))
        ts_output = str(f"{ts_type}:\t{out_biome64}")
    except Exception:
        handle(sys.exc_info())
        out_biome64 = ts_output = False
    return out_biome64, ts_output


def from_s32(timestamp):
    """Convert an S32 timestamp to a date/time value"""
    """Since BlueSky is not yet in use, this function is essentially a beta"""
    ts_type, reason = ts_types["s32"]
    try:
        result = 0
        timestamp = str(timestamp)
        if len(timestamp) != 9 or not all(char in S32_CHARS for char in timestamp):
            in_s32 = indiv_output = combined_output = False
        else:
            for char in timestamp:
                result = result * 32 + S32_CHARS.index(char)
            dt_obj = dt.utcfromtimestamp(result / 1000.0)
            in_s32 = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_s32} UTC")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_s32} UTC{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_s32 = indiv_output = combined_output = False
    return in_s32, indiv_output, combined_output, reason


def to_s32(dt_val):
    """Convert a date/time to an S32-encoded timestamp"""
    """Since BlueSky is not yet in use, this function is essentially a beta"""
    ts_type, _ = ts_types["s32"]
    try:
        result = ""
        index = 0
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_mil = int(((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz)) * 1000
        while unix_mil:
            index = unix_mil % 32
            unix_mil = math.floor(unix_mil / 32)
            result = S32_CHARS[index] + result
        out_s32 = result
        ts_output = str(f"{ts_type}:\t\t{out_s32}")
    except Exception:
        handle(sys.exc_info())
        out_s32 = ts_output = False
    return out_s32, ts_output


def date_range(start, end, check_date):
    """Check if date is in range of start and end, return True if it is"""
    if start <= end:
        return start <= check_date <= end
    return start <= check_date or check_date <= end


def from_all(timestamps):
    """Output all processed timestamp values and find date from provided timestamp"""
    this_yr = int(dt.now().strftime("%Y"))
    full_list = {}
    for func in from_funcs:
        func_name = func.__name__.replace("from_", "")
        (result, _, combined_output, _) = func(timestamps)
        if result and combined_output:
            if isinstance(result, str):
                if int(duparser.parse(result).strftime("%Y")) not in range(
                    this_yr - 5, this_yr + 5
                ):
                    combined_output = combined_output.strip(__red__).strip(__clr__)
            full_list[func_name] = [result, combined_output]
    return full_list


def to_timestamps(dt_val):
    """Convert provided date to all timestamps"""
    results = {}
    ts_outputs = []
    for func in to_funcs:
        result, ts_output = func(dt_val)
        func_name = (func.__name__).replace("to_", "")
        if isinstance(result, str):
            results[func_name] = result
            ts_outputs.append(ts_output)
    return results, ts_outputs


single_funcs = {
    "unix": from_unix_sec,
    "umil": from_unix_milli,
    "wh": from_windows_hex_64,
    "whle": from_windows_hex_64le,
    "chrome": from_chrome,
    "active": from_ad,
    "uhbe": from_unix_hex_32be,
    "uhle": from_unix_hex_32le,
    "cookie": from_cookie,
    "oleb": from_ole_be,
    "olel": from_ole_le,
    "nsdate": from_nsdate,
    "hfsdec": from_hfs_dec,
    "hfsbe": from_hfs_be,
    "hfsle": from_hfs_le,
    "fat": from_fat,
    "msdos": from_msdos,
    "systime": from_systemtime,
    "ft": from_filetime,
    "hotmail": from_hotmail,
    "pr": from_prtime,
    "auto": from_ole_auto,
    "ms1904": from_ms1904,
    "sym": from_symtime,
    "gps": from_gpstime,
    "eitime": from_eitime,
    "gsm": from_gsm,
    "vm": from_vm,
    "tiktok": from_tiktok,
    "twitter": from_twitter,
    "discord": from_discord,
    "ksuid": from_ksuid,
    "mastodon": from_mastodon,
    "meta": from_metasploit,
    "sony": from_sony,
    "uu": from_uuid,
    "dhcp6": from_dhcp6,
    "dotnet": from_dotnet,
    "gbound": from_gbound,
    "gmsgid": from_gmsgid,
    "moto": from_moto,
    "nokia": from_nokia,
    "nokiale": from_nokiale,
    "ns40": from_ns40,
    "ns40le": from_ns40le,
    "bitdec": from_bitdec,
    "bitdate": from_bitdate,
    "kstime": from_kstime,
    "exfat": from_exfat,
    "biome64": from_biome64,
    "biomehex": from_biomehex,
    "s32": from_s32,
}
from_funcs = [
    from_ad,
    from_biome64,
    from_biomehex,
    from_bitdate,
    from_bitdec,
    from_dhcp6,
    from_discord,
    from_exfat,
    from_fat,
    from_gbound,
    from_gmsgid,
    from_chrome,
    from_eitime,
    from_gpstime,
    from_gsm,
    from_hfs_be,
    from_hfs_le,
    from_nsdate,
    from_ksuid,
    from_kstime,
    from_hfs_dec,
    from_mastodon,
    from_metasploit,
    from_systemtime,
    from_filetime,
    from_hotmail,
    from_dotnet,
    from_moto,
    from_prtime,
    from_msdos,
    from_ms1904,
    from_ns40,
    from_ns40le,
    from_nokia,
    from_nokiale,
    from_ole_auto,
    from_s32,
    from_sony,
    from_symtime,
    from_tiktok,
    from_twitter,
    from_unix_hex_32be,
    from_unix_hex_32le,
    from_unix_sec,
    from_unix_milli,
    from_uuid,
    from_vm,
    from_windows_hex_64,
    from_windows_hex_64le,
    from_cookie,
    from_ole_be,
    from_ole_le,
]
to_funcs = [
    to_ad,
    to_biome64,
    to_biomehex,
    to_bitdate,
    to_bitdec,
    to_dhcp6,
    to_exfat,
    to_fat,
    to_gbound,
    to_gmsgid,
    to_chrome,
    to_eitime,
    to_gpstime,
    to_gsm,
    to_hfs_be,
    to_hfs_le,
    to_kstime,
    to_hfs_dec,
    to_mastodon,
    to_systemtime,
    to_filetime,
    to_hotmail,
    to_dotnet,
    to_moto,
    to_prtime,
    to_msdos,
    to_ms1904,
    to_ns40,
    to_ns40le,
    to_nokia,
    to_nokiale,
    to_bplist,
    to_iostime,
    to_mac,
    to_ole_auto,
    to_s32,
    to_symtime,
    to_unix_hex_32be,
    to_unix_hex_32le,
    to_unix_sec,
    to_unix_milli,
    to_vm,
    to_windows_hex_64,
    to_windows_hex_64le,
    to_cookie,
    to_ole_be,
    to_ole_le,
]


def main():
    """Parse all passed arguments"""
    now = dt.now().strftime(__fmt__)
    arg_parse = argparse.ArgumentParser(
        description=f"Time Decoder and Converter v"
        f"{str(__version__)} - supporting "
        f"{str(__types__)} timestamps!",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    arg_parse.add_argument(
        "--guess", metavar="", help="guess format and output possibilities"
    )
    arg_parse.add_argument(
        "--timestamp",
        metavar="DATE",
        help="convert date to every timestamp\n"
        'enter date as "YYYY-MM-DD HH:MM:SS.f" in 24h fmt.\n'
        "Without argument gives current date/time\n",
        nargs="?",
        const=now,
    )
    arg_parse.add_argument(
        "--active", metavar="", help="convert from Active Directory value"
    )
    arg_parse.add_argument(
        "--auto", metavar="", help="convert from OLE Automation Date format"
    )
    arg_parse.add_argument(
        "--biome64", metavar="", help="convert from an Apple Biome 64-bit decimal"
    )
    arg_parse.add_argument(
        "--biomehex", metavar="", help="convert from an Apple Biome hex value"
    )
    arg_parse.add_argument(
        "--bitdate", metavar="", help="convert from a Samsung/LG 4-byte value"
    )
    arg_parse.add_argument(
        "--bitdec", metavar="", help="convert from a bitwise decimal 10-digit value"
    )
    arg_parse.add_argument(
        "--bplist", metavar="", help="convert from an iOS Binary Plist value"
    )
    arg_parse.add_argument(
        "--chrome", metavar="", help="convert from Google Chrome value"
    )
    arg_parse.add_argument(
        "--cookie", metavar="", help="convert from Windows Cookie Date (Low,High)"
    )
    arg_parse.add_argument(
        "--dhcp6", metavar="", help="convert from a DHCP6 DUID value"
    )
    arg_parse.add_argument(
        "--discord", metavar="", help="convert from a Discord URL value"
    )
    arg_parse.add_argument(
        "--dotnet", metavar="", help="convert from a .NET DateTime value"
    )
    arg_parse.add_argument(
        "--eitime", metavar="", help="convert from a Google EI URL value"
    )
    arg_parse.add_argument(
        "--exfat", metavar="", help="convert from an exFAT 4-byte value"
    )
    arg_parse.add_argument(
        "--fat", metavar="", help="convert from FAT Date + Time (wFat)"
    )
    arg_parse.add_argument("--ft", metavar="", help="convert from FILETIME value")
    arg_parse.add_argument(
        "--gbound", metavar="", help="convert from a GMail Boundary value"
    )
    arg_parse.add_argument(
        "--gmsgid", metavar="", help="convert from a GMail Message ID value"
    )
    arg_parse.add_argument("--gps", metavar="", help="convert from a GPS value")
    arg_parse.add_argument("--gsm", metavar="", help="convert from a GSM value")
    arg_parse.add_argument(
        "--hfsbe", metavar="", help="convert from HFS(+) BE, HFS Local, HFS+ UTC"
    )
    arg_parse.add_argument(
        "--hfsle", metavar="", help="convert from HFS(+) LE, HFS Local, HFS+ UTC"
    )
    arg_parse.add_argument(
        "--hfsdec", metavar="", help="convert from Mac OS/HFS+ Decimal Time"
    )
    arg_parse.add_argument("--hotmail", metavar="", help="convert from a Hotmail value")
    arg_parse.add_argument("--ios", metavar="", help="convert from iOS 11 value")
    arg_parse.add_argument(
        "--kstime", metavar="", help="convert from a KSUID 9-digit value"
    )
    arg_parse.add_argument(
        "--ksuid", metavar="", help="convert from a KSUID 27-character value"
    )
    arg_parse.add_argument("--mac", metavar="", help="convert from Mac Absolute Time")
    arg_parse.add_argument(
        "--mastodon", metavar="", help="convert from a Mastodon URL value"
    )
    arg_parse.add_argument(
        "--meta", metavar="", help="convert from a Metasploit Payload UUID"
    )
    arg_parse.add_argument(
        "--moto", metavar="", help="convert from Motorola's 6-byte value"
    )
    arg_parse.add_argument(
        "--ms1904", metavar="", help="convert from MS Excel 1904 Date format"
    )
    arg_parse.add_argument(
        "--msdos", metavar="", help="convert from 32-bit MS-DOS time, result is Local"
    )
    arg_parse.add_argument(
        "--nokia", metavar="", help="convert from a Nokia 4-byte value"
    )
    arg_parse.add_argument(
        "--nokiale", metavar="", help="convert from a Nokia 4-byte LE value"
    )
    arg_parse.add_argument(
        "--ns40", metavar="", help="convert from a Nokia S40 7-byte value"
    )
    arg_parse.add_argument(
        "--ns40le", metavar="", help="convert from a Nokia S40 7-byte LE value"
    )
    arg_parse.add_argument(
        "--nsdate",
        metavar="",
        help="convert from an Apple NSDate (iOS, BPList, Cocoa, Mac Absolute)",
    )
    arg_parse.add_argument(
        "--oleb",
        metavar="",
        help="convert from Windows OLE 64-bit BE, remove 0x & space\n"
        "- example from SRUM: 0x40e33f5d 0x97dfe8fb should be 40e33f5d97dfe8fb",
    )
    arg_parse.add_argument(
        "--olel", metavar="", help="convert from Windows OLE 64-bit LE"
    )
    arg_parse.add_argument("--pr", metavar="", help="convert from Mozilla's PRTime")
    arg_parse.add_argument(
        "--s32", metavar="", help="convert from an S32-encoded timestamp"
    )
    arg_parse.add_argument(
        "--sony", metavar="", help="convert from a Sonyflake URL value"
    )
    arg_parse.add_argument(
        "--sym", metavar="", help="convert from Symantec's 6-byte AV value"
    )
    arg_parse.add_argument(
        "--systime", metavar="", help="convert from 128-bit SYSTEMTIME value"
    )
    arg_parse.add_argument(
        "--tiktok", metavar="", help="convert from a TikTok URL value"
    )
    arg_parse.add_argument(
        "--twitter", metavar="", help="convert from a Twitter URL value"
    )
    arg_parse.add_argument("--uhbe", metavar="", help="convert from Unix Hex 32-bit BE")
    arg_parse.add_argument("--uhle", metavar="", help="convert from Unix Hex 32-bit LE")
    arg_parse.add_argument("--unix", metavar="", help="convert from Unix Seconds")
    arg_parse.add_argument("--umil", metavar="", help="convert from Unix Milliseconds")
    arg_parse.add_argument(
        "--uu",
        metavar="",
        help="convert from a UUID: 00000000-0000-0000-0000-000000000000",
    )
    arg_parse.add_argument(
        "--vm",
        metavar="",
        help="convert from a VMWare Snapshot (.vmsd) value\n"
        '- enter as "high value,low value"',
    )
    arg_parse.add_argument(
        "--wh", metavar="", help="convert from Windows 64-bit Hex BE"
    )
    arg_parse.add_argument(
        "--whle", metavar="", help="convert from Windows 64-bit Hex LE"
    )
    arg_parse.add_argument(
        "--version", "-v", action="version", version=arg_parse.description
    )

    if len(sys.argv[1:]) == 0:
        arg_parse.print_help()
        arg_parse.exit()

    args = arg_parse.parse_args()
    analyze(args)


if __name__ == "__main__":
    main()