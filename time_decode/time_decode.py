#!/usr/bin/env python3
"""
This application is designed to decode timestamps into human-readable date/times and vice-versa
Additional information regarding the source of the timestamp formats and associated equations
is provided in the REFERENCES.md file at https://github.com/digitalsleuth/time_decode.
"""

from datetime import datetime as dt, timedelta, timezone
import functools
import math
from fractions import Fraction
import struct
from string import hexdigits, ascii_lowercase
import argparse
import re
import sys
import os
import base64
import uuid
import traceback
import warnings
import csv
from typing import NamedTuple
from zoneinfo import ZoneInfo as tzone, ZoneInfoNotFoundError
from colorama import init
import blackboxprotobuf
from blackboxprotobuf.lib.exceptions import DecoderException
from ulid import ULID
from prettytable import PrettyTable, TableStyle

warnings.filterwarnings("ignore", category=DeprecationWarning)
init(autoreset=True)
__author__ = "Corey Forman (digitalsleuth)"
__date__ = "2026-10-09"
__version__ = "11.0.0"
__description__ = "Python 3 Date Time Conversion Tool"
__fmt__ = "%Y-%m-%d %H:%M:%S.%f"
__red__ = "\033[1;31m"
__clr__ = "\033[1;m"
__source__ = "https://github.com/digitalsleuth/time_decode"
__appname__ = f"Time Decode v{__version__}"


class TsTypes(NamedTuple):
    """Defines the structure of a Timestamp Type"""

    ts_type: str
    reason: str
    example: str
    time_zone: str


ts_types = {
    "active": TsTypes(
        "Active Directory/LDAP",
        "Active Directory/LDAP timestamps are up to 19 digits",
        "133908455300649390",
        "UTC",
    ),
    "apache": TsTypes(
        "Apache Cookie Hex time",
        "Apache Cookie hex timestamps are up to 15 hex characters long",
        "63450e689882b",
        "UTC",
    ),
    "apfs": TsTypes(
        "APFS time",
        "APFS timestamps are 16 hex characters (8 bytes), little-endian",
        "f8e73b89045c3c18",
        "UTC",
    ),
    "biome64": TsTypes(
        "Apple Biome 64-bit decimal",
        "Apple Biome 64-bit decimal is up to 20 digits in length",
        "4739726202305531884",
        "UTC",
    ),
    "biomehex": TsTypes(
        "Apple Biome Hex time",
        "Apple Biome Hex value is 8 bytes (16 chars) long",
        "41c6e3de6d084fec",
        "UTC",
    ),
    "nsdate": TsTypes(
        "Apple NSDate - All",
        "Apple NSDates are up to 12, up to 12.6, or 15-18 digits in length",
        "704656778.285777",
        "UTC",
    ),
    "bplist": TsTypes(
        "Apple NSDate - bplist / Cocoa",
        "Apple NSDates (bplist) are up to 12 digits in length",
        "768064730",
        "UTC",
    ),
    "iostime": TsTypes(
        "Apple NSDate - iOS 11+",
        "Apple NSDates (iOS) are 15-18 digits in length",
        "768064730064939008",
        "UTC",
    ),
    "mac": TsTypes(
        "Apple NSDate - Mac Absolute",
        "Apple NSDates (Mac) are up to 12 digits '.' up to 6 digits",
        "768064730.064939",
        "UTC",
    ),
    "xray": TsTypes(
        "AWS X-Ray trace ID time",
        "AWS X-Ray trace IDs are in the format 1-00000000-000000000000000000000000",
        "1-6817855a-a006649127e371903a2de979",
        "UTC",
    ),
    "bcd": TsTypes(
        "Binary Coded Decimal",
        "Binary Coded Decimal timestamps are 12 digits in length",
        "250506232221",
        "Local",
    ),
    "bitdate": TsTypes(
        "BitDate time",
        "BitDate (Samsung/LG) timestamps are 8 hex characters",
        "d223957e",
        "Local",
    ),
    "bitdec": TsTypes(
        "Bitwise Decimal time",
        "Bitwise Decimal timestamps are up to 10 digits",
        "2123703250",
        "Local",
    ),
    "tid": TsTypes(
        "Bluesky TID time",
        "Bluesky TIDs are 13 characters, from 234567a-z",
        "3loe5ncn43f5v",
        "UTC",
    ),
    "btrfs": TsTypes(
        "Btrfs inode time",
        "Btrfs inode times are 24 hex characters little-endian",
        "5a85176800000000f8e3de03",
        "UTC",
    ),
    "cdma": TsTypes(
        "CDMA SMS time",
        "CDMA SMS times are 12 digits (6 BCD bytes)",
        "990712151030",
        "Local",
    ),
    "cuid": TsTypes(
        "cuid time",
        "cuid values are 25 characters, starting with c",
        "cma9sr9ao0000k2w9b3qzd5r6",
        "UTC",
    ),
    "dhcp6": TsTypes(
        "DHCPv6 DUID time",
        "DHCPv6 DUID values are at least 14 bytes long",
        "000100012faa41da000000000000",
        "UTC",
    ),
    "discord": TsTypes(
        "Discord time",
        "Discord timestamps are up to 20 digits",
        "1102608904745127937",
        "UTC",
    ),
    "dvr": TsTypes(
        "DVR (WFS / DHFS) File System",
        "DVR timestamps are 4 bytes",
        "654D7595",
        "Local",
    ),
    "exfat": TsTypes(
        "exFAT time",
        "exFAT 32-bit timestamps are 8 hex characters (4 bytes)",
        "5aa47a59",
        "Local",
    ),
    "exfatext": TsTypes(
        "exFAT time with extras",
        "exFAT times with extras are 12 hex characters",
        "5aa47a590700",
        "Local / UTC",
    ),
    "ext4": TsTypes(
        "ext4 inode time",
        "ext4 inode times are 8 hex characters",
        "6817855a:0f7b8fe0",
        "UTC",
    ),
    "fbcookie": TsTypes(
        "Facebook cookie time",
        "Facebook _fbp/_fbc values are in the format fb.1.0000000000000.0000000000",
        "fb.1.1746371930064.1116446470",
        "UTC",
    ),
    "fat": TsTypes(
        "FAT Date + Time",
        "FAT (MS-DOS wFatDate wFatTime) timestamps are 8 hex characters (4 bytes)",
        "a45a597a",
        "Local",
    ),
    "firebase": TsTypes(
        "Firebase Push ID time",
        "Firebase Push IDs are 20 characters, from A-Za-z0-9-_",
        "-OPQsDUF7Gkq3VtZb0Xa",
        "UTC",
    ),
    "garmin": TsTypes(
        "Garmin FIT time",
        "Garmin FIT timestamps are 1 to 10 digits, seconds since 1989-12-31",
        "1115306330",
        "UTC",
    ),
    "gbound": TsTypes(
        "GMail Boundary time",
        "GMail Boundary values are 28 hex chars",
        "00000000000089882b063450e600",
        "UTC",
    ),
    "gmsgid": TsTypes(
        "GMail Message ID time",
        "GMail Message ID values are 6-17 hex chars or 19 digits (IMAP)",
        "1969be0e7d000000",
        "UTC",
    ),
    "gacookie": TsTypes(
        "Google Analytics cookie time",
        "Google Analytics _ga/_gid values are in the format GA1.2.0000000000.0000000000",
        "GA1.2.1033914209.1746371930",
        "UTC",
    ),
    "chrome": TsTypes(
        "Google Chrome",
        "Google Chrome/Webkit timestamp is up to 18 digits",
        "13390845530064940",
        "UTC",
    ),
    "eitime": TsTypes(
        "Google EI time",
        "Google ei timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_",
        "WoUXaA",
        "UTC",
    ),
    "gclid": TsTypes(
        "Google GCLID time",
        "Google GCLID timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_",
        "CKSDxc_qhLkCFQyk4AodO24Arg",
        "UTC",
    ),
    "ved": TsTypes(
        "Google VED time",
        "Google VED timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_",
        "0ahUKEwilufv7joqNAxW3nYkEHd0vMyIQ4dUDCA8",
        "UTC",
    ),
    "gps": TsTypes(
        "GPS time", "GPS timestamps are up to 12 digits", "1430407111", "UTC"
    ),
    "gsm": TsTypes(
        "GSM time",
        "GSM timestamps are 14 hex characters (7 bytes)",
        "52504051810500",
        "UTC",
    ),
    "hfsbe": TsTypes(
        "HFS / HFS+ 32-bit Hex BE",
        "HFS / HFS+ Big-Endian timestamps are 8 hex characters (4 bytes)",
        "e43d35da",
        "Local / UTC",
    ),
    "hfsle": TsTypes(
        "HFS / HFS+ 32-bit Hex LE",
        "HFS / HFS+ Little-Endian timestamps are 8 hex characters (4 bytes)",
        "da353de4",
        "Local / UTC",
    ),
    "hfsdec": TsTypes(
        "HFS+ Decimal Time",
        "HFS+ Decimal timestamps are up to 12 digits",
        "3829216730",
        "UTC",
    ),
    "horolog": TsTypes(
        "Horolog Time",
        "Horolog timestamps are two whole numbers separated by a comma (days, seconds)",
        "67637,80193",
        "Local",
    ),
    "instagram": TsTypes(
        "Instagram time",
        "Instagram IDs are up to 20 digits",
        "3625152955542620216",
        "UTC",
    ),
    "iso9660": TsTypes(
        "ISO 9660 recording date",
        "ISO 9660 recording dates are 14 hex characters (7 bytes)",
        "7d05040f123200",
        "UTC",
    ),
    "logtime": TsTypes(
        "JET LogTime",
        "JET LogTime values are 8 bytes, one byte for each YY-MM-DD HH:MM:SS and 2 fillers",
        "343a0d17037b0000",
        "UTC",
    ),
    "juliandec": TsTypes(
        "Julian Date decimal",
        "Julian Date decimal values are 7 digits '.' up to 10 digits",
        "2460800.1380787035",
        "UTC",
    ),
    "julianhex": TsTypes(
        "Julian Date hex",
        "Julian Date hex values are 14 characters (7 bytes)",
        "258c80524d235b",
        "UTC",
    ),
    "ksalnum": TsTypes(
        "KSUID Alpha-numeric",
        "KSUID values are 27 alpha-numeric characters",
        "2PChRqPZDwT9m2gBDLd5uy7XNTr",
        "UTC",
    ),
    "ksdec": TsTypes(
        "KSUID Decimal",
        "KSUID decimal timestamps are up to 10 digits in length",
        "346371930",
        "UTC",
    ),
    "leb128hex": TsTypes(
        "LEB128 Hex time",
        "LEB128 Hex timestamps are variable-length and even-length",
        "d0cf83dfe932",
        "UTC",
    ),
    "linkedin": TsTypes(
        "LinkedIn Activity time",
        "LinkedIn Activity timestamps contain only digits",
        "7324176984442343424",
        "UTC",
    ),
    "mars": TsTypes(
        "Mars Sol Date time",
        "Mars Sol Date time values are up to 7 digits '.' 1 or more digits",
        "54103.12581",
        "TT",
    ),
    "mastodon": TsTypes(
        "Mastodon time",
        "Mastodon timestamps are up to 20 digits",
        "114450230804480000",
        "UTC",
    ),
    "matlab": TsTypes(
        "MATLAB datenum",
        "MATLAB datenum values are up to 7 digits, optionally '.' up to 15 digits",
        "739741.638079455312",
        "Local / UTC",
    ),
    "matroska": TsTypes(
        "Matroska/WebM time",
        "Matroska/WebM dates are up to 19 digits",
        "768064730064939000",
        "UTC",
    ),
    "metasploit": TsTypes(
        "Metasploit Payload UUID",
        "Metasploit Payload UUID's are at least 22 chars and base64 urlsafe encoded",
        "4PGoVGYmx8l6F3sVI4Rc8g",
        "UTC",
    ),
    "dotnet": TsTypes(
        "Microsoft .NET Ticks",
        "Microsoft .NET Ticks values are up to 19 digits",
        "638819687300649472",
        "UTC",
    ),
    "dotnetbin": TsTypes(
        "Microsoft .NET ToBinary",
        "Microsoft .NET ToBinary values are up to 19 digits",
        "5250505705728037294",
        "UTC",
    ),
    "systemtime": TsTypes(
        "Microsoft 128-bit SYSTEMTIME",
        "Microsoft 128-bit SYSTEMTIME timestamps are 32 hex characters (16 bytes)",
        "e9070500000004000f00120032004000",
        "UTC",
    ),
    "dttm": TsTypes(
        "Microsoft DTTM date",
        "Microsoft DTTM timestamps are 4 bytes",
        "8768f513",
        "Local",
    ),
    "ms1904": TsTypes(
        "Microsoft Excel 1904 date",
        "Microsoft Excel 1904 timestamps are up to 7 digits '.' up to 15 digits",
        "44319.638079455312",
        "UTC",
    ),
    "hotmail": TsTypes(
        "Microsoft Hotmail time",
        "Microsoft Hotmail timestamps are 2x 8 hex chars (4 bytes) colon separated",
        "07bddb01:aed19dd6",
        "UTC",
    ),
    "msdos": TsTypes(
        "Microsoft MS-DOS 32-bit Hex",
        "Microsoft MS-DOS 32-bit timestamps are 8 hex characters (4 bytes)",
        "597aa45a",
        "Local",
    ),
    "mssql": TsTypes(
        "Microsoft SQL Server date",
        "Microsoft SQL Server date values are 16 hex characters",
        "0000b2d300fc5d78",
        "Local",
    ),
    "mssqlle": TsTypes(
        "Microsoft SQL Server date LE",
        "Microsoft SQL Server date LE values are 16 hex characters",
        "785dfc00d3b20000",
        "Local",
    ),
    "mjd": TsTypes(
        "Modified Julian Date",
        "Modified Julian Dates are up to 7 digits, optionally '.' up to 15 digits",
        "60799.638079455312",
        "UTC",
    ),
    "objectid": TsTypes(
        "MongoDB ObjectId time",
        "MongoDB ObjectIds are 24 hex characters (12 bytes)",
        "6817855a1b2c3d4e5f607182",
        "UTC",
    ),
    "moto": TsTypes(
        "Motorola time",
        "Motorola 6-byte hex timestamps are 12 hex characters",
        "3705040f1232",
        "UTC",
    ),
    "prtime": TsTypes(
        "Mozilla PRTime",
        "Mozilla PRTime timestamps are up to 18 digits",
        "1746371930064939",
        "UTC",
    ),
    "mysql": TsTypes(
        "MySQL DATETIME",
        "MySQL DATETIME values are 10 hex characters, then 2, 4 or 6 more for a fraction",
        "99b688f4b200fdab",
        "Local",
    ),
    "ns40": TsTypes(
        "Nokia S40 time",
        "Nokia 7-byte hex timestamps are 14 hex characters",
        "07e905040f1232",
        "UTC",
    ),
    "ns40le": TsTypes(
        "Nokia S40 time LE",
        "Nokia 7-byte hex timestamps are 14 hex characters",
        "e90705040f1232",
        "UTC",
    ),
    "nokia": TsTypes(
        "Nokia time",
        "Nokia 4-byte hex timestamps are 8 hex characters",
        "d19d0f5a",
        "UTC",
    ),
    "nokiale": TsTypes(
        "Nokia time LE",
        "Nokia 4-byte hex timestamps are 8 hex characters",
        "5a0f9dd1",
        "UTC",
    ),
    "ntp64": TsTypes(
        "NTP 64-bit hex",
        "NTP 64-bit timestamps are 16 hex characters (8 bytes)",
        "ebc203da109fd7a1",
        "UTC",
    ),
    "ntp": TsTypes(
        "NTP time",
        "NTP timestamps are up to 12 digits, optionally '.' up to 30 digits",
        "3981841662.020607",
        "UTC",
    ),
    "oracle": TsTypes(
        "Oracle DATE",
        "Oracle DATE values are 14 hex characters (7 bytes) or 7 comma separated numbers",
        "787d0504101333",
        "Local",
    ),
    "int96": TsTypes(
        "Parquet INT96 time",
        "Parquet INT96 timestamps are 24 hex characters (12 bytes)",
        "f8e7eff723320000808c2500",
        "Local / UTC",
    ),
    "pcap": TsTypes(
        "pcap record time",
        "pcap record times are 16 hex characters: seconds, microseconds, little-endian",
        "5a851768abfd0000",
        "UTC",
    ),
    "pcapbe": TsTypes(
        "pcap record time BE",
        "pcap record times are 16 hex characters: seconds, microseconds, big-endian",
        "6817855a0000fdab",
        "UTC",
    ),
    "postgres": TsTypes(
        "PostgreSQL timestamp",
        "PostgreSQL timestamp values are up to 19 digits",
        "799687130064939",
        "Local / UTC",
    ),
    "postgresbe": TsTypes(
        "PostgreSQL timestamp hex BE",
        "PostgreSQL timestamp hex BE values are 16 hex characters",
        "0002d74fab51a82b",
        "Local / UTC",
    ),
    "postgresle": TsTypes(
        "PostgreSQL timestamp hex LE",
        "PostgreSQL timestamp hex LE values are 16 hex characters",
        "2ba851ab4fd70200",
        "Local / UTC",
    ),
    "quicktime": TsTypes(
        "QuickTime/MP4 time",
        "QuickTime/MP4 times are 8 hex characters (4 bytes) or 16 hex characters (8 bytes)",
        "e43d35da",
        "Local / UTC",
    ),
    "s32": TsTypes(
        "S32 Encoded (Bluesky) time",
        "S32 encoded (Bluesky) timestamps are 9 characters long",
        "3muhy3twk",
        "UTC",
    ),
    "sasdate": TsTypes(
        "SAS date",
        "SAS date values are up to 7 digits",
        "23865",
        "Local / UTC",
    ),
    "sas": TsTypes(
        "SAS datetime",
        "SAS datetime values are up to 12 digits, optionally '.' up to 9 digits",
        "2061991130.064939",
        "Local / UTC",
    ),
    "semioctet": TsTypes(
        "Semi-Octet decimal",
        "Semi-Octet decimal values are 12 digits long",
        "525040518105",
        "Local",
    ),
    "sony": TsTypes(
        "Sonyflake time",
        "Sonyflake values are up to 16 hex characters",
        "65dd4bb89000001",
        "UTC",
    ),
    "spss": TsTypes(
        "SPSS date",
        "SPSS date values are up to 12 digits, optionally '.' up to 9 digits",
        "13965751130.064939",
        "Local / UTC",
    ),
    "stardatetng": TsTypes(
        "Star Trek TNG Stardate",
        "Star Trek TNG Stardates are up to 7 digits, optionally '.' up to 6 digits",
        "41153.7",
        "UTC",
    ),
    "stardatetos": TsTypes(
        "Star Trek TOS Stardate",
        "Star Trek TOS Stardates are up to 8 digits, optionally '.' up to 6 digits",
        "1312.4",
        "UTC",
    ),
    "stata": TsTypes(
        "Stata %tc time",
        "Stata %tc values are up to 15 digits",
        "2061991130064",
        "Local / UTC",
    ),
    "symantec": TsTypes(
        "Symantec AV time",
        "Symantec 6-byte hex timestamps are 12 hex characters",
        "3704040f1232",
        "UTC",
    ),
    "symbian": TsTypes(
        "Symbian time",
        "Symbian time values are up to 18 digits, microseconds since the year 0",
        "63913591130064939",
        "UTC",
    ),
    "taimilli": TsTypes(
        "TAI Milliseconds",
        "TAI (International Atomic Time) values (based on ms) are up to 15 digits",
        "1599755800000",
        "UTC",
    ),
    "tai": TsTypes(
        "TAI Seconds",
        "TAI (International Atomic Time) values (based on sec) are up to 12 digits",
        "1599755800",
        "UTC",
    ),
    "tai64n": TsTypes(
        "TAI64N time",
        "TAI64N labels are 24 hex characters, optionally with a leading '@'",
        "400000006817856403dee3f8",
        "UTC",
    ),
    "tar": TsTypes(
        "tar header time",
        "tar header times are 1 to 12 octal digits",
        "15005702532",
        "UTC",
    ),
    "telegram": TsTypes(
        "Telegram MTProto ID time",
        "Telegram MTProto message IDs are up to 20 digits",
        "7500610326281312160",
        "UTC",
    ),
    "tiktok": TsTypes(
        "TikTok time",
        "TikTok timestamps are up to 20 digits long",
        "7228142017547750661",
        "UTC",
    ),
    "twitter": TsTypes(
        "Twitter time",
        "Twitter timestamps are up to 20 digits",
        "1189581422684274688",
        "UTC",
    ),
    "udf": TsTypes(
        "UDF timestamp",
        "UDF timestamps are 24 hex characters (12 bytes)",
        "0118e90705040f1232063127",
        "Local / UTC",
    ),
    "efitime": TsTypes(
        "UEFI EFI_TIME",
        "UEFI EFI_TIME values are 32 hex characters (16 bytes)",
        "e90705040f123200f8e3de03ff070000",
        "Local / UTC",
    ),
    "ulid": TsTypes(
        "ULID time",
        "ULID timestamp contains only Base32 characters",
        "01JTDY1SYGCZWCBPCSEBHV1DW2",
        "UTC",
    ),
    "unixdays": TsTypes(
        "Unix Days",
        "Unix days timestamp is up to 7 digits in length",
        "20212",
        "UTC",
    ),
    "unixhex32be": TsTypes(
        "Unix Hex 32-bit BE",
        "Unix Hex 32-bit Big-Endian timestamps are 8 hex characters (4 bytes)",
        "6817855a",
        "UTC",
    ),
    "unixhex32le": TsTypes(
        "Unix Hex 32-bit LE",
        "Unix Hex 32-bit Little-Endian timestamps are 8 hex characters (4 bytes)",
        "5a851768",
        "UTC",
    ),
    "unixmilli": TsTypes(
        "Unix Milliseconds",
        "Unix milliseconds timestamp is 1 to 15 digits in length",
        "1746371930064",
        "UTC",
    ),
    "unixmillihex": TsTypes(
        "Unix Milliseconds hex",
        "Unix Milliseconds hex timestamp is up to 12 hex characters (6 bytes)",
        "01969be0e7d0",
        "UTC",
    ),
    "unixnano": TsTypes(
        "Unix Nanoseconds",
        "Unix nanoseconds timestamp is up to 21 digits in length",
        "1746371930064939000",
        "UTC",
    ),
    "unixsec": TsTypes(
        "Unix Seconds",
        "Unix seconds timestamp is up to 12 digits in length",
        "1746371930",
        "UTC",
    ),
    "unixsecfrac": TsTypes(
        "Unix Seconds with fraction",
        "Unix seconds with a fraction are up to 12 digits '.' up to 9 digits",
        "1746371930.064939",
        "UTC",
    ),
    "uuid": TsTypes(
        "UUID time",
        "UUIDs are in the format 00000000-0000-0000-0000-000000000000",
        "d93026f0-e857-11ed-a05b-0242ac120003",
        "UTC",
    ),
    "uuid6": TsTypes(
        "UUID v6 time",
        "UUID v6 values are in the format 00000000-0000-6000-8000-000000000000",
        "1f028fb1-4e09-61ae-8c4f-0342ac120003",
        "UTC",
    ),
    "uuid7": TsTypes(
        "UUID v7 time",
        "UUID v7 values are in the format 00000000-0000-7000-8000-000000000000",
        "01969be0-e7d0-7a3c-9b2e-5f60718293a4",
        "UTC",
    ),
    "vm": TsTypes(
        "VMSD time",
        "VMSD values are two signed whole numbers separated by a comma",
        "406608,-427259264",
        "UTC",
    ),
    "cookie": TsTypes(
        "Windows Cookie Date",
        "Windows Cookie times consist of 2 ints, entered with a comma between them",
        "3600017664,31177991",
        "UTC",
    ),
    "filetimelohi": TsTypes(
        "Windows FILETIME (Low|High)",
        "Windows FILETIME Low|High times are 8 hex chars, a colon, and up to 8 hex chars",
        "d69dd1ae:01dbbd07",
        "UTC",
    ),
    "filetimebe": TsTypes(
        "Windows FILETIME BE",
        "Windows FILETIME Hex Big-Endian timestamp is 16 hex characters (8 bytes)",
        "01dbbd07d69dd1ae",
        "UTC",
    ),
    "filetimele": TsTypes(
        "Windows FILETIME LE",
        "Windows FILETIME Hex Little-Endian timestamp is 16 hex characters (8 bytes)",
        "aed19dd607bddb01",
        "UTC",
    ),
    "olebe": TsTypes(
        "Windows OLE 64-bit hex BE",
        "Windows OLE Big-Endian timestamps are 16 hex characters (8 bytes)",
        "40e65ab46b259b1a",
        "UTC",
    ),
    "olele": TsTypes(
        "Windows OLE 64-bit hex LE",
        "Windows OLE Little-Endian timestamps are 16 hex characters (8 bytes)",
        "1a9b256bb45ae640",
        "UTC",
    ),
    "oleauto": TsTypes(
        "Windows OLE Automation Date",
        "Windows OLE Automation timestamps are up to 7 digits '.' up to 15 digits",
        "45781.638079455312",
        "UTC",
    ),
    "xfsbig": TsTypes(
        "XFS bigtime",
        "XFS bigtime values are 16 hex characters (8 bytes), big-endian",
        "3609c104893be7f8",
        "UTC",
    ),
    "xfs": TsTypes(
        "XFS inode time",
        "XFS inode times are 16 hex characters big-endian",
        "6817855a03dee3f8",
        "UTC",
    ),
    "xid": TsTypes(
        "xid time",
        "xid values are 20 characters, 0-9 and a-v",
        "d0boaml1mb1t9pfm0sc0",
        "UTC",
    ),
}

epochs = {
    1: dt(1, 1, 1, tzinfo=timezone.utc),
    1582: dt(1582, 10, 15, tzinfo=timezone.utc),
    1601: dt(1601, 1, 1, tzinfo=timezone.utc),
    1840: dt(1840, 12, 31, tzinfo=timezone.utc),
    1873: dt(1873, 12, 29, tzinfo=timezone.utc),
    1899: dt(1899, 12, 30, tzinfo=timezone.utc),
    1904: dt(1904, 1, 1, tzinfo=timezone.utc),
    1970: dt(1970, 1, 1, tzinfo=timezone.utc),
    1980: dt(1980, 1, 6, tzinfo=timezone.utc),
    2000: dt(2000, 1, 1, tzinfo=timezone.utc),
    2001: dt(2001, 1, 1, tzinfo=timezone.utc),
    2050: dt(2050, 1, 1, tzinfo=timezone.utc),
    "active": 116444736000000000,
    "win_unix": 11644473600,
    "hfs_dec_sub": 2082844800,
    "kstime": 1400000000,
    "ticks": 621355968000000000,
    "ntp": 2208988800,
    "tai": 37,
}

# There have been no further leapseconds since 2017,1,1 at the __date__ of this script
# which is why the leapseconds end with a dt.now object to valid/relevant timestamp output.
# See REFERENCES.md for source info.
leapseconds = {
    10: [dt(1972, 1, 1, tzinfo=timezone.utc), dt(1972, 7, 1, tzinfo=timezone.utc)],
    11: [dt(1972, 7, 1, tzinfo=timezone.utc), dt(1973, 1, 1, tzinfo=timezone.utc)],
    12: [dt(1973, 1, 1, tzinfo=timezone.utc), dt(1974, 1, 1, tzinfo=timezone.utc)],
    13: [dt(1974, 1, 1, tzinfo=timezone.utc), dt(1975, 1, 1, tzinfo=timezone.utc)],
    14: [dt(1975, 1, 1, tzinfo=timezone.utc), dt(1976, 1, 1, tzinfo=timezone.utc)],
    15: [dt(1976, 1, 1, tzinfo=timezone.utc), dt(1977, 1, 1, tzinfo=timezone.utc)],
    16: [dt(1977, 1, 1, tzinfo=timezone.utc), dt(1978, 1, 1, tzinfo=timezone.utc)],
    17: [dt(1978, 1, 1, tzinfo=timezone.utc), dt(1979, 1, 1, tzinfo=timezone.utc)],
    18: [dt(1979, 1, 1, tzinfo=timezone.utc), dt(1980, 1, 1, tzinfo=timezone.utc)],
    19: [dt(1980, 1, 1, tzinfo=timezone.utc), dt(1981, 7, 1, tzinfo=timezone.utc)],
    20: [dt(1981, 7, 1, tzinfo=timezone.utc), dt(1982, 7, 1, tzinfo=timezone.utc)],
    21: [dt(1982, 7, 1, tzinfo=timezone.utc), dt(1983, 7, 1, tzinfo=timezone.utc)],
    22: [dt(1983, 7, 1, tzinfo=timezone.utc), dt(1985, 7, 1, tzinfo=timezone.utc)],
    23: [dt(1985, 7, 1, tzinfo=timezone.utc), dt(1988, 1, 1, tzinfo=timezone.utc)],
    24: [dt(1988, 1, 1, tzinfo=timezone.utc), dt(1990, 1, 1, tzinfo=timezone.utc)],
    25: [dt(1990, 1, 1, tzinfo=timezone.utc), dt(1991, 1, 1, tzinfo=timezone.utc)],
    26: [dt(1991, 1, 1, tzinfo=timezone.utc), dt(1992, 7, 1, tzinfo=timezone.utc)],
    27: [dt(1992, 7, 1, tzinfo=timezone.utc), dt(1993, 7, 1, tzinfo=timezone.utc)],
    28: [dt(1993, 7, 1, tzinfo=timezone.utc), dt(1994, 7, 1, tzinfo=timezone.utc)],
    29: [dt(1994, 7, 1, tzinfo=timezone.utc), dt(1996, 1, 1, tzinfo=timezone.utc)],
    30: [dt(1996, 1, 1, tzinfo=timezone.utc), dt(1997, 7, 1, tzinfo=timezone.utc)],
    31: [dt(1997, 7, 1, tzinfo=timezone.utc), dt(1999, 1, 1, tzinfo=timezone.utc)],
    32: [dt(1999, 1, 1, tzinfo=timezone.utc), dt(2006, 1, 1, tzinfo=timezone.utc)],
    33: [dt(2006, 1, 1, tzinfo=timezone.utc), dt(2009, 1, 1, tzinfo=timezone.utc)],
    34: [dt(2009, 1, 1, tzinfo=timezone.utc), dt(2012, 7, 1, tzinfo=timezone.utc)],
    35: [dt(2012, 7, 1, tzinfo=timezone.utc), dt(2015, 7, 1, tzinfo=timezone.utc)],
    36: [dt(2015, 7, 1, tzinfo=timezone.utc), dt(2017, 1, 1, tzinfo=timezone.utc)],
    37: [
        dt(2017, 1, 1, tzinfo=timezone.utc),
        dt.now(timezone.utc) - timedelta(seconds=37),
    ],
}

date_formats = {
    "Default": __fmt__,
    "ISO 8601": "%Y-%m-%dT%H:%M:%S.%f",
    "DD/MM/YY": "%d/%m/%Y %H:%M:%S.%f",
    "DMY": "%d-%m-%Y %H:%M:%S.%f",
    "MDY": "%m-%d-%Y %H:%M:%S.%f",
    "YMD": __fmt__,
}

S32_CHARS = "234567abcdefghijklmnopqrstuvwxyz"
BASE32_CHARS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
URLSAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_"
KSALNUM_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
IOSTIME_DIGITS = range(15, 19)
PUSH_CHARS = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
UUID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_JULIAN_UNIX_EPOCH = Fraction(4881175, 2)
_DAY_MICROSECONDS = 86400 * 10**6
_JULIAN_FIXED_DIGITS = 0x800000
_UTC = timezone.utc
_MICROSECOND = timedelta(microseconds=1)
_AWARE_MIN = dt.min.replace(tzinfo=_UTC)
_AWARE_MAX = dt.max.replace(tzinfo=_UTC)
_UINT32 = 0x100000000
_STARDATE_TNG_ORIGIN = dt(2318, 7, 5, 12, tzinfo=_UTC)
_STARDATE_TNG_UNIT = 34367056400
_STARDATE_TOS_ORIGIN = dt(2265, 4, 25, tzinfo=_UTC)
_STARDATE_TOS_UNIT = 86400 * 10**6 * Fraction("365.2422") / Fraction("2635.10833")
_INSTAGRAM_EPOCH_MILLISECONDS = 1314220021721
_DOTNET_KIND_UTC = 0x4000000000000000
_DOTNET_TICKS_MASK = 0x3FFFFFFFFFFFFFFF
_MSSQL_TICKS_PER_DAY = 86400 * 300
_SYMBIAN_YEAR_ZERO_SECONDS = 62167219200
_MATLAB_UNIX_EPOCH = 719529
_MATROSKA_SPAN = timedelta(microseconds=2**63 // 1000)
_INT96_UNIX_DAY = 2440588
_XFS_BIGTIME_EPOCH = dt(1970, 1, 1, tzinfo=timezone.utc) - timedelta(seconds=2**31)
XID_CHARS = "0123456789abcdefghijklmnopqrstuv"
BASE36_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"


"""
Where necessary (during --guess scenarios), the max accepted date for
some conversions 3001-01-19 02:59:59 UTC, because this is the max
Windows can handle for conversion. Additionally, for others, the max
year to be accepted will be one of 2499, 3000 or 4769. Anything higher generates an error.

Since these time scenarios are currently not feasible for results, these are
being considered as acceptable boundaries.
"""


def microseconds_since(dt_obj, epoch):
    """Whole microseconds from an epoch to a date, without float rounding"""
    return (dt_obj - epoch) // timedelta(microseconds=1)


def seconds_since(dt_obj, epoch):
    """Whole seconds from an epoch to a date, rounded down, without float rounding"""
    return (dt_obj - epoch) // timedelta(seconds=1)


def days_since(dt_obj, epoch):
    """Days, with their fraction, from an epoch to a date as an exact fraction"""
    return Fraction(microseconds_since(dt_obj, epoch), 86400 * 10**6)


def date_string(dt_obj):
    return dt_obj.strftime(__fmt__.replace("%Y", f"{dt_obj.year:04d}"))


def date_text(epoch, microseconds):
    """An epoch plus a count of microseconds, in the current date format. "" beyond the dates allowed"""
    try:
        return date_string(epoch + timedelta(microseconds=microseconds))
    except OverflowError:
        return ""


def units_to_microseconds(count, per_second):
    """A count of units that are 1 / per_second of a second, as whole microseconds rounded half to even"""
    return round(Fraction(count * 10**6, per_second))


def is_digits(text, longest, shortest=1):
    """Whether text is made of ASCII digits and its length is from shortest to longest"""
    return text.isascii() and text.isdigit() and shortest <= len(text) <= longest


def is_hex(text, longest, shortest=1):
    """Whether text is made of hex digits and its length is from shortest to longest"""
    return all(char in hexdigits for char in text) and shortest <= len(text) <= longest


def dos_datetime(value):
    """The date in a 32 bit DOS value, or None where its fields are not a date"""
    try:
        return dt(
            (value >> 25) + 1980,
            (value >> 21) & 0xF,
            (value >> 16) & 0x1F,
            (value >> 11) & 0x1F,
            (value >> 5) & 0x3F,
            (value & 0x1F) * 2,
        )
    except ValueError:
        return None


def utc_offset_label(zone, quarters):
    """A zone label with an offset in quarter hours, such as UTC+5.5"""
    hours = quarters * 0.25
    return f"{zone}{'+' if hours > 0 else ''}{hours:g}" if hours else zone


def formatted(ts_type, text, tz_out):
    """A date text with its two output forms, or three empty strings where there is no date"""
    if not text:
        return "", "", ""
    indiv_output, combined_output = format_output(ts_type, text, tz_out)
    return text, indiv_output, combined_output


def decoder(name):
    """Make the decoder of a type from a function that turns a value into the text of a date"""

    def decorate(read):
        @functools.wraps(read)
        def decode(timestamp, *args, **kwargs):
            ts_type, reason, _, tz_out = ts_types[name]
            try:
                found = read(timestamp, *args, **kwargs)
                text, tz_out = found if isinstance(found, tuple) else (found, tz_out)
                return (*formatted(ts_type, text, tz_out), reason, tz_out)
            except Exception:
                handle(sys.exc_info())
                return "", "", "", reason, tz_out

        return decode

    return decorate


def encoder(name):
    """Make the encoder of a type from a function that turns a date into the text of a timestamp"""

    def decorate(write):
        @functools.wraps(write)
        def encode(dt_obj):
            try:
                text = write(dt_obj)
                if not text:
                    return "", ""
                return text, format_output(ts_types[name].ts_type, text)[0]
            except Exception:
                handle(sys.exc_info())
                return "", ""

        return encode

    return decorate


def seconds_to_date_text(epoch, seconds):
    """An epoch plus a number of seconds, which may be a float, as text. "" beyond the dates allowed"""
    try:
        return date_text(epoch, round(Fraction(seconds) * 10**6))
    except (ValueError, OverflowError):
        return ""


def biome_seconds(raw):
    """Seconds since 2001 in 8 bytes that are a double, in either byte order"""
    plausible = set(range(0x3F, 0x44)) | set(range(0xBF, 0xC4))
    if raw[-1] in plausible and raw[0] not in plausible:
        return struct.unpack("<d", raw)[0]
    return struct.unpack(">d", raw)[0]


def days_to_date_text(epoch, days):
    """An epoch plus a number of days, or an exact fraction of them, as text. "" beyond the dates allowed"""
    try:
        return date_text(epoch, round(Fraction(days) * 86400 * 10**6))
    except (ValueError, OverflowError):
        return ""


def decimal_days(dt_obj, epoch, offset=0):
    """Days from an epoch to a date as text with 12 decimal places, rounded without float error"""
    scaled = round((days_since(dt_obj, epoch) + offset) * 10**12)
    return f"{scaled // 10**12}.{scaled % 10**12:012d}"


@decoder("unixsec")
def from_unixsec(timestamp, guess=False):
    """Convert Unix Seconds value to a date"""
    if not is_digits(timestamp, 10 if guess else 12, 10 if guess else 1):
        return ""
    return date_text(epochs[1970], int(timestamp) * 10**6)


@encoder("unixsec")
def to_unixsec(dt_obj):
    """Convert date to a Unix Seconds value"""
    return str(seconds_since(dt_obj, epochs[1970]))


@decoder("unixmilli")
def from_unixmilli(timestamp, guess=False):
    """Convert Unix Millisecond value to a date"""
    if not is_digits(str(timestamp), 13 if guess else 15, 13 if guess else 1):
        return ""
    return date_text(epochs[1970], int(timestamp) * 1000)


@encoder("unixmilli")
def to_unixmilli(dt_obj):
    """Convert date to a Unix Millisecond value"""
    return str(microseconds_since(dt_obj, epochs[1970]) // 1000)


@decoder("unixmillihex")
def from_unixmillihex(timestamp, guess=False):
    """Convert a Unix Millisecond hex value to a date"""
    timestamp = str(timestamp)
    if not is_hex(timestamp, 12, 12 if guess else 1):
        return ""
    unix_mil = int(timestamp, 16)
    if guess and len(str(unix_mil)) != 13:
        return ""
    return date_text(epochs[1970], unix_mil * 1000)


@encoder("unixmillihex")
def to_unixmillihex(dt_obj):
    """Convert a date to a Unix Millisecond hex value"""
    unix_mil, _ = to_unixmilli(dt_obj)
    return f"{int(unix_mil):012x}"


@decoder("filetimebe")
def from_filetimebe(timestamp, guess=False):
    """Convert a Windows 64 Hex Big-Endian value to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    ticks = int(timestamp, 16)
    if guess and ticks >= 10**18:
        return ""
    return date_text(epochs[1601], units_to_microseconds(ticks, 10**7))


@encoder("filetimebe")
def to_filetimebe(dt_obj):
    """Convert a date to a Windows 64 Hex Big-Endian value"""
    return f"{microseconds_since(dt_obj, epochs[1601]) * 10:016x}"


@decoder("filetimele")
def from_filetimele(timestamp, guess=False):
    """Convert a Windows 64 Hex Little-Endian value to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    ticks = int.from_bytes(struct.pack("<Q", int(timestamp, 16)), "big")
    if guess and ticks >= 10**18:
        return ""
    return date_text(epochs[1601], units_to_microseconds(ticks, 10**7))


@encoder("filetimele")
def to_filetimele(dt_obj):
    """Convert a date to a Windows 64 Hex Little-Endian value"""
    return struct.pack("<Q", microseconds_since(dt_obj, epochs[1601]) * 10).hex()


@decoder("chrome")
def from_chrome(timestamp, guess=False):
    """Convert a Chrome Timestamp/Webkit Value to a date"""
    if not is_digits(timestamp, 17 if guess else 18, 17 if guess else 1):
        return ""
    return date_text(epochs[1601], int(timestamp))


@encoder("chrome")
def to_chrome(dt_obj):
    """Convert a date to a Chrome Timestamp/Webkit value"""
    return str(microseconds_since(dt_obj, epochs[1601]))


@decoder("active")
def from_active(timestamp, guess=False):
    """Convert an Active Directory/LDAP timestamp to a date"""
    if not is_digits(timestamp, 18 if guess else 19, 18 if guess else 1):
        return ""
    microseconds = units_to_microseconds(int(timestamp), 10**7)
    unix_microseconds = microseconds - epochs["win_unix"] * 10**6
    if guess and not 0 <= unix_microseconds < 32536799999 * 10**6:
        return ""
    return date_text(epochs[1601], microseconds)


@encoder("active")
def to_active(dt_obj):
    """Convert a date to an Active Directory/LDAP timestamp"""
    return str(microseconds_since(dt_obj, epochs[1601]) * 10)


@decoder("unixhex32be")
def from_unixhex32be(timestamp):
    """Convert a Unix Hex 32-bit Big-Endian timestamp to a date"""
    if not is_hex(timestamp, 8, 8):
        return ""
    return date_text(epochs[1970], int(timestamp, 16) * 10**6)


@encoder("unixhex32be")
def to_unixhex32be(dt_obj):
    """Convert a date to a Unix Hex 32-bit Big-Endian timestamp"""
    return struct.pack(">L", seconds_since(dt_obj, epochs[1970])).hex()


@decoder("unixhex32le")
def from_unixhex32le(timestamp):
    """Convert a Unix Hex 32-bit Little-Endian timestamp to a date"""
    if not is_hex(timestamp, 8, 8):
        return ""
    seconds = int.from_bytes(struct.pack("<L", int(timestamp, 16)), "big")
    return date_text(epochs[1970], seconds * 10**6)


@encoder("unixhex32le")
def to_unixhex32le(dt_obj):
    """Convert a date to a Unix Hex 32-bit Little-Endian timestamp"""
    return struct.pack("<L", seconds_since(dt_obj, epochs[1970])).hex()


@decoder("cookie")
def from_cookie(timestamp, guess=False):
    """Convert an Internet Explorer timestamp to a date"""
    parts = timestamp.split(",")
    if len(parts) != 2 or not all(is_digits(part, 20) for part in parts):
        return ""
    low, high = [int(part) for part in parts]
    microseconds = units_to_microseconds(high * 2**32 + low, 10**7)
    unix_microseconds = microseconds - epochs["win_unix"] * 10**6
    if guess and not 0 <= unix_microseconds < 32536799999 * 10**6:
        return ""
    return date_text(epochs[1601], microseconds)


@encoder("cookie")
def to_cookie(dt_obj):
    """Convert a date to Internet Explorer timestamp values"""
    high, low = divmod(microseconds_since(dt_obj, epochs[1601]) * 10, 2**32)
    return f"{low},{high}"


@decoder("olebe")
def from_olebe(timestamp, guess=False):
    """Convert an OLE Big-Endian timestamp to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    delta = struct.unpack(">d", bytes.fromhex(timestamp))[0]
    if guess and not 0 <= delta <= 2e6:
        return ""
    return days_to_date_text(epochs[1899], delta)


@encoder("olebe")
def to_olebe(dt_obj):
    """Convert a date to an OLE Big-Endian timestamp"""
    return struct.pack(">d", float(days_since(dt_obj, epochs[1899]))).hex()


@decoder("olele")
def from_olele(timestamp, guess=False):
    """Convert an OLE Little-Endian timestamp to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    delta = struct.unpack("<d", bytes.fromhex(timestamp))[0]
    if guess and not 0 <= delta <= 99999:
        return ""
    return days_to_date_text(epochs[1899], delta)


@encoder("olele")
def to_olele(dt_obj):
    """Convert a date to an OLE Little-Endian timestamp"""
    return struct.pack("<d", float(days_since(dt_obj, epochs[1899]))).hex()


@decoder("bplist")
def from_bplist(timestamp, guess=False):
    """Convert a bplist NSDate timestamp to a date value"""
    if not is_digits(timestamp, 9 if guess else 12, 9 if guess else 1):
        return ""
    return date_text(epochs[2001], int(timestamp) * 10**6)


@encoder("bplist")
def to_bplist(dt_obj):
    """Convert a date to a Binary Plist timestamp"""
    return str(seconds_since(dt_obj, epochs[2001]))


@decoder("iostime")
def from_iostime(timestamp):
    """Convert an iOS NSDate timestamp to a date value"""
    if not is_digits(timestamp, IOSTIME_DIGITS[-1], IOSTIME_DIGITS[0]):
        return ""
    return date_text(epochs[2001], units_to_microseconds(int(timestamp), 10**9))


@encoder("iostime")
def to_iostime(dt_obj):
    """Convert a date to an iOS 11 timestamp"""
    return str(microseconds_since(dt_obj, epochs[2001]) * 1000)


@decoder("mac")
def from_mac(timestamp, guess=False):
    """Convert a mac NSDate timestamp to a date value"""
    whole, point, fraction = timestamp.partition(".")
    if not (point and is_digits(whole, 9 if guess else 12, 9 if guess else 1)):
        return ""
    if fraction and not is_digits(fraction, 6):
        return ""
    return date_text(epochs[2001], int(whole) * 10**6 + int(fraction.ljust(6, "0")))


@encoder("mac")
def to_mac(dt_obj):
    """Convert a date to a Mac Absolute timestamp"""
    seconds, fraction = divmod(microseconds_since(dt_obj, epochs[2001]), 10**6)
    return f"{seconds}.{fraction:06d}"


@decoder("hfsdec")
def from_hfsdec(timestamp, guess=False):
    """Convert a Mac OS/HFS+ Decimal Timestamp to a date"""
    if not is_digits(timestamp, 10 if guess else 12, 10 if guess else 1):
        return ""
    if guess and int(timestamp) < epochs["hfs_dec_sub"]:
        return ""
    return date_text(epochs[1904], int(timestamp) * 10**6)


@encoder("hfsdec")
def to_hfsdec(dt_obj):
    """Convert a date to a Mac OS/HFS+ Decimal Timestamp"""
    return str(seconds_since(dt_obj, epochs[1904]))


@decoder("hfsbe")
def from_hfsbe(timestamp):
    """Convert an HFS / HFS+ Big-Endian timestamp to a date (HFS+ is in UTC)"""
    if not is_hex(timestamp, 8, 8):
        return ""
    return date_text(epochs[1904], int(timestamp, 16) * 10**6)


@encoder("hfsbe")
def to_hfsbe(dt_obj):
    """Convert a date to an HFS / HFS+ Big-Endian timestamp"""
    return f"{seconds_since(dt_obj, epochs[1904]):08x}"


@decoder("hfsle")
def from_hfsle(timestamp):
    """Convert an HFS / HFS+ Little-Endian timestamp to a date (HFS+ is in UTC)"""
    if not is_hex(timestamp, 8, 8):
        return ""
    seconds = int.from_bytes(bytes.fromhex(timestamp), "little")
    return date_text(epochs[1904], seconds * 10**6)


@encoder("hfsle")
def to_hfsle(dt_obj):
    """Convert a date to an HFS / HFS+ Little-Endian timestamp"""
    return struct.pack("<I", seconds_since(dt_obj, epochs[1904])).hex()


def fields_date_text(*fields):
    """
    The date of year, month, day and the following fields in the current date format.
    "" where they are not a date.
    """
    try:
        return date_string(dt(*fields))
    except ValueError:
        return ""


def dos_date_text(value, guess):
    """
    The date in a 32 bit DOS value, or "" where its fields are not a date.
    From the top bit the fields are the year from 1980 (7 bits), month (4), day (5), hour (5),
    minute (6) and seconds in twos (5). When guessing, only the years up to 2099 are taken.
    """
    year = (value >> 25) + 1980
    if guess and year >= 2100:
        return ""
    return fields_date_text(
        year,
        (value >> 21) & 0xF,
        (value >> 16) & 0x1F,
        (value >> 11) & 0x1F,
        (value >> 5) & 0x3F,
        (value & 0x1F) * 2,
    )


def dos_value(dt_obj):
    """The 32-bit DOS value of a date, in the layout read by dos_date_text"""
    return (
        (dt_obj.year - 1980) << 25
        | dt_obj.month << 21
        | dt_obj.day << 16
        | dt_obj.hour << 11
        | dt_obj.minute << 5
        | dt_obj.second // 2
    )


@decoder("fat")
def from_fat(timestamp, guess=False):
    """Convert an MS-DOS wFatDate wFatTime timestamp to a date"""
    if not is_hex(timestamp, 8, 8):
        return ""
    date_word, time_word = struct.unpack("<HH", bytes.fromhex(timestamp))
    return dos_date_text(date_word << 16 | time_word, guess)


@encoder("fat")
def to_fat(dt_obj):
    """Convert a date to an MS-DOS wFatDate wFatTime timestamp"""
    value = dos_value(dt_obj)
    return struct.pack("<HH", value >> 16, value & 0xFFFF).hex()


@decoder("msdos")
def from_msdos(timestamp, guess=False):
    """Convert an MS-DOS timestamp to a date"""
    if not is_hex(timestamp, 8, 8):
        return ""
    return dos_date_text(int.from_bytes(bytes.fromhex(timestamp), "little"), guess)


@encoder("msdos")
def to_msdos(dt_obj):
    """Convert a date to an MS-DOS timestamp"""
    return struct.pack("<I", dos_value(dt_obj)).hex()


@decoder("exfat")
def from_exfat(timestamp, guess=False):
    """Convert an exFAT timestamp (LE) to a date"""
    if not is_hex(timestamp, 8, 8):
        return ""
    return dos_date_text(int(timestamp, 16), guess)


@encoder("exfat")
def to_exfat(dt_obj):
    """Convert a date to an exFAT timestamp (LE)"""
    return struct.pack(">I", dos_value(dt_obj)).hex()


@decoder("systemtime")
def from_systemtime(timestamp, guess=False):
    """Convert a Microsoft 128-bit SYSTEMTIME timestamp to a date"""
    if not is_hex(timestamp, 32, 32):
        return ""
    year, month, day_of_week, day, hour, minute, second, millisecond = struct.unpack(
        "<8H", bytes.fromhex(timestamp)
    )
    if (guess and year > 3000) or month > 12 or day_of_week > 31:
        return ""
    return fields_date_text(year, month, day, hour, minute, second, millisecond * 1000)


@encoder("systemtime")
def to_systemtime(dt_obj):
    """Convert a date to a Microsoft 128-bit SYSTEMTIME timestamp"""
    utc = dt_obj.astimezone(timezone.utc)
    return struct.pack(
        "<8H",
        utc.year,
        utc.month,
        utc.isoweekday() % 7,
        utc.day,
        utc.hour,
        utc.minute,
        utc.second,
        utc.microsecond // 1000,
    ).hex()


@decoder("filetimelohi")
def from_filetimelohi(timestamp, guess=False):
    """Convert a Microsoft FILETIME timestamp to a date"""
    parts = timestamp.split(":")
    if len(parts) != 2 or not is_hex(parts[0], 8, 8) or not is_hex(parts[1], 8):
        return ""
    low, high = [int(part, 16) for part in parts]
    ticks = high << 32 | low
    if guess and not epochs["active"] <= ticks < 10**18:
        return ""
    return date_text(epochs[1601], units_to_microseconds(ticks, 10**7))


@encoder("filetimelohi")
def to_filetimelohi(dt_obj):
    """Convert a date to a Microsoft FILETIME timestamp"""
    ticks = struct.pack(">Q", microseconds_since(dt_obj, epochs[1601]) * 10).hex()
    return f"{ticks[8:]}:{ticks[:8]}"


@decoder("hotmail")
def from_hotmail(timestamp, guess=False):
    """Convert a Microsoft Hotmail timestamp to a date"""
    parts = timestamp.split(":")
    if len(parts) != 2 or not is_hex(parts[0], 8, 8) or not is_hex(parts[1], 8, 8):
        return ""
    high, low = struct.unpack("<LL", bytes.fromhex("".join(parts)))
    ticks = high << 32 | low
    if guess and not epochs["active"] <= ticks < 10**18:
        return ""
    return date_text(epochs[1601], units_to_microseconds(ticks, 10**7))


@encoder("hotmail")
def to_hotmail(dt_obj):
    """Convert a date to a Microsoft Hotmail timestamp"""
    ticks = microseconds_since(dt_obj, epochs[1601]) * 10
    halves = struct.pack("<LL", ticks >> 32, ticks & 0xFFFFFFFF).hex()
    return f"{halves[:8]}:{halves[8:]}"


@decoder("prtime")
def from_prtime(timestamp, guess=False):
    """Convert a Mozilla PRTime timestamp to a date"""
    if not is_digits(timestamp, 16 if guess else 18, 16 if guess else 1):
        return ""
    return date_text(epochs[1970], int(timestamp))


@encoder("prtime")
def to_prtime(dt_obj):
    """Convert a date to Mozilla's PRTime timestamp"""
    return str(microseconds_since(dt_obj, epochs[1970]))


def decimal_days_text(epoch, timestamp, guess):
    """
    The date of days and their decimals from an epoch.
    When guessing, only 5 digits of days and 9 to 12 decimals are taken.
    """
    whole, point, fraction = timestamp.partition(".")
    if not point or not is_digits(whole, 5 if guess else 7, 5 if guess else 1):
        return ""
    if not is_digits(fraction, 12 if guess else 15, 9 if guess else 1):
        return ""
    return days_to_date_text(
        epoch, Fraction(int(whole + fraction), 10 ** len(fraction))
    )


@decoder("oleauto")
def from_oleauto(timestamp, guess=False):
    """Convert an OLE Automation timestamp to a date"""
    return decimal_days_text(epochs[1899], timestamp, guess)


@encoder("oleauto")
def to_oleauto(dt_obj):
    """Convert a date to an OLE Automation timestamp"""
    return decimal_days(dt_obj, epochs[1899])


@decoder("ms1904")
def from_ms1904(timestamp, guess=False):
    """Convert a Microsoft Excel 1904 timestamp to a date"""
    return decimal_days_text(epochs[1904], timestamp, guess)


@encoder("ms1904")
def to_ms1904(dt_obj):
    """Convert a date to a Microsoft Excel 1904 timestamp"""
    return decimal_days(dt_obj, epochs[1904])


@decoder("symantec")
def from_symantec(timestamp):
    """Convert a Symantec 6-byte hex timestamp to a date"""
    if not is_hex(timestamp, 12, 12):
        return ""
    year, month, day, hour, minute, second = bytes.fromhex(timestamp)
    return fields_date_text(year + 1970, month + 1, day, hour, minute, second)


@encoder("symantec")
def to_symantec(dt_obj):
    """Convert a date to Symantec's 6-byte hex timestamp"""
    utc = dt_obj.astimezone(timezone.utc)
    return bytes(
        [utc.year - 1970, utc.month - 1, utc.day, utc.hour, utc.minute, utc.second]
    ).hex()


def leap_offset(utc_date):
    """
    TAI minus UTC in seconds at a UTC date, or None before the first leap second entry.
    The offset of the latest entry applies to every later date, since
    there have been no leap seconds added since 2017.
    """
    offset = None
    for seconds, (start, _) in leapseconds.items():
        if start <= utc_date:
            offset = seconds
    return offset


def gps_to_utc(gps_seconds):
    """The UTC date for a count of GPS seconds since 1980-01-06"""
    latest = max(leapseconds)
    for offset, (start, end) in leapseconds.items():
        try:
            utc_date = epochs[1980] + timedelta(seconds=gps_seconds - (offset - 19))
        except OverflowError:
            continue
        if start <= utc_date and (utc_date < end or offset == latest):
            return utc_date
    return None


@decoder("gps")
def from_gps(timestamp, guess=False):
    """Convert a GPS timestamp to a date (involves leap seconds)"""
    if not is_digits(timestamp, 10 if guess else 12, 10 if guess else 1):
        return ""
    utc_date = gps_to_utc(int(timestamp))
    return date_string(utc_date) if utc_date else ""


@encoder("gps")
def to_gps(dt_obj):
    """Convert a date to a GPS timestamp (involves leap seconds)"""
    return str(seconds_since(dt_obj, epochs[1980]) + leap_offset(dt_obj) - 19)


@decoder("eitime")
def from_eitime(timestamp):
    """Convert a Google ei URL timestamp"""
    if not timestamp or not all(char in URLSAFE_CHARS for char in timestamp):
        return ""
    try:
        decoded = base64.urlsafe_b64decode(timestamp + "=" * (-len(timestamp) % 4))
    except base64.binascii.Error:
        return ""
    seconds = int.from_bytes(struct.pack("<L", int(decoded.hex()[:8], 16)), "big")
    return date_text(epochs[1970], seconds * 10**6)


@encoder("eitime")
def to_eitime(dt_obj):
    """Try to convert a value to an ei URL timestamp"""
    unix_hex = struct.pack("<L", seconds_since(dt_obj, epochs[1970]))
    return base64.urlsafe_b64encode(unix_hex).decode("UTF-8").strip("=")


def gsm_quarters(octet):
    """
    The signed quarter hours of the offset in a GSM time zone byte.
    The byte is two BCD digits with their nibbles swapped and the sign in bit 3 of the tens digit.
    Offsets from -12 hours to +14 hours are real.
    """
    value = int(octet, 16)
    tens, ones = value & 0x0F, value >> 4
    negative = bool(tens & 8)
    quarters = (tens & 7) * 10 + ones
    if ones > 9 or not (quarters <= 56 if not negative else quarters <= 48):
        return None
    return -quarters if negative else quarters


@decoder("gsm")
def from_gsm(timestamp, guess=False):
    """Convert a GSM timestamp to a date"""
    if not is_hex(timestamp, 14, 14) or not is_digits(timestamp[:12], 12, 12):
        return ""
    quarters = gsm_quarters(timestamp[12:14])
    if quarters is None or (guess and abs(quarters) > 48):
        return ""
    year, month, day, hour, minute, second = [
        int(timestamp[i : i + 2][::-1]) for i in range(0, 12, 2)
    ]
    # the two digit year is 1990 to 2089
    year += 2000 if year < 90 else 1900
    text = fields_date_text(year, month, day, hour, minute, second)
    if not text:
        return ""
    return text, utc_offset_label(ts_types["gsm"].time_zone, quarters)


@encoder("gsm")
def to_gsm(dt_obj):
    """Convert a timestamp to a GSM timestamp"""
    quarters = int(dt_obj.utcoffset().total_seconds()) // 900
    tens, ones = divmod(abs(quarters), 10)
    if quarters < 0:
        tens |= 8
    fields = [
        f"{dt_obj.year % 100:02d}",
        f"{dt_obj.month:02d}",
        f"{dt_obj.day:02d}",
        f"{dt_obj.hour:02d}",
        f"{dt_obj.minute:02d}",
        f"{dt_obj.second:02d}",
        f"{tens:X}{ones:X}",
    ]
    return "".join(field[::-1] for field in fields)


@decoder("vm")
def from_vm(timestamp, guess=False):
    """Convert from a .vmsd createTimeHigh/createTimeLow timestamp"""
    if not re.fullmatch(r"-?[0-9]{1,30},-?[0-9]{1,30}", timestamp):
        return ""
    high, low = [int(part) for part in timestamp.split(",")]
    if not -(2**31) <= low < 2**31:  # low is a signed 32-bit int
        return ""
    microseconds = high * 2**32 + (low & 0xFFFFFFFF)
    if guess and microseconds >= 32536799999 * 10**6:
        return ""
    return date_text(epochs[1970], microseconds)


@encoder("vm")
def to_vm(dt_obj):
    """Convert date to a .vmsd createTime* value"""
    high, low = divmod(microseconds_since(dt_obj, epochs[1970]), 2**32)
    signed_low = struct.unpack("i", struct.pack("I", low))[0]
    return f"{high},{signed_low}"


@decoder("tiktok")
def from_tiktok(timestamp, guess=False):
    """Convert a TikTok URL value to a date/time"""
    if not is_digits(timestamp, 20, 19 if guess else 1):
        return ""
    seconds = int(timestamp) >> 32
    if guess and seconds >= 32536799999:
        return ""
    return date_text(epochs[1970], seconds * 10**6)


@encoder("tiktok")
def to_tiktok(dt_obj):
    """Convert a date/time to a TikTok timestamp"""
    return str(seconds_since(dt_obj, epochs[1970]) << 32)


@decoder("twitter")
def from_twitter(timestamp, guess=False):
    """Convert a Twitter URL value to a date/time"""
    if not is_digits(timestamp, 20, 18 if guess else 1):
        return ""
    unix_milli = (int(timestamp) >> 22) + 1288834974657
    if guess and unix_milli >= 32536799999000:
        return ""
    return date_text(epochs[1970], unix_milli * 1000)


@encoder("twitter")
def to_twitter(dt_obj):
    """Convert a date/time value to a Twitter value"""
    unix_milli = microseconds_since(dt_obj, epochs[1970]) // 1000
    return str((unix_milli - 1288834974657) << 22)


@decoder("discord")
def from_discord(timestamp, guess=False):
    """Convert a Discord URL value to a date/time"""
    if not is_digits(timestamp, 20, 18 if guess else 1):
        return ""
    unix_milli = (int(timestamp) >> 22) + 1420070400000
    if guess and unix_milli >= 32536799999000:
        return ""
    return date_text(epochs[1970], unix_milli * 1000)


@encoder("discord")
def to_discord(dt_obj):
    """Convert a date/time to a Discord URL value"""
    unix_milli = microseconds_since(dt_obj, epochs[1970]) // 1000
    return str((unix_milli - 1420070400000) << 22)


@decoder("ksalnum")
def from_ksalnum(timestamp):
    """Extract a timestamp from a KSUID alpha-numeric value"""
    if len(str(timestamp)) != 27 or not all(
        char in KSALNUM_CHARS for char in timestamp
    ):
        return ""
    value = 0
    for char in timestamp:
        value = value * 62 + KSALNUM_CHARS.index(char)
    if value >= 1 << 160:
        return ""
    seconds = int.from_bytes(value.to_bytes(20, "big")[0:4], "big") + epochs["kstime"]
    return date_text(epochs[1970], seconds * 10**6)


@encoder("ksalnum")
def to_ksalnum(dt_obj):
    """Convert a date/time to a KSUID alpha-numeric value"""
    ks_time = seconds_since(dt_obj, epochs[1970]) - epochs["kstime"]
    big_int = int.from_bytes(ks_time.to_bytes(4, "big") + os.urandom(16), "big")
    out_ksalnum = ""
    while big_int > 0:
        big_int, rem = divmod(big_int, 62)
        out_ksalnum = KSALNUM_CHARS[rem] + out_ksalnum
    return out_ksalnum.rjust(27, "0")


@decoder("mastodon")
def from_mastodon(timestamp, guess=False):
    """Convert a Mastodon value to a date/time"""
    if not is_digits(timestamp, 20, 18 if guess else 1):
        return ""
    unix_milli = int(timestamp) >> 16
    if guess and unix_milli // 1000 >= 32536799999:
        return ""
    return date_text(epochs[1970], unix_milli * 1000)


@encoder("mastodon")
def to_mastodon(dt_obj):
    """Convert a date/time to a Mastodon value"""
    return str((microseconds_since(dt_obj, epochs[1970]) // 1000) << 16)


@decoder("metasploit")
def from_metasploit(timestamp):
    """Convert a Metasploit Payload UUID value to a date/time"""
    meta_format = "8sBBBBBBBB"
    if len(str(timestamp)) < 22 or not all(char in URLSAFE_CHARS for char in timestamp):
        return ""
    raw = base64.urlsafe_b64decode(timestamp[0:22] + "==")
    if len(raw) < struct.calcsize(meta_format):
        return ""
    _, xor1, xor2, _, _, ts1, ts2, ts3, ts4 = struct.unpack(meta_format, raw)
    (seconds,) = struct.unpack(
        ">I", bytes([ts1 ^ xor1, ts2 ^ xor2, ts3 ^ xor1, ts4 ^ xor2])
    )
    return date_text(epochs[1970], seconds * 10**6)


@decoder("sony")
def from_sony(timestamp, guess=False):
    """Convert a Sonyflake value to a date/time"""
    if not is_hex(timestamp, 15 if guess else 16, 15 if guess else 1):
        return ""
    units = (int(timestamp, 16) >> 24) + 140952960000
    return date_text(epochs[1970], units * 10000)


@encoder("sony")
def to_sony(dt_obj):
    """Convert a date/time to a Sonyflake value"""
    return f"{(microseconds_since(dt_obj, _utc(2014, 9, 1)) // 10000) << 24:x}"


@decoder("stardatetng")
def from_stardatetng(timestamp, guess=False):
    """Convert a Star Trek TNG Stardate to a date"""
    shape = r"[0-9]{5}\.[0-9]" if guess else r"[0-9]{1,7}(\.[0-9]{1,6})?"
    if not re.fullmatch(shape, timestamp):
        return ""
    return date_text(
        _STARDATE_TNG_ORIGIN, round(Fraction(timestamp) * _STARDATE_TNG_UNIT)
    )


@encoder("stardatetng")
def to_stardatetng(dt_obj):
    """Convert a date to a Star Trek TNG Stardate, to a tenth"""
    tenths = round(
        Fraction(microseconds_since(dt_obj, _STARDATE_TNG_ORIGIN), _STARDATE_TNG_UNIT)
        * 10
    )
    return f"{tenths // 10}.{tenths % 10}"


@decoder("stardatetos")
def from_stardatetos(timestamp, guess=False):
    """Convert a Star Trek TOS Stardate to a date"""
    shape = r"[0-9]{4}\.[0-9]{1,2}" if guess else r"[0-9]{1,8}(\.[0-9]{1,6})?"
    if not re.fullmatch(shape, timestamp):
        return ""
    return date_text(
        _STARDATE_TOS_ORIGIN, math.ceil(Fraction(timestamp) * _STARDATE_TOS_UNIT)
    )


@encoder("stardatetos")
def to_stardatetos(dt_obj):
    """Convert a date to a Star Trek TOS Stardate, cut to hundredths"""
    hundredths = math.floor(
        microseconds_since(dt_obj, _STARDATE_TOS_ORIGIN) / _STARDATE_TOS_UNIT * 100
    )
    return f"{hundredths // 100}.{hundredths % 100:02d}"


@decoder("uuid")
def from_uuid(timestamp):
    """Convert a UUID value to date/time"""
    uuid_lower = timestamp.lower()
    if not re.match(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uuid_lower
    ):
        return ""
    u_data = uuid.UUID(uuid_lower)
    if u_data.version != 1:
        return ""
    return date_text(epochs[1582], units_to_microseconds(u_data.time, 10**7))


@encoder("uuid")
def to_uuid(dt_obj):
    """Convert a date/time value to a UUID"""
    ticks = microseconds_since(dt_obj, epochs[1582]) * 10
    node = uuid.getnode()
    clock_seq = node & 0x3FFF
    return str(
        uuid.UUID(
            fields=(
                ticks & 0xFFFFFFFF,
                (ticks >> 32) & 0xFFFF,
                ((ticks >> 48) & 0x0FFF) | (1 << 12),
                (clock_seq >> 8) | 0x80,
                clock_seq & 0xFF,
                node,
            )
        )
    )


@decoder("dhcp6")
def from_dhcp6(timestamp):
    """Convert a DHCPv6 DUID value to date/time"""
    if len(timestamp) < 28 or not is_hex(timestamp, len(timestamp)):
        return ""
    return date_text(epochs[2000], int(timestamp[8:16], 16) * 10**6)


@encoder("dhcp6")
def to_dhcp6(dt_obj):
    """Convert a timestamp to a DHCP DUID value"""
    return f"00010001{struct.pack('>L', seconds_since(dt_obj, epochs[2000])).hex()}000000000000"


@decoder("dotnet")
def from_dotnet(timestamp, guess=False):
    """Convert a .NET DateTime Ticks value to date/time"""
    if not is_digits(timestamp, 18 if guess else 19, 18 if guess else 1):
        return ""
    if (
        guess
        and not epochs["ticks"]
        <= int(timestamp)
        < epochs["ticks"] + 32536799999 * 10**7
    ):
        return ""
    return date_text(epochs[1], units_to_microseconds(int(timestamp), 10**7))


@encoder("dotnet")
def to_dotnet(dt_obj):
    """Convert date to a .NET DateTime Ticks value"""
    return str(microseconds_since(dt_obj, epochs[1]) * 10)


@decoder("gbound")
def from_gbound(timestamp, guess=False):
    """Convert a GMail Boundary value to date/time"""
    if not is_hex(timestamp, 28, 28):
        return ""
    working_value = timestamp[12:26]
    end = working_value[:6]
    begin = working_value[6:14]
    full_dec = int(begin + end, 16)
    if guess and full_dec >= 32536799999 * 10**6:
        return ""
    return date_text(epochs[1970], full_dec)


@encoder("gbound")
def to_gbound(dt_obj):
    """Convert date to a GMail Boundary value"""
    to_int = f"{microseconds_since(dt_obj, epochs[1970]):014x}"
    return f"000000000000{to_int[8:]}{to_int[:8]}00"


@decoder("gmsgid")
def from_gmsgid(timestamp, guess=False):
    """Convert a GMail Message ID to a date/time value"""
    gmsgid = str(timestamp)
    if is_digits(gmsgid, 19, 19):
        gmsgid = f"{int(gmsgid):x}"
    if not is_hex(gmsgid, 16 if guess else 17, 16 if guess else 6):
        return ""
    return date_text(epochs[1970], int(gmsgid[:-5], 16) * 1000)


@encoder("gmsgid")
def to_gmsgid(dt_obj):
    """Convert date to a GMail Message ID value"""
    return f"{microseconds_since(dt_obj, epochs[1970]) // 1000:x}00000"


@decoder("moto")
def from_moto(timestamp):
    """Convert a Motorola 6-byte hex timestamp to a date"""
    if not is_hex(timestamp, 12, 12):
        return ""
    year, month, day, hour, minute, second = bytes.fromhex(timestamp)
    return fields_date_text(year + 1970, month, day, hour, minute, second)


@encoder("moto")
def to_moto(dt_obj):
    """Convert a date to Motorola's 6-byte hex timestamp"""
    utc = dt_obj.astimezone(timezone.utc)
    return bytes(
        [utc.year - 1970, utc.month, utc.day, utc.hour, utc.minute, utc.second]
    ).hex()


def nokia_date_text(value, guess):
    """
    The date of a Nokia 4-byte value, which counts the seconds before
    2050-01-01 down from 4294967295.
    """
    seconds_before_2050 = 4294967295 - value
    if guess and seconds_before_2050 > (epochs[2050] - epochs[1970]).days * 86400:
        return ""
    return date_text(epochs[2050], -seconds_before_2050 * 10**6)


@decoder("nokia")
def from_nokia(timestamp, guess=False):
    """Convert a Nokia 4-byte value to date/time"""
    if not is_hex(timestamp, 8, 8):
        return ""
    return nokia_date_text(int(timestamp, 16), guess)


@encoder("nokia")
def to_nokia(dt_obj):
    """Convert a date/time value to a Nokia 4-byte timestamp"""
    return f"{4294967295 + seconds_since(dt_obj, epochs[2050]):08x}"


@decoder("nokiale")
def from_nokiale(timestamp, guess=False):
    """Convert a little-endian Nokia 4-byte value to date/time"""
    if not is_hex(timestamp, 8, 8):
        return ""
    return nokia_date_text(int.from_bytes(bytes.fromhex(timestamp), "little"), guess)


@encoder("nokiale")
def to_nokiale(dt_obj):
    """Convert a date/time value to a little-endian Nokia 4-byte timestamp"""
    return struct.pack("<I", 4294967295 + seconds_since(dt_obj, epochs[2050])).hex()


@decoder("ns40")
def from_ns40(timestamp):
    """Convert a Nokia S40 7-byte value to a time/time"""
    if not is_hex(timestamp, 14, 14):
        return ""
    return fields_date_text(*struct.unpack(">HBBBBB", bytes.fromhex(timestamp)))


@encoder("ns40")
def to_ns40(dt_obj):
    """Convert a date/time value to a Nokia S40 7-byte timestamp"""
    utc = dt_obj.astimezone(timezone.utc)
    return struct.pack(
        ">HBBBBB", utc.year, utc.month, utc.day, utc.hour, utc.minute, utc.second
    ).hex()


@decoder("ns40le")
def from_ns40le(timestamp):
    """Convert a little-endian Nokia S40 7-byte value to a date/time"""
    if not is_hex(timestamp, 14, 14):
        return ""
    return fields_date_text(*struct.unpack("<HBBBBB", bytes.fromhex(timestamp)))


@encoder("ns40le")
def to_ns40le(dt_obj):
    """Convert a date/time value to a little-endian Nokia S40 7-byte timestamp"""
    utc = dt_obj.astimezone(timezone.utc)
    return struct.pack(
        "<HBBBBB", utc.year, utc.month, utc.day, utc.hour, utc.minute, utc.second
    ).hex()


def bitwise_date_text(value):
    """The date in a value whose bits are the year, month (4), day (5), hour (5) and minute (6)"""
    return fields_date_text(
        value >> 20,
        (value >> 16) & 15,
        (value >> 11) & 31,
        (value >> 6) & 31,
        value & 63,
    )


def bitwise_value(dt_obj):
    """The value of a date in the bits that bitwise_date_text reads"""
    return (
        (dt_obj.year << 20)
        + (dt_obj.month << 16)
        + (dt_obj.day << 11)
        + (dt_obj.hour << 6)
        + dt_obj.minute
    )


@decoder("bitdec")
def from_bitdec(timestamp, guess=False):
    """Convert a 10-digit Bitwise Decimal value to a date/time"""
    if not is_digits(str(timestamp), 10, 10 if guess else 1):
        return ""
    return bitwise_date_text(int(timestamp))


@encoder("bitdec")
def to_bitdec(dt_obj):
    """Convert a date/time value to a Bitwise Decimal timestamp"""
    return str(bitwise_value(dt_obj))


@decoder("bitdate")
def from_bitdate(timestamp, guess=False):
    """Convert a Samsung/LG 4-byte hex timestamp to a date/time"""
    if not is_hex(str(timestamp), 8, 8):
        return ""
    value = int.from_bytes(bytes.fromhex(timestamp), "little")
    if guess and not 1900 <= value >> 20 < 2500:
        return ""
    return bitwise_date_text(value)


@encoder("bitdate")
def to_bitdate(dt_obj):
    """Convert a date/time value to a Samsung/LG timestamp"""
    return struct.pack("<I", bitwise_value(dt_obj)).hex()


@decoder("ksdec")
def from_ksdec(timestamp, guess=False):
    """Convert a KSUID decimal value to a date"""
    if not is_digits(timestamp, 9 if guess else 10, 9 if guess else 1):
        return ""
    if int(timestamp) > 0xFFFFFFFF:
        return ""
    return date_text(epochs[1970], (int(timestamp) + epochs["kstime"]) * 10**6)


@encoder("ksdec")
def to_ksdec(dt_obj):
    """Convert date to a KSUID decimal value"""
    return str(seconds_since(dt_obj, epochs[1970]) - epochs["kstime"])


@decoder("biomehex")
def from_biomehex(timestamp, guess=False):
    """Convert an Apple Biome Hex value to a date, from either byte order"""
    biomehex = str(timestamp)
    if not is_hex(biomehex, 16, 16):
        return ""
    seconds = biome_seconds(bytes.fromhex(biomehex))
    if guess and not seconds < 1e17:
        return ""
    return seconds_to_date_text(epochs[2001], seconds)


@encoder("biomehex")
def to_biomehex(dt_obj):
    """Convert a date/time to an Apple Biome Hex value"""
    return struct.pack(">d", (dt_obj - epochs[2001]).total_seconds()).hex()


@decoder("biome64")
def from_biome64(timestamp, guess=False):
    """Convert a 64-bit decimal value to a date/time value"""
    if not is_digits(timestamp, 20, 19 if guess else 1) or int(timestamp) >= 2**64:
        return ""
    seconds = struct.unpack("<d", int(timestamp).to_bytes(8, "little"))[0]
    if guess and not seconds < 1e17:
        return ""
    return seconds_to_date_text(epochs[2001], seconds)


@encoder("biome64")
def to_biome64(dt_obj):
    """Convert a date/time value to a 64-bit decimal Biome value"""
    seconds = (dt_obj - epochs[2001]).total_seconds()
    return str(int.from_bytes(struct.pack(">d", seconds), "big"))


@decoder("s32")
def from_s32(timestamp, guess=False):
    """Convert an S32 timestamp to a date/time value"""
    timestamp = str(timestamp)
    if len(timestamp) != 9 or not all(char in S32_CHARS for char in timestamp):
        return ""
    milliseconds = 0
    for char in timestamp:
        milliseconds = milliseconds * 32 + S32_CHARS.index(char)
    if guess and milliseconds >= 32536799999 * 10**3:
        return ""
    return date_text(epochs[1970], milliseconds * 1000)


@encoder("s32")
def to_s32(dt_obj):
    """Convert a date/time to an S32-encoded timestamp"""
    milliseconds = microseconds_since(dt_obj, epochs[1970]) // 1000
    result = ""
    while milliseconds:
        milliseconds, index = divmod(milliseconds, 32)
        result = S32_CHARS[index] + result
    return result.rjust(9, S32_CHARS[0])


@decoder("apache")
def from_apache(timestamp, guess=False):
    """Convert an Apache hex timestamp to a date/time value

    This value has 13 hex characters, and does not fit a byte boundary
    """
    timestamp = str(timestamp)
    if not is_hex(timestamp, 13 if guess else 15, 13 if guess else 1):
        return ""
    return date_text(epochs[1970], int(timestamp, 16))


@encoder("apache")
def to_apache(dt_obj):
    """Convert a date/time to an Apache cookie value"""
    return f"{microseconds_since(dt_obj, epochs[1970]):x}"


@decoder("leb128hex")
def from_leb128hex(timestamp, guess=False):
    """Convert a LEB 128 hex value to a date"""
    if not timestamp or len(timestamp) % 2 or not is_hex(timestamp, len(timestamp)):
        return ""
    unix_milli = 0
    shift = 0
    for byte_val in bytes.fromhex(timestamp):
        unix_milli |= (byte_val & 0x7F) << shift
        if (byte_val & 0x80) == 0:
            break
        shift += 7
    if guess and len(str(unix_milli)) != 13:
        return ""
    return date_text(epochs[1970], unix_milli * 1000)


@encoder("leb128hex")
def to_leb128hex(dt_obj):
    """Convert a date to a LEB128 hex value."""
    unix_milli = microseconds_since(dt_obj, epochs[1970]) // 1000
    byte_list = []
    while True:
        byte_val = unix_milli & 0x7F
        unix_milli >>= 7
        if unix_milli != 0:
            byte_val |= 0x80
        byte_list.append(byte_val)
        if unix_milli == 0:
            break
    return bytes(byte_list).hex()


@decoder("juliandec")
def from_juliandec(timestamp):
    """Convert Julian Date decimal value to a date"""
    if not re.fullmatch(r"[0-9]{7}\.[0-9]{0,10}", timestamp):
        return ""
    whole, _, fraction = timestamp.partition(".")
    julian_date = Fraction(int(whole + fraction), 10 ** len(fraction))
    return days_to_date_text(epochs[1970], julian_date - _JULIAN_UNIX_EPOCH)


@encoder("juliandec")
def to_juliandec(dt_obj):
    """Convert a date to a Julian Date"""
    julian_date = _JULIAN_UNIX_EPOCH + Fraction(
        microseconds_since(dt_obj, epochs[1970]), _DAY_MICROSECONDS
    )
    whole, decimals = divmod(round(julian_date * 10**10), 10**10)
    out_julian_dec = f"{whole}.{decimals:010d}".rstrip("0")
    return out_julian_dec + "0" if out_julian_dec.endswith(".") else out_julian_dec


"""
The top bit of the 3 byte day number is free, as the day numbers of years 1 to 9999 stay below
0x800000. When it is set, the 4 bytes are a fraction of exactly 10 digits, so a leading zero
(a fraction under 0.1) is kept. This sets it for those fractions.
Values from elsewhere do not carry it and are read as plain digits.
This is a makeshift method to ensure the leading zero following a decimal place for a fraction
under 0.1 is tracked and applied accordingly.
This is not a "documented" method, just an attempt to retain accuracy.
"""


def julian_hex_to_date(day_field, digits):
    """The UTC date for the day number and fraction digits of a 7 byte Julian date."""
    if day_field & _JULIAN_FIXED_DIGITS:
        day, fraction = day_field ^ _JULIAN_FIXED_DIGITS, Fraction(digits, 10**10)
    else:
        day, fraction = day_field, Fraction(digits, 10 ** len(str(digits)))
    microseconds = round((day + fraction - _JULIAN_UNIX_EPOCH) * _DAY_MICROSECONDS)
    return epochs[1970] + timedelta(microseconds=microseconds)


def julian_hex_parts(dt_obj):
    """The day number and fraction digits to store for a date in 7 bytes."""
    jd_date = _JULIAN_UNIX_EPOCH + Fraction(
        microseconds_since(dt_obj, epochs[1970]), _DAY_MICROSECONDS
    )
    day, fraction = divmod(jd_date, 1)
    digits = round(fraction * 10**10)
    if digits == 10**10:
        return day + 1, 0
    if digits == 0:
        return day, 0
    if digits < 10**9:
        return day | _JULIAN_FIXED_DIGITS, digits
    if digits <= 0xFFFFFFFF:
        return day, digits
    digits = round(fraction * 10**9)
    if digits == 10**9:
        return day + 1, 0
    return day, digits


@decoder("julianhex")
def from_julianhex(timestamp, guess=False):
    """Convert Julian Date hex value to a date"""
    if not is_hex(timestamp, 14, 14):
        return ""
    try:
        utc_date = julian_hex_to_date(int(timestamp[:6], 16), int(timestamp[6:], 16))
    except OverflowError:
        return ""
    if guess and utc_date.year > 3000:
        return ""
    return date_string(utc_date)


@encoder("julianhex")
def to_julianhex(dt_obj):
    """Convert a date to a Julian Hex Date"""
    day_field, digits = julian_hex_parts(dt_obj.astimezone(timezone.utc))
    return f"{day_field:06x}{digits:08x}"


@decoder("semioctet")
def from_semioctet(timestamp):
    """Convert from a Semi-Octet decimal value to a date"""
    if not is_digits(str(timestamp), 12, 12):
        return ""
    year, month, day, hour, minute, second = [
        int(timestamp[i : i + 2][::-1]) for i in range(0, 12, 2)
    ]
    return fields_date_text(year + 2000, month, day, hour, minute, second)


@encoder("semioctet")
def to_semioctet(dt_obj):
    """Convert a date to a Semi-Octet decimal value"""
    fields = [
        f"{dt_obj.year - 2000:02d}",
        f"{dt_obj.month:02d}",
        f"{dt_obj.day:02d}",
        f"{dt_obj.hour:02d}",
        f"{dt_obj.minute:02d}",
        f"{dt_obj.second:02d}",
    ]
    return "".join(field[::-1] for field in fields)


def urlsafe_protobuf(text):
    """
    The message in a urlsafe base64 encoded protobuf.
    A leading 0, 1 or 2 is skipped, as a prefix that is not part of the base64.
    """
    if not text or not all(char in URLSAFE_CHARS for char in text):
        return None
    if text[0].isdigit() and int(text[0]) in range(0, 3):
        text = text[1:]
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        message, _ = blackboxprotobuf.decode_message(raw)
    except (base64.binascii.Error, DecoderException, TypeError):
        return None
    return message


@decoder("ved")
def from_ved(timestamp):
    """Convert from a VED urlsafe base64 encoded protobuf"""
    message = urlsafe_protobuf(timestamp)
    if message is None:
        return ""
    ved_field = message.get("13")
    ved_inner = ved_field.get("1") if isinstance(ved_field, dict) else None
    ved_ts = ved_inner.get("1") if isinstance(ved_inner, dict) else None
    if not isinstance(ved_ts, int):
        return ""
    return date_text(epochs[1970], ved_ts)


@decoder("gclid")
def from_gclid(timestamp):
    """Convert from a gclid urlsafe base64 encoded protobuf"""
    message = urlsafe_protobuf(timestamp)
    if message is None:
        return ""
    gclid_ts = message.get("1")
    if not isinstance(gclid_ts, int) or len(str(gclid_ts)) != 16:
        return ""
    return date_text(epochs[1970], gclid_ts)


@decoder("linkedin")
def from_linkedin(timestamp, guess=False):
    """Convert from a LinkedIn Post Activity ID"""
    if not is_digits(str(timestamp), 20, 19 if guess else 1):
        return ""
    return date_text(epochs[1970], (int(timestamp) >> 22) * 1000)


@encoder("linkedin")
def to_linkedin(dt_obj):
    """Convert a date/time to a LinkedIn Post Activity ID"""
    padding = "1011100101100100110110"
    unix_milli = microseconds_since(dt_obj, epochs[1970]) // 1000
    return str((unix_milli << len(padding)) | int(padding, 2))


@decoder("ulid")
def from_ulid(timestamp, guess=False):
    """Convert from a ULID value"""
    if not all(char in BASE32_CHARS for char in timestamp) or len(str(timestamp)) != 26:
        return ""
    try:
        unix_milli = int.from_bytes(ULID.parse(timestamp).bytes[:6], "big")
    except ValueError:
        return ""
    if guess and unix_milli >= 32536799999 * 10**3:
        return ""
    return date_text(epochs[1970], unix_milli * 1000)


@encoder("ulid")
def to_ulid(dt_obj):
    """Convert a date to a ULID value"""
    unix_milli = microseconds_since(dt_obj, epochs[1970]) // 1000
    return str(ULID.from_bytes(unix_milli.to_bytes(6, "big") + os.urandom(10)))


@decoder("dttm")
def from_dttm(timestamp, guess=False):
    """Convert a Microsoft DTTM timestamp to a date"""
    if not is_hex(timestamp, 8, 8):
        return ""
    value = int(timestamp, 16)
    day_of_week, year = value >> 29, ((value >> 20) & 0x1FF) + 1900
    if day_of_week > 6 or (guess and year >= 2050):
        return ""
    return fields_date_text(
        year, (value >> 16) & 15, (value >> 11) & 31, (value >> 6) & 31, value & 63
    )


@encoder("dttm")
def to_dttm(dt_obj):
    """Convert a date to a Microsoft DTTM timestamp"""
    day_of_week = dt_obj.isoweekday() % 7
    value = (
        day_of_week << 29
        | (dt_obj.year - 1900) << 20
        | dt_obj.month << 16
        | dt_obj.day << 11
        | dt_obj.hour << 6
        | dt_obj.minute
    )
    return struct.pack(">I", value).hex()


@decoder("bcd")
def from_bcd(timestamp):
    """Convert a Binary Coded Decimal timestamp to a date"""
    if not is_digits(timestamp, 12, 12):
        return ""
    year, month, day, hour, minute, second = [
        int(timestamp[i : i + 2]) for i in range(0, 12, 2)
    ]
    return fields_date_text(year + 2000, month, day, hour, minute, second)


@encoder("bcd")
def to_bcd(dt_obj):
    """Convert a date/time to a Binary Coded Decimal"""
    return (
        f"{dt_obj.year - 2000:02d}{dt_obj.month:02d}{dt_obj.day:02d}"
        f"{dt_obj.hour:02d}{dt_obj.minute:02d}{dt_obj.second:02d}"
    )


@decoder("dvr")
def from_dvr(timestamp):
    """Convert a DVR (WFS / DHFS) file system timestamp to a date"""
    if not is_hex(timestamp, 8, 8):
        return ""
    value = int(timestamp, 16)
    return fields_date_text(
        (value >> 26) + 2000,
        (value >> 22) & 15,
        (value >> 17) & 31,
        (value >> 12) & 31,
        (value >> 6) & 63,
        value & 63,
    )


@encoder("dvr")
def to_dvr(dt_obj):
    """Convert a date to a DVR (WFS / DHFS) file system timestamp"""
    value = (
        (dt_obj.year - 2000) << 26
        | dt_obj.month << 22
        | dt_obj.day << 17
        | dt_obj.hour << 12
        | dt_obj.minute << 6
        | dt_obj.second
    )
    return struct.pack(">I", value).hex()


@decoder("logtime")
def from_logtime(timestamp, guess=False):
    """Convert a 16 character hex log time, of seconds to the year from 1900 in 6 bytes, to a date"""
    if not is_hex(str(timestamp), 16, 16):
        return ""
    second, minute, hour, day, month, year = bytes.fromhex(timestamp)[:6]
    if guess and year + 1900 < 2000:
        return ""
    return fields_date_text(year + 1900, month, day, hour, minute, second)


@encoder("logtime")
def to_logtime(dt_obj):
    """Convert a date to a 16 character hex log time"""
    utc = dt_obj.astimezone(timezone.utc)
    fields = [utc.second, utc.minute, utc.hour, utc.day, utc.month, utc.year - 1900]
    return "".join(f"{field:02X}" for field in fields) + "0000"


@decoder("ntp")
def from_ntp(timestamp, guess=False):
    """Convert an NTP seconds value, with or without a fraction, to a date"""
    parts = str(timestamp).split(".")
    if len(parts) > 2 or not is_digits(parts[0], 12):
        return ""
    if len(parts) == 2 and not is_digits(parts[1], 30):
        return ""
    if guess and len(parts) == 1 and len(parts[0]) != 10:
        return ""
    fraction = parts[1] if len(parts) == 2 else ""
    microseconds = units_to_microseconds(int(parts[0] + fraction), 10 ** len(fraction))
    if guess and microseconds < epochs["ntp"] * 10**6:
        return ""
    return date_text(_utc(1900), microseconds)


@encoder("ntp")
def to_ntp(dt_obj):
    """Convert a date to an NTP seconds value with its fraction"""
    seconds, fraction = divmod(microseconds_since(dt_obj, _utc(1900)), 10**6)
    return f"{seconds}.{f'{fraction:06d}'.rstrip('0') or '0'}"


@decoder("tai")
def from_tai(timestamp, guess=False):
    """Convert TAI Seconds value to a date"""
    if not is_digits(timestamp, 10 if guess else 12, 10 if guess else 1):
        return ""
    return date_text(epochs[1970], (int(timestamp) - epochs["tai"]) * 10**6)


@encoder("tai")
def to_tai(dt_obj):
    """Convert date to a TAI Seconds value"""
    return str(seconds_since(dt_obj, epochs[1970]) + epochs["tai"])


@decoder("taimilli")
def from_taimilli(timestamp, guess=False):
    """Convert TAI Millisecond value to a date"""
    if not is_digits(str(timestamp), 13 if guess else 15, 13 if guess else 1):
        return ""
    return date_text(epochs[1970], (int(timestamp) - epochs["tai"] * 1000) * 1000)


@encoder("taimilli")
def to_taimilli(dt_obj):
    """Convert date to a TAI Millisecond value"""
    return str(microseconds_since(dt_obj, epochs[1970]) // 1000 + epochs["tai"] * 1000)


@decoder("horolog")
def from_horolog(timestamp):
    """Convert a Horolog value to a date"""
    parts = str(timestamp).split(",")
    if len(parts) != 2:
        return ""
    try:
        days, secs = int(parts[0]), int(parts[1])
    except ValueError:
        return ""
    if len(str(days)) != 5 and not str(days).isdigit() and not str(secs).isdigit():
        return ""
    return date_text(epochs[1840], (days * 86400 + secs) * 10**6)


@encoder("horolog")
def to_horolog(dt_obj):
    """Convert date to a Horolog value"""
    days = (dt_obj.replace(tzinfo=None) - epochs[1840].replace(tzinfo=None)).days
    secs = (dt_obj.hour * 3600) + (dt_obj.minute * 60) + dt_obj.second
    return f"{days},{secs}"


@decoder("mars")
def from_mars(timestamp, guess=False):
    """Convert a Mars Sol Date value to a date"""
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)", timestamp)
    if not match or not is_digits(
        str(int(match[1])), 5 if guess else 7, 5 if guess else 1
    ):
        return ""
    msd = Fraction(timestamp)
    jd_tt = ((msd + Fraction("0.00096")) - 44796) * Fraction(
        "1.02749125242"
    ) + Fraction("2451549.5")
    jd_utc = jd_tt - (epochs["tai"] + Fraction("32.184")) / 86400
    unix_ts = (jd_utc - Fraction("2440587.5")) * 86400
    if guess and not 0 <= unix_ts < 32536799999:
        return ""
    return seconds_to_date_text(epochs[1970], unix_ts)


@encoder("mars")
def to_mars(dt_obj):
    """Convert date to a Mars Sol Date value"""
    unix_ts = Fraction(microseconds_since(dt_obj, epochs[1970]), 10**6)
    jd_utc = (unix_ts / 86400) + _JULIAN_UNIX_EPOCH
    jd_tt = jd_utc + ((epochs["tai"] + Fraction("32.184")) / 86400)
    msd = (
        ((jd_tt - Fraction("2451549.5")) / Fraction("1.02749125242"))
        + 44796
        - Fraction("0.00096")
    )
    whole, decimals = divmod(round(msd * 10**10), 10**10)
    return f"{whole}.{decimals:010d}"


@decoder("uuid6")
def from_uuid6(timestamp):
    """Convert a version 6 UUID value to date/time"""
    uuid_lower = timestamp.lower()
    if not re.fullmatch(UUID_PATTERN, uuid_lower) or uuid.UUID(uuid_lower).version != 6:
        return ""
    digits = uuid_lower.replace("-", "")
    ticks = int(digits[:12] + digits[13:16], 16)
    return date_text(epochs[1582], units_to_microseconds(ticks, 10**7))


@encoder("uuid6")
def to_uuid6(dt_obj):
    """Convert a date/time value to a version 6 UUID, with a random clock and node"""
    ticks = microseconds_since(dt_obj, epochs[1582]) * 10
    random_bits = int.from_bytes(os.urandom(8), "big")
    clock_seq = (random_bits >> 48) & 0x3FFF
    node = (random_bits & 0xFFFFFFFFFFFF) | (1 << 40)
    return str(
        uuid.UUID(
            fields=(
                ticks >> 28,
                (ticks >> 12) & 0xFFFF,
                0x6000 | (ticks & 0xFFF),
                (clock_seq >> 8) | 0x80,
                clock_seq & 0xFF,
                node,
            )
        )
    )


@decoder("uuid7")
def from_uuid7(timestamp):
    """Convert a version 7 UUID value to date/time"""
    uuid_lower = timestamp.lower()
    if not re.fullmatch(UUID_PATTERN, uuid_lower) or uuid.UUID(uuid_lower).version != 7:
        return ""
    return date_text(epochs[1970], int(uuid_lower[:8] + uuid_lower[9:13], 16) * 1000)


@encoder("uuid7")
def to_uuid7(dt_obj):
    """Convert a date/time value to a version 7 UUID, with random bits after the time"""
    milliseconds = microseconds_since(dt_obj, epochs[1970]) // 1000
    random_bits = int.from_bytes(os.urandom(10), "big")
    rand_a, rand_b = (random_bits >> 62) & 0xFFF, random_bits & (2**62 - 1)
    return str(
        uuid.UUID(int=milliseconds << 80 | 7 << 76 | rand_a << 64 | 0b10 << 62 | rand_b)
    )


@decoder("objectid")
def from_objectid(timestamp, guess=False):
    """Convert a MongoDB ObjectId to a date/time"""
    if not is_hex(timestamp, 24, 24):
        return ""
    seconds = int(timestamp[:8], 16)
    if guess and not 1230768000 <= seconds < 2**31:
        return ""
    return date_text(epochs[1970], seconds * 10**6)


@encoder("objectid")
def to_objectid(dt_obj):
    """Convert a date/time to a MongoDB ObjectId, with 8 random bytes after the seconds"""
    return (
        struct.pack(">I", seconds_since(dt_obj, epochs[1970])).hex()
        + os.urandom(8).hex()
    )


@decoder("unixnano")
def from_unixnano(timestamp, guess=False):
    """Convert Unix Nanosecond value to a date"""
    if not is_digits(timestamp, 19 if guess else 21, 19 if guess else 1):
        return ""
    return date_text(epochs[1970], units_to_microseconds(int(timestamp), 10**9))


@encoder("unixnano")
def to_unixnano(dt_obj):
    """Convert date to a Unix Nanosecond value"""
    return str(microseconds_since(dt_obj, epochs[1970]) * 1000)


@decoder("apfs")
def from_apfs(timestamp, guess=False):
    """Convert an APFS little-endian 64-bit nanosecond value to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    nanoseconds = int.from_bytes(bytes.fromhex(timestamp), "little")
    if guess and not 10**18 <= nanoseconds < 4102444800 * 10**9:
        return ""
    return date_text(epochs[1970], units_to_microseconds(nanoseconds, 10**9))


@encoder("apfs")
def to_apfs(dt_obj):
    """Convert a date to an APFS little-endian 64-bit nanosecond value"""
    return struct.pack("<Q", microseconds_since(dt_obj, epochs[1970]) * 1000).hex()


@decoder("unixsecfrac")
def from_unixsecfrac(timestamp, guess=False):
    """Convert Unix seconds with a fraction to a date"""
    shape = r"[0-9]{10}\.[0-9]{1,9}" if guess else r"[0-9]{1,12}\.[0-9]{1,9}"
    if not re.fullmatch(shape, timestamp):
        return ""
    return date_text(epochs[1970], round(Fraction(timestamp) * 10**6))


@encoder("unixsecfrac")
def to_unixsecfrac(dt_obj):
    """Convert a date to Unix seconds with 6 decimals"""
    seconds, microseconds = divmod(microseconds_since(dt_obj, epochs[1970]), 10**6)
    return f"{seconds}.{microseconds:06d}"


@decoder("instagram")
def from_instagram(timestamp, guess=False):
    """Convert an Instagram ID to a date/time"""
    if not is_digits(timestamp, 20, 19 if guess else 1) or int(timestamp) >= 2**64:
        return ""
    milliseconds = (int(timestamp) >> 23) + _INSTAGRAM_EPOCH_MILLISECONDS
    return date_text(epochs[1970], milliseconds * 1000)


@encoder("instagram")
def to_instagram(dt_obj):
    """Convert a date/time to an Instagram ID, with no shard or sequence"""
    milliseconds = microseconds_since(dt_obj, epochs[1970]) // 1000
    return str((milliseconds - _INSTAGRAM_EPOCH_MILLISECONDS) << 23)


@decoder("firebase")
def from_firebase(timestamp, guess=False):
    """Convert a Firebase Push ID to a date/time"""
    if len(timestamp) != 20 or not all(char in PUSH_CHARS for char in timestamp):
        return ""
    milliseconds = 0
    for char in timestamp[:8]:
        milliseconds = milliseconds * 64 + PUSH_CHARS.index(char)
    if guess and not 1325376000000 <= milliseconds < 2**42:
        return ""
    return date_text(epochs[1970], milliseconds * 1000)


@encoder("firebase")
def to_firebase(dt_obj):
    """Convert a date/time to a Firebase Push ID, with 12 random characters after the time"""
    milliseconds = microseconds_since(dt_obj, epochs[1970]) // 1000
    prefix = ""
    for _ in range(8):
        milliseconds, digit = divmod(milliseconds, 64)
        prefix = PUSH_CHARS[digit] + prefix
    return prefix + "".join(PUSH_CHARS[byte & 63] for byte in os.urandom(12))


@decoder("dotnetbin")
def from_dotnetbin(timestamp, guess=False):
    """Convert a .NET DateTime.ToBinary value to a date/time"""
    if (
        not re.fullmatch(r"-?[0-9]{1,19}", timestamp)
        or not -(2**63) <= int(timestamp) < 2**63
    ):
        return ""
    value = int(timestamp) & 0xFFFFFFFFFFFFFFFF
    if guess and value >> 62 == 0:
        return ""
    ticks = value & _DOTNET_TICKS_MASK
    return date_text(epochs[1], units_to_microseconds(ticks, 10**7))


@encoder("dotnetbin")
def to_dotnetbin(dt_obj):
    """Convert a date to a .NET DateTime.ToBinary value of the UTC kind"""
    return str(_DOTNET_KIND_UTC | microseconds_since(dt_obj, epochs[1]) * 10)


def mssql_date_text(days, ticks, guess):
    """The date of a SQL Server datetime from its days since 1900 and 300ths of a second"""
    if ticks >= _MSSQL_TICKS_PER_DAY:
        return ""
    if (
        guess
        and not (dt(1990, 1, 1) - dt(1900, 1, 1)).days
        <= days
        < (dt(2100, 1, 1) - dt(1900, 1, 1)).days
    ):
        return ""
    return date_text(
        _utc(1900), days * 86400 * 10**6 + units_to_microseconds(ticks, 300)
    )


def mssql_parts(dt_obj):
    """The days since 1900 and 300ths of a second of a date, to the nearest 300th"""
    microseconds = (dt_obj.replace(tzinfo=None) - dt(1900, 1, 1)) // _MICROSECOND
    return divmod(round(Fraction(microseconds * 300, 10**6)), _MSSQL_TICKS_PER_DAY)


@decoder("mssql")
def from_mssql(timestamp, guess=False):
    """Convert a SQL Server datetime, as CAST to binary(8) shows it, to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    days, ticks = struct.unpack(">iI", bytes.fromhex(timestamp))
    return mssql_date_text(days, ticks, guess)


@encoder("mssql")
def to_mssql(dt_obj):
    """Convert a date to a SQL Server datetime, as CAST to binary(8) shows it"""
    days, ticks = mssql_parts(dt_obj)
    return struct.pack(">iI", days, ticks).hex()


@decoder("mssqlle")
def from_mssqlle(timestamp, guess=False):
    """Convert a SQL Server datetime, as it is stored on disk, to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    ticks, days = struct.unpack("<Ii", bytes.fromhex(timestamp))
    return mssql_date_text(days, ticks, guess)


@encoder("mssqlle")
def to_mssqlle(dt_obj):
    """Convert a date to a SQL Server datetime, as it is stored on disk"""
    days, ticks = mssql_parts(dt_obj)
    return struct.pack("<Ii", ticks, days).hex()


@decoder("oracle")
def from_oracle(timestamp, guess=False):
    """Convert an Oracle DATE, as 14 hex characters or the 7 bytes DUMP shows, to a date"""
    if re.fullmatch(r"[0-9]{1,3}(,[0-9]{1,3}){6}", timestamp):
        values = [int(part) for part in timestamp.split(",")]
        if max(values) > 255:
            return ""
    elif is_hex(timestamp, 14, 14):
        values = list(bytes.fromhex(timestamp))
    else:
        return ""
    century, year, month, day, hour, minute, second = values
    full_year = (century - 100) * 100 + year - 100
    if guess and not 1950 <= full_year < 2100:
        return ""
    return fields_date_text(full_year, month, day, hour - 1, minute - 1, second - 1)


@encoder("oracle")
def to_oracle(dt_obj):
    """Convert a date to an Oracle DATE as 14 hex characters"""
    return bytes(
        [
            dt_obj.year // 100 + 100,
            dt_obj.year % 100 + 100,
            dt_obj.month,
            dt_obj.day,
            dt_obj.hour + 1,
            dt_obj.minute + 1,
            dt_obj.second + 1,
        ]
    ).hex()


@decoder("ntp64")
def from_ntp64(timestamp, guess=False):
    """Convert an NTP 64-bit timestamp, 32 bits of seconds and 32 bits of fraction, to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    seconds, fraction = int(timestamp[:8], 16), int(timestamp[8:], 16)
    if guess and seconds < 3155673600:
        return ""
    return date_text(
        _utc(1900), seconds * 10**6 + units_to_microseconds(fraction, 2**32)
    )


@encoder("ntp64")
def to_ntp64(dt_obj):
    """Convert a date to an NTP 64-bit timestamp"""
    total = round(Fraction(microseconds_since(dt_obj, _utc(1900)) * 2**32, 10**6))
    seconds, fraction = divmod(total, 2**32)
    return f"{seconds:08x}{fraction:08x}"


@decoder("symbian")
def from_symbian(timestamp, guess=False):
    """Convert a Symbian TTime, microseconds since the year 0, to a date"""
    if not is_digits(timestamp, 18, 17 if guess else 1):
        return ""
    return date_text(epochs[1970], int(timestamp) - _SYMBIAN_YEAR_ZERO_SECONDS * 10**6)


@encoder("symbian")
def to_symbian(dt_obj):
    """Convert a date to a Symbian TTime"""
    return str(
        microseconds_since(dt_obj, epochs[1970]) + _SYMBIAN_YEAR_ZERO_SECONDS * 10**6
    )


@decoder("garmin")
def from_garmin(timestamp, guess=False):
    """Convert a Garmin FIT date_time to a date"""
    if not is_digits(timestamp, 10, 9 if guess else 1) or int(timestamp) >= _UINT32:
        return ""
    if guess and int(timestamp) < 0x10000000:
        return ""
    return date_text(_utc(1989, 12, 31), int(timestamp) * 10**6)


@encoder("garmin")
def to_garmin(dt_obj):
    """Convert a date to a Garmin FIT date_time"""
    return str(seconds_since(dt_obj, _utc(1989, 12, 31)))


@decoder("ext4")
def from_ext4(timestamp, guess=False):
    """Convert an ext4 inode time to a date"""
    match = re.fullmatch(
        r"(?:0x)?([0-9a-f]{8}):(?:0x)?([0-9a-f]{8})", timestamp.lower()
    )
    if not match:
        return ""
    seconds, extra = int(match[1], 16), int(match[2], 16)
    if seconds >= 2**31:
        seconds -= 2**32
    seconds += (extra & 3) << 32
    nanoseconds = extra >> 2
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if nanoseconds >= 10**9 or (guess and not 946684800 <= seconds < 4102444800):
        return ""
    return date_text(
        epochs[1970], seconds * 10**6 + units_to_microseconds(nanoseconds, 10**9)
    )


@encoder("ext4")
def to_ext4(dt_obj):
    """Convert a date to an ext4 inode time"""
    seconds, microseconds = divmod(microseconds_since(dt_obj, epochs[1970]), 10**6)
    epoch_bits = (seconds + 2**31) >> 32
    low = seconds - (epoch_bits << 32)
    return f"{low & 0xFFFFFFFF:08x}:{(microseconds * 1000 << 2 | epoch_bits):08x}"


def pcap_date_text(seconds, microseconds, guess):
    """The date of the seconds and microseconds in a pcap record header"""
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if microseconds >= 10**6 or (guess and not 946684800 <= seconds < 4102444800):
        return ""
    return date_text(epochs[1970], seconds * 10**6 + microseconds)


@decoder("pcap")
def from_pcap(timestamp, guess=False):
    """Convert a little-endian pcap record time to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    return pcap_date_text(*struct.unpack("<II", bytes.fromhex(timestamp)), guess)


@encoder("pcap")
def to_pcap(dt_obj):
    """Convert a date to a little-endian pcap record time"""
    return struct.pack(
        "<II", *divmod(microseconds_since(dt_obj, epochs[1970]), 10**6)
    ).hex()


@decoder("pcapbe")
def from_pcapbe(timestamp, guess=False):
    """Convert a big-endian pcap record time to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    return pcap_date_text(*struct.unpack(">II", bytes.fromhex(timestamp)), guess)


@encoder("pcapbe")
def to_pcapbe(dt_obj):
    """Convert a date to a big-endian pcap record time"""
    return struct.pack(
        ">II", *divmod(microseconds_since(dt_obj, epochs[1970]), 10**6)
    ).hex()


@decoder("iso9660")
def from_iso9660(timestamp, guess=False):
    """Convert an ISO 9660 7-byte recording date to a date"""
    if not is_hex(timestamp, 14, 14):
        return ""
    year, month, day, hour, minute, second, quarters = struct.unpack(
        "<6Bb", bytes.fromhex(timestamp)
    )
    # when guessing, only the years 1990 to 2099 are taken
    if not -48 <= quarters <= 52 or (guess and not 1990 <= 1900 + year < 2100):
        return ""
    text = fields_date_text(1900 + year, month, day, hour, minute, second)
    return (
        (text, utc_offset_label(ts_types["iso9660"].time_zone, quarters))
        if text
        else ""
    )


@encoder("iso9660")
def to_iso9660(dt_obj):
    """Convert a date to an ISO 9660 7-byte recording date in local time with its UTC offset"""
    quarters = int(dt_obj.utcoffset().total_seconds()) // 900
    if not -48 <= quarters <= 52:
        return ""
    fields = (
        dt_obj.year - 1900,
        dt_obj.month,
        dt_obj.day,
        dt_obj.hour,
        dt_obj.minute,
        dt_obj.second,
    )
    return struct.pack("<6Bb", *fields, quarters).hex()


@decoder("exfatext")
def from_exfatext(timestamp, guess=False):
    """Convert an exFAT time with its 10 ms increment and UTC offset bytes to a date"""
    if not is_hex(timestamp, 12, 12):
        return ""
    value, increment, offset = (
        int(timestamp[:8], 16),
        int(timestamp[8:10], 16),
        int(timestamp[10:], 16),
    )
    moment = dos_datetime(value)
    if moment is None or increment > 199:
        return ""
    # when guessing, only the years up to 2099 are taken
    if guess and moment.year >= 2100:
        return ""
    text = date_string(moment + timedelta(milliseconds=increment * 10))
    if not offset & 0x80:
        return text
    return text, utc_offset_label(
        "UTC", (offset & 0x7F) - (0x80 if offset & 0x40 else 0)
    )  # offset is a signed 7 bit count of 15 minute steps


@encoder("exfatext")
def to_exfatext(dt_obj):
    """Convert a date to an exFAT time with its 10 ms increment"""
    quarters = int(dt_obj.utcoffset().total_seconds()) // 900
    if not -64 <= quarters <= 63:
        return ""
    increment = ((dt_obj.second % 2) * 10**6 + dt_obj.microsecond) // 10000
    return f"{dos_value(dt_obj):08x}{increment:02x}{0x80 | quarters & 0x7F:02x}"


@decoder("tar")
def from_tar(timestamp, guess=False):
    """Convert a tar header time to a date"""
    if not re.fullmatch(r"[0-7]{11}" if guess else r"[0-7]{1,12}", timestamp):
        return ""
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if guess and not 946684800 <= int(timestamp, 8) < 4102444800:
        return ""
    return date_text(epochs[1970], int(timestamp, 8) * 10**6)


@encoder("tar")
def to_tar(dt_obj):
    """Convert a date to a tar header time of 11 octal digits"""
    return f"{seconds_since(dt_obj, epochs[1970]):011o}"


@decoder("tai64n")
def from_tai64n(timestamp, guess=False):
    """Convert a TAI64N label to a date"""
    text = timestamp[1:] if timestamp.startswith("@") else timestamp
    if not is_hex(text, 24, 24):
        return ""
    label, nanoseconds = int(text[:16], 16), int(text[16:], 16)
    seconds = label - 2**62 - 10
    if not 2**62 <= label < 2**63 or nanoseconds >= 10**9:
        return ""
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if guess and not 946684800 <= seconds < 4102444800:
        return ""
    return date_text(
        epochs[1970], seconds * 10**6 + units_to_microseconds(nanoseconds, 10**9)
    )


@encoder("tai64n")
def to_tai64n(dt_obj):
    """Convert a date to a TAI64N label"""
    seconds, microseconds = divmod(microseconds_since(dt_obj, epochs[1970]), 10**6)
    return f"{2**62 + 10 + seconds:016x}{microseconds * 1000:08x}"


@decoder("cdma")
def from_cdma(timestamp, guess=False):
    """Convert a CDMA SMS time of 6 BCD bytes to a date"""
    if not is_digits(timestamp, 12, 12):
        return ""
    year, month, day, hour, minute, second = [
        int(timestamp[i : i + 2]) for i in range(0, 12, 2)
    ]
    full_year = year + (1900 if year >= 96 else 2000)
    if guess and full_year >= 2000:
        return ""
    return fields_date_text(full_year, month, day, hour, minute, second)


@encoder("cdma")
def to_cdma(dt_obj):
    """Convert a date to a CDMA SMS time"""
    return (
        f"{dt_obj.year % 100:02d}{dt_obj.month:02d}{dt_obj.day:02d}"
        f"{dt_obj.hour:02d}{dt_obj.minute:02d}{dt_obj.second:02d}"
    )


@decoder("tid")
def from_tid(timestamp, guess=False):
    """Convert a Bluesky TID to a date"""
    if not re.fullmatch(r"[234567a-j][234567a-z]{12}", timestamp):
        return ""
    value = 0
    for char in timestamp:
        value = value * 32 + S32_CHARS.index(char)
    microseconds = value >> 10
    if guess and microseconds < 1640995200 * 10**6:
        return ""
    return date_text(epochs[1970], microseconds)


@encoder("tid")
def to_tid(dt_obj):
    """Convert a date to a Bluesky TID"""
    value = (
        microseconds_since(dt_obj, epochs[1970]) << 10
        | int.from_bytes(os.urandom(2), "big") & 1023
    )
    characters = ""
    for _ in range(13):
        value, index = divmod(value, 32)
        characters = S32_CHARS[index] + characters
    return characters


@decoder("mjd")
def from_mjd(timestamp, guess=False):
    """Convert a Modified Julian Date to a date"""
    shape = r"[0-9]{5}\.[0-9]{1,12}" if guess else r"[0-9]{1,7}(\.[0-9]{1,15})?"
    if not re.fullmatch(shape, timestamp):
        return ""
    return days_to_date_text(_utc(1858, 11, 17), Fraction(timestamp))


@encoder("mjd")
def to_mjd(dt_obj):
    """Convert a date to a Modified Julian Date"""
    return decimal_days(dt_obj, _utc(1858, 11, 17))


@decoder("quicktime")
def from_quicktime(timestamp, guess=False):
    """Convert a QuickTime / MP4 time to a date"""
    if len(timestamp) not in (8, 16) or not is_hex(timestamp, 16):
        return ""
    seconds = int(timestamp, 16)
    # when guessing, only 1990-01-01 to 2099-12-31 are taken
    if guess and not 2713996800 <= seconds < 6185289600:
        return ""
    return date_text(epochs[1904], seconds * 10**6)


@encoder("quicktime")
def to_quicktime(dt_obj):
    """Convert a date to a QuickTime / MP4 time"""
    seconds = seconds_since(dt_obj, epochs[1904])
    return f"{seconds:08x}" if seconds < _UINT32 else f"{seconds:016x}"


@decoder("matroska")
def from_matroska(timestamp, guess=False):
    """Convert a Matroska / WebM date to a date"""
    if not re.fullmatch(r"[0-9]{18,19}" if guess else r"-?[0-9]{1,19}", timestamp):
        return ""
    nanoseconds = int(timestamp)
    # when guessing, only 2004-03-03 (18 digits) to 2099-12-31 are taken
    if not -(2**63) <= nanoseconds < 2**63 or (
        guess and nanoseconds >= 3124137600 * 10**9
    ):
        return ""
    return date_text(epochs[2001], units_to_microseconds(nanoseconds, 10**9))


@encoder("matroska")
def to_matroska(dt_obj):
    """Convert a date to a Matroska / WebM date"""
    return str(microseconds_since(dt_obj, epochs[2001]) * 1000)


def postgres_date_text(microseconds, guess):
    """The date of the signed microseconds since 2000-01-01 in a PostgreSQL timestamp"""
    # when guessing, only 2003-03-01 to 2099-12-31 are taken
    if not -(2**63) <= microseconds < 2**63 or (
        guess and not 10**14 <= microseconds < 3155760000 * 10**6
    ):
        return ""
    return date_text(epochs[2000], microseconds)


@decoder("postgres")
def from_postgres(timestamp, guess=False):
    """Convert a PostgreSQL timestamp to a date"""
    if not re.fullmatch(r"[0-9]{15,16}" if guess else r"-?[0-9]{1,19}", timestamp):
        return ""
    return postgres_date_text(int(timestamp), guess)


@encoder("postgres")
def to_postgres(dt_obj):
    """Convert a date to a PostgreSQL timestamp"""
    return str(microseconds_since(dt_obj, epochs[2000]))


@decoder("postgresbe")
def from_postgresbe(timestamp, guess=False):
    """Convert a big-endian PostgreSQL timestamp to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    return postgres_date_text(struct.unpack(">q", bytes.fromhex(timestamp))[0], guess)


@encoder("postgresbe")
def to_postgresbe(dt_obj):
    """Convert a date to a big-endian PostgreSQL timestamp"""
    return struct.pack(">q", microseconds_since(dt_obj, epochs[2000])).hex()


@decoder("postgresle")
def from_postgresle(timestamp, guess=False):
    """Convert a little-endian PostgreSQL timestamp to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    return postgres_date_text(struct.unpack("<q", bytes.fromhex(timestamp))[0], guess)


@encoder("postgresle")
def to_postgresle(dt_obj):
    """Convert a date to a little-endian PostgreSQL timestamp"""
    return struct.pack("<q", microseconds_since(dt_obj, epochs[2000])).hex()


@decoder("telegram")
def from_telegram(timestamp, guess=False):
    """Convert a Telegram MTProto message ID to a date"""
    if not is_digits(timestamp, 20, 19 if guess else 1) or int(timestamp) >= 2**64:
        return ""
    seconds, fraction = divmod(int(timestamp), _UINT32)
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if guess and not 946684800 <= seconds < 4102444800:
        return ""
    return date_text(
        epochs[1970], seconds * 10**6 + units_to_microseconds(fraction, _UINT32)
    )


@encoder("telegram")
def to_telegram(dt_obj):
    """Convert a date to a Telegram MTProto message ID"""
    fraction = round(
        Fraction(microseconds_since(dt_obj, epochs[1970]) * _UINT32, 10**6)
    )
    return str(fraction & ~3)


@decoder("unixdays")
def from_unixdays(timestamp, guess=False):
    """Convert whole days since 1970-01-01 to a date"""
    if not is_digits(timestamp, 5 if guess else 7, 5 if guess else 1):
        return ""
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if guess and not 10957 <= int(timestamp) < 47482:
        return ""
    return date_text(epochs[1970], int(timestamp) * _DAY_MICROSECONDS)


@encoder("unixdays")
def to_unixdays(dt_obj):
    """Convert a date to whole days since 1970-01-01"""
    return str((dt_obj - epochs[1970]) // timedelta(days=1))


@decoder("matlab")
def from_matlab(timestamp, guess=False):
    """Convert a MATLAB datenum to a date"""
    if not re.fullmatch(
        r"[0-9]{6}\.[0-9]{1,12}" if guess else r"[0-9]{1,7}(\.[0-9]{1,15})?", timestamp
    ):
        return ""
    days = Fraction(timestamp)
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if guess and not 730486 <= days < 767011:
        return ""
    return days_to_date_text(epochs[1970], days - _MATLAB_UNIX_EPOCH)


@encoder("matlab")
def to_matlab(dt_obj):
    """Convert a date to a MATLAB datenum"""
    return decimal_days(dt_obj, epochs[1970], _MATLAB_UNIX_EPOCH)


@decoder("sas")
def from_sas(timestamp, guess=False):
    """Convert a SAS datetime to a date"""
    if not re.fullmatch(
        r"[0-9]{10}(\.[0-9]{1,6})?" if guess else r"[0-9]{1,12}(\.[0-9]{1,9})?",
        timestamp,
    ):
        return ""
    seconds = Fraction(timestamp)
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if guess and not 1262304000 <= seconds < 4418064000:
        return ""
    return date_text(_utc(1960), round(seconds * 10**6))


@encoder("sas")
def to_sas(dt_obj):
    """Convert a date to a SAS datetime"""
    seconds, microseconds = divmod(microseconds_since(dt_obj, _utc(1960)), 10**6)
    return f"{seconds}.{microseconds:06d}"


@decoder("sasdate")
def from_sasdate(timestamp, guess=False):
    """Convert a SAS datetime to a date"""
    if not is_digits(timestamp, 5 if guess else 7, 5 if guess else 1):
        return ""
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if guess and not 14610 <= int(timestamp) < 51135:
        return ""
    return date_text(_utc(1960), int(timestamp) * _DAY_MICROSECONDS)


@encoder("sasdate")
def to_sasdate(dt_obj):
    """Convert a date to a SAS datetime"""
    return str((dt_obj - _utc(1960)) // timedelta(days=1))


@decoder("gacookie")
def from_gacookie(timestamp):
    """Convert the time in a Google Analytics _ga or _gid cookie to a date"""
    match = re.fullmatch(r"GA[0-9]\.[0-9]{1,2}\.[0-9]{1,10}\.([0-9]{1,12})", timestamp)
    return date_text(epochs[1970], int(match[1]) * 10**6) if match else ""


@decoder("fbcookie")
def from_fbcookie(timestamp):
    """Convert the time in a Facebook _fbp or _fbc cookie to a date"""
    match = re.fullmatch(
        r"fb\.[0-9]{1,2}\.([0-9]{1,15})\.[0-9A-Za-z_-]{1,200}", timestamp
    )
    return date_text(epochs[1970], int(match[1]) * 1000) if match else ""


@decoder("xray")
def from_xray(timestamp):
    """Convert an AWS X-Ray trace ID to a date"""
    match = re.fullmatch(r"1-([0-9a-fA-F]{8})-[0-9a-fA-F]{24}", timestamp)
    return date_text(epochs[1970], int(match[1], 16) * 10**6) if match else ""


@encoder("xray")
def to_xray(dt_obj):
    """Convert a date to an AWS X-Ray trace ID"""
    return f"1-{seconds_since(dt_obj, epochs[1970]):08x}-{os.urandom(12).hex()}"


@decoder("int96")
def from_int96(timestamp, guess=False):
    """Convert a Parquet INT96 timestamp to a date"""
    if not is_hex(timestamp, 24, 24):
        return ""
    nanoseconds, day = struct.unpack("<qi", bytes.fromhex(timestamp))
    # when guessing, only the days from 2000-01-01 to 2099-12-31 are taken
    if not 0 <= nanoseconds < 86400 * 10**9 or (guess and not 2451545 <= day < 2488070):
        return ""
    microseconds = (day - _INT96_UNIX_DAY) * _DAY_MICROSECONDS + units_to_microseconds(
        nanoseconds, 10**9
    )
    return date_text(epochs[1970], microseconds)


@encoder("int96")
def to_int96(dt_obj):
    """Convert a date to a Parquet INT96 timestamp"""
    days, microseconds = divmod(
        microseconds_since(dt_obj, epochs[1970]), _DAY_MICROSECONDS
    )
    return struct.pack("<qi", microseconds * 1000, days + _INT96_UNIX_DAY).hex()


@decoder("xfs")
def from_xfs(timestamp, guess=False):
    """Convert an XFS inode time to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    seconds, nanoseconds = struct.unpack(">iI", bytes.fromhex(timestamp))
    # when guessing, only 2000-01-01 to 2038 are taken
    if nanoseconds >= 10**9 or (guess and not 946684800 <= seconds):
        return ""
    return date_text(
        epochs[1970], seconds * 10**6 + units_to_microseconds(nanoseconds, 10**9)
    )


@encoder("xfs")
def to_xfs(dt_obj):
    """Convert a date to an XFS inode time"""
    seconds, microseconds = divmod(microseconds_since(dt_obj, epochs[1970]), 10**6)
    return struct.pack(">iI", seconds, microseconds * 1000).hex()


@decoder("xfsbig")
def from_xfsbig(timestamp, guess=False):
    """Convert an XFS bigtime value to a date"""
    if not is_hex(timestamp, 16, 16):
        return ""
    nanoseconds = int(timestamp, 16)
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if (
        guess
        and not (946684800 + 2**31) * 10**9
        <= nanoseconds
        < (4102444800 + 2**31) * 10**9
    ):
        return ""
    return date_text(_XFS_BIGTIME_EPOCH, units_to_microseconds(nanoseconds, 10**9))


@encoder("xfsbig")
def to_xfsbig(dt_obj):
    """Convert a date to an XFS bigtime value"""
    return f"{microseconds_since(dt_obj, _XFS_BIGTIME_EPOCH) * 1000:016x}"


@decoder("btrfs")
def from_btrfs(timestamp, guess=False):
    """Convert a Btrfs inode time to a date"""
    if not is_hex(timestamp, 24, 24):
        return ""
    seconds, nanoseconds = struct.unpack("<qI", bytes.fromhex(timestamp))
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if nanoseconds >= 10**9 or (guess and not 946684800 <= seconds < 4102444800):
        return ""
    return date_text(
        epochs[1970], seconds * 10**6 + units_to_microseconds(nanoseconds, 10**9)
    )


@encoder("btrfs")
def to_btrfs(dt_obj):
    """Convert a date to a Btrfs inode time"""
    seconds, microseconds = divmod(microseconds_since(dt_obj, epochs[1970]), 10**6)
    return struct.pack("<qI", seconds, microseconds * 1000).hex()


@decoder("efitime")
def from_efitime(timestamp, guess=False):
    """Convert a UEFI EFI_TIME to a date"""
    if not is_hex(timestamp, 32, 32):
        return ""
    year, month, day, hour, minute, second, nanosecond, zone, _ = struct.unpack(
        "<HBBBBBxIhBx", bytes.fromhex(timestamp)
    )
    # when guessing, only the years 1990 to 2099 are taken
    if (
        nanosecond >= 10**9
        or not (-1440 <= zone <= 1440 or zone == 2047)
        or not 1900 <= year
        or (guess and not 1990 <= year < 2100)
    ):
        return ""
    try:
        base = dt(year, month, day, hour, minute, second)
    except ValueError:
        return ""
    text = date_text(base, units_to_microseconds(nanosecond, 10**9))
    return (
        (text, utc_offset_label("UTC", -zone / 15)) if text and zone != 2047 else text
    )


@encoder("efitime")
def to_efitime(dt_obj):
    """Convert a date to a UEFI EFI_TIME"""
    zone = -int(dt_obj.utcoffset().total_seconds()) // 60
    if not -1440 <= zone <= 1440:
        return ""
    fields = (
        dt_obj.year,
        dt_obj.month,
        dt_obj.day,
        dt_obj.hour,
        dt_obj.minute,
        dt_obj.second,
    )
    return struct.pack(
        "<HBBBBBxIhBx", *fields, dt_obj.microsecond * 1000, zone, 0
    ).hex()


@decoder("xid")
def from_xid(timestamp, guess=False):
    """Convert an xid to a date"""
    if not re.fullmatch(r"[0-9a-v]{20}", timestamp):
        return ""
    seconds = int(timestamp, 32) >> 68
    # when guessing, only 2010-01-01 to 2099-12-31 are taken
    if guess and not 1262304000 <= seconds < 4102444800:
        return ""
    return date_text(epochs[1970], seconds * 10**6)


@encoder("xid")
def to_xid(dt_obj):
    """Convert a date to an xid"""
    value = (
        int.from_bytes(
            seconds_since(dt_obj, epochs[1970]).to_bytes(4, "big") + os.urandom(8),
            "big",
        )
        << 4
    )
    characters = ""
    for _ in range(20):
        value, index = divmod(value, 32)
        characters = XID_CHARS[index] + characters
    return characters


@decoder("cuid")
def from_cuid(timestamp, guess=False):
    """Convert a cuid to a date"""
    if not re.fullmatch(r"c[0-9a-z]{24}", timestamp):
        return ""
    milliseconds = int(timestamp[1:9], 36)
    # when guessing, only 2012-01-01 on is taken, which is the first cuid
    if guess and milliseconds < 1325376000000:
        return ""
    return date_text(epochs[1970], milliseconds * 1000)


@encoder("cuid")
def to_cuid(dt_obj):
    """Convert a date to a cuid"""
    value = microseconds_since(dt_obj, epochs[1970]) // 1000
    characters = ""
    for _ in range(8):
        value, index = divmod(value, 36)
        characters = BASE36_CHARS[index] + characters
    return (
        "c"
        + characters
        + "0000"
        + "".join(BASE36_CHARS[byte % 36] for byte in os.urandom(12))
    )


@decoder("stata")
def from_stata(timestamp, guess=False):
    """Convert a Stata %tc clock time to a date"""
    if not is_digits(timestamp, 13 if guess else 15, 13 if guess else 1):
        return ""
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if guess and not 1262304000000 <= int(timestamp) < 4418064000000:
        return ""
    return date_text(_utc(1960), int(timestamp) * 1000)


@encoder("stata")
def to_stata(dt_obj):
    """Convert a date to a Stata %tc clock time"""
    return str(microseconds_since(dt_obj, _utc(1960)) // 1000)


@decoder("spss")
def from_spss(timestamp, guess=False):
    """Convert an SPSS value to a date"""
    if not re.fullmatch(
        r"[0-9]{11}(\.[0-9]{1,6})?" if guess else r"[0-9]{1,12}(\.[0-9]{1,9})?",
        timestamp,
    ):
        return ""
    seconds = Fraction(timestamp)
    # when guessing, only 2000-01-01 to 2099-12-31 are taken
    if guess and not 13166064000 <= seconds < 16321824000:
        return ""
    return date_text(_utc(1582, 10, 14), round(seconds * 10**6))


@encoder("spss")
def to_spss(dt_obj):
    """Convert a date to an SPSS value"""
    seconds, microseconds = divmod(
        microseconds_since(dt_obj, _utc(1582, 10, 14)), 10**6
    )
    return f"{seconds}.{microseconds:06d}"


@decoder("mysql")
def from_mysql(timestamp, guess=False):
    """Convert a MySQL DATETIME to a date"""
    if len(timestamp) not in (10, 12, 14, 16) or not is_hex(timestamp, 16):
        return ""
    # the sign bit, 17 bits of year * 13 + month, then day, hour, minute and second in 5, 5, 6 and 6 bits
    packed = int(timestamp[:10], 16)
    year, month = divmod(packed >> 22 & 0x1FFFF, 13)
    day, hour, minute, second = (
        packed >> 17 & 31,
        packed >> 12 & 31,
        packed >> 6 & 63,
        packed & 63,
    )
    # fraction is hundredths in 1 byte, units of 100 microseconds in 2, and microseconds in 3
    fraction, (unit, limit) = (
        int(timestamp[10:] or "0", 16),
        {0: (0, 1), 2: (10000, 100), 4: (100, 10000), 6: (1, 10**6)}[
            len(timestamp) - 10
        ],
    )
    # when guessing, only the years 1990 to 2099 are taken
    if not packed >> 39 or fraction >= limit or (guess and not 1990 <= year < 2100):
        return ""
    try:
        base = dt(year, month, day, hour, minute, second)
    except ValueError:
        return ""
    return date_text(base, fraction * unit)


@encoder("mysql")
def to_mysql(dt_obj):
    """Convert a date to a MySQL DATETIME"""
    packed = (
        1 << 39
        | (dt_obj.year * 13 + dt_obj.month) << 22
        | dt_obj.day << 17
        | dt_obj.hour << 12
        | dt_obj.minute << 6
        | dt_obj.second
    )
    return f"{packed:010x}" + (
        f"{dt_obj.microsecond:06x}" if dt_obj.microsecond else ""
    )


@decoder("udf")
def from_udf(timestamp, guess=False):
    """Convert a UDF timestamp to a date"""
    if not is_hex(timestamp, 24, 24):
        return ""
    type_zone, year, month, day, hour, minute, second, centis, hundreds, micros = (
        struct.unpack("<HHBBBBBBBB", bytes.fromhex(timestamp))
    )
    kind, zone = type_zone >> 12, type_zone & 0xFFF
    if zone & 0x800:
        zone -= 0x1000
    # when guessing, only the years 1990 to 2099 are taken
    if (
        kind > 2
        or max(centis, hundreds, micros) > 99
        or (guess and not 1990 <= year < 2100)
    ):
        return ""
    if kind == 1 and not (-1440 <= zone <= 1440 or zone == -2047):
        return ""
    try:
        base = dt(year, month, day, hour, minute, second)
    except ValueError:
        return ""
    text = date_text(base, centis * 10000 + hundreds * 100 + micros)
    if not text or kind == 2 or (kind == 1 and zone == -2047):
        return text
    return text, utc_offset_label("UTC", zone / 15 if kind else 0)


@encoder("udf")
def to_udf(dt_obj):
    """Convert a date to a UDF timestamp"""
    zone = int(dt_obj.utcoffset().total_seconds()) // 60
    centis, rest = divmod(dt_obj.microsecond, 10000)
    fields = (
        dt_obj.year,
        dt_obj.month,
        dt_obj.day,
        dt_obj.hour,
        dt_obj.minute,
        dt_obj.second,
    )
    return struct.pack(
        "<HHBBBBBBBB", 1 << 12 | zone & 0xFFF, *fields, centis, rest // 100, rest % 100
    ).hex()


def result_year(result):
    """Get the year from a formatted result, in any date format, with or without a UTC offset"""
    parts = result.split(" ")
    try:
        return dt.fromisoformat(parts[0]).year
    except ValueError:
        clock = re.sub(r"[+-]\d{2}:\d{2}$", "", parts[1])
        return dt.strptime(f"{parts[0]} {clock}", __fmt__).year


def accepts_guess(func):
    """Whether a decoder takes a guess argument, to read only what is likely when guessing."""
    code = getattr(func, "__wrapped__", func).__code__
    return "guess" in code.co_varnames[: code.co_argcount]


def from_all(timestamps, tz_name=None):
    """Output all processed timestamp values and find date from provided timestamp"""
    this_yr = int(dt.now(timezone.utc).strftime("%Y"))
    full_list = {}
    for _, funcs in single_funcs.items():
        func = funcs[0]
        func_name = func.__name__.replace("from_", "")
        if accepts_guess(func):
            (result, _, combined_output, _, tz_out) = func(timestamps, guess=True)
        else:
            (result, _, combined_output, _, tz_out) = func(timestamps)
        if result and combined_output:
            if isinstance(result, str):
                if tz_name is not None:
                    new_ts, new_tz, _ = convert_timezone(tz_name, result)
                    if not new_ts:
                        continue
                    combined_output = combined_output.replace(result, new_ts)
                    combined_output = combined_output.replace(tz_out, new_tz)
                    tz_out = new_tz
                    result = new_ts
                result_yr = result_year(result)
                if result_yr not in range(this_yr - 5, this_yr + 5):
                    combined_output = combined_output.strip(__red__).strip(__clr__)
            full_list[func_name] = [result, combined_output, tz_out]
    return full_list


def to_timestamps(dt_obj, tz_name=None):
    """Convert provided date to all timestamps"""
    results = {}
    ts_outputs = []
    if isinstance(dt_obj, str):
        try:
            dt_obj = dt.fromisoformat(dt_obj)
        except ValueError:
            dt_obj = dt.strptime(dt_obj, __fmt__)
        except Exception as exc:
            print(
                f"[!] Check that your input timestamp follows the format: 'YYYY-MM-DD HH:MM:SS'\n"
                f"[!] with '.ffffff' for milliseconds and '+/-HH:MM' for timezones\n"
                f"[!] or use --date-formats to pick a format and use the --date-format NAME:\n{exc}"
            )
            sys.exit(1)
    if dt_obj.tzinfo is None and tz_name is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    elif tz_name is not None:
        tz = tzone(tz_name)
        dt_obj = dt_obj.replace(tzinfo=tz)
    for _, funcs in single_funcs.items():
        func = funcs[1]
        if not func:
            continue
        result, ts_output = func(dt_obj)
        func_name = (func.__name__).replace("to_", "")
        if result and isinstance(result, str):
            results[func_name] = result
            ts_outputs.append(ts_output)
    return results, ts_outputs


def gui():
    """Execute the application"""
    if __package__ in (None, "") and not getattr(sys, "frozen", False):
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from time_decode.gui import run
    except ImportError as error:
        if (error.name or "").split(".")[0] != "PyQt6":
            raise
        print(
            f"[!] The GUI needs PyQt6, which could not be loaded ({error}).\n"
            '    Install it with: python3 -m pip install "time-decode[gui]"',
            file=sys.stderr,
        )
        sys.exit(1)
    run()


def set_date_format(fmt):
    global __fmt__
    __fmt__ = fmt


def __getattr__(name):
    if name in (
        "NewWindow",
        "CsvWindow",
        "AboutWindow",
        "ContextMenu",
        "UiMainWindow",
        "TimeDecodeGui",
    ):
        from time_decode import gui as gui_module

        return getattr(gui_module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def handle(error):
    """Error handling output and formatting to include function causing error"""
    exc_type, exc_obj, _ = error
    error_tb = traceback.extract_stack()[:-3] + traceback.extract_tb(
        exc_obj.__traceback__
    )
    _, line_no, function_name, _ = error_tb[-1]
    print(
        f"{str(exc_type.__name__)}: {str(exc_obj)} - {function_name} line {line_no}",
        file=sys.stderr,
    )


def formats(display="ALL"):
    """Displays a PrettyTable output of examples of all timestamps and their formats"""
    structures = {}
    for arg, data_list in ts_types.items():
        structures[data_list[0]] = (data_list[1], data_list[2], arg)
    structures = sorted(structures.items(), key=lambda item: item[0].casefold())
    table = PrettyTable()
    table.set_style(TableStyle.SINGLE_BORDER)
    table.align = "l"
    table.field_names = ["Type", "Format", "Example", "Argument"]
    for structure in structures:
        ts_type, details = structure
        argument = f"--{details[2]}"
        if display == "ALL":
            table.add_row([ts_type, details[0], details[1], argument])
        elif details[2] == display:
            table.add_row([ts_type, details[0], details[1], argument])
    print(table)
    print("* BE = Big-Endian / LE = Little-Endian")


def format_output(ts_type, ts, tz=None):
    """Format the output of the timestamp functions"""
    tabs = ""
    if len(ts_type) < 15:
        tabs = "\t\t\t"
    elif len(ts_type) in range(15, 23):
        tabs = "\t\t"
    elif len(ts_type) in range(23, 32):
        tabs = "\t"
    if tz:
        indiv_output = f"{ts_type}: {ts} {tz}"
        combined_output = f"{__red__}{ts_type}:{tabs}{ts} {tz}{__clr__}"
    else:
        indiv_output = f"{ts_type}:{tabs}{ts}"
        combined_output = None
    return indiv_output, combined_output


@functools.lru_cache(maxsize=None)
def tzdata_names():
    try:
        import tzdata

        zoneinfo_dir = os.path.join(tzdata.__path__[0], "zoneinfo")
        timezones = set()
        for root, _, files in os.walk(zoneinfo_dir):
            for name in files:
                rel_path = os.path.relpath(
                    os.path.join(root, name), zoneinfo_dir
                ).replace(os.sep, "/")
                if rel_path.startswith(("posix", "right")):
                    continue
                timezones.add(rel_path)
        return tuple(sorted(timezones))
    except ModuleNotFoundError:
        from zoneinfo import available_timezones

        return tuple(
            sorted(
                tz
                for tz in available_timezones()
                if not tz.startswith(("posix", "right"))
            )
        )


def tzdata_timezones():
    """Get the tzdata timezones and put them in a list for the timezone drop-down"""
    return list(tzdata_names())


@functools.lru_cache(maxsize=None)
def cached_zone(tz_name):
    try:
        return tzone(tz_name)
    except Exception:
        return None


DUPLICATE_ZONES = frozenset(
    (
        "Factory",
        "Zulu",
        "Etc/Zulu",
        "Etc/UTC",
        "GMT-0",
        "GMT+0",
        "Etc/Universal",
        "GMT0",
        "UCT",
        "Etc/Greenwich",
        "Etc/GMT",
        "Etc/GMT+0",
        "Etc/GMT-0",
        "Etc/GMT0",
        "Etc/UCT",
        "Universal",
    )
)


def common_timezone_offsets(dt_obj):
    """Generates a list of all tzdata timezones for conversion, sorted by UTC offset"""
    timezone_offsets = [("UTC - Default", "")]
    for tz_name in tzdata_names():
        if tz_name in DUPLICATE_ZONES:
            continue
        set_timezone = cached_zone(tz_name)
        if set_timezone is None:
            continue
        try:
            offset_tz = dt_obj.astimezone(set_timezone).utcoffset()
        except Exception:
            continue
        if offset_tz is None:
            continue
        timezone_offsets.append((f"UTC{utc_offset_text(offset_tz)}", tz_name))
    timezone_offsets.sort(key=lambda x: x[0])
    return timezone_offsets


def decode_group(group, timestamp):
    """Decode with each type in a group, returning the first hit or an empty result"""
    for name in type_groups[group]:
        result = single_funcs[name][0](timestamp)
        if result[0]:
            return result
    _, reason, _, tz_out = ts_types[group]
    return "", "", "", reason, tz_out


def generate_csv(src_file, ts_choice, column_num=None, tz_name=None):
    """Loads a CSV file, reads a column and decodes the timestamps from the selected format"""
    if ts_choice in type_groups:
        ts_func = lambda ts: decode_group(ts_choice, ts)
    else:
        ts_func = single_funcs[ts_choice][0]
    src_file = os.path.normpath(os.path.abspath(src_file))
    dst_file = f"{os.path.splitext(src_file)[0]}_out.csv"
    status = False
    reason = None
    csv_output = []
    if isinstance(column_num, str) and not column_num.isdigit():
        if len(column_num) == 1:
            column_num = int(ascii_lowercase.index(column_num.lower()))
        else:
            return status, dst_file, reason
    elif isinstance(column_num, str) and column_num.isdigit():
        column_num = int(column_num)
        if column_num > 0:
            column_num -= 1
        elif column_num < 0:
            column_num = 0
    elif isinstance(column_num, int):
        if column_num > 0:
            column_num -= 1
        elif column_num < 0:
            column_num = 0
    elif column_num is None:
        column_num = 0
    try:
        with open(src_file, "r", newline="", encoding="utf-8") as src:
            sample = src.read(2048)
            try:
                dialect = csv.Sniffer().sniff(sample)
            except csv.Error:
                dialect = csv.get_dialect("excel")
            try:
                has_header = csv.Sniffer().has_header(sample)
            except csv.Error:
                has_header = False
                header_check = sample.count(",")
                content = sample.split("\n")
                if len(content) < 2:
                    pass
                elif header_check == 0:
                    if len(content[0]) != len(content[1]):
                        has_header = True
                else:
                    line_two = content[1].split(",")
                    if len(line_two) > 1 and len(content[0].split(",")[0]) != len(
                        line_two[1]
                    ):
                        has_header = True
            src.seek(0)
            reader = csv.reader(src, dialect)
            columns = len(next(reader, None) or [])
            src.seek(0)
            if has_header:
                header = next(reader)
            if columns == 0:
                reason = "The file is empty."
                return status, dst_file, reason
            if column_num >= columns:
                reason = "The selected column number is higher than the amount of actual columns."
                return status, dst_file, reason
            type_reason = None
            skipped = 0
            for row in reader:
                if not row:
                    continue
                result = ""
                if column_num < len(row):
                    results = ts_func(row[column_num])
                    result = results[0]
                    type_reason = results[3]
                if result and tz_name is not None:
                    new_result, new_tz, _ = convert_timezone(tz_name, result)
                    if not new_result:
                        result = ""
                    elif new_tz.startswith("+") or new_tz.startswith("-"):
                        result = f"{new_result}{new_tz}"
                    else:
                        result = f"{new_result} {new_tz}"
                if not result:
                    skipped += 1
                row.append(result)
                csv_output.append(row)
        if not csv_output or skipped == len(csv_output):
            reason = type_reason or "No timestamps were found in the selected column."
            return status, dst_file, reason
        if skipped:
            reason = f"{skipped} of {len(csv_output)} rows could not be converted and were left blank"
        with open(dst_file, "w", newline="", encoding="utf-8") as dst:
            writer = csv.writer(dst, quotechar='"', quoting=csv.QUOTE_MINIMAL)
            if has_header:
                header.append(f"{ts_choice}_ts")
                writer.writerow(header)
            writer.writerows(csv_output)
        status = True
    except (FileNotFoundError, PermissionError):
        handle(sys.exc_info())
        status = False
    return status, dst_file, reason


def utc_offset_text(offset):
    total = int(offset.total_seconds())
    hours, remainder = divmod(abs(total), 3600)
    minutes, seconds = divmod(remainder, 60)
    text = f"{'-' if total < 0 else '+'}{hours:02d}:{minutes:02d}"
    return f"{text}:{seconds:02d}" if seconds else text


def convert_timezone(tz_name, dt_val):
    """Separate function to take a string date/time and convert it to the identified time zone"""
    tz = tzone(tz_name)
    try:
        dt_obj = dt.fromisoformat(dt_val).replace(tzinfo=timezone.utc)
    except ValueError:
        dt_obj = dt.strptime(dt_val, __fmt__).replace(tzinfo=timezone.utc)
    try:
        tz_change = dt_obj.astimezone(tz)
    except OverflowError:
        return "", "", None
    tz_offset = utc_offset_text(tz_change.utcoffset())
    tz_selected = date_string(tz_change)
    if check_daylight(dt_obj, tz):
        tz_out = f"{tz_offset} DST"
    else:
        tz_out = tz_offset
    return tz_selected, tz_out, tz_change


def check_daylight(dtval, tz):
    """Checks to see if the provided timestamp, in the provided timezone, is observing DST"""
    if dtval.tzinfo is None:
        dtval = dtval.replace(tzinfo=tz)
    else:
        dtval = dtval.astimezone(tz)
    return dtval.dst() != timedelta(0, 0)


def parse_date(value):
    """Parse an ISO 8601 or current date-format string, returning None if neither fits"""
    try:
        return dt.fromisoformat(value)
    except ValueError:
        pass
    try:
        return dt.strptime(value, __fmt__)
    except ValueError:
        return None


def valid_timezone(tz_name):
    """Check that a time zone name can be loaded"""
    try:
        tzone(tz_name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return False
    return True


def list_timezones():
    """Displays all available time zone conversion options in a PrettyTable"""
    tzs = common_timezone_offsets(dt.now(timezone.utc))
    tzs = tzs[1:]
    tzs.sort(key=lambda x: x[1])
    table = PrettyTable()
    table.set_style(TableStyle.SINGLE_BORDER)
    table.align = "l"
    table.field_names = ["Time Zone Name", "Current Offset"]
    for tz in tzs:
        table.add_row([tz[1], tz[0]])
    print(table)
    print(f"* Based on the current date/time of {dt.now(timezone.utc)}")


def list_date_formats():
    """Displays available date/time format strings"""
    table = PrettyTable()
    table.set_style(TableStyle.SINGLE_BORDER)
    table.align = "l"
    table.field_names = ["Name", "Format"]
    for k, v in date_formats.items():
        table.add_row([k, v.replace("%", "")])
    print(table)


def _utc(year, month=1, day=1, hour=0, minute=0, second=0, microsecond=0):
    return dt(year, month, day, hour, minute, second, microsecond, tzinfo=_UTC)


def _end_of(year):
    """The last instant of a year"""
    return dt(year, 12, 31, 23, 59, 59, 999999)


def _span(epoch, seconds=0, milliseconds=0, microseconds=0):
    """The last instant a counter of the given size can reach from its epoch"""
    return (
        epoch
        + timedelta(
            seconds=seconds, milliseconds=milliseconds, microseconds=microseconds
        )
        - _MICROSECOND
    )


# The first and last date each encoder can write, as (first, last, wall_clock).
ENCODER_RANGES = {
    "active": (_utc(1601), _AWARE_MAX, False),
    "apache": (_utc(1970), _AWARE_MAX, False),
    "apfs": (epochs[1970], _span(epochs[1970], microseconds=2**64 // 1000), False),
    "bcd": (dt(2000, 1, 1), _end_of(2099), True),
    "biome64": (_AWARE_MIN, _utc(9999, 12, 31, 23, 59, 59), False),
    "biomehex": (_AWARE_MIN, _utc(9999, 12, 31, 23, 59, 59), False),
    "bitdate": (dt(1, 1, 1), _end_of(4095), True),
    "bitdec": (dt(1, 1, 1), _end_of(4095), True),
    "bplist": (epochs[2001], _AWARE_MAX, False),
    "btrfs": (_AWARE_MIN, _AWARE_MAX, False),
    "cdma": (dt(1996, 1, 1), _end_of(2095), True),
    "chrome": (_utc(1601), _AWARE_MAX, False),
    "cookie": (_utc(1601), _AWARE_MAX, False),
    "cuid": (epochs[1970], _span(epochs[1970], milliseconds=36**8), False),
    "dhcp6": (epochs[2000], _span(epochs[2000], seconds=_UINT32), False),
    "discord": (
        _utc(2015),
        _span(_utc(2015), milliseconds=2**42),
        False,
    ),
    "dotnet": (_AWARE_MIN, _AWARE_MAX, False),
    "dotnetbin": (_AWARE_MIN, _AWARE_MAX, False),
    "dttm": (dt(1900, 1, 1), _end_of(2411), True),
    "dvr": (dt(2000, 1, 1), _end_of(2063), True),
    "efitime": (dt(1900, 1, 1), dt.max, True),
    "eitime": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
    "exfat": (dt(1980, 1, 1), _end_of(2107), True),
    "exfatext": (dt(1980, 1, 1), _end_of(2107), True),
    "ext4": (
        epochs[1970] - timedelta(seconds=2**31),
        _span(epochs[1970], seconds=2**34 - 2**31),
        False,
    ),
    "fat": (dt(1980, 1, 1), _end_of(2107), True),
    "filetimebe": (_utc(1601), _AWARE_MAX, False),
    "filetimele": (_utc(1601), _AWARE_MAX, False),
    "filetimelohi": (_utc(1601), _AWARE_MAX, False),
    "firebase": (epochs[1970], _AWARE_MAX, False),
    "garmin": (_utc(1989, 12, 31), _span(_utc(1989, 12, 31), seconds=_UINT32), False),
    "gbound": (epochs[1970], _span(epochs[1970], microseconds=2**56), False),
    "gmsgid": (epochs[1970], _AWARE_MAX, False),
    "gps": (epochs[1980], _AWARE_MAX, False),
    "gsm": (dt(1990, 1, 1), _end_of(2089), True),
    "hfsbe": (epochs[1904], _span(epochs[1904], seconds=_UINT32), False),
    "hfsdec": (epochs[1904], _AWARE_MAX, False),
    "hfsle": (epochs[1904], _span(epochs[1904], seconds=_UINT32), False),
    "horolog": (dt(1840, 12, 31), dt.max, True),
    "hotmail": (_utc(1601), _AWARE_MAX, False),
    "instagram": (
        _utc(2011, 8, 24, 21, 7, 1, 721000),
        _span(_utc(2011, 8, 24, 21, 7, 1, 721000), milliseconds=2**41),
        False,
    ),
    "int96": (_AWARE_MIN, _AWARE_MAX, False),
    "iostime": (
        epochs[2001] + timedelta(microseconds=10 ** (IOSTIME_DIGITS[0] - 1) // 1000),
        epochs[2001]
        + timedelta(microseconds=10 ** IOSTIME_DIGITS[-1] // 1000)
        - _MICROSECOND,
        False,
    ),
    "iso9660": (dt(1900, 1, 1), _end_of(2155), True),
    "juliandec": (_AWARE_MIN, _utc(9999, 12, 31, 23, 59, 59), False),
    "julianhex": (_AWARE_MIN, _utc(9999, 12, 31, 23, 59, 59), False),
    "ksalnum": (
        _utc(2014, 5, 13, 16, 53, 20),
        _span(_utc(2014, 5, 13, 16, 53, 20), seconds=_UINT32),
        False,
    ),
    "ksdec": (
        _utc(2014, 5, 13, 16, 53, 20),
        _span(_utc(2014, 5, 13, 16, 53, 20), seconds=_UINT32),
        False,
    ),
    "leb128hex": (epochs[1970], _AWARE_MAX, False),
    "linkedin": (epochs[1970], _span(epochs[1970], milliseconds=2**42), False),
    "logtime": (_utc(1900), _end_of(2155).replace(tzinfo=_UTC), False),
    "mac": (epochs[2001], _AWARE_MAX, False),
    "mars": (_utc(1873, 12, 29, 12, 2, 56, 449929), _AWARE_MAX, False),
    "mastodon": (epochs[1970], _AWARE_MAX, False),
    "matlab": (_AWARE_MIN, _AWARE_MAX, False),
    "matroska": (epochs[2001] - _MATROSKA_SPAN, epochs[2001] + _MATROSKA_SPAN, False),
    "mjd": (_utc(1858, 11, 17), _AWARE_MAX, False),
    "moto": (_utc(1970), _end_of(2225).replace(tzinfo=_UTC), False),
    "ms1904": (epochs[1904], _AWARE_MAX, False),
    "msdos": (dt(1980, 1, 1), _end_of(2107), True),
    "mssql": (dt(1753, 1, 1), dt(9999, 12, 31, 23, 59, 59, 998332), True),
    "mssqlle": (dt(1753, 1, 1), dt(9999, 12, 31, 23, 59, 59, 998332), True),
    "mysql": (dt(1000, 1, 1), dt.max, True),
    "nokia": (
        epochs[2050] - timedelta(seconds=_UINT32 - 1),
        epochs[2050] + timedelta(seconds=1) - _MICROSECOND,
        False,
    ),
    "nokiale": (
        epochs[2050] - timedelta(seconds=_UINT32 - 1),
        epochs[2050] + timedelta(seconds=1) - _MICROSECOND,
        False,
    ),
    "ns40": (_AWARE_MIN, _AWARE_MAX, False),
    "ns40le": (_AWARE_MIN, _AWARE_MAX, False),
    "ntp": (_utc(1900), _AWARE_MAX, False),
    "ntp64": (_utc(1900), _span(_utc(1900), seconds=_UINT32), False),
    "objectid": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
    "oleauto": (epochs[1899], _AWARE_MAX, False),
    "olebe": (_AWARE_MIN, _utc(9999, 12, 31, 23, 59, 59), False),
    "olele": (_AWARE_MIN, _utc(9999, 12, 31, 23, 59, 59), False),
    "oracle": (dt(1, 1, 1), dt.max, True),
    "prtime": (epochs[1970], _AWARE_MAX, False),
    "s32": (epochs[1970], _span(epochs[1970], milliseconds=32**9), False),
    "semioctet": (dt(2000, 1, 1), _end_of(2099), True),
    "sony": (_utc(2014, 9, 1), _span(_utc(2014, 9, 1), milliseconds=10 * 2**39), False),
    "pcap": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
    "pcapbe": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
    "postgres": (_AWARE_MIN, _AWARE_MAX, False),
    "postgresbe": (_AWARE_MIN, _AWARE_MAX, False),
    "postgresle": (_AWARE_MIN, _AWARE_MAX, False),
    "quicktime": (epochs[1904], _AWARE_MAX, False),
    "sas": (_utc(1960), _AWARE_MAX, False),
    "sasdate": (_utc(1960), _AWARE_MAX, False),
    "spss": (_utc(1582, 10, 14), _AWARE_MAX, False),
    "stardatetng": (
        _STARDATE_TNG_ORIGIN,
        _utc(9999, 12, 31, 23, 30),
        False,
    ),
    "stardatetos": (_STARDATE_TOS_ORIGIN, _AWARE_MAX, False),
    "stata": (_utc(1960), _AWARE_MAX, False),
    "symantec": (_utc(1970), _end_of(2225).replace(tzinfo=_UTC), False),
    "symbian": (_AWARE_MIN, _AWARE_MAX, False),
    "systemtime": (_AWARE_MIN, _AWARE_MAX, False),
    "tai": (epochs[1970], _AWARE_MAX, False),
    "tai64n": (epochs[1970], _AWARE_MAX, False),
    "taimilli": (epochs[1970], _AWARE_MAX, False),
    "tar": (epochs[1970], _span(epochs[1970], seconds=8**11), False),
    "telegram": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
    "tid": (epochs[1970], _span(epochs[1970], microseconds=2**53), False),
    "tiktok": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
    "twitter": (
        _utc(2010, 11, 4, 1, 42, 54, 657000),
        _span(_utc(2010, 11, 4, 1, 42, 54, 657000), milliseconds=2**42),
        False,
    ),
    "udf": (dt(1, 1, 1), dt.max, True),
    "ulid": (epochs[1970], _utc(9999, 12, 31, 23, 59, 59), False),
    "uuid6": (epochs[1582], _span(epochs[1582], microseconds=2**60 // 10), False),
    "uuid7": (epochs[1970], _AWARE_MAX, False),
    "unixdays": (epochs[1970], _AWARE_MAX, False),
    "unixhex32be": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
    "unixhex32le": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
    "unixmilli": (epochs[1970], _AWARE_MAX, False),
    "unixmillihex": (epochs[1970], _AWARE_MAX, False),
    "unixnano": (epochs[1970], _AWARE_MAX, False),
    "unixsec": (epochs[1970], _AWARE_MAX, False),
    "unixsecfrac": (epochs[1970], _AWARE_MAX, False),
    "uuid": (epochs[1582], _span(epochs[1582], microseconds=2**60 // 10), False),
    "vm": (epochs[1970], _AWARE_MAX, False),
    "xfs": (
        epochs[1970] - timedelta(seconds=2**31),
        _span(epochs[1970], seconds=2**31),
        False,
    ),
    "xfsbig": (
        _XFS_BIGTIME_EPOCH,
        _XFS_BIGTIME_EPOCH + timedelta(microseconds=2**64 // 1000),
        False,
    ),
    "xid": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
    "xray": (epochs[1970], _span(epochs[1970], seconds=_UINT32), False),
}


def _within_range(func, first, last, wall_clock):
    """Wrap an encoder so that it returns an empty result outside of its first and last dates"""

    @functools.wraps(func)
    def guarded(dt_obj):
        try:
            value = dt_obj.replace(tzinfo=None) if wall_clock else dt_obj
            if not first <= value <= last:
                return "", ""
        except (OverflowError, TypeError):
            return "", ""
        return func(dt_obj)

    guarded.first, guarded.last = first, last
    return guarded


for _name, (_first, _last, _wall_clock) in ENCODER_RANGES.items():
    globals()[f"to_{_name}"] = _within_range(
        globals()[f"to_{_name}"], _first, _last, _wall_clock
    )


single_funcs = {
    "active": [from_active, to_active],
    "apache": [from_apache, to_apache],
    "apfs": [from_apfs, to_apfs],
    "biome64": [from_biome64, to_biome64],
    "biomehex": [from_biomehex, to_biomehex],
    "bplist": [from_bplist, to_bplist],
    "iostime": [from_iostime, to_iostime],
    "mac": [from_mac, to_mac],
    "xray": [from_xray, to_xray],
    "bcd": [from_bcd, to_bcd],
    "bitdate": [from_bitdate, to_bitdate],
    "bitdec": [from_bitdec, to_bitdec],
    "tid": [from_tid, to_tid],
    "btrfs": [from_btrfs, to_btrfs],
    "cdma": [from_cdma, to_cdma],
    "cuid": [from_cuid, to_cuid],
    "dhcp6": [from_dhcp6, to_dhcp6],
    "discord": [from_discord, to_discord],
    "dvr": [from_dvr, to_dvr],
    "exfat": [from_exfat, to_exfat],
    "exfatext": [from_exfatext, to_exfatext],
    "ext4": [from_ext4, to_ext4],
    "fbcookie": [from_fbcookie, None],
    "fat": [from_fat, to_fat],
    "firebase": [from_firebase, to_firebase],
    "garmin": [from_garmin, to_garmin],
    "gbound": [from_gbound, to_gbound],
    "gmsgid": [from_gmsgid, to_gmsgid],
    "gacookie": [from_gacookie, None],
    "chrome": [from_chrome, to_chrome],
    "eitime": [from_eitime, to_eitime],
    "gclid": [from_gclid, None],
    "ved": [from_ved, None],
    "gps": [from_gps, to_gps],
    "gsm": [from_gsm, to_gsm],
    "hfsbe": [from_hfsbe, to_hfsbe],
    "hfsle": [from_hfsle, to_hfsle],
    "hfsdec": [from_hfsdec, to_hfsdec],
    "horolog": [from_horolog, to_horolog],
    "instagram": [from_instagram, to_instagram],
    "iso9660": [from_iso9660, to_iso9660],
    "logtime": [from_logtime, to_logtime],
    "juliandec": [from_juliandec, to_juliandec],
    "julianhex": [from_julianhex, to_julianhex],
    "ksalnum": [from_ksalnum, to_ksalnum],
    "ksdec": [from_ksdec, to_ksdec],
    "leb128hex": [from_leb128hex, to_leb128hex],
    "linkedin": [from_linkedin, to_linkedin],
    "mars": [from_mars, to_mars],
    "mastodon": [from_mastodon, to_mastodon],
    "matlab": [from_matlab, to_matlab],
    "matroska": [from_matroska, to_matroska],
    "metasploit": [from_metasploit, None],
    "dotnet": [from_dotnet, to_dotnet],
    "dotnetbin": [from_dotnetbin, to_dotnetbin],
    "systemtime": [from_systemtime, to_systemtime],
    "dttm": [from_dttm, to_dttm],
    "ms1904": [from_ms1904, to_ms1904],
    "hotmail": [from_hotmail, to_hotmail],
    "msdos": [from_msdos, to_msdos],
    "mssql": [from_mssql, to_mssql],
    "mssqlle": [from_mssqlle, to_mssqlle],
    "mjd": [from_mjd, to_mjd],
    "objectid": [from_objectid, to_objectid],
    "moto": [from_moto, to_moto],
    "prtime": [from_prtime, to_prtime],
    "mysql": [from_mysql, to_mysql],
    "ns40": [from_ns40, to_ns40],
    "ns40le": [from_ns40le, to_ns40le],
    "nokia": [from_nokia, to_nokia],
    "nokiale": [from_nokiale, to_nokiale],
    "ntp64": [from_ntp64, to_ntp64],
    "ntp": [from_ntp, to_ntp],
    "oracle": [from_oracle, to_oracle],
    "int96": [from_int96, to_int96],
    "pcap": [from_pcap, to_pcap],
    "pcapbe": [from_pcapbe, to_pcapbe],
    "postgres": [from_postgres, to_postgres],
    "postgresbe": [from_postgresbe, to_postgresbe],
    "postgresle": [from_postgresle, to_postgresle],
    "quicktime": [from_quicktime, to_quicktime],
    "s32": [from_s32, to_s32],
    "sasdate": [from_sasdate, to_sasdate],
    "sas": [from_sas, to_sas],
    "semioctet": [from_semioctet, to_semioctet],
    "sony": [from_sony, to_sony],
    "spss": [from_spss, to_spss],
    "stardatetng": [from_stardatetng, to_stardatetng],
    "stardatetos": [from_stardatetos, to_stardatetos],
    "stata": [from_stata, to_stata],
    "symantec": [from_symantec, to_symantec],
    "symbian": [from_symbian, to_symbian],
    "taimilli": [from_taimilli, to_taimilli],
    "tai": [from_tai, to_tai],
    "tai64n": [from_tai64n, to_tai64n],
    "tar": [from_tar, to_tar],
    "telegram": [from_telegram, to_telegram],
    "tiktok": [from_tiktok, to_tiktok],
    "twitter": [from_twitter, to_twitter],
    "udf": [from_udf, to_udf],
    "efitime": [from_efitime, to_efitime],
    "ulid": [from_ulid, to_ulid],
    "unixdays": [from_unixdays, to_unixdays],
    "unixhex32be": [from_unixhex32be, to_unixhex32be],
    "unixhex32le": [from_unixhex32le, to_unixhex32le],
    "unixmilli": [from_unixmilli, to_unixmilli],
    "unixmillihex": [from_unixmillihex, to_unixmillihex],
    "unixnano": [from_unixnano, to_unixnano],
    "unixsec": [from_unixsec, to_unixsec],
    "unixsecfrac": [from_unixsecfrac, to_unixsecfrac],
    "uuid": [from_uuid, to_uuid],
    "uuid6": [from_uuid6, to_uuid6],
    "uuid7": [from_uuid7, to_uuid7],
    "vm": [from_vm, to_vm],
    "cookie": [from_cookie, to_cookie],
    "filetimelohi": [from_filetimelohi, to_filetimelohi],
    "filetimebe": [from_filetimebe, to_filetimebe],
    "filetimele": [from_filetimele, to_filetimele],
    "olebe": [from_olebe, to_olebe],
    "olele": [from_olele, to_olele],
    "oleauto": [from_oleauto, to_oleauto],
    "xfsbig": [from_xfsbig, to_xfsbig],
    "xfs": [from_xfs, to_xfs],
    "xid": [from_xid, to_xid],
}
__types__ = len(single_funcs)
type_groups = {"nsdate": ("bplist", "mac", "iostime")}


class HelpFormatter(argparse.RawTextHelpFormatter):
    """Keeps the timestamp options listed as plain flags though they take an optional value"""

    def _format_args(self, action, default_metavar):
        if action.nargs == "?" and action.metavar == "":
            return ""
        return super()._format_args(action, default_metavar)


def use_unicode_output():
    for stream in (sys.stdout, sys.stderr):
        try:
            "┌─┬┐│└┴┘".encode(getattr(stream, "encoding", None) or "ascii")
        except (UnicodeEncodeError, LookupError):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError, OSError):
                pass


def main():
    """Parse all passed arguments"""
    global __fmt__
    use_unicode_output()
    now = date_string(dt.now(timezone.utc))
    arg_parse = argparse.ArgumentParser(
        description=f"Time Decoder and Converter v"
        f"{str(__version__)} - supporting "
        f"{str(__types__)} timestamps!\n\n"
        f"Some timestamps are only part of the entire value, and as such, full\n"
        f"timestamps may not be generated based on only the date/time portion.",
        formatter_class=HelpFormatter,
        usage=argparse.SUPPRESS,
    )
    arg_parse.add_argument(
        "--csv",
        metavar="SRC_FILE TS_FORMAT <column-number>",
        help=(
            "Process a csv/txt file with timestamps and convert them to the selected timestamp\n"
            "Requires a timestamp format be provided without --. ie. 'unixsec' vice '--unixsec'.\n"
            "You can also provide a column number if your input file contains multiple columns."
        ),
        nargs="*",
    )
    arg_parse.add_argument(
        "--date-format",
        metavar="FORMAT_NAME",
        help=(
            "Changes the output format of a date/time value.\n"
            "Use the NAME for the format provided.\n"
            "Use --date-formats to see all available options."
        ),
        type=str,
        default="Default",
    )
    arg_parse.add_argument(
        "--date-formats",
        action="store_true",
        help="Displays available date formats for the output of a date/time value",
    )
    arg_parse.add_argument(
        "--formats",
        metavar="ARGUMENT",
        help=(
            "Display timestamp format and example by providing an available argument (without --)."
            "\nIf no argument is selected, all will be displayed."
        ),
        nargs="?",
        const="ALL",
    )
    arg_parse.add_argument(
        "--guess",
        metavar="TIMESTAMP",
        help="Guess the timestamp format and output possibilities",
    )
    arg_parse.add_argument(
        "--gui",
        "-g",
        action="store_true",
        help="Launch the gui",
    )
    arg_parse.add_argument(
        "--minimal",
        "-m",
        action="store_true",
        help="Output only the timestamp, not the description",
    )
    arg_parse.add_argument(
        "--now",
        "-n",
        action="store_true",
        help="With --to, use the current date/time as the value for conversion",
    )
    arg_parse.add_argument(
        "--to",
        action="store_true",
        help="Convert a date/time to a selected timestamp format",
    )
    arg_parse.add_argument(
        "--timestamp",
        metavar="DATE",
        help=(
            "Convert date to every timestamp\n"
            'Enter date as "YYYY-MM-DD HH:MM:SS.f" in 24h fmt\n'
            "Without a provided DATE, it will convert the current UTC date/time\n"
        ),
        nargs="?",
        const=now,
    )
    arg_parse.add_argument(
        "--timezones",
        help="Prints a list of timezones to use for conversion",
        action="store_true",
    )
    arg_parse.add_argument(
        "--tz",
        metavar="TIMEZONE_NAME",
        help=(
            "Provide the name of a timezone for conversion within quotes.\n"
            "Use --timezones to see a list."
        ),
        type=str,
        default=None,
    )
    for argument, data in ts_types.items():
        arg_parse.add_argument(
            f"--{argument}",
            metavar="",
            nargs="?",
            const=True,
            help=data.ts_type.replace("%", "%%"),
        )
    arg_parse.add_argument(
        "--version", "-v", action="version", version=arg_parse.description
    )

    if len(sys.argv[1:]) == 0:
        arg_parse.print_help()
        arg_parse.exit()
    if len(sys.argv[1:]) > 0 and ("--timezones" in sys.argv):
        list_timezones()
        sys.exit(0)
    args = arg_parse.parse_args()
    if args.date_format in date_formats:
        __fmt__ = date_formats[args.date_format]
    else:
        arg_parse.error(
            (
                f"[!] The format {args.date_format} is not one of the available options.\n"
                "Please use the --date-formats argument to find a valid NAME."
            )
        )
    if args.tz is not None and not valid_timezone(args.tz):
        arg_parse.error(
            f"[!] The time zone {args.tz} was not found.\n"
            "Please use the --timezones argument to find a valid name."
        )
    all_args = vars(args)
    if args.gui:
        gui()
        return
    for argument in ts_types:
        if all_args[argument] is True and not (args.to and args.now):
            arg_parse.error(f"argument --{argument}: expected one argument")
    if args.now and not args.to:
        arg_parse.error(
            "[!] --now can only be used with --to, ie. --to --unixsec --now"
        )
    if args.formats:
        formats(args.formats)
        sys.exit(0)
    if args.date_formats:
        list_date_formats()
        sys.exit(0)
    if args.guess:
        full_list = from_all(args.guess, args.tz)
        if len(full_list) == 0:
            print("[!] No valid dates found. Check your input and try again")
        else:
            print(
                f"[+] Guessing timestamp format for {args.guess}\n"
                f"[+] Outputs which do NOT result in a date/time value are NOT displayed\r"
            )
            if len(full_list) == 1:
                dt_text = "date"
            else:
                dt_text = "dates"
            print(
                f"[+] Displaying {len(full_list)} potential {dt_text}\n"
                f"{__red__}[+] Most likely results (+/- 5 years) are highlighted\n{__clr__}"
            )
            for _, output in enumerate(full_list):
                print(f"{full_list[output][1]}")
        print("\r")
        return
    if args.timestamp:
        ts_dict, ts_outputs = to_timestamps(args.timestamp, args.tz)
        if args.minimal:
            for ts_value in ts_dict.values():
                print(ts_value)
        else:
            print(
                f"\n[+] Converting {args.timestamp} to {len(ts_outputs)} timestamps:\n"
            )
            for ts_val in ts_outputs:
                print(ts_val)
        print("\r")
        return
    if args.csv:
        if len(args.csv) == 2:
            src_file = os.path.normpath(os.path.abspath(args.csv[0]))
            ts_type = args.csv[1]
            src_exists = os.path.exists(src_file) and os.path.isfile(src_file)
            if (ts_type in single_funcs or ts_type in type_groups) and src_exists:
                result, dst, reason = generate_csv(src_file, ts_type, tz_name=args.tz)
                dst = os.path.normpath(dst)
                if result:
                    print(f"[+] CSV file was saved as {dst}.")
                    if reason:
                        print(f"[!] {reason}.")
                else:
                    print(f"[!] Unable to complete CSV export to {dst} - {reason}.")
            else:
                arg_parse.error(
                    "[!] Provided argument is not in the list of conversion options"
                )
        elif len(args.csv) == 3:
            src_file = os.path.normpath(os.path.abspath(args.csv[0]))
            ts_type = args.csv[1]
            column = args.csv[2]
            src_exists = os.path.exists(src_file) and os.path.isfile(src_file)
            if (ts_type in single_funcs or ts_type in type_groups) and src_exists:
                result, dst, reason = generate_csv(
                    src_file, ts_type, column, tz_name=args.tz
                )
                dst = os.path.normpath(dst)
                if result:
                    print(f"[+] CSV file was saved as {dst}.")
                    if reason:
                        print(f"[!] {reason}.")
                else:
                    print(f"[!] Unable to complete CSV export to {dst} - {reason}.")
            else:
                arg_parse.error(
                    "[!] Provided argument is not in the list of conversion options"
                )
        else:
            arg_parse.error(
                (
                    "[!] --csv requires the file name to process "
                    f"and the timestamp type without the '--' {args.csv}"
                )
            )
        return
    if args.to and not any(all_args[arg] for arg in ts_types):
        arg_parse.error(
            "[!] --to requires a timestamp type to convert to, "
            "ie. --to --unixsec 'YYYY-MM-DD HH:MM:SS'"
        )
    now = dt.now(tzone(args.tz) if args.tz else timezone.utc)
    requests = [(arg, all_args[arg], None) for arg in single_funcs if all_args[arg]]
    for group, members in type_groups.items():
        if all_args[group]:
            requests.extend((member, all_args[group], group) for member in members)
    group_hits = set()
    for arg_passed, requested, group in requests:
        funcs = single_funcs[arg_passed]
        if not args.to:
            date_time, indiv_output, _, reason, tz_label = funcs[0](requested)
            if not date_time:
                if group is None:
                    print(f"[!] {reason}")
            else:
                group_hits.add(group)
                if args.tz is not None:
                    date_time, tz_label, _ = convert_timezone(args.tz, date_time)
                    if not date_time:
                        print(
                            f"[!] {requested} is outside the dates that {args.tz} can show."
                        )
                        continue
                    indiv_output = (
                        f"{ts_types[arg_passed].ts_type}: {date_time} {tz_label}"
                    )
                if args.minimal:
                    print(f"{date_time} {tz_label}")
                else:
                    print(indiv_output)
        else:
            if args.now:
                if requested is not True:
                    arg_parse.error(
                        f"[!] --now cannot be combined with a date/time for --{arg_passed}."
                    )
                dt_obj = now
                requested = "now"
            else:
                dt_obj = parse_date(requested)
            if dt_obj is None:
                arg_parse.error(
                    f"[!] Unable to read '{requested}' as a date/time.\n"
                    "[!] Format should be 'YYYY-MM-DD HH:MM:SS.fff' in 24h fmt. "
                    "Milliseconds (.fff) are optional.\n"
                    "[!] Otherwise, use --date-formats to find an accepted format and use:\n"
                    "[!] --date-format NAME where NAME is the format NAME, not the format STRING."
                )
            if not dt_obj.tzinfo:
                if not args.tz:
                    dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                else:
                    tz = tzone(args.tz)
                    dt_obj = dt_obj.replace(tzinfo=tz)
            out_func = funcs[1]
            timestamp = ""
            formatted_output = ""
            if out_func is not None:
                timestamp, formatted_output = out_func(dt_obj)
            else:
                arg_parse.error(f"[!] {arg_passed} does not support a 'to' conversion.")
            if timestamp == "":
                print(f"[!] Unable to convert {requested} to {arg_passed}.")
            else:
                if args.minimal:
                    print(timestamp)
                else:
                    print(formatted_output)
    if not args.to:
        for group in type_groups:
            if all_args[group] and group not in group_hits:
                print(f"[!] {ts_types[group].reason}")


if __name__ == "__main__":
    main()
