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
bplist timestamp / Mac Absolute
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
"""

from datetime import datetime as dt, timedelta
import struct
from string import hexdigits
import argparse
import re
import sys
import base64
import uuid
import traceback
from calendar import monthrange
from dateutil import parser as duparser
from colorama import init

init(autoreset=True)

__author__ = 'Corey Forman'
__date__ = '22 Jul 2022'
__version__ = '4.1.1'
__description__ = 'Python 3 CLI Date Time Conversion Tool'
__fmt__ = '%Y-%m-%d %H:%M:%S.%f'
__red__ = "\033[1;31m"
__clr__ = "\033[1;m"
__types__ = 51

class Error(Exception):
    """Catch Exception"""


class ErrorHandler(Error):
    """Handle Error"""

    @classmethod
    def handle(cls, error):
        """Error handling output and formatting to include function causing error"""
        exc_type, exc_obj, _ = error
        error_tb = traceback.extract_stack()[:-3] + traceback.extract_tb(exc_obj.__traceback__)
        _, line_no, function_name, _ = error_tb[-1]
        print(f'{str(exc_type.__name__)}: {str(exc_obj)} - {function_name} line {line_no}')


class TimeDecoder():
    """Run the decoding class"""
    def __init__(self, args):
        all_args = vars(args)

        if args.guess:
            for each_arg in all_args:
                all_args[each_arg] = args.guess

        for name, value in all_args.items():
            if not hasattr(self, name):
                setattr(self, name, value)

        self.epochs = {
            1: dt(1, 1, 1),
            1601: dt(1601, 1, 1),
            1899: dt(1899, 12, 30),
            1904: dt(1904, 1, 1),
            1970: dt(1970, 1, 1),
            1980: dt(1980, 1, 6),
            2000: dt(2000, 1, 1),
            2001: dt(2001, 1, 1),
            2050: dt(2050, 1, 1),
            'hundreds_nano': 10000000,
            'nano_2001': 1000000000,
            'active': 116444736000000000,
            'hfs_dec_sub': 2082844800,
            'kstime': 1400000000
        }
        self.single_funcs = {
            self.unix: self.from_unix_sec, self.umil: self.from_unix_milli,
            self.wh: self.from_win_64_hex, self.whle: self.from_win_64_hexle,
            self.chrome: self.from_chrome, self.active: self.from_ad,
            self.uhbe: self.from_unix_hex_32be, self.uhle: self.from_unix_hex_32le,
            self.cookie: self.from_cookie, self.oleb: self.from_ole_be,
            self.olel: self.from_ole_le, self.mac: self.from_mac,
            self.hfsdec: self.from_hfs_dec, self.hfsbe: self.from_hfs_be,
            self.hfsle: self.from_hfs_le, self.fat: self.from_fat,
            self.msdos: self.from_msdos, self.systime: self.from_systime,
            self.ft: self.from_filetime, self.hotmail: self.from_hotmail,
            self.pr: self.from_prtime, self.auto: self.from_ole_auto,
            self.ms1904: self.from_ms1904, self.ios: self.from_ios_time,
            self.sym: self.from_sym_time, self.gps: self.from_gps_time,
            self.eitime: self.from_eitime, self.bplist: self.from_bplist,
            self.gsm: self.from_gsm, self.vm: self.from_vm, self.tiktok: self.from_tiktok,
            self.twitter: self.from_twitter, self.discord: self.from_discord,
            self.ksuid: self.from_ksuid, self.mastodon: self.from_mastodon,
            self.meta: self.from_metasploit, self.sony: self.from_sony,
            self.uu: self.from_uuid, self.dhcp6: self.from_dhcp6,
            self.dotnet: self.from_dotnet, self.gbound: self.from_gbound,
            self.gmsgid: self.from_gmsgid, self.moto: self.from_moto,
            self.nokia: self.from_nokia, self.nokiale: self.from_nokiale,
            self.ns40: self.from_ns40, self.ns40le: self.from_ns40le,
            self.bitdec: self.from_bitdec, self.bitdate: self.from_bitdate,
            self.kstime: self.from_kstime, self.exfat: self.from_exfat
        }
        self.from_funcs = [
            self.from_ad, self.from_bitdate, self.from_bitdec, self.from_dhcp6, self.from_discord,
            self.from_exfat, self.from_fat, self.from_gbound, self.from_gmsgid, self.from_chrome,
            self.from_eitime, self.from_gps_time, self.from_gsm, self.from_hfs_be, self.from_hfs_le,
            self.from_ios_time, self.from_bplist, self.from_ksuid, self.from_kstime, self.from_mac,
            self.from_hfs_dec, self.from_mastodon, self.from_metasploit, self.from_systime,
            self.from_filetime, self.from_hotmail, self.from_dotnet, self.from_moto,
            self.from_prtime, self.from_msdos, self.from_ms1904, self.from_ns40, self.from_ns40le,
            self.from_nokia, self.from_nokiale, self.from_ole_auto, self.from_sony,
            self.from_sym_time, self.from_tiktok, self.from_twitter, self.from_unix_hex_32be,
            self.from_unix_hex_32le, self.from_unix_sec, self.from_unix_milli, self.from_uuid,
            self.from_vm, self.from_win_64_hex, self.from_win_64_hexle, self.from_cookie,
            self.from_ole_be, self.from_ole_le
        ]
        self.to_funcs = [
            self.to_ad, self.to_bitdate, self.to_bitdec, self.to_dhcp6, self.to_exfat,
            self.to_fat, self.to_gbound, self.to_gmsgid, self.to_chrome, self.to_eitime,
            self.to_gps_time, self.to_gsm, self.to_hfs_be, self.to_hfs_le, self.to_ios_time,
            self.to_bplist, self.to_kstime, self.to_mac, self.to_hfs_dec, self.to_mastodon,
            self.to_systime, self.to_filetime, self.to_hotmail, self.to_dotnet, self.to_moto,
            self.to_prtime, self.to_msdos, self.to_ms1904, self.to_ns40, self.to_ns40le,
            self.to_nokia, self.to_nokiale, self.to_ole_auto, self.to_sym_time,
            self.to_unix_hex_32be, self.to_unix_hex_32le, self.to_unix_sec, self.to_unix_milli,
            self.to_vm, self.to_win_64_hex, self.to_win_64_hexle, self.to_cookie,
            self.to_ole_be, self.to_ole_le
        ]
        self.in_unix_sec = self.in_unix_milli = self.in_windows_hex_64 = None
        self.in_windows_hex_le = self.in_chrome = self.in_ad = self.in_unix_hex_32 = None
        self.in_unix_hex_32le = self.in_cookie = self.in_ole_be = self.in_ole_le = None
        self.in_mac = self.in_hfs_dec = self.in_hfs_be = self.in_hfs_le = self.in_fat = None
        self.in_msdos = self.in_systemtime = self.in_filetime = self.in_prtime = None
        self.in_ole_auto = self.in_ms1904 = self.in_iostime = self.in_symtime = None
        self.in_hotmail = self.in_gpstime = self.in_eitime = self.in_bplist = None
        self.in_gsm = self.in_vm = self.in_tiktok = self.in_twitter = self.in_discord = None
        self.in_ksuid = self.in_mastodon = self.in_metasploit = self.in_sony = None
        self.in_uuid = self.in_dhcp6 = self.in_dotnet = self.in_gbound = self.in_gmsgid = None
        self.in_moto = self.in_nokia = self.in_nokiale = self.in_ns40 = self.in_ns40le = None
        self.in_bitdec = self.in_bitdate = self.in_kstime = self.in_exfat = None

        self.out_unix_sec = self.out_unix_milli = self.out_windows_hex_64 = self.out_hotmail = None
        self.out_windows_hex_le = self.out_chrome = self.out_adtime = self.out_unix_hex_32 = None
        self.out_unix_hex_32le = self.out_cookie = self.out_ole_be = self.out_ole_le = None
        self.out_mac = self.out_hfs_dec = self.out_hfs_be = self.out_hfs_le = self.out_fat = None
        self.out_msdos = self.out_systemtime = self.out_filetime = self.out_prtime = None
        self.out_ole_auto = self.out_ms1904 = self.out_iostime = self.out_symtime = None
        self.out_gpstime = self.out_eitime = self.out_bplist = self.out_gsm = self.out_vm = None
        self.out_dhcp6 = self.out_mastodon = self.out_dotnet = self.out_gbound = None
        self.out_gmsgid = self.out_moto = self.out_nokia = self.out_nokiale = self.out_ns40 = None
        self.out_ns40le = self.out_bitdec = self.out_bitdate = self.out_kstime = None
        self.out_exfat = None

        self.leapseconds = {
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
            37: [dt(2017, 1, 1), dt.now() - timedelta(seconds=37)]
        }
        # There have been no further leapseconds since 2017,1,1 at the __date__ of this script
        # which is why the leapseconds end with a dt.now object to valid/relevant timestamp output.
        self.ts_types = {
            'unix_sec': 'Unix Seconds:',
            'unix_milli': 'Unix Milliseconds:',
            'windows_hex_64': 'Windows 64-bit Hex BE:',
            'windows_hex_le': 'Windows 64-bit Hex LE:',
            'chrome': 'Google Chrome:',
            'ad': 'Active Directory/LDAP dt:',
            'unix_hex_32': 'Unix Hex 32-bit BE:',
            'unix_hex_32le': 'Unix Hex 32-bit LE:',
            'cookie': 'Windows Cookie Date:',
            'ole_be': 'Windows OLE 64-bit double BE:',
            'ole_le': 'Windows OLE 64-bit double LE:',
            'mac': 'Mac Absolute Time:',
            'hfs_dec': 'Mac OS/HFS+ Decimal Time:',
            'hfs_be': 'HFS/HFS+ 32-bit Hex BE:',
            'hfs_le': 'HFS/HFS+ 32-bit Hex LE:',
            'msdos': 'MS-DOS 32-bit Hex Value:',
            'fat': 'FAT Date + Time:',
            'systemtime': 'Microsoft 128-bit SYSTEMTIME:',
            'filetime': 'Microsoft FILETIME time:',
            'hotmail': 'Microsoft Hotmail time:',
            'prtime': 'Mozilla PRTime:',
            'ole_auto': 'OLE Automation Date:',
            'ms1904': 'MS Excel 1904 Date:',
            'iostime': 'iOS 11 Date:',
            'symtime': 'Symantec AV time:',
            'gpstime': 'GPS time:',
            'eitime': 'Google EI time:',
            'bplist': 'iOS Binary Plist time:',
            'gsm': 'GSM time:',
            'vm': 'VMSD time:',
            'tiktok': 'TikTok time:',
            'twitter': 'Twitter time:',
            'discord': 'Discord time:',
            'ksuid': 'KSUID time:',
            'mastodon': 'Mastodon time:',
            'metasploit': 'Metasploit Payload UUID:',
            'sony': 'Sonyflake time:',
            'uu': 'UUID time:',
            'dhcp6': 'DHCP6 DUID time:',
            'dotnet': 'Microsoft .NET DateTime:',
            'gbound': 'GMail Boundary time:',
            'gmsgid': 'GMail Message ID time:',
            'moto': 'Motorola time:',
            'nokia': 'Nokia time:',
            'nokiale': 'Nokia time LE:',
            'ns40': 'Nokia S40 time:',
            'ns40le': 'Nokia S40 time LE:',
            'bitdec': 'Bitwise Decimal time:',
            'bitdate': 'BitDate time:',
            'kstime': 'KSUID Decimal:',
            'exfat': 'exFAT time:'
        }

    def run(self):
        """Process arguments and errors"""
        try:
            if self.guess:
                self.from_all()
                return

            for arg_passed in self.single_funcs:
                if arg_passed:
                    _, indiv_output, _, reason = self.single_funcs[arg_passed]()
                    if indiv_output is False:
                        print(reason)
                    else:
                        print(indiv_output)

            if self.timestamp:
                self.to_timestamps()
        except Exception:
            ErrorHandler.handle(sys.exc_info())

    def to_timestamps(self):
        """Convert provided date to all timestamps"""
        print(f'\nConverting Date: {self.timestamp}\n')
        for func in self.to_funcs:
            func()
        self.timestamp_output()

    def from_unix_sec(self):
        """Convert Unix Seconds value to a date"""
        reason = "[!] Unix seconds timestamp is 10 digits in length"
        ts_type = self.ts_types['unix_sec']
        try:
            if not len(self.unix) == 10 or not self.unix.isdigit():
                self.in_unix_sec = indiv_output = combined_output = False
            else:
                self.in_unix_sec = dt.utcfromtimestamp(float(self.unix)).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_unix_sec} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_unix_sec} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_unix_sec = indiv_output = combined_output = False
        return self.in_unix_sec, indiv_output, combined_output, reason

    def to_unix_sec(self):
        """Convert date to a Unix Seconds value"""
        ts_type = self.ts_types['unix_sec']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            self.out_unix_sec = str(int((dt_obj - self.epochs[1970]).total_seconds()) - int(dt_tz))
            ts_output = str(f"{ts_type}\t\t\t{self.out_unix_sec}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_unix_sec = ts_output = False
        return self.out_unix_sec, ts_output

    def from_unix_milli(self):
        """Convert Unix Millisecond value to a date"""
        reason = "[!] Unix milliseconds timestamp is 13 digits in length"
        ts_type = self.ts_types['unix_milli']
        try:
            if not len(self.umil) == 13 or not self.umil.isdigit():
                self.in_unix_milli = indiv_output = combined_output = False
            else:
                self.in_unix_milli = dt.utcfromtimestamp(float(self.umil) /
                                                         1000.0).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_unix_milli} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_unix_milli} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_unix_milli = indiv_output = combined_output = False
        return self.in_unix_milli, indiv_output, combined_output, reason

    def to_unix_milli(self):
        """Convert date to a Unix Millisecond value"""
        ts_type = self.ts_types['unix_milli']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            self.out_unix_milli = str(int(((dt_obj -
                                            self.epochs[1970]).total_seconds() -
                                           int(dt_tz))*1000))
            ts_output = str(f"{ts_type}\t\t{self.out_unix_milli}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_unix_milli = ts_output = False
        return self.out_unix_milli, ts_output

    def from_win_64_hex(self):
        """Convert a Windows 64 Hex Big-Endian value to a date"""
        reason = "[!] Windows 64-bit Hex Big-Endian timestamp is 16 hex characters (8 bytes)"
        ts_type = self.ts_types['windows_hex_64']
        try:
            if not len(self.wh) == 16 or not all(char in hexdigits for char in self.wh):
                self.in_windows_hex_64 = indiv_output = combined_output = False
            else:
                base10_microseconds = int(self.wh, 16) / 10
                if base10_microseconds >= 1e+17:
                    self.in_windows_hex_64 = indiv_output = combined_output = False
                else:
                    dt_obj = self.epochs[1601] + timedelta(microseconds=base10_microseconds)
                    self.in_windows_hex_64 = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_windows_hex_64} UTC")
                    combined_output = str(f"{__red__}{ts_type}\t\t{self.in_windows_hex_64} "
                                          f"UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_windows_hex_64 = indiv_output = combined_output = False
        return self.in_windows_hex_64, indiv_output, combined_output, reason

    def to_win_64_hex(self):
        """Convert a date to a Windows 64 Hex Big-Endian value"""
        ts_type = self.ts_types['windows_hex_64']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            minus_epoch = dt_obj - self.epochs[1601]
            calc_time = (minus_epoch.microseconds +
                         ((minus_epoch.seconds - int(dt_tz)) * 1000000) +
                         (minus_epoch.days * 86400000000))
            self.out_windows_hex_64 = str(hex(int(calc_time)*10))[2:].zfill(16)
            ts_output = str(f"{ts_type}\t\t{self.out_windows_hex_64}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_windows_hex_64 = ts_output = False
        return self.out_windows_hex_64, ts_output

    def from_win_64_hexle(self):
        """Convert a Windows 64 Hex Little-Endian value to a date"""
        reason = "[!] Windows 64-bit Hex Little-Endian timestamp is 16 hex characters (8 bytes)"
        ts_type = self.ts_types['windows_hex_le']
        try:
            if not len(self.whle) == 16 or not all(char in hexdigits for char in self.whle):
                self.in_windows_hex_le = indiv_output = combined_output = False
            else:
                indiv_output = combined_output = False
                endianness_change = int.from_bytes(struct.pack("<Q", int(self.whle, 16)), 'big')
                converted_time = endianness_change / 10
                try:
                    dt_obj = self.epochs[1601] + timedelta(microseconds=converted_time)
                    self.in_windows_hex_le = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_windows_hex_le} UTC")
                    combined_output = str(f"{__red__}{ts_type}\t\t{self.in_windows_hex_le} "
                                          f"UTC{__clr__}")
                except OverflowError:
                    pass
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_windows_hex_le = indiv_output = combined_output = False
        return self.in_windows_hex_le, indiv_output, combined_output, reason

    def to_win_64_hexle(self):
        """Convert a date to a Windows 64 Hex Little-Endian value"""
        ts_type = self.ts_types['windows_hex_le']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            minus_epoch = dt_obj - self.epochs[1601]
            calc_time = (minus_epoch.microseconds +
                         ((minus_epoch.seconds - int(dt_tz)) * 1000000) +
                         (minus_epoch.days * 86400000000))
            self.out_windows_hex_le = str(struct.pack("<Q", int(calc_time * 10)).hex()).zfill(16)
            ts_output = str(f"{ts_type}\t\t{self.out_windows_hex_le}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_windows_hex_le = ts_output = False
        return self.out_windows_hex_le, ts_output

    def from_chrome(self):
        """Convert a Chrome Timestamp/Webkit Value to a date"""
        reason = "[!] Chrome/Webkit timestamp is 17 digits"
        ts_type = self.ts_types['chrome']
        try:
            if not len(self.chrome) == 17 or not self.chrome.isdigit():
                self.in_chrome = indiv_output = combined_output = False
            else:
                delta = timedelta(microseconds=int(self.chrome))
                converted_time = self.epochs[1601] + delta
                self.in_chrome = converted_time.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_chrome} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_chrome} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_chrome = indiv_output = combined_output = False
        return self.in_chrome, indiv_output, combined_output, reason

    def to_chrome(self):
        """Convert a date to a Chrome Timestamp/Webkit value"""
        ts_type = self.ts_types['chrome']
        try:
            dt_obj = duparser.parse(self.timestamp)
            nano_seconds = ''
            if '.' in self.timestamp:
                nano_seconds = self.timestamp.split('.')[1].split(' ')[0]
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            micro_seconds = (dt_obj - self.epochs[1601]).microseconds
            chrome_time = ((dt_obj - self.epochs[1601]).total_seconds() - int(dt_tz))
            chrome_micro = str(chrome_time).split('.')[1]
            if (len(nano_seconds) == 6 and len(chrome_micro) < 6) or \
                len(nano_seconds) > 6 or len(nano_seconds) == 6:
                chrome_time = str(chrome_time).replace(str(chrome_time).split('.')[1],
                                                       str(micro_seconds).zfill(6))
                self.out_chrome = str(chrome_time).replace('.', '')
            else:
                self.out_chrome = str(int(chrome_time * 1000000))
            ts_output = str(f"{ts_type}\t\t\t{self.out_chrome}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_chrome = ts_output = False
        return self.out_chrome, ts_output

    def from_ad(self):
        """Convert an Active Directory/LDAP timestamp to a date"""
        reason = "[!] Active Directory/LDAP timestamps are 18 digits"
        ts_type = self.ts_types['ad']
        try:
            if not len(self.active) == 18 or not self.active.isdigit():
                self.in_ad = indiv_output = combined_output = False
            else:
                dt_obj = (dt.utcfromtimestamp((float(int(self.active) - self.epochs['active']) /
                                               self.epochs['hundreds_nano'])))
                self.in_ad = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_ad} UTC")
                combined_output = str(f"{__red__}{ts_type}\t{self.in_ad} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_ad = indiv_output = combined_output = False
        return self.in_ad, indiv_output, combined_output, reason

    def to_ad(self):
        """Convert a date to an Active Directory/LDAP timestamp"""
        ts_type = self.ts_types['ad']
        try:
            nano_seconds = ''
            if '.' in self.timestamp:
                nano_seconds = self.timestamp.split('.')[1].split(' ')[0]
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            else:
                dt_tz = 0
                dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            if len(nano_seconds) == 7:
                dt_obj = dt_obj.replace(microsecond=0)
                nano_seconds = int(nano_seconds)
            elif len(nano_seconds) > 7:
                dt_obj = dt_obj.replace(microsecond=0)
                nano_seconds = int(nano_seconds[:-(len(nano_seconds) - 7)])
            elif len(nano_seconds) == 6 or \
                 (len(nano_seconds) == 5 and len(str(dt_obj.microsecond)) == 6):
                nano_seconds = dt_obj.microsecond * 10
                dt_obj = dt_obj.replace(microsecond=0)
            else:
                nano_seconds = 0
            tz_shift = int(((dt_obj - self.epochs[1970]).total_seconds() -
                            int(dt_tz)) * self.epochs['hundreds_nano']) + nano_seconds
            self.out_adtime = str(int(tz_shift) + int(self.epochs['active']))
            ts_output = str(f"{ts_type}\t{self.out_adtime}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_adtime = ts_output = False
        return self.out_adtime, ts_output

    def from_unix_hex_32be(self):
        """Convert a Unix Hex 32-bit Big-Endian timestamp to a date"""
        reason = "[!] Unix Hex 32-bit Big-Endian timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['unix_hex_32']
        try:
            if not len(self.uhbe) == 8 or not all(char in hexdigits for char in self.uhbe):
                self.in_unix_hex_32 = indiv_output = combined_output = False
            else:
                to_dec = int(self.uhbe, 16)
                self.in_unix_hex_32 = dt.utcfromtimestamp(float(to_dec)).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_unix_hex_32} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_unix_hex_32} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_unix_hex_32 = indiv_output = combined_output = False
        return self.in_unix_hex_32, indiv_output, combined_output, reason

    def to_unix_hex_32be(self):
        """Convert a date to a Unix Hex 32-bit Big-Endian timestamp"""
        ts_type = self.ts_types['unix_hex_32']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_time = int((dt_obj - self.epochs[1970]).total_seconds() - int(dt_tz))
            self.out_unix_hex_32 = str(struct.pack(">L", unix_time).hex())
            ts_output = str(f"{ts_type}\t\t{self.out_unix_hex_32}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_unix_hex_32 = ts_output = False
        return self.out_unix_hex_32, ts_output

    def from_unix_hex_32le(self):
        """Convert a Unix Hex 32-bit Little-Endian timestamp to a date"""
        reason = "[!] Unix Hex 32-bit Little-Endian timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['unix_hex_32le']
        try:
            if not len(self.uhle) == 8 or not all(char in hexdigits for char in self.uhle):
                self.in_unix_hex_32le = indiv_output = combined_output = False
            else:
                to_dec = int.from_bytes(struct.pack("<L", int(self.uhle, 16)), 'big')
                self.in_unix_hex_32le = dt.utcfromtimestamp(float(to_dec)).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_unix_hex_32le} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_unix_hex_32le} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_unix_hex_32le = indiv_output = combined_output = False
        return self.in_unix_hex_32le, indiv_output, combined_output, reason

    def to_unix_hex_32le(self):
        """Convert a date to a Unix Hex 32-bit Little-Endian timestamp"""
        ts_type = self.ts_types['unix_hex_32le']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_time = int((dt_obj - self.epochs[1970]).total_seconds() - int(dt_tz))
            self.out_unix_hex_32le = str(struct.pack("<L", unix_time).hex())
            ts_output = str(f"{ts_type}\t\t{self.out_unix_hex_32le}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_unix_hex_32le = ts_output = False
        return self.out_unix_hex_32le, ts_output

    def from_cookie(self):
        """Convert an Internet Explorer timestamp to a date"""
        reason = "[!] IE text cookie times consist of 2 ints. Enter with a comma between them."
        ts_type = self.ts_types['cookie']
        try:
            if not ("," in self.cookie) or not \
                (self.cookie.split(",")[0].isdigit() and self.cookie.split(",")[1].isdigit()):
                self.in_cookie = indiv_output = combined_output = False
            else:
                low, high = [int(h, base=10) for h in self.cookie.split(',')]
                calc = 10**-7 * (high * 2**32 + low) - 11644473600
                if calc >= 1e+11:
                    self.in_cookie = indiv_output = combined_output = False
                else:
                    dt_obj = dt.utcfromtimestamp(calc)
                    self.in_cookie = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_cookie} UTC")
                    combined_output = str(f"{__red__}{ts_type}\t\t{self.in_cookie} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_cookie = indiv_output = combined_output = False
        return self.in_cookie, indiv_output, combined_output, reason

    def to_cookie(self):
        """Convert a date to Internet Explorer timestamp values"""
        ts_type = self.ts_types['cookie']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_time = int((dt_obj - self.epochs[1970]).total_seconds() - int(dt_tz))
            high = int(((unix_time + 11644473600) * 10**7) / 2**32)
            low = int((unix_time + 11644473600) * 10**7) - (high * 2**32)
            self.out_cookie = f'{str(low)},{str(high)}'
            ts_output = str(f"{ts_type}\t\t{self.out_cookie}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_cookie = ts_output = False
        return self.out_cookie, ts_output

    def from_ole_be(self):
        """Convert an OLE Big-Endian timestamp to a date"""
        reason = "[!] OLE Big-Endian timestamps are 16 hex characters (8 bytes)"
        ts_type = self.ts_types['ole_be']
        try:
            if not len(self.oleb) == 16 or not all(char in hexdigits for char in self.oleb):
                self.in_ole_be = indiv_output = combined_output = False
            else:
                delta = struct.unpack('>d', struct.pack('>Q', int(self.oleb, 16)))[0]
                if delta != delta or int(delta) < 0 or delta > 2e+6:
                    self.in_ole_be = indiv_output = combined_output = False
                else:
                    dt_obj = self.epochs[1899] + timedelta(days=delta)
                    self.in_ole_be = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_ole_be} UTC")
                    combined_output = str(f"{__red__}{ts_type}\t{self.in_ole_be} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_ole_be = indiv_output = combined_output = False
        return self.in_ole_be, indiv_output, combined_output, reason

    def to_ole_be(self):
        """Convert a date to an OLE Big-Endian timestamp"""
        ts_type = self.ts_types['ole_be']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            delta = ((dt_obj - self.epochs[1899]).total_seconds() - int(dt_tz)) / 86400
            conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
            self.out_ole_be = str(struct.pack('>Q', conv).hex())
            ts_output = str(f"{ts_type}\t{self.out_ole_be}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_ole_be = ts_output = False
        return self.out_ole_be, ts_output

    def from_ole_le(self):
        """Convert an OLE Little-Endian timestamp to a date"""
        reason = "[!] OLE Little-Endian timestamps are 16 hex characters (8 bytes)"
        ts_type = self.ts_types['ole_le']
        try:
            if not len(self.olel) == 16 or not all(char in hexdigits for char in self.olel):
                self.in_ole_le = indiv_output = combined_output = False
            else:
                to_le = hex(int.from_bytes(struct.pack('<Q', int(self.olel, 16)), 'big'))
                delta = struct.unpack('>d', struct.pack('>Q', int(to_le[2:], 16)))[0]
                if delta != delta or int(delta) < 0 or int(delta) > 99999:
                    self.in_ole_le = indiv_output = combined_output = False
                else:
                    dt_obj = self.epochs[1899] + timedelta(days=delta)
                    self.in_ole_le = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_ole_le} UTC")
                    combined_output = str(f"{__red__}{ts_type}\t{self.in_ole_le} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_ole_le = indiv_output = combined_output = False
        return self.in_ole_le, indiv_output, combined_output, reason

    def to_ole_le(self):
        """Convert a date to an OLE Little-Endian timestamp"""
        ts_type = self.ts_types['ole_le']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            delta = ((dt_obj - self.epochs[1899]).total_seconds() - int(dt_tz)) / 86400
            conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
            self.out_ole_le = str(struct.pack('<Q', conv).hex())
            ts_output = str(f"{ts_type}\t{self.out_ole_le}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_ole_le = ts_output = False
        return self.out_ole_le, ts_output

    def from_mac(self):
        """Convert a Mac Absolute timestamp to a date - Also used for Safari plist timestamps"""
        reason = "[!] Mac Absolute values are 9 digits, a decimal, and up to 6 digits for ms"
        ts_type = self.ts_types['mac']
        try:
            if "." not in self.mac or not \
                ((len(self.mac.split(".")[0]) == 9) and
                 (len(self.mac.split(".")[1]) in range(0, 7))) or not \
                 ''.join(self.mac.split(".")).isdigit():
                self.in_mac = indiv_output = combined_output = False
            else:
                dt_obj = self.epochs[2001] + timedelta(seconds=float(self.mac))
                self.in_mac = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_mac} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_mac} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_mac = indiv_output = combined_output = False
        return self.in_mac, indiv_output, combined_output, reason

    def to_mac(self):
        """Convert a date to a Mac Absolute timestamp"""
        ts_type = self.ts_types['mac']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            self.out_mac = str(int((dt_obj - self.epochs[2001]).total_seconds() - int(dt_tz)))
            ts_output = str(f"{ts_type}\t\t{self.out_mac}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_mac = ts_output = False
        return self.out_mac, ts_output

    def from_hfs_dec(self):
        """Convert a Mac OS/HFS+ Decimal Timestamp to a date"""
        reason = "[!] Mac OS/HFS+ Decimal timestamps are 10 digits"
        ts_type = self.ts_types['hfs_dec']
        try:
            if len(str(self.hfsdec)) != 10 or not (self.hfsdec).isdigit():
                self.in_hfs_dec = indiv_output = combined_output = False
            else:
                self.in_hfs_dec = dt.utcfromtimestamp(float
                                                      (int(self.hfsdec)
                                                       - self.epochs['hfs_dec_sub'])
                                                      ).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_hfs_dec} UTC")
                combined_output = str(f"{__red__}{ts_type}\t{self.in_hfs_dec} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_hfs_dec = indiv_output = combined_output = False
        return self.in_hfs_dec, indiv_output, combined_output, reason

    def to_hfs_dec(self):
        """Convert a date to a Mac OS/HFS+ Decimal Timestamp"""
        ts_type = self.ts_types['hfs_dec']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            self.out_hfs_dec = str(int((dt_obj - self.epochs[1904]).total_seconds() - int(dt_tz)))
            ts_output = str(f"{ts_type}\t{self.out_hfs_dec}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_hfs_dec = ts_output = False
        return self.out_hfs_dec, ts_output

    def from_hfs_be(self):
        """Convert an HFS/HFS+ Big-Endian timestamp to a date (HFS+ is in UTC)"""
        reason = "[!] HFS/HFS+ Big-Endian timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['hfs_be']
        try:
            if not len(self.hfsbe) == 8 or not all(char in hexdigits for char in self.hfsbe):
                self.in_hfs_be = indiv_output = combined_output = False
            else:
                dt_obj = self.epochs[1904] + timedelta(seconds=int(self.hfsbe, 16))
                self.in_hfs_be = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_hfs_be} HFS Local / HFS+ UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_hfs_be} "
                                      f"HFS Local / HFS+ UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_hfs_be = indiv_output = combined_output = False
        return self.in_hfs_be, indiv_output, combined_output, reason

    def to_hfs_be(self):
        """Convert a date to an HFS/HFS+ Big-Endian timestamp"""
        ts_type = self.ts_types['hfs_be']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            conv = int((dt_obj - self.epochs[1904]).total_seconds() - int(dt_tz))
            self.out_hfs_be = f'{conv:08x}'
            ts_output = str(f"{ts_type}\t\t{self.out_hfs_be}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_hfs_be = ts_output = False
        return self.out_hfs_be, ts_output

    def from_hfs_le(self):
        """Convert an HFS/HFS+ Little-Endian timestamp to a date (HFS+ is in UTC)"""
        reason = "[!] HFS/HFS+ Little-Endian timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['hfs_le']
        try:
            if not len(self.hfsle) == 8 or not all(char in hexdigits for char in self.hfsle):
                self.in_hfs_le = indiv_output = combined_output = False
            else:
                to_le = struct.unpack('>I', struct.pack('<I', int(self.hfsle, 16)))[0]
                dt_obj = self.epochs[1904] + timedelta(seconds=to_le)
                self.in_hfs_le = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_hfs_le} HFS Local / HFS+ UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_hfs_le} "
                                      f"HFS Local / HFS+ UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_hfs_le = indiv_output = combined_output = False
        return self.in_hfs_le, indiv_output, combined_output, reason

    def to_hfs_le(self):
        """Convert a date to an HFS/HFS+ Little-Endian timestamp"""
        ts_type = self.ts_types['hfs_le']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            conv = int((dt_obj - self.epochs[1904]).total_seconds() - int(dt_tz))
            self.out_hfs_le = str(struct.pack('<I', conv).hex())
            ts_output = str(f"{ts_type}\t\t{self.out_hfs_le}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_hfs_le = ts_output = False
        return self.out_hfs_le, ts_output

    def from_fat(self):
        """Convert an MS-DOS wFatDate wFatTime timestamp to a date"""
        reason = "[!] MS-DOS wFatDate wFatTime timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['fat']
        try:
            if not len(self.fat) == 8 or not all(char in hexdigits for char in self.fat):
                self.in_fat = indiv_output = combined_output = False
            else:
                byte_swap = [self.fat[i:i+2] for i in range(0, len(self.fat), 2)]
                to_le = byte_swap[1]+byte_swap[0]+byte_swap[3]+byte_swap[2]
                binary = f'{int(to_le, 16):032b}'
                stamp = [binary[:7], binary[7:11], binary[11:16],
                         binary[16:21], binary[21:27], binary[27:32]]
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
                if fat_year not in range(1970, 2100) \
                   or fat_month not in range(1, 13) \
                   or fat_day not in range(1, 32) \
                   or fat_hour not in range(0, 24) \
                   or fat_min not in range(0, 60) \
                   or fat_sec not in range(0, 60):
                    self.in_fat = indiv_output = combined_output = False
                else:
                    dt_obj = dt(fat_year, fat_month, fat_day, fat_hour, fat_min, fat_sec)
                    self.in_fat = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_fat} Local")
                    combined_output = str(f"{__red__}{ts_type}\t\t{self.in_fat} Local{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_fat = indiv_output = combined_output = False
        return self.in_fat, indiv_output, combined_output, reason

    def to_fat(self):
        """Convert a date to an MS-DOS wFatDate wFatTime timestamp"""
        ts_type = self.ts_types['fat']
        try:
            dt_obj = duparser.parse(self.timestamp)
            year = f'{(dt_obj.year - 1980):07b}'
            month = f'{dt_obj.month:04b}'
            day = f'{dt_obj.day:05b}'
            hour = f'{dt_obj.hour:05b}'
            minute = f'{dt_obj.minute:06b}'
            seconds = f'{int(dt_obj.second / 2):05b}'
            to_hex = str(struct.pack('>I',
                                     int(year + month + day + hour + minute + seconds, 2)).hex())
            byte_swap = ''.join([to_hex[i:i+2] for i in range(0, len(to_hex), 2)][::-1])
            self.out_fat = ''.join([byte_swap[i:i+4] for i in range(0, len(byte_swap), 4)][::-1])
            ts_output = str(f"{ts_type}\t\t{self.out_fat}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_fat = ts_output = False
        return self.out_fat, ts_output

    def from_msdos(self):
        """Convert an MS-DOS timestamp to a date"""
        reason = "[!] MS-DOS 32-bit timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['msdos']
        try:
            if not len(self.msdos) == 8 or not all(char in hexdigits for char in self.msdos):
                self.in_msdos = indiv_output = combined_output = False
            else:
                swap = ''.join([self.msdos[i:i+2] for i in range(0, len(self.msdos), 2)][::-1])
                binary = f'{int(swap, 16):032b}'
                stamp = [binary[:7], binary[7:11], binary[11:16],
                         binary[16:21], binary[21:27], binary[27:32]]
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
                if dos_year not in range(1970, 2100) \
                   or dos_month not in range(1, 13) \
                   or dos_day not in range(1, 32) \
                   or dos_hour not in range(0, 24) \
                   or dos_min not in range(0, 60) \
                   or dos_sec not in range(0, 60) \
                   or dos_day not in range(1, monthrange(dos_year, dos_month)[1]):
                    self.in_msdos = indiv_output = combined_output = False
                else:
                    dt_obj = dt(dos_year, dos_month, dos_day, dos_hour, dos_min, dos_sec)
                    self.in_msdos = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_msdos} Local")
                    combined_output = str(f"{__red__}{ts_type}\t{self.in_msdos} Local{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_msdos = indiv_output = combined_output = False
        return self.in_msdos, indiv_output, combined_output, reason

    def to_msdos(self):
        """Convert a date to an MS-DOS timestamp"""
        ts_type = self.ts_types['msdos']
        try:
            dt_obj = duparser.parse(self.timestamp)
            year = f'{(dt_obj.year - 1980):07b}'
            month = f'{dt_obj.month:04b}'
            day = f'{dt_obj.day:05b}'
            hour = f'{dt_obj.hour:05b}'
            minute = f'{dt_obj.minute:06b}'
            seconds = f'{int(dt_obj.second / 2):05b}'
            hexval = str(struct.pack('>I',
                                     int(year + month + day + hour + minute + seconds, 2)).hex())
            self.out_msdos = ''.join([hexval[i:i+2] for i in range(0, len(hexval), 2)][::-1])
            ts_output = str(f"{ts_type}\t{self.out_msdos}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_msdos = ts_output = False
        return self.out_msdos, ts_output

    def from_exfat(self):
        """Convert an exFAT timestamp (LE) to a date"""
        reason = "[!] exFAT 32-bit timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['exfat']
        try:
            if not len(self.exfat) == 8 or not all(char in hexdigits for char in self.exfat):
                self.in_exfat = indiv_output = combined_output = False
            else:
                binary = f'{int(self.exfat, 16):032b}'
                stamp = [binary[:7], binary[7:11], binary[11:16],
                         binary[16:21], binary[21:27], binary[27:32]]
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
                if exfat_year not in range(1970, 2100) \
                   or exfat_month not in range(1, 13) \
                   or exfat_day not in range(1, 32) \
                   or exfat_hour not in range(0, 24) \
                   or exfat_min not in range(0, 60) \
                   or exfat_sec not in range(0, 60) \
                   or exfat_day not in range(1, monthrange(exfat_year, exfat_month)[1]):
                    self.in_exfat = indiv_output = combined_output = False
                else:
                    dt_obj = dt(exfat_year, exfat_month, exfat_day, exfat_hour, exfat_min, exfat_sec)
                    self.in_exfat = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_exfat} Local")
                    combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_exfat} Local{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_exfat = indiv_output = combined_output = False
        return self.in_exfat, indiv_output, combined_output, reason

    def to_exfat(self):
        """Convert a date to an exFAT timestamp (LE)"""
        ts_type = self.ts_types['exfat']
        try:
            dt_obj = duparser.parse(self.timestamp)
            year = f'{(dt_obj.year - 1980):07b}'
            month = f'{dt_obj.month:04b}'
            day = f'{dt_obj.day:05b}'
            hour = f'{dt_obj.hour:05b}'
            minute = f'{dt_obj.minute:06b}'
            seconds = f'{int(dt_obj.second / 2):05b}'
            self.out_exfat = str(struct.pack('>I',
                                     int(year + month + day + hour + minute + seconds, 2)).hex())
            ts_output = str(f"{ts_type}\t\t\t{self.out_exfat}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_exfat = ts_output = False
        return self.out_exfat, ts_output

    def from_systime(self):
        """Convert a Microsoft 128-bit SYSTEMTIME timestamp to a date"""
        reason = "[!] Microsoft 128-bit SYSTEMTIME timestamps are 32 hex characters (16 bytes)"
        ts_type = self.ts_types['systemtime']
        try:
            if not len(self.systime) == 32 or not all(char in hexdigits for char in self.systime):
                self.in_systemtime = indiv_output = combined_output = False
            else:
                to_le = ''.join([self.systime[i:i+2] for i in range(0, len(self.systime), 2)][::-1])
                converted = [to_le[i:i + 4] for i in range(0, len(to_le), 4)][::-1]
                stamp = []
                for i in converted:
                    dec = int(i, 16)
                    stamp.append(dec)
                dt_obj = dt(stamp[0], stamp[1], stamp[3], stamp[4],
                            stamp[5], stamp[6], stamp[7]*1000)
                self.in_systemtime = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_systemtime} UTC")
                combined_output = str(f"{__red__}{ts_type}\t{self.in_systemtime} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_systemtime = indiv_output = combined_output = False
        return self.in_systemtime, indiv_output, combined_output, reason

    def to_systime(self):
        """Convert a date to a Microsoft 128-bit SYSTEMTIME timestamp"""
        ts_type = self.ts_types['systemtime']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            micro = int(dt_obj.microsecond / 1000)
            tz_shift = dt_obj.timestamp() - int(dt_tz)
            add_micro = (tz_shift * 1000) + micro
            convert_to_seconds = add_micro / 1000
            new_dt_obj = dt.fromtimestamp(convert_to_seconds)
            full_date = new_dt_obj.strftime('%Y, %m, %w, %d, %H, %M, %S, ' + str(micro))
            stamp = []
            for val in full_date.split(','):
                to_hex = int(hex(int.from_bytes(struct.pack('<H', int(val)), 'big'))[2:], 16)
                stamp.append(f'{to_hex:04x}')
            self.out_systemtime = ''.join(stamp)
            ts_output = str(f"{ts_type}\t{self.out_systemtime}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_systemtime = ts_output = False
        return self.out_systemtime, ts_output

    def from_filetime(self):
        """Convert a Microsoft FILETIME timestamp to a date"""
        reason = "[!] FILETIME timestamps are 2 sets of 8 hex chars (4 bytes) separated by a colon"
        ts_type = self.ts_types['filetime']
        try:
            if not (":" in self.ft) or not (all(char in hexdigits for char in self.ft[0:8])
                                            and all(char in hexdigits for char in self.ft[9:])):
                self.in_filetime = indiv_output = combined_output = False
            else:
                part2, part1 = [int(h, base=16) for h in self.ft.split(':')]
                converted_time = struct.unpack('>Q', struct.pack('>LL', part1, part2))[0]
                if converted_time >= 1e+18:
                    self.in_filetime = indiv_output = combined_output = False
                else:
                    dt_obj = dt.utcfromtimestamp(float(converted_time - self.epochs['active']) /
                                                 self.epochs['hundreds_nano'])
                    self.in_filetime = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_filetime} UTC")
                    combined_output = str(f"{__red__}{ts_type}\t{self.in_filetime} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_filetime = indiv_output = combined_output = False
        return self.in_filetime, indiv_output, combined_output, reason

    def to_filetime(self):
        """Convert a date to a Microsoft FILETIME timestamp"""
        ts_type = self.ts_types['filetime']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            minus_epoch = dt_obj - self.epochs[1601]
            calc_time = minus_epoch.microseconds + \
                              ((minus_epoch.seconds - int(dt_tz)) * 1000000) \
                              + (minus_epoch.days * 86400000000)
            indiv_output = str(struct.pack(">Q", int(calc_time*10)).hex())
            self.out_filetime = f'{str(indiv_output[8:])}:{str(indiv_output[:8])}'
            ts_output = str(f"{ts_type}\t{self.out_filetime}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_filetime = ts_output = False
        return self.out_filetime, ts_output

    def from_hotmail(self):
        """Convert a Microsoft Hotmail timestamp to a date"""
        reason = "[!] Hotmail timestamps are 2 sets of 8 hex chars (4 bytes), separated by a colon"
        ts_type = self.ts_types['hotmail']
        try:
            if ":" not in self.hotmail \
                or not (all(char in hexdigits for char in self.hotmail[0:8])
                        and all(char in hexdigits for char in self.hotmail[9:])):
                self.in_hotmail = indiv_output = combined_output = False
            else:
                hm_repl = self.hotmail.replace(':', '')
                byte_swap = ''.join([hm_repl[i:i+2] for i in range(0, len(hm_repl), 2)][::-1])
                part2 = int(byte_swap[:8], base=16)
                part1 = int(byte_swap[8:], base=16)
                converted_time = struct.unpack('>Q', struct.pack('>LL', part1, part2))[0]
                if converted_time >= 1e+18:
                    self.in_hotmail = indiv_output = combined_output = False
                else:
                    dt_obj = dt.utcfromtimestamp(float(converted_time - self.epochs['active']) /
                                                 self.epochs['hundreds_nano'])
                    self.in_hotmail = dt_obj.strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_hotmail} UTC")
                    combined_output = str(f"{__red__}{ts_type}\t\t{self.in_hotmail} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_hotmail = indiv_output = combined_output = False
        return self.in_hotmail, indiv_output, combined_output, reason

    def to_hotmail(self):
        """Convert a date to a Microsoft Hotmail timestamp"""
        ts_type = self.ts_types['hotmail']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            minus_epoch = dt_obj - self.epochs[1601]
            calc_time = minus_epoch.microseconds + \
                              ((minus_epoch.seconds - int(dt_tz)) * 1000000) + \
                              (minus_epoch.days * 86400000000)
            indiv_output = str(struct.pack(">Q", int(calc_time*10)).hex())
            byte_swap = ''.join([indiv_output[i:i+2] for i in range(0, len(indiv_output), 2)][::-1])
            self.out_hotmail = f'{str(byte_swap[8:])}:{str(byte_swap[:8])}'
            ts_output = str(f"{ts_type}\t\t{self.out_hotmail}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_hotmail = ts_output = False
        return self.out_hotmail, ts_output

    def from_prtime(self):
        """Convert a Mozilla PRTime timestamp to a date"""
        reason = "[!] Mozilla PRTime timestamps are 16 digits"
        ts_type = self.ts_types['prtime']
        try:
            if not len(self.pr) == 16 or not self.pr.isdigit():
                self.in_prtime = indiv_output = combined_output = False
            else:
                dt_obj = self.epochs[1970] + timedelta(microseconds=int(self.pr))
                self.in_prtime = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_prtime} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_prtime} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_prtime = indiv_output = combined_output = False
        return self.in_prtime, indiv_output, combined_output, reason

    def to_prtime(self):
        """Convert a date to Mozilla's PRTime timestamp"""
        ts_type = self.ts_types['prtime']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            self.out_prtime = str(int(((dt_obj - self.epochs[1970]).total_seconds() -
                                       int(dt_tz)) * 1000000))
            ts_output = str(f"{ts_type}\t\t\t{self.out_prtime}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_prtime = ts_output = False
        return self.out_prtime, ts_output

    def from_ole_auto(self):
        """Convert an OLE Automation timestamp to a date"""
        reason = ("[!] OLE Automation timestamps are 2 ints, separated by a dot."
                  "Left is 5 digits, fight is between 9-12 digits")
        ts_type = self.ts_types['ole_auto']
        try:
            if "." not in self.auto or not ((len(self.auto.split(".")[0]) == 5)
                                            and (len(self.auto.split(".")[1]) in range(9, 13))) \
                                            or not ''.join(self.auto.split(".")).isdigit():
                self.in_ole_auto = indiv_output = combined_output = False
            else:
                dt_obj = self.epochs[1899] + timedelta(days=float(self.auto))
                self.in_ole_auto = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_ole_auto} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_ole_auto} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_ole_auto = indiv_output = combined_output = False
        return self.in_ole_auto, indiv_output, combined_output, reason

    def to_ole_auto(self):
        """Convert a date to an OLE Automation timestamp"""
        ts_type = self.ts_types['ole_auto']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            ole_ts = ((dt_obj - self.epochs[1899]).total_seconds() - int(dt_tz)) / 86400
            self.out_ole_auto = f"{ole_ts:.12f}"
            ts_output = str(f"{ts_type}\t\t{self.out_ole_auto}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_ole_auto = ts_output = False
        return self.out_ole_auto, ts_output

    def from_ms1904(self):
        """Convert a Microsoft Excel 1904 timestamp to a date"""
        reason = ("[!] Excel 1904 timestamps are 2 ints, separated by a dot."
                  "The left is 5 digits, the right is between 9-12 digits")
        ts_type = self.ts_types['ms1904']
        try:
            if "." not in self.ms1904 \
                or not ((len(self.ms1904.split(".")[0]) == 5) and
                        (len(self.ms1904.split(".")[1]) in range(9, 13))) \
                or not ''.join(self.ms1904.split(".")).isdigit():
                self.in_ms1904 = indiv_output = combined_output = False
            else:
                dt_obj = self.epochs[1904] + timedelta(days=float(self.ms1904))
                self.in_ms1904 = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_ms1904} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_ms1904} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_ms1904 = indiv_output = combined_output = False
        return self.in_ms1904, indiv_output, combined_output, reason

    def to_ms1904(self):
        """Convert a date to a Microsoft Excel 1904 timestamp"""
        ts_type = self.ts_types['ms1904']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            ms1904_ts = ((dt_obj - self.epochs[1904]).total_seconds() - int(dt_tz)) / 86400
            self.out_ms1904 = f"{ms1904_ts:.12f}"
            ts_output = str(f"{ts_type}\t\t{self.out_ms1904}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_ms1904 = ts_output = False
        return self.out_ms1904, ts_output

    def from_ios_time(self):
        """Convert an iOS 11 timestamp to a date"""
        reason = "[!] iOS 11 timestamps are typically 15-18 digits"
        ts_type = self.ts_types['iostime']
        try:
            if not len(self.ios) in range(15, 19) or not self.ios.isdigit():
                self.in_iostime = indiv_output = combined_output = False
            else:
                dt_obj = (int(self.ios) / int(self.epochs['nano_2001'])) + 978307200
                self.in_iostime = dt.utcfromtimestamp(dt_obj).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_iostime} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_iostime} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_iostime = indiv_output = combined_output = False
        return self.in_iostime, indiv_output, combined_output, reason

    def to_ios_time(self):
        """Convert a date to an iOS 11 timestamp"""
        ts_type = self.ts_types['iostime']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            self.out_iostime = str(int(((dt_obj - self.epochs[2001]).total_seconds() -
                                        int(dt_tz)) * self.epochs['nano_2001']))
            ts_output = str(f"{ts_type}\t\t\t{self.out_iostime}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_iostime = ts_output = False
        return self.out_iostime, ts_output

    def from_sym_time(self):
        """Convert a Symantec 6-byte hex timestamp to a date"""
        reason = "[!] Symantec 6-byte hex timestamps are 12 hex characters"
        ts_type = self.ts_types['symtime']
        try:
            if not len(self.sym) == 12 or not all(char in hexdigits for char in self.sym):
                self.in_symtime = indiv_output = combined_output = False
            else:
                hex_to_dec = [int(self.sym[i:i+2], 16) for i in range(0, len(self.sym), 2)]
                hex_to_dec[0] = hex_to_dec[0] + 1970
                hex_to_dec[1] = hex_to_dec[1] + 1
                if hex_to_dec[1] not in range(1, 13):
                    self.in_symtime = indiv_output = combined_output = False
                else:
                    dt_obj = dt(hex_to_dec[0], hex_to_dec[1], hex_to_dec[2],
                                hex_to_dec[3], hex_to_dec[4], hex_to_dec[5])
                    self.in_symtime = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type} {self.in_symtime}")
            combined_output = str(f"{__red__}{ts_type}\t\t{self.in_symtime} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_symtime = indiv_output = combined_output = False
        return self.in_symtime, indiv_output, combined_output, reason

    def to_sym_time(self):
        """Convert a date to Symantec's 6-byte hex timestamp"""
        ts_type = self.ts_types['symtime']
        try:
            dt_obj = duparser.parse(self.timestamp)
            sym_year = '{0:x}'.format(dt_obj.year - 1970).zfill(2)
            sym_month = '{0:x}'.format(dt_obj.month - 1).zfill(2)
            sym_day = '{0:x}'.format(dt_obj.day).zfill(2)
            sym_hour = '{0:x}'.format(dt_obj.hour).zfill(2)
            sym_minute = '{0:x}'.format(dt_obj.minute).zfill(2)
            sym_second = '{0:x}'.format(dt_obj.second).zfill(2)
            self.out_symtime = f'{sym_year}{sym_month}{sym_day}{sym_hour}{sym_minute}{sym_second}'
            ts_output = str(f"{ts_type}\t\t{self.out_symtime}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_symtime = ts_output = False
        return self.out_symtime, ts_output

    def from_gps_time(self):
        """Convert a GPS timestamp to a date (involves leap seconds)"""
        reason = "[!] GPS timestamps are 10 digits"
        ts_type = self.ts_types['gpstime']
        try:
            if not len(self.gps) == 10 or not self.gps.isdigit():
                self.in_gpstime = indiv_output = combined_output = False
            else:
                leapseconds = self.leapseconds
                gps_stamp = self.epochs[1980] + timedelta(seconds=(float(self.gps)))
                tai_convert = gps_stamp + timedelta(seconds=19)
                epoch_convert = (tai_convert - self.epochs[1970]).total_seconds()
                check_date = dt.utcfromtimestamp(epoch_convert)
                for entry in leapseconds:
                    check = self.date_range(leapseconds.get(entry)[0],
                                            leapseconds.get(entry)[1], check_date)
                    if check is True:
                        variance = entry
                    else:
                        variance = 0
                gps_out = check_date - timedelta(seconds=variance)
                self.in_gpstime = gps_out.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_gpstime}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_gpstime} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_gpstime = indiv_output = combined_output = False
        return self.in_gpstime, indiv_output, combined_output, reason

    def to_gps_time(self):
        """Convert a date to a GPS timestamp (involves leap seconds)"""
        ts_type = self.ts_types['gpstime']
        try:
            leapseconds = self.leapseconds
            check_date = duparser.parse(self.timestamp)
            if hasattr(check_date.tzinfo, '_offset'):
                dt_tz = check_date.tzinfo._offset.total_seconds()
                check_date = duparser.parse(self.timestamp, ignoretz=True)
            else:
                dt_tz = 0
                check_date = duparser.parse(self.timestamp, ignoretz=True)
            for entry in leapseconds:
                check = self.date_range(leapseconds.get(entry)[0],
                                        leapseconds.get(entry)[1], check_date)
                if check is True:
                    variance = entry
                else:
                    variance = 0
            leap_correction = check_date + timedelta(seconds=variance)
            epoch_shift = leap_correction - self.epochs[1970]
            gps_stamp = (dt.utcfromtimestamp(epoch_shift.total_seconds()) -
                         self.epochs[1980]).total_seconds() - 19
            gps_stamp = int(gps_stamp) - int(dt_tz)
            self.out_gpstime = str(gps_stamp)
            ts_output = str(f"{ts_type}\t\t\t{self.out_gpstime}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_gpstime = ts_output = False
        return self.out_gpstime, ts_output

    def from_eitime(self):
        """Convert a Google ei URL timestamp"""
        reason = "[!] Google ei timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_"
        ts_type = self.ts_types['eitime']
        try:
            urlsafe_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_'
            if not all(char in urlsafe_chars for char in self.eitime):
                self.in_eitime = indiv_output = combined_output = False
            else:
                padding_check = (len(self.eitime) % 4)
                if padding_check != 0:
                    padding_reqd = (4 - padding_check)
                    result_eitime = self.eitime + (padding_reqd * '=')
                else:
                    result_eitime = self.eitime
                try:
                    decoded_eitime = base64.urlsafe_b64decode(result_eitime).hex()[:8]
                    unix_ts = int.from_bytes(struct.pack("<L", int(decoded_eitime, 16)), 'big')
                    self.in_eitime = dt.utcfromtimestamp(unix_ts).strftime(__fmt__)
                    indiv_output = str(f"{ts_type}\t\t\t{self.in_eitime}")
                    combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_eitime} UTC{__clr__}")
                except base64.binascii.Error:
                    self.in_eitime = indiv_output = combined_output = False
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_eitime = indiv_output = combined_output = False
        return self.in_eitime, indiv_output, combined_output, reason

    def to_eitime(self):
        """ Try to convert a value to an ei URL timestamp"""
        ts_type = self.ts_types['eitime']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_time = int((dt_obj - self.epochs[1970]).total_seconds() + int(dt_tz))
            unix_hex = struct.pack("<L", unix_time)
            urlsafe_encode = base64.urlsafe_b64encode(unix_hex)
            self.out_eitime = urlsafe_encode.decode(encoding="UTF-8").strip("=")
            ts_output = str(f"{ts_type}\t\t\t{self.out_eitime}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_eitime = ts_output = False
        return self.out_eitime, ts_output

    def from_bplist(self):
        """Convert a Binary Plist timestamp to a date"""
        reason = "[!] Binary Plist timestamps are 9 digits"
        ts_type = self.ts_types['bplist']
        try:
            if not len(self.bplist) == 9 or not self.bplist.isdigit():
                self.in_bplist = indiv_output = combined_output = False
            else:
                dt_obj = self.epochs[2001] + timedelta(seconds=float(self.bplist))
                self.in_bplist = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_bplist}")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_bplist} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_bplist = indiv_output = combined_output = False
        return self.in_bplist, indiv_output, combined_output, reason

    def to_bplist(self):
        """Convert a date to a Binary Plist timestamp"""
        ts_type = self.ts_types['bplist']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            self.out_bplist = str(int((dt_obj - self.epochs[2001]).total_seconds()) - int(dt_tz))
            ts_output = str(f"{ts_type}\t\t{self.out_bplist}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_bplist = ts_output = False
        return self.out_bplist, ts_output

    def from_gsm(self):
        """Convert a GSM timestamp to a date"""
        reason = "[!] GSM timestamps are 14 hex characters (7 bytes)"
        ts_type = self.ts_types['gsm']
        try:
            # The last byte of the GSM timestamp is a hex representation of the timezone.
            # If the timezone bitwise operation on this byte results in a timezone offset
            # of less than -12 or greater than 12, then the value is incorrect.
            # The values in tz_in_range are hex bytes which return proper timezones.
            tz_in_range = [
                '00', '01', '02', '03', '04', '05', '06', '07', '08', '09',
                '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13',
                '14', '15', '16', '17', '18', '19', '20', '21', '22', '23',
                '24', '25', '26', '27', '28', '29', '30', '31', '32', '33',
                '34', '35', '36', '37', '38', '39', '40', '41', '42', '43',
                '44', '45', '46', '47', '48', '80', '81', '82', '83', '84',
                '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e',
                '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98',
                '99', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8',
                'a9', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8',
                'b9', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8']
            tz_check = self.gsm[12:14][::-1].lower()
            if not len(self.gsm) == 14 \
                or not all(char in hexdigits for char in self.gsm) \
                or tz_check not in tz_in_range:
                self.in_gsm = indiv_output = combined_output = False
            else:
                swap = [self.gsm[i:i+2] for i in range(0, len(self.gsm), 2)]
                for value in swap[:]:
                    l_endian = value[::-1]
                    swap.remove(value)
                    swap.append(l_endian)
                ts_tz = '{0:08b}'.format(int(swap[6], 16))
                if int(ts_tz[0]) == 1:
                    utc_offset = -int(str(int(ts_tz[1:4], 2)) + str(int(ts_tz[4:8], 2))) * 0.25
                elif int(ts_tz[0]) == 0:
                    utc_offset = int(str(int(ts_tz[0:4], 2)) + str(int(ts_tz[4:8], 2))) * 0.25
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
                self.in_gsm = str((dt(dt_year, dt_month, dt_day, dt_hour,
                                      dt_min, dt_sec).strftime(__fmt__)) + dt_tz)
                indiv_output = str(f"{ts_type} {self.in_gsm}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_gsm}{__clr__}")
        except ValueError:
            self.in_gsm = indiv_output = combined_output = False
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_gsm = indiv_output = combined_output = False
        return self.in_gsm, indiv_output, combined_output, reason

    def to_gsm(self):
        """Convert a timestamp to a GSM timestamp"""
        ts_type = self.ts_types['gsm']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            if dt_tz == 0:
                hex_tz = f'{0:02d}'
            elif dt_tz < 0:
                dt_tz = dt_tz / 3600
                conversion = str(f'{(int(abs(dt_tz)) * 4):02d}')
                conv_list = list(conversion)
                high_order = f'{int(conv_list[0]):04b}'
                low_order = f'{int(conv_list[1]):04b}'
                high_order = f'{(int(high_order, 2) + 8):04b}'
                hex_tz = hex(int((high_order + low_order), 2)).lstrip('0x').upper()
            else:
                dt_tz = dt_tz / 3600
                conversion = str(int(dt_tz) * 4).zfill(2)
                conv_list = list(conversion)
                high_order = f'{int(conv_list[0]):04b}'
                low_order = f'{int(conv_list[1]):04b}'
                hex_tz = hex(int((high_order + low_order), 2)).lstrip('0x').upper()
            date_list = [f'{(dt_obj.year - 2000):02d}',
                         f'{dt_obj.month:02d}',
                         f'{dt_obj.day:02d}',
                         f'{dt_obj.hour:02d}',
                         f'{dt_obj.minute:02d}',
                         f'{dt_obj.second:02d}', hex_tz]
            date_value_swap = []
            for value in date_list[:]:
                b_endian = value[::-1]
                date_value_swap.append(b_endian)
            self.out_gsm = ''.join(date_value_swap)
            ts_output = str(f"{ts_type}\t\t\t{self.out_gsm}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_gsm = ts_output = False
        return self.out_gsm, ts_output

    def from_vm(self):
        """Convert from a .vmsd createTimeHigh/createTimeLow timestamp"""
        reason = "[!] VMSD values are a 6-digit value and a signed/unsigned int at least 9 digits"
        ts_type = self.ts_types['vm']
        try:
            if "," not in self.vm:
                self.in_vm = indiv_output = combined_output = False
            else:
                create_time_high = int(self.vm.split(',')[0])
                create_time_low = int(self.vm.split(',')[1])
                vmsd = float((create_time_high * 2**32) +
                             struct.unpack('I', struct.pack('i', create_time_low))[0]) / 1000000
                if vmsd >= 1e+13:
                    self.in_vm = indiv_output = combined_output = False
                else:
                    self.in_vm = dt.utcfromtimestamp(vmsd).strftime(__fmt__)
                    indiv_output = str(f"{ts_type} {self.in_vm}")
                    combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_vm} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_vm = indiv_output = combined_output = False
        return self.in_vm, indiv_output, combined_output, reason

    def to_vm(self):
        """Convert date to a .vmsd createTime* value"""
        ts_type = self.ts_types['vm']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_seconds = (int((dt_obj - self.epochs[1970]).total_seconds() - int(dt_tz))*1000000)
            create_time_high = int(float(unix_seconds) / 2**32)
            unpacked_int = unix_seconds - (create_time_high * 2**32)
            create_time_low = struct.unpack('i', struct.pack('I', unpacked_int))[0]
            self.out_vm = f'{str(create_time_high)},{str(create_time_low)}'
            ts_output = str(f"{ts_type}\t\t\t{self.out_vm}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_vm = ts_output = False
        return self.out_vm, ts_output

    def from_tiktok(self):
        """Convert a TikTok URL value to a date/time"""
        reason = "[!] TikTok timestamps are 19 digits long"
        ts_type = self.ts_types['tiktok']
        try:
            if len(str(self.tiktok)) < 19 or not self.tiktok.isdigit():
                self.in_tiktok = indiv_output = combined_output = False
            else:
                unix_ts = (int(self.tiktok) >> 32)
                self.in_tiktok = dt.utcfromtimestamp(float(unix_ts)).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_tiktok}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_tiktok} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_tiktok = indiv_output = combined_output = False
        return self.in_tiktok, indiv_output, combined_output, reason

    def from_twitter(self):
        """Convert a Twitter URL value to a date/time"""
        reason = "[!] Twitter timestamps are 18 digits or longer"
        ts_type = self.ts_types['twitter']
        try:
            if len(str(self.twitter)) < 18 or not self.twitter.isdigit():
                self.in_twitter = indiv_output = combined_output = False
            else:
                unix_ts = (int(self.twitter) >> 22) + 1288834974657
                self.in_twitter = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_twitter}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_twitter} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_twitter = indiv_output = combined_output = False
        return self.in_twitter, indiv_output, combined_output, reason

    def from_discord(self):
        """Convert a Discord URL value to a date/time"""
        reason = "[!] Discord timestamps are 18 digits or longer"
        ts_type = self.ts_types['discord']
        try:
            if len(str(self.discord)) < 18 or not self.discord.isdigit():
                self.in_discord = indiv_output = combined_output = False
            else:
                unix_ts = (int(self.discord) >> 22) + 1420070400000
                self.in_discord = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_discord}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_discord} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_discord = indiv_output = combined_output = False
        return self.in_discord, indiv_output, combined_output, reason

    def from_ksuid(self):
        """Extract a timestamp from a KSUID value"""
        reason = "[!] KSUID values are 27 characters"
        ts_type = self.ts_types['ksuid']
        try:
            ksuid_chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
            if len(str(self.ksuid)) != 27 or not all(char in ksuid_chars for char in self.ksuid):
                self.in_ksuid = indiv_output = combined_output = False
            else:
                length, i, variation = len(self.ksuid), 0, 0
                b_array = bytearray()
                for val in self.ksuid:
                    variation += ksuid_chars.index(val) * (62 ** (length - (i + 1)))
                    i += 1
                while variation > 0:
                    b_array.append(variation & 0xFF)
                    variation //= 256
                b_array.reverse()
                ts_bytes = bytes(b_array)[0:4]
                unix_ts = int.from_bytes(ts_bytes, 'big', signed=False) + 1400000000
                self.in_ksuid = dt.utcfromtimestamp(float(unix_ts)).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_ksuid}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_ksuid} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_ksuid = indiv_output = combined_output = False
        return self.in_ksuid, indiv_output, combined_output, reason

    def from_mastodon(self):
        """Convert a Mastodon value to a date/time"""
        reason = "[!] Mastodon timestamps are 18 digits or longer"
        ts_type = self.ts_types['mastodon']
        try:
            if len(str(self.mastodon)) < 18 or not self.mastodon.isdigit():
                self.in_mastodon = indiv_output = combined_output = False
            else:
                unix_ts = (int(self.mastodon) >> 16)
                self.in_mastodon = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_mastodon}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_mastodon} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_mastodon = indiv_output = combined_output = False
        return self.in_mastodon, indiv_output, combined_output, reason

    def to_mastodon(self):
        """Convert a date/time to a Mastodon value"""
        ts_type = self.ts_types['mastodon']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_seconds = (int((dt_obj - self.epochs[1970]).total_seconds() - int(dt_tz)) * 1000)
            bit_shift = unix_seconds << 16
            self.out_mastodon = f'{str(bit_shift)}'
            ts_output = str(f"{ts_type}\t\t\t{self.out_mastodon}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_mastodon = ts_output = False
        return self.out_mastodon, ts_output

    def from_metasploit(self):
        """Convert a Metasploit Payload UUID value to a date/time"""
        reason = "[!] Metasploit Payload UUID's are at least 22 chars and base64 urlsafe encoded"
        ts_type = self.ts_types['metasploit']
        try:
            urlsafe_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_'
            meta_format = '8sBBBBBBBB'
            if len(str(self.meta)) < 22 or not all(char in urlsafe_chars for char in self.meta):
                self.in_metasploit = indiv_output = combined_output = False
            else:
                b64decoded = base64.urlsafe_b64decode(self.meta[0:22] + '==')
                if len(b64decoded) < struct.calcsize('8sBBBBBBBB'):
                    raise Exception
                (_, xor1, xor2, _, _, ts1_xored,
                 ts2_xored, ts3_xored, ts4_xored) = struct.unpack('8sBBBBBBBB', b64decoded)
                unix_ts = struct.unpack('>I', bytes([ts1_xored ^ xor1,
                                                     ts2_xored ^ xor2,
                                                     ts3_xored ^ xor1,
                                                     ts4_xored ^ xor2]))[0]
                self.in_metasploit = dt.utcfromtimestamp(float(unix_ts)).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_metasploit}")
                combined_output = str(f"{__red__}{ts_type}\t{self.in_metasploit} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_metasploit = indiv_output = combined_output = False
        return self.in_metasploit, indiv_output, combined_output, reason

    def from_sony(self):
        """Convert a Sonyflake value to a date/time"""
        reason = "[!] Sonyflake values are 15 hex characters"
        ts_type = self.ts_types['sony']
        try:
            if len(str(self.sony)) != 15 or not all(char in hexdigits for char in self.sony):
                self.in_sony = indiv_output = combined_output = False
            else:
                dec_value = int(self.sony, 16)
                ts_value = dec_value >> 24
                unix_ts = (ts_value + 140952960000) * 10
                self.in_sony = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_sony}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_sony} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_sony = indiv_output = combined_output = False
        return self.in_sony, indiv_output, combined_output, reason

    def from_uuid(self):
        """Convert a UUID value to date/time"""
        reason = "[!] UUID's are in the format 00000000-0000-0000-0000-000000000000"
        ts_type = self.ts_types['uu']
        try:
            uuid_lower = self.uu.lower()
            uuid_regex = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
            if not bool(uuid_regex.match(uuid_lower)):
                self.in_uuid = indiv_output = combined_output = False
            else:
                u_data = uuid.UUID(uuid_lower)
                if u_data.version == 1:
                    unix_ts = int((u_data.time / 10000) - 12219292800000)
                    self.in_uuid = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime(__fmt__)
                else:
                    pass
                indiv_output = str(f"{ts_type} {self.in_uuid}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_uuid} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_uuid = indiv_output = combined_output = False
        return self.in_uuid, indiv_output, combined_output, reason

    def from_dhcp6(self):
        """Convert a DHCPv6 DUID value to date/time"""
        reason = "[!] DHCPv6 DUID values are at least 14 bytes long"
        ts_type = self.ts_types['dhcp6']
        try:
            if len(str(self.dhcp6)) < 28 or not all(char in hexdigits for char in self.dhcp6):
                self.in_dhcp6 = indiv_output = combined_output = False
            else:
                dhcp6_bytes = self.dhcp6[8:16]
                dhcp6_dec = int(dhcp6_bytes, 16)
                dhcp6_ts = self.epochs[2000] + timedelta(seconds=int(dhcp6_dec))
                self.in_dhcp6 = dhcp6_ts.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_dhcp6}")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_dhcp6} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_dhcp6 = indiv_output = combined_output = False
        return self.in_dhcp6, indiv_output, combined_output, reason

    def to_dhcp6(self):
        """Convert a timestamp to a DHCP DUID value"""
        ts_type = self.ts_types['dhcp6']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_time = int((dt_obj - self.epochs[2000]).total_seconds() - int(dt_tz))
            self.out_dhcp6 = str(struct.pack(">L", unix_time).hex())
            ts_output = str(f"{ts_type}\t\t00010001{self.out_dhcp6}000000000000")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_dhcp6 = ts_output = False
        return self.out_dhcp6, ts_output

    def from_dotnet(self):
        """Convert a .NET DateTime value to date/time"""
        reason = "[!] .NET DateTime values are 18 digits"
        ts_type = self.ts_types['dotnet']
        try:
            if len(str(self.dotnet)) != 18 or not (self.dotnet).isdigit():
                self.in_dotnet = indiv_output = combined_output = False
            else:
                dotnet_offset = int((self.epochs[1970] - self.epochs[1]).total_seconds()) * 10000000
                dotnet_to_umil = (int(self.dotnet) - dotnet_offset) / 10000000
                self.in_dotnet = dt.utcfromtimestamp(dotnet_to_umil).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_dotnet} UTC")
                combined_output = str(f"{__red__}{ts_type}\t{self.in_dotnet} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_dotnet = indiv_output = combined_output = False
        return self.in_dotnet, indiv_output, combined_output, reason

    def to_dotnet(self):
        """Convert date to a .NET DateTime value"""
        ts_type = self.ts_types['dotnet']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            self.out_dotnet = str(int(((dt_obj - self.epochs[1]).total_seconds() -
                                       int(dt_tz)) * 10000000))
            ts_output = str(f"{ts_type}\t{self.out_dotnet}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_dotnet = ts_output = False
        return self.out_dotnet, ts_output

    def from_gbound(self):
        """Convert a GMail Boundary value to date/time"""
        reason = "[!] GMail Boundary values are 28 hex chars"
        ts_type = self.ts_types['gbound']
        try:
            if len(str(self.gbound)) != 28 or not all(char in hexdigits for char in self.gbound):
                self.in_gbound = indiv_output = combined_output = False
            else:
                working_value = self.gbound[12:26]
                end = working_value[:6]
                begin = working_value[6:14]
                full_dec = int(''.join(begin + end), 16)
                self.in_gbound = dt.utcfromtimestamp(full_dec / 1000000).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_gbound} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_gbound} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_gbound = indiv_output = combined_output = False
        return self.in_gbound, indiv_output, combined_output, reason

    def to_gbound(self):
        """Convert date to a GMail Boundary value"""
        ts_type = self.ts_types['gbound']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            to_int = (int(((dt_obj - self.epochs[1970]).total_seconds() -
                           int(dt_tz)) * 1000000))
            if len(f'{to_int:x}') < 14:
                to_int = f'0{to_int:x}'
            begin = to_int[8:]
            end = to_int[:8]
            self.out_gbound = f"000000000000{begin}{end}00"
            ts_output = str(f"{ts_type}\t\t{self.out_gbound}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_gbound = ts_output = False
        return self.out_gbound, ts_output

    def from_gmsgid(self):
        """Convert a GMail Message ID to a date/time value"""
        reason = "[!] GMail Message ID values are 16 hex chars or 19 digits (IMAP)"
        ts_type = self.ts_types['gmsgid']
        try:
            gmsgid = self.gmsgid
            if str(gmsgid).isdigit() and len(str(gmsgid)) == 19:
                gmsgid = str(f'{int(gmsgid):x}')
            if len(str(gmsgid)) != 16 or not all(char in hexdigits for char in gmsgid):
                self.in_gmsgid = indiv_output = combined_output = False
            else:
                working_value = gmsgid[:11]
                to_int = int(working_value, 16)
                self.in_gmsgid = dt.utcfromtimestamp(to_int / 1000).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_gmsgid} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_gmsgid} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_gmsgid = indiv_output = combined_output = False
        return self.in_gmsgid, indiv_output, combined_output, reason

    def to_gmsgid(self):
        """Convert date to a GMail Message ID value"""
        ts_type = self.ts_types['gmsgid']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            to_int = (int(((dt_obj - self.epochs[1970]).total_seconds() -
                           int(dt_tz)) * 1000))
            ts_hex = f'{to_int:x}'
            self.out_gmsgid = f"{ts_hex}00000"
            ts_output = str(f"{ts_type}\t\t{self.out_gmsgid}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_gmsgid = ts_output = False
        return self.out_gmsgid, ts_output

    def from_moto(self):
        """Convert a Motorola 6-byte hex timestamp to a date"""
        reason = "[!] Motorola 6-byte hex timestamps are 12 hex characters"
        ts_type = self.ts_types['moto']
        try:
            if len(str(self.moto)) != 12 or not all(char in hexdigits for char in self.moto):
                self.in_moto = indiv_output = combined_output = False
            else:
                hex_to_dec = [int(self.moto[i:i+2], 16) for i in range(0, len(self.moto), 2)]
                hex_to_dec[0] = hex_to_dec[0] + 1970
                if hex_to_dec[1] not in range(1, 13):
                    self.in_moto = indiv_output = combined_output = False
                else:
                    dt_obj = dt(hex_to_dec[0], hex_to_dec[1], hex_to_dec[2],
                                hex_to_dec[3], hex_to_dec[4], hex_to_dec[5])
                    self.in_moto = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_moto}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_moto} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_moto = indiv_output = combined_output = False
        return self.in_moto, indiv_output, combined_output, reason

    def to_moto(self):
        """Convert a date to Motorola's 6-byte hex timestamp"""
        ts_type = self.ts_types['moto']
        try:
            dt_obj = duparser.parse(self.timestamp)
            moto_year = '{0:x}'.format(dt_obj.year - 1970).zfill(2)
            moto_month = '{0:x}'.format(dt_obj.month).zfill(2)
            moto_day = '{0:x}'.format(dt_obj.day).zfill(2)
            moto_hour = '{0:x}'.format(dt_obj.hour).zfill(2)
            moto_minute = '{0:x}'.format(dt_obj.minute).zfill(2)
            moto_second = '{0:x}'.format(dt_obj.second).zfill(2)
            self.out_moto = str(f"{moto_year}{moto_month}{moto_day}"
                                f"{moto_hour}{moto_minute}{moto_second}")
            ts_output = str(f"{ts_type}\t\t\t{self.out_moto}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_moto = ts_output = False
        return self.out_moto, ts_output

    def from_nokia(self):
        """Convert a Nokia 4-byte value to date/time"""
        reason = "[!] Nokia 4-byte hex timestamps are 8 hex characters"
        ts_type = self.ts_types['nokia']
        try:
            if not len(self.nokia) == 8 or not all(char in hexdigits for char in self.nokia):
                self.in_nokia = indiv_output = combined_output = False
            else:
                to_int = int(self.nokia, 16)
                int_diff = to_int ^ 4294967295
                int_diff = ~ int_diff + 1
                unix_ts = int_diff + (self.epochs[2050] - self.epochs[1970]).total_seconds()
                if unix_ts < 0:
                    pass
                else:
                    self.in_nokia = dt.utcfromtimestamp(unix_ts).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_nokia}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_nokia} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_nokia = indiv_output = combined_output = False
        return self.in_nokia, indiv_output, combined_output, reason

    def to_nokia(self):
        """Convert a date/time value to a Nokia 4-byte timestamp"""
        ts_type = self.ts_types['nokia']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_ts = ((dt_obj - self.epochs[1970]).total_seconds() - int(dt_tz))
            int_diff = int(unix_ts - (self.epochs[2050] - self.epochs[1970]).total_seconds())
            int_diff = int_diff - 1
            dec_value = ~ int_diff ^ 4294967295
            self.out_nokia = f'{dec_value:x}'
            ts_output = str(f"{ts_type}\t\t\t{self.out_nokia}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_nokia = ts_output = False
        return self.out_nokia, ts_output

    def from_nokiale(self):
        """Convert a little-endian Nokia 4-byte value to date/time"""
        reason = "[!] Nokia 4-byte hex timestamps are 8 hex characters"
        ts_type = self.ts_types['nokiale']
        try:
            if not len(self.nokiale) == 8 or not all(char in hexdigits for char in self.nokiale):
                self.in_nokiale = indiv_output = combined_output = False
            else:
                to_be = ''.join([self.nokiale[i:i+2] for i in range(0, len(self.nokiale), 2)][::-1])
                to_int = int(to_be, 16)
                int_diff = to_int ^ 4294967295
                int_diff = ~ int_diff + 1
                unix_ts = int_diff + (self.epochs[2050] - self.epochs[1970]).total_seconds()
                if unix_ts < 0:
                    pass
                else:
                    self.in_nokiale = dt.utcfromtimestamp(unix_ts).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_nokiale}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_nokiale} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_nokiale = indiv_output = combined_output = False
        return self.in_nokiale, indiv_output, combined_output, reason

    def to_nokiale(self):
        """Convert a date/time value to a little-endian Nokia 4-byte timestamp"""
        ts_type = self.ts_types['nokiale']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_ts = ((dt_obj - self.epochs[1970]).total_seconds() - int(dt_tz))
            int_diff = int(unix_ts - (self.epochs[2050] - self.epochs[1970]).total_seconds())
            int_diff = int_diff - 1
            dec_val = ~ int_diff ^ 4294967295
            hex_val = f'{dec_val:x}'
            self.out_nokiale = ''.join([hex_val[i:i+2] for i in range(0, len(hex_val), 2)][::-1])
            ts_output = str(f"{ts_type}\t\t\t{self.out_nokiale}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_nokiale = ts_output = False
        return self.out_nokiale, ts_output

    def from_ns40(self):
        """Convert a Nokia S40 7-byte value to a time/time"""
        reason = "[!] Nokia 7-byte hex timestamps are 14 hex characters"
        ts_type = self.ts_types['ns40']
        try:
            if not len(self.ns40) == 14 or not all(char in hexdigits for char in self.ns40):
                self.in_ns40 = indiv_output = combined_output = False
            else:
                ns40 = self.ns40
                ns40_val = {}
                ns40_val['yr'] = ns40[:4]
                ns40_val['mon'] = ns40[4:6]
                ns40_val['day'] = ns40[6:8]
                ns40_val['hr'] = ns40[8:10]
                ns40_val['min'] = ns40[10:12]
                ns40_val['sec'] = ns40[12:]
                for each_key, _ in ns40_val.items():
                    ns40_val[str(each_key)] = int(ns40_val[str(each_key)], 16)
                if ns40_val['yr'] > 9999:
                    self.in_ns40 = indiv_output = combined_output = False
                else:
                    self.in_ns40 = dt(ns40_val["yr"], ns40_val["mon"], ns40_val["day"],
                                      ns40_val["hr"], ns40_val["min"],
                                      ns40_val["sec"]).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_ns40}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_ns40} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_ns40 = indiv_output = combined_output = False
        return self.in_ns40, indiv_output, combined_output, reason

    def to_ns40(self):
        """Convert a date/time value to a Nokia S40 7-byte timestamp"""
        ts_type = self.ts_types['ns40']
        try:
            dt_obj = duparser.parse(self.timestamp)
            dt_tz = 0
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            dt_obj = str(int((dt_obj - self.epochs[1970]).total_seconds()) - int(dt_tz))
            dt_obj = dt.utcfromtimestamp(int(dt_obj))
            hex_vals = []
            hex_vals.append(f'{dt_obj.year:x}'.zfill(4))
            hex_vals.append(f'{dt_obj.month:x}'.zfill(2))
            hex_vals.append(f'{dt_obj.day:x}'.zfill(2))
            hex_vals.append(f'{dt_obj.hour:x}'.zfill(2))
            hex_vals.append(f'{dt_obj.minute:x}'.zfill(2))
            hex_vals.append(f'{dt_obj.second:x}'.zfill(2))
            self.out_ns40 = ''.join(hex_vals)
            ts_output = str(f"{ts_type}\t\t\t{self.out_ns40}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_ns40 = ts_output = False
        return self.out_ns40, ts_output

    def from_ns40le(self):
        """Convert a little-endian Nokia S40 7-byte value to a date/time"""
        reason = "[!] Nokia 7-byte hex timestamps are 14 hex characters"
        ts_type = self.ts_types['ns40le']
        try:
            ns40le = self.ns40le
            if len(str(ns40le)) != 14 or not all(char in hexdigits for char in ns40le):
                self.in_ns40le = indiv_output = combined_output = False
            else:
                ns40_val = {}
                ns40_val['yr'] = ''.join([ns40le[i:i+2] for i in range(0, len(ns40le[:4]), 2)][::-1])
                ns40_val['mon'] = ns40le[4:6]
                ns40_val['day'] = ns40le[6:8]
                ns40_val['hr'] = ns40le[8:10]
                ns40_val['min'] = ns40le[10:12]
                ns40_val['sec'] = ns40le[12:]
                for each_key, _ in ns40_val.items():
                    ns40_val[str(each_key)] = int(ns40_val[str(each_key)], 16)
                if ns40_val['yr'] > 9999:
                    self.in_ns40le = indiv_output = combined_output = False
                else:
                    self.in_ns40le = dt(ns40_val["yr"], ns40_val["mon"], ns40_val["day"],
                                        ns40_val["hr"], ns40_val["min"],
                                        ns40_val["sec"]).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_ns40le}")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_ns40le} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_ns40le = indiv_output = combined_output = False
        return self.in_ns40le, indiv_output, combined_output, reason

    def to_ns40le(self):
        """Convert a date/time value to a little-endian Nokia S40 7-byte timestamp"""
        ts_type = self.ts_types['ns40le']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            dt_obj = str(int((dt_obj - self.epochs[1970]).total_seconds()) - int(dt_tz))
            dt_obj = dt.utcfromtimestamp(int(dt_obj))
            hex_vals = []
            year_le = f'{dt_obj.year:x}'.zfill(4)
            year_le = ''.join([year_le[i:i+2] for i in range(0, len(year_le[:4]), 2)][::-1])
            hex_vals.append(f'{year_le}'.zfill(4))
            hex_vals.append(f'{dt_obj.month:x}'.zfill(2))
            hex_vals.append(f'{dt_obj.day:x}'.zfill(2))
            hex_vals.append(f'{dt_obj.hour:x}'.zfill(2))
            hex_vals.append(f'{dt_obj.minute:x}'.zfill(2))
            hex_vals.append(f'{dt_obj.second:x}'.zfill(2))
            self.out_ns40le = ''.join(hex_vals)
            ts_output = str(f"{ts_type}\t\t{self.out_ns40le}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_ns40le = ts_output = False
        return self.out_ns40le, ts_output

    def from_bitdec(self):
        """Convert a 10-digit Bitwise Decimal value to a date/time"""
        reason = "[!] Bitwise Decimal timestamps are 10 digits"
        ts_type = self.ts_types['bitdec']
        try:
            if len(str(self.bitdec)) != 10 or not (self.bitdec).isdigit():
                self.in_bitdec = indiv_output = combined_output = False
            else:
                full_ts = int(self.bitdec)
                bd_yr = (full_ts >> 20)
                bd_mon = (full_ts >> 16) & 15
                bd_day = (full_ts >> 11) & 31
                bd_hr = (full_ts >> 6) & 31
                bd_min = full_ts & 63
                self.in_bitdec = dt(bd_yr, bd_mon, bd_day, bd_hr, bd_min).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_bitdec}")
                combined_output = str(f"{__red__}{ts_type}\t\t{self.in_bitdec}  ?{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_bitdec = indiv_output = combined_output = False
        return self.in_bitdec, indiv_output, combined_output, reason

    def to_bitdec(self):
        """Convert a date/time value to a Bitwise Decimal timestamp"""
        ts_type = self.ts_types['bitdec']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            dt_obj = str(int((dt_obj - self.epochs[1970]).total_seconds()) - int(dt_tz))
            dt_obj = dt.utcfromtimestamp(int(dt_obj))
            self.out_bitdec = str((dt_obj.year << 20) + (dt_obj.month << 16) + (dt_obj.day << 11) +
                                  (dt_obj.hour << 6) + (dt_obj.minute))
            ts_output = str(f"{ts_type}\t\t{self.out_bitdec}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_bitdec = ts_output = False
        return self.out_bitdec, ts_output

    def from_bitdate(self):
        """Convert a Samsung/LG 4-byte hex timestamp to a date/time"""
        reason = "[!] Samsung/LG BitDate timestamps are 8 hex characters"
        ts_type = self.ts_types['bitdate']
        try:
            bitdate = self.bitdate
            if len(str(bitdate)) != 8 or not all(char in hexdigits for char in bitdate):
                self.in_bitdate = indiv_output = combined_output = False
            else:
                to_le = ''.join([bitdate[i:i+2] for i in range(0, len(str(bitdate)), 2)][::-1])
                to_binary = f'{int(to_le, 16):032b}'
                bitdate_yr = int(to_binary[:12], 2)
                bitdate_mon = int(to_binary[12:16], 2)
                bitdate_day = int(to_binary[16:21], 2)
                bitdate_hr = int(to_binary[21:26], 2)
                bitdate_min = int(to_binary[26:32], 2)
                try:
                    self.in_bitdate = (dt(bitdate_yr, bitdate_mon, bitdate_day,
                                          bitdate_hr, bitdate_min).strftime(__fmt__))
                except ValueError:
                    pass
                indiv_output = str(f"{ts_type} {self.in_bitdate}")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_bitdate} Local{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_bitdate = indiv_output = combined_output = False
        return self.in_bitdate, indiv_output, combined_output, reason

    def to_bitdate(self):
        """Convert a date/time value to a Samsung/LG timestamp"""
        ts_type = self.ts_types['bitdate']
        try:
            dt_obj = duparser.parse(self.timestamp)
            bitdate_yr = f'{dt_obj.year:012b}'
            bitdate_mon = f'{dt_obj.month:04b}'
            bitdate_day = f'{dt_obj.day:05b}'
            bitdate_hr = f'{dt_obj.hour:05b}'
            bitdate_min = f'{dt_obj.minute:06b}'
            to_hex = str(struct.pack('>I',
                                     int(bitdate_yr +
                                         bitdate_mon +
                                         bitdate_day +
                                         bitdate_hr +
                                         bitdate_min, 2)).hex())
            self.out_bitdate = ''.join([to_hex[i:i+2] for i in range(0, len(to_hex), 2)][::-1])
            ts_output = str(f"{ts_type}\t\t\t{self.out_bitdate}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_bitdate = ts_output = False
        return self.out_bitdate, ts_output

    def from_kstime(self):
        """Convert a KSUID decimal value to a date"""
        reason = "[!] KSUID decimal timestamps are 9 digits in length"
        ts_type = self.ts_types['kstime']
        try:
            kstime = self.kstime
            if len(kstime) != 9 or not kstime.isdigit():
                self.in_kstime = indiv_output = combined_output = False
            else:
                ts_val = int(kstime) + int(self.epochs['kstime'])
                self.in_kstime = dt.utcfromtimestamp(float(ts_val)).strftime(__fmt__)
                indiv_output = str(f"{ts_type} {self.in_kstime} UTC")
                combined_output = str(f"{__red__}{ts_type}\t\t\t{self.in_kstime} UTC{__clr__}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.in_kstime = indiv_output = combined_output = False
        return self.in_kstime, indiv_output, combined_output, reason

    def to_kstime(self):
        """Convert date to a KSUID decimal value"""
        ts_type = self.ts_types['kstime']
        try:
            dt_obj = duparser.parse(self.timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            dt_obj = duparser.parse(self.timestamp, ignoretz=True)
            unix_ts = str(int((dt_obj - self.epochs[1970]).total_seconds()) - int(dt_tz))
            self.out_kstime = str(int(unix_ts) - int(self.epochs['kstime']))
            ts_output = str(f"{ts_type}\t\t\t{self.out_kstime}")
        except Exception:
            ErrorHandler.handle(sys.exc_info())
            self.out_kstime = ts_output = False
        return self.out_kstime, ts_output

    @staticmethod
    def date_range(start, end, check_date):
        """Check if date is in range of start and end, return True if it is"""
        if start <= end:
            return start <= check_date <= end
        return start <= check_date or check_date <= end

    def from_all(self):
        """Output all processed timestamp values and find date from provided timestamp"""
        this_yr = int(dt.now().strftime('%Y'))
        states = []
        print('Outputs which do not result in a date/time value are not displayed.\r')
        print(f'{__red__}Most likely results (within +/- 5 years) are highlighted.\n{__clr__}')
        for func in self.from_funcs:
            (result, _, combined_output, _) = func()
            states.append(result)
            if isinstance(result, str):
                if int(duparser.parse(result).strftime('%Y')) in range(this_yr - 5, this_yr + 5):
                    print(combined_output)
                else:
                    print(combined_output.strip(__red__).strip(__clr__))
        if all([state is False for state in states]):
            print('No valid dates found. Check your input and try again.')
        print('\r')

    def timestamp_output(self):
        """Output all processed dates from timestamp values"""
        for func in self.to_funcs:
            result, ts_output = func()
            if isinstance(result, str):
                print(ts_output)
        print('\r')


def main():
    """Parse all passed arguments"""
    now = dt.now().strftime(__fmt__)
    arg_parse = argparse.ArgumentParser(description=f'Time Decoder and Converter v'
                                                    f'{str(__version__)} - supporting '
                                                    f'{str(__types__)} timestamps!',
                                        formatter_class=argparse.RawTextHelpFormatter)
    arg_parse.add_argument('--guess', metavar='', help='guess format and output possibilities')
    arg_parse.add_argument('--timestamp', metavar='DATE', help='convert date to every timestamp\n'
                           'enter date as \"YYYY-MM-DD HH:MM:SS.f\" in 24h fmt.\n'
                           'Without argument gives current date/time\n', nargs='?', const=now)
    arg_parse.add_argument('--active', metavar='', help='convert from Active Directory value')
    arg_parse.add_argument('--auto', metavar='', help='convert from OLE Automation Date format')
    arg_parse.add_argument('--bitdate', metavar='', help='convert from a Samsung/LG 4-byte value')
    arg_parse.add_argument('--bitdec', metavar='', help='convert from a bitwise decimal 10-digit value')
    arg_parse.add_argument('--bplist', metavar='', help='convert from an iOS Binary Plist value')
    arg_parse.add_argument('--chrome', metavar='', help='convert from Google Chrome value')
    arg_parse.add_argument('--cookie', metavar='', help='convert from Windows Cookie Date (Low,High)')
    arg_parse.add_argument('--dhcp6', metavar='', help='convert from a DHCP6 DUID value')
    arg_parse.add_argument('--discord', metavar='', help='convert from a Discord URL value')
    arg_parse.add_argument('--dotnet', metavar='', help='convert from a .NET DateTime value')
    arg_parse.add_argument('--eitime', metavar='', help='convert from a Google EI URL value')
    arg_parse.add_argument('--exfat', metavar='', help='convert from an exFAT 4-byte value')
    arg_parse.add_argument('--fat', metavar='', help='convert from FAT Date + Time (wFat)')
    arg_parse.add_argument('--ft', metavar='', help='convert from FILETIME value')
    arg_parse.add_argument('--gbound', metavar='', help='convert from a GMail Boundary value')
    arg_parse.add_argument('--gmsgid', metavar='', help='convert from a GMail Message ID value')
    arg_parse.add_argument('--gps', metavar='', help='convert from a GPS value')
    arg_parse.add_argument('--gsm', metavar='', help='convert from a GSM value')
    arg_parse.add_argument('--hfsbe', metavar='', help='convert from HFS(+) BE, HFS Local, HFS+ UTC')
    arg_parse.add_argument('--hfsle', metavar='', help='convert from HFS(+) LE, HFS Local, HFS+ UTC')
    arg_parse.add_argument('--hfsdec', metavar='', help='convert from Mac OS/HFS+ Decimal Time')
    arg_parse.add_argument('--hotmail', metavar='', help='convert from a Hotmail value')
    arg_parse.add_argument('--ios', metavar='', help='convert from iOS 11 value')
    arg_parse.add_argument('--kstime', metavar='', help='convert from a KSUID 9-digit value')
    arg_parse.add_argument('--ksuid', metavar='', help='convert from a KSUID 27-character value')
    arg_parse.add_argument('--mac', metavar='', help='convert from Mac Absolute Time')
    arg_parse.add_argument('--mastodon', metavar='', help='convert from a Mastodon URL value')
    arg_parse.add_argument('--meta', metavar='', help='convert from a Metasploit Payload UUID')
    arg_parse.add_argument('--moto', metavar='', help='convert from Motorola\'s 6-byte value')
    arg_parse.add_argument('--ms1904', metavar='', help='convert from MS Excel 1904 Date format')
    arg_parse.add_argument('--msdos', metavar='', help='convert from 32-bit MS-DOS time, result is Local')
    arg_parse.add_argument('--nokia', metavar='', help='convert from a Nokia 4-byte value')
    arg_parse.add_argument('--nokiale', metavar='', help='convert from a Nokia 4-byte LE value')
    arg_parse.add_argument('--ns40', metavar='', help='convert from a Nokia S40 7-byte value')
    arg_parse.add_argument('--ns40le', metavar='', help='convert from a Nokia S40 7-byte LE value')
    arg_parse.add_argument('--oleb', metavar='', help='convert from Windows OLE 64-bit BE, remove 0x & space\n'
                           '- example from SRUM: 0x40e33f5d 0x97dfe8fb should be 40e33f5d97dfe8fb')
    arg_parse.add_argument('--olel', metavar='', help='convert from Windows OLE 64-bit LE')
    arg_parse.add_argument('--pr', metavar='', help='convert from Mozilla\'s PRTime')
    arg_parse.add_argument('--sony', metavar='', help='convert from a Sonyflake URL value')
    arg_parse.add_argument('--sym', metavar='', help='convert from Symantec\'s 6-byte AV value')
    arg_parse.add_argument('--systime', metavar='', help='convert from 128-bit SYSTEMTIME value')
    arg_parse.add_argument('--tiktok', metavar='', help='convert from a TikTok URL value')
    arg_parse.add_argument('--twitter', metavar='', help='convert from a Twitter URL value')
    arg_parse.add_argument('--uhbe', metavar='', help='convert from Unix Hex 32-bit BE')
    arg_parse.add_argument('--uhle', metavar='', help='convert from Unix Hex 32-bit LE')
    arg_parse.add_argument('--unix', metavar='', help='convert from Unix Seconds')
    arg_parse.add_argument('--umil', metavar='', help='convert from Unix Milliseconds')
    arg_parse.add_argument('--uu', metavar='', help='convert from a UUID: 00000000-0000-0000-0000-000000000000')
    arg_parse.add_argument('--vm', metavar='', help='convert from a VMWare Snapshot (.vmsd) value\n'
                           '- enter as "high value,low value"')
    arg_parse.add_argument('--wh', metavar='', help='convert from Windows 64-bit Hex BE')
    arg_parse.add_argument('--whle', metavar='', help='convert from Windows 64-bit Hex LE')
    arg_parse.add_argument('--version', '-v', action='version', version=arg_parse.description)

    if len(sys.argv[1:]) == 0:
        arg_parse.print_help()
        arg_parse.exit()

    args = arg_parse.parse_args()
    td_class = TimeDecoder(args)
    td_class.run()


if __name__ == '__main__':
    main()
