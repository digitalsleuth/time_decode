#!/usr/bin/env python3
"""
This application is designed to decode timestamps into human-readable date/times and vice-versa
Additional information regarding the source of the timestamp formats and associated equations
will be provided in the docstrings below.
TO DO:
    Re-evaluate error handling.
    MSDOS and FAT timestamps both need method for accepting time offset

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
bplist timestamp:
    https://developer.apple.com/documentation/corefoundation/cfabsolutetime
    https://developer.apple.com/documentation/foundation/nsdate
GSM Timestamps:
    https://en.wikipedia.org/wiki/GSM_03.40
    http://seven-bit-forensics.blogspot.com/2014/02/decoding-gsmsms-timestamps.html
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
"""

from datetime import datetime as dt, timedelta
import struct
from binascii import hexlify, unhexlify
from string import hexdigits
import argparse
import re
import sys
import base64
import uuid
from calendar import monthrange
from dateutil import parser as duparser
from colorama import init

init(autoreset=True)

__author__ = 'Corey Forman'
__date__ = '27 May 2021'
__version__ = '3.1.1'
__description__ = 'Python 3 CLI Date Time Conversion Tool'


class TimeDecoder(object):
    """Run the decoding class"""
    def __init__(self):
        self.epoch_1601 = dt(1601, 1, 1)
        self.epoch_1899 = dt(1899, 12, 30)
        self.epoch_1904 = dt(1904, 1, 1)
        self.epoch_1970 = dt(1970, 1, 1)
        self.epoch_1980 = dt(1980, 1, 6)
        self.epoch_2000 = dt(2000, 1, 1)
        self.epoch_2001 = dt(2001, 1, 1)
        self.hundreds_nano = 10000000
        self.nano_2001 = 1000000000
        self.epoch_active = 116444736000000000
        self.hfs_dec_subtract = 2082844800
        self.ts_funcs = [self.from_unix_sec, self.from_unix_milli, self.from_win_64_hex,
                         self.from_win_64_hexle, self.from_chrome, self.from_ad,
                         self.from_unix_hex_32be, self.from_unix_hex_32le, self.from_cookie,
                         self.from_ole_be, self.from_ole_le, self.from_mac,
                         self.from_hfs_dec, self.from_hfs_be, self.from_hfs_le, self.from_msdos,
                         self.from_fat, self.from_systime, self.from_filetime, self.from_hotmail,
                         self.from_prtime, self.from_ole_auto, self.from_ms1904,
                         self.from_ios_time, self.from_sym_time, self.from_gps_time,
                         self.from_eitime, self.from_bplist, self.from_gsm, self.from_vm,
                         self.from_tiktok, self.from_twitter, self.from_discord, self.from_ksuid,
                         self.from_mastodon, self.from_metasploit, self.from_sony, self.from_uuid]
        self.date_funcs = [self.to_unix_sec, self.to_unix_milli, self.to_win_64_hex,
                           self.to_win_64_hexle, self.to_chrome, self.to_ad, self.to_unix_hex_32be,
                           self.to_unix_hex_32le, self.to_cookie, self.to_ole_be, self.to_ole_le,
                           self.to_mac, self.to_hfs_dec, self.to_hfs_be, self.to_hfs_le,
                           self.to_msdos, self.to_fat, self.to_systime, self.to_filetime,
                           self.to_hotmail, self.to_prtime, self.to_ole_auto, self.to_ms1904,
                           self.to_ios_time, self.to_sym_time, self.to_gps_time, self.to_eitime,
                           self.to_bplist, self.to_gsm, self.to_vm]
        self.in_unix_sec = self.in_unix_milli = self.in_windows_hex_64 = None
        self.in_windows_hex_le = self.in_chrome = self.in_ad = self.in_unix_hex_32 = None
        self.in_unix_hex_32le = self.in_cookie = self.in_ole_be = self.in_ole_le = None
        self.in_mac = self.in_hfs_dec = self.in_hfs_be = self.in_hfs_le = self.in_fat = None
        self.in_msdos = self.in_systemtime = self.in_filetime = self.in_prtime = None
        self.in_ole_auto = self.in_ms1904 = self.in_iostime = self.in_symtime = self.in_hotmail = None
        self.in_gpstime = self.in_eitime = self.in_bplist = self.in_gsm = self.in_vm = None
        self.in_tiktok = self.in_twitter = self.in_discord = self.in_ksuid = self.in_mastodon = None
        self.in_metasploit = self.in_sony = self.in_uuid = None

        self.out_unix_sec = self.out_unix_milli = self.out_windows_hex_64 = self.out_hotmail = None
        self.out_windows_hex_le = self.out_chrome = self.out_adtime = self.out_unix_hex_32 = None
        self.out_unix_hex_32le = self.out_cookie = self.out_ole_be = self.out_ole_le = None
        self.out_mac = self.out_hfs_dec = self.out_hfs_be = self.out_hfs_le = self.out_fat = None
        self.out_msdos = self.out_systemtime = self.out_filetime = self.out_prtime = None
        self.out_ole_auto = self.out_ms1904 = self.out_iostime = self.out_symtime = None
        self.out_gpstime = self.out_eitime = self.out_bplist = self.out_gsm = self.out_vm = None

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
        self.left_color = "\033[1;31m"
        self.right_color = "\033[1;m"
        self.ts_types = {'unix_sec': 'Unix Seconds:',
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
                         'uu': 'UUID time:'}

    def run(self):
        """Process arguments and errors"""
        if len(sys.argv[1:]) == 0:
            arg_parse.print_help()
            arg_parse.exit()
        try:
            if args.unix:
                result, indiv_output, combined_output, reason = self.from_unix_sec()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.umil:
                result, indiv_output, combined_output, reason = self.from_unix_milli()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.wh:
                result, indiv_output, combined_output, reason = self.from_win_64_hex()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.whle:
                result, indiv_output, combined_output, reason = self.from_win_64_hexle()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.chrome:
                result, indiv_output, combined_output, reason = self.from_chrome()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.active:
                result, indiv_output, combined_output, reason = self.from_ad()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.uhbe:
                result, indiv_output, combined_output, reason = self.from_unix_hex_32be()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.uhle:
                result, indiv_output, combined_output, reason = self.from_unix_hex_32le()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.cookie:
                result, indiv_output, combined_output, reason = self.from_cookie()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.oleb:
                result, indiv_output, combined_output, reason = self.from_ole_be()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.olel:
                result, indiv_output, combined_output, reason = self.from_ole_le()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.mac:
                result, indiv_output, combined_output, reason = self.from_mac()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.hfsdec:
                result, indiv_output, combined_output, reason = self.from_hfs_dec()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.hfsbe:
                result, indiv_output, combined_output, reason = self.from_hfs_be()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.hfsle:
                result, indiv_output, combined_output, reason = self.from_hfs_le()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.fat:
                result, indiv_output, combined_output, reason = self.from_fat()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.msdos:
                result, indiv_output, combined_output, reason = self.from_msdos()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.systime:
                result, indiv_output, combined_output, reason = self.from_systime()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.ft:
                result, indiv_output, combined_output, reason = self.from_filetime()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.hotmail:
                result, indiv_output, combined_output, reason = self.from_hotmail()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.pr:
                result, indiv_output, combined_output, reason = self.from_prtime()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.auto:
                result, indiv_output, combined_output, reason = self.from_ole_auto()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.ms1904:
                result, indiv_output, combined_output, reason = self.from_ms1904()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.ios:
                result, indiv_output, combined_output, reason = self.from_ios_time()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.sym:
                result, indiv_output, combined_output, reason = self.from_sym_time()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.gps:
                result, indiv_output, combined_output, reason = self.from_gps_time()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.eitime:
                result, indiv_output, combined_output, reason = self.from_eitime()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.bplist:
                result, indiv_output, combined_output, reason = self.from_bplist()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.gsm:
                result, indiv_output, combined_output, reason = self.from_gsm()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.vm:
                result, indiv_output, combined_output, reason = self.from_vm()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.tiktok:
                result, indiv_output, combined_output, reason = self.from_tiktok()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.twitter:
                result, indiv_output, combined_output, reason = self.from_twitter()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.discord:
                result, indiv_output, combined_output, reason = self.from_discord()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.ksuid:
                result, indiv_output, combined_output, reason = self.from_ksuid()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.mastodon:
                result, indiv_output, combined_output, reason = self.from_mastodon()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.meta:
                result, indiv_output, combined_output, reason = self.from_metasploit()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.sony:
                result, indiv_output, combined_output, reason = self.from_sony()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.uu:
                result, indiv_output, combined_output, reason = self.from_uuid()
                if indiv_output is False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.timestamp:
                self.to_timestamps()
            elif args.guess:
                self.from_all()
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))

    def to_timestamps(self):
        """Convert provided date to all timestamps"""
        print('\nConverting Date: ' + timestamp + '\n')
        for func in self.date_funcs:
            func()
        self.timestamp_output()

    def from_unix_sec(self):
        """Convert Unix Seconds value to a date"""
        reason = "[!] Unix seconds timestamp is 10 digits in length"
        ts_type = self.ts_types['unix_sec']
        try:
            if not len(unix) == 10 or not unix.isdigit():
                self.in_unix_sec = indiv_output = combined_output = False
                pass
            else:
                self.in_unix_sec = dt.utcfromtimestamp(float(unix)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_unix_sec))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_unix_sec, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_unix_sec = indiv_output = combined_output = False
        return self.in_unix_sec, indiv_output, combined_output, reason

    def to_unix_sec(self):
        """Convert date to a Unix Seconds value"""
        ts_type = self.ts_types['unix_sec']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_unix_sec = str(int((dt_obj - self.epoch_1970).total_seconds()) - int(dt_tz))
            ts_output = str("{}\t\t\t{}".format(ts_type, self.out_unix_sec))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_unix_sec = ts_output = False
        return self.out_unix_sec, ts_output

    def from_unix_milli(self):
        """Convert Unix Millisecond value to a date"""
        reason = "[!] Unix milliseconds timestamp is 13 digits in length"
        ts_type = self.ts_types['unix_milli']
        try:
            if not len(umil) == 13 or not umil.isdigit():
                self.in_unix_milli = indiv_output = combined_output = False
                pass
            else:
                self.in_unix_milli = dt.utcfromtimestamp(float(umil) / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_unix_milli))
                combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_unix_milli, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_unix_milli = indiv_output = combined_output = False
        return self.in_unix_milli, indiv_output, combined_output, reason

    def to_unix_milli(self):
        """Convert date to a Unix Millisecond value"""
        ts_type = self.ts_types['unix_milli']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_unix_milli = str(int(((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))*1000))
            ts_output = str("{}\t\t{}".format(ts_type, self.out_unix_milli))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_unix_milli = ts_output = False
        return self.out_unix_milli, ts_output

    def from_win_64_hex(self):
        """Convert a Windows 64 Hex Big-Endian value to a date"""
        reason = "[!] Windows 64-bit Hex Big-Endian timestamp is 16 hex characters (8 bytes)"
        ts_type = self.ts_types['windows_hex_64']
        try:
            if not len(wh) == 16 or not all(char in hexdigits for char in wh):
                self.in_windows_hex_64 = indiv_output = combined_output = False
                pass
            else:
                base10_microseconds = int(wh, 16) / 10
                if base10_microseconds >= 1e+17:
                    self.in_windows_hex_64 = indiv_output = combined_output = False
                    pass
                else:
                    dt_obj = self.epoch_1601 + timedelta(microseconds=base10_microseconds)
                    self.in_windows_hex_64 = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {} UTC".format(ts_type, self.in_windows_hex_64))
                    combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_windows_hex_64, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_windows_hex_64 = indiv_output = combined_output = False
        return self.in_windows_hex_64, indiv_output, combined_output, reason

    def to_win_64_hex(self):
        """Convert a date to a Windows 64 Hex Big-Endian value"""
        ts_type = self.ts_types['windows_hex_64']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            minus_epoch = dt_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + ((minus_epoch.seconds - int(dt_tz)) * 1000000) + (minus_epoch.days * 86400000000)
            self.out_windows_hex_64 = str(hex(int(calculated_time)*10))[2:].zfill(16)
            ts_output = str("{}\t\t{}".format(ts_type, self.out_windows_hex_64))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_windows_hex_64 = ts_output = False
        return self.out_windows_hex_64, ts_output

    def from_win_64_hexle(self):
        """Convert a Windows 64 Hex Little-Endian value to a date"""
        reason = "[!] Windows 64-bit Hex Little-Endian timestamp is 16 hex characters (8 bytes)"
        ts_type = self.ts_types['windows_hex_le']
        try:
            if not len(whle) == 16 or not all(char in hexdigits for char in whle):
                self.in_windows_hex_le = indiv_output = combined_output = False
                pass
            else:
                indiv_output = combined_output = False
                endianness_change, = struct.unpack("<Q", unhexlify(whle))
                converted_time = endianness_change / 10
                try:
                    dt_obj = self.epoch_1601 + timedelta(microseconds=converted_time)
                    self.in_windows_hex_le = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {} UTC".format(ts_type, self.in_windows_hex_le))
                    combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_windows_hex_le, self.right_color))
                except OverflowError:
                    pass
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_windows_hex_le = indiv_output = combined_output = False
        return self.in_windows_hex_le, indiv_output, combined_output, reason

    def to_win_64_hexle(self):
        """Convert a date to a Windows 64 Hex Little-Endian value"""
        ts_type = self.ts_types['windows_hex_le']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            minus_epoch = dt_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + ((minus_epoch.seconds - int(dt_tz)) * 1000000) + (minus_epoch.days * 86400000000)
            self.out_windows_hex_le = str(struct.pack("<Q", int(calculated_time*10)).hex()).zfill(16)
            ts_output = str("{}\t\t{}".format(ts_type, self.out_windows_hex_le))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_windows_hex_le = ts_output = False
        return self.out_windows_hex_le, ts_output

    def from_chrome(self):
        """Convert a Chrome Timestamp/Webkit Value to a date"""
        reason = "[!] Chrome/Webkit timestamp is 17 digits"
        ts_type = self.ts_types['chrome']
        try:
            if not len(chrome) == 17 or not chrome.isdigit():
                self.in_chrome = indiv_output = combined_output = False
                pass
            else:
                delta = timedelta(microseconds=int(chrome))
                converted_time = self.epoch_1601 + delta
                self.in_chrome = converted_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_chrome))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_chrome, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_chrome = indiv_output = combined_output = False
        return self.in_chrome, indiv_output, combined_output, reason

    def to_chrome(self):
        """Convert a date to a Chrome Timestamp/Webkit value"""
        ts_type = self.ts_types['chrome']
        try:
            dt_obj = duparser.parse(timestamp)
            nano_seconds = ''
            if '.' in timestamp:
                nano_seconds = timestamp.split('.')[1].split(' ')[0]
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            micro_seconds = (dt_obj - self.epoch_1601).microseconds
            chrome_time = ((dt_obj - self.epoch_1601).total_seconds() - int(dt_tz))
            chrome_micro = str(chrome_time).split('.')[1]
            if (len(nano_seconds) == 6 and len(chrome_micro) < 6) or len(nano_seconds) > 6 or len(nano_seconds) == 6:
                chrome_time = str(chrome_time).replace(str(chrome_time).split('.')[1], str(micro_seconds))
                self.out_chrome = str(chrome_time).replace('.', '')
            else:
                self.out_chrome = str(int(chrome_time * 1000000))
            ts_output = str("{}\t\t\t{}".format(ts_type, self.out_chrome))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_chrome = ts_output = False
        return self.out_chrome, ts_output

    def from_ad(self):
        """Convert an Active Directory/LDAP timestamp to a date"""
        reason = "[!] Active Directory/LDAP timestamps are 18 digits"
        ts_type = self.ts_types['ad']
        try:
            if not len(active) == 18 or not active.isdigit():
                self.in_ad = indiv_output = combined_output = False
                pass
            else:
                dt_obj = dt.utcfromtimestamp((float(int(active) - self.epoch_active) / self.hundreds_nano))
                self.in_ad = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_ad))
                combined_output = str("{}{}\t{} UTC{}".format(self.left_color, ts_type, self.in_ad, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ad = indiv_output = combined_output = False
        return self.in_ad, indiv_output, combined_output, reason

    def to_ad(self):
        """Convert a date to an Active Directory/LDAP timestamp"""
        ts_type = self.ts_types['ad']
        try:
            nano_seconds = ''
            if '.' in timestamp:
                nano_seconds = timestamp.split('.')[1].split(' ')[0]
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            if len(nano_seconds) == 7:
                dt_obj = dt_obj.replace(microsecond=0)
                nano_seconds = int(nano_seconds)
            elif len(nano_seconds) > 7:
                dt_obj = dt_obj.replace(microsecond=0)
                nano_seconds = int(nano_seconds[:-(len(nano_seconds) - 7)])
            elif len(nano_seconds) == 6 or (len(nano_seconds) == 5 and len(str(dt_obj.microsecond)) == 6):
                nano_seconds = dt_obj.microsecond * 10
                dt_obj = dt_obj.replace(microsecond=0)
            else:
                nano_seconds = 0
            tz_shift = int(((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz)) * self.hundreds_nano) + nano_seconds
            self.out_adtime = str(int(tz_shift) + int(self.epoch_active))
            ts_output = str("{}\t{}".format(ts_type, self.out_adtime))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_adtime = ts_output = False
        return self.out_adtime, ts_output

    def from_unix_hex_32be(self):
        """Convert a Unix Hex 32-bit Big-Endian timestamp to a date"""
        reason = "[!] Unix Hex 32-bit Big-Endian timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['unix_hex_32']
        try:
            if not len(uhbe) == 8 or not all(char in hexdigits for char in uhbe):
                self.in_unix_hex_32 = indiv_output = combined_output = False
                pass
            else:
                to_dec = int(uhbe, 16)
                self.in_unix_hex_32 = dt.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_unix_hex_32))
                combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_unix_hex_32, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_unix_hex_32 = indiv_output = combined_output = False
        return self.in_unix_hex_32, indiv_output, combined_output, reason

    def to_unix_hex_32be(self):
        """Convert a date to a Unix Hex 32-bit Big-Endian timestamp"""
        ts_type = self.ts_types['unix_hex_32']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            unix_time = int((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))
            self.out_unix_hex_32 = str(struct.pack(">L", unix_time).hex())
            ts_output = str("{}\t\t{}".format(ts_type, self.out_unix_hex_32))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_unix_hex_32 = ts_output = False
        return self.out_unix_hex_32, ts_output

    def from_unix_hex_32le(self):
        """Convert a Unix Hex 32-bit Little-Endian timestamp to a date"""
        reason = "[!] Unix Hex 32-bit Little-Endian timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['unix_hex_32le']
        try:
            if not len(uhle) == 8 or not all(char in hexdigits for char in uhle):
                self.in_unix_hex_32le = indiv_output = combined_output = False
                pass
            else:
                to_dec = struct.unpack("<L", unhexlify(uhle))[0]
                self.in_unix_hex_32le = dt.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_unix_hex_32le))
                combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_unix_hex_32le, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_unix_hex_32le = indiv_output = combined_output = False
        return self.in_unix_hex_32le, indiv_output, combined_output, reason

    def to_unix_hex_32le(self):
        """Convert a date to a Unix Hex 32-bit Little-Endian timestamp"""
        ts_type = self.ts_types['unix_hex_32le']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            unix_time = int((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))
            self.out_unix_hex_32le = str(struct.pack("<L", unix_time).hex())
            ts_output = str("{}\t\t{}".format(ts_type, self.out_unix_hex_32le))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_unix_hex_32le = ts_output = False
        return self.out_unix_hex_32le, ts_output

    def from_cookie(self):
        """Convert an Internet Explorer timestamp to a date"""
        reason = "[!] Internet Explorer Cookie timestamps (txt cookies) consist of 2 integers values. Must be input with a comma between them."
        ts_type = self.ts_types['cookie']
        try:
            if not ("," in cookie) or not (cookie.split(",")[0].isdigit() and cookie.split(",")[1].isdigit()):
                self.in_cookie = indiv_output = combined_output = False
                pass
            else:
                low, high = [int(h, base=10) for h in cookie.split(',')]
                calc = 10**-7 * (high * 2**32 + low) - 11644473600
                if calc >= 1e+11:
                    self.in_cookie = indiv_output = combined_output = False
                    pass
                else:
                    dt_obj = dt.utcfromtimestamp(calc)
                    self.in_cookie = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {} UTC".format(ts_type, self.in_cookie))
                    combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_cookie, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_cookie = indiv_output = combined_output = False
        return self.in_cookie, indiv_output, combined_output, reason

    def to_cookie(self):
        """Convert a date to Internet Explorer timestamp values"""
        ts_type = self.ts_types['cookie']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            unix_time = int((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))
            high = int(((unix_time + 11644473600) * 10**7) / 2**32)
            low = int((unix_time + 11644473600) * 10**7) - (high * 2**32)
            self.out_cookie = str(low) + ',' + str(high)
            ts_output = str("{}\t\t{}".format(ts_type, self.out_cookie))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_cookie = ts_output = False
        return self.out_cookie, ts_output

    def from_ole_be(self):
        """Convert an OLE Big-Endian timestamp to a date"""
        reason = "[!] OLE Big-Endian timestamps are 16 hex characters (8 bytes)"
        ts_type = self.ts_types['ole_be']
        try:
            if not len(oleb) == 16 or not all(char in hexdigits for char in oleb):
                self.in_ole_be = indiv_output = combined_output = False
                pass
            else:
                delta = struct.unpack('>d', struct.pack('>Q', int(oleb, 16)))[0]
                if int(delta) < 0:
                    self.in_ole_be = indiv_output = combined_output = False
                    pass
                else:
                    dt_obj = self.epoch_1899 + timedelta(days=delta)
                    self.in_ole_be = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {} UTC".format(ts_type, self.in_ole_be))
                    combined_output = str("{}{}\t{} UTC{}".format(self.left_color, ts_type, self.in_ole_be, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ole_be = indiv_output = combined_output = False
        return self.in_ole_be, indiv_output, combined_output, reason

    def to_ole_be(self):
        """Convert a date to an OLE Big-Endian timestamp"""
        ts_type = self.ts_types['ole_be']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            delta = ((dt_obj - self.epoch_1899).total_seconds() - int(dt_tz)) / 86400
            conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
            self.out_ole_be = str(struct.pack('>Q', conv).hex())
            ts_output = str("{}\t{}".format(ts_type, self.out_ole_be))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_ole_be = ts_output = False
        return self.out_ole_be, ts_output

    def from_ole_le(self):
        """Convert an OLE Little-Endian timestamp to a date"""
        reason = "[!] OLE Little-Endian timestamps are 16 hex characters (8 bytes)"
        ts_type = self.ts_types['ole_le']
        try:
            if not len(olel) == 16 or not all(char in hexdigits for char in olel):
                self.in_ole_le = indiv_output = combined_output = False
                pass
            else:
                to_le = hexlify(struct.pack('<Q', int(olel, 16)))
                delta = struct.unpack('>d', struct.pack('>Q', int(to_le, 16)))[0]
                if int(delta) < 0:
                    self.in_ole_le = indiv_output = combined_output = False
                    pass
                else:
                    dt_obj = self.epoch_1899 + timedelta(days=delta)
                    self.in_ole_le = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {} UTC".format(ts_type, self.in_ole_le))
                    combined_output = str("{}{}\t{} UTC{}".format(self.left_color, ts_type, self.in_ole_le, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ole_le = indiv_output = combined_output = False
        return self.in_ole_le, indiv_output, combined_output, reason

    def to_ole_le(self):
        """Convert a date to an OLE Little-Endian timestamp"""
        ts_type = self.ts_types['ole_le']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            delta = ((dt_obj - self.epoch_1899).total_seconds() - int(dt_tz)) / 86400
            conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
            self.out_ole_le = str(struct.pack('<Q', conv).hex())
            ts_output = str("{}\t{}".format(ts_type, self.out_ole_le))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_ole_le = ts_output = False
        return self.out_ole_le, ts_output

    def from_mac(self):
        """Convert a Mac Absolute timestamp to a date - Also used for Safari plist timestamps"""
        reason = "[!] Mac Absolute timestamps are 9 digits, commonly followed by a decimal and up to 6 digits for milliseconds"
        ts_type = self.ts_types['mac']
        try:
            if "." not in mac or not ((len(mac.split(".")[0]) == 9) and (len(mac.split(".")[1]) in range(0, 7))) or not ''.join(mac.split(".")).isdigit():
                self.in_mac = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_2001 + timedelta(seconds=float(mac))
                self.in_mac = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_mac))
                combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_mac, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_mac = indiv_output = combined_output = False
        return self.in_mac, indiv_output, combined_output, reason

    def to_mac(self):
        """Convert a date to a Mac Absolute timestamp"""
        ts_type = self.ts_types['mac']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_mac = str(int((dt_obj - self.epoch_2001).total_seconds() - int(dt_tz)))
            ts_output = str("{}\t\t{}".format(ts_type, self.out_mac))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_mac = ts_output = False
        return self.out_mac, ts_output

    def from_hfs_dec(self):
        """Convert a Mac OS/HFS+ Decimal Timestamp to a date"""
        reason = "[!] Mac OS/HFS+ Decimal timestamps are 10 digits"
        ts_type = self.ts_types['hfs_dec']
        try:
            if not len(hfsdec) == 10 or not hfsdec.isdigit() or int(hfsdec) >= 2082844800:
                self.in_hfs_dec = indiv_output = combined_output = False
                pass
            else:
                self.in_hfs_dec = dt.utcfromtimestamp(float(int(hfsdec) - self.hfs_dec_subtract)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_hfs_dec))
                combined_output = str("{}{}\t{} UTC{}".format(self.left_color, ts_type, self.in_hfs_dec, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_hfs_dec = indiv_output = combined_output = False
        return self.in_hfs_dec, indiv_output, combined_output, reason

    def to_hfs_dec(self):
        """Convert a date to a Mac OS/HFS+ Decimal Timestamp"""
        ts_type = self.ts_types['hfs_dec']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_hfs_dec = str(int((dt_obj - self.epoch_1904).total_seconds() - int(dt_tz)))
            ts_output = str("{}\t{}".format(ts_type, self.out_hfs_dec))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_hfs_dec = ts_output = False
        return self.out_hfs_dec, ts_output

    def from_hfs_be(self):
        """Convert an HFS/HFS+ Big-Endian timestamp to a date (HFS+ is in UTC)"""
        reason = "[!] HFS/HFS+ Big-Endian timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['hfs_be']
        try:
            if not len(hfsbe) == 8 or not all(char in hexdigits for char in hfsbe):
                self.in_hfs_be = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_1904 + timedelta(seconds=int(hfsbe, 16))
                self.in_hfs_be = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} HFS Local / HFS+ UTC".format(ts_type, self.in_hfs_be))
                combined_output = str("{}{}\t\t{} HFS Local / HFS+ UTC{}".format(self.left_color, ts_type, self.in_hfs_be, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_hfs_be = indiv_output = combined_output = False
        return self.in_hfs_be, indiv_output, combined_output, reason

    def to_hfs_be(self):
        """Convert a date to an HFS/HFS+ Big-Endian timestamp"""
        ts_type = self.ts_types['hfs_be']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            conv = int((dt_obj - self.epoch_1904).total_seconds() - int(dt_tz))
            self.out_hfs_be = '{0:08x}'.format(conv)
            ts_output = str("{}\t\t{}".format(ts_type, self.out_hfs_be))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_hfs_be = ts_output = False
        return self.out_hfs_be, ts_output

    def from_hfs_le(self):
        """Convert an HFS/HFS+ Little-Endian timestamp to a date (HFS+ is in UTC)"""
        reason = "[!] HFS/HFS+ Little-Endian timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['hfs_le']
        try:
            if not len(hfsle) == 8 or not all(char in hexdigits for char in hfsle):
                self.in_hfs_le = indiv_output = combined_output = False
                pass
            else:
                to_le = struct.unpack('>I', struct.pack('<I', int(hfsle, 16)))[0]
                dt_obj = self.epoch_1904 + timedelta(seconds=to_le)
                self.in_hfs_le = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} HFS Local / HFS+ UTC".format(ts_type, self.in_hfs_le))
                combined_output = str("{}{}\t\t{} HFS Local / HFS+ UTC{}".format(self.left_color, ts_type, self.in_hfs_le, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_hfs_le = indiv_output = combined_output = False
        return self.in_hfs_le, indiv_output, combined_output, reason

    def to_hfs_le(self):
        """Convert a date to an HFS/HFS+ Little-Endian timestamp"""
        ts_type = self.ts_types['hfs_le']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            conv = int((dt_obj - self.epoch_1904).total_seconds() - int(dt_tz))
            self.out_hfs_le = str(struct.pack('<I', conv).hex())
            ts_output = str("{}\t\t{}".format(ts_type, self.out_hfs_le))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_hfs_le = ts_output = False
        return self.out_hfs_le, ts_output

    def from_fat(self):
        """Convert an MS-DOS wFatDate wFatTime timestamp to a date"""
        reason = "[!] MS-DOS wFatDate wFatTime timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['fat']
        try:
            if not len(fat) == 8 or not all(char in hexdigits for char in fat):
                self.in_fat = indiv_output = combined_output = False
                pass
            else:
                byte_swap = [fat[i:i+2] for i in range(0, len(fat), 2)]
                to_le = byte_swap[1]+byte_swap[0]+byte_swap[3]+byte_swap[2]
                binary = '{0:032b}'.format(int(to_le, 16))
                stamp = [binary[:7], binary[7:11], binary[11:16], binary[16:21], binary[21:27], binary[27:32]]
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
                    self.in_fat = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {} Local".format(ts_type, self.in_fat))
                    combined_output = str("{}{}\t\t{} Local{}".format(self.left_color, ts_type, self.in_fat, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_fat = indiv_output = combined_output = False
        return self.in_fat, indiv_output, combined_output, reason

    def to_fat(self):
        """Convert a date to an MS-DOS wFatDate wFatTime timestamp"""
        ts_type = self.ts_types['fat']
        try:
            dt_obj = duparser.parse(timestamp)
            year = '{0:07b}'.format(dt_obj.year - 1980)
            month = '{0:04b}'.format(dt_obj.month)
            day = '{0:05b}'.format(dt_obj.day)
            hour = '{0:05b}'.format(dt_obj.hour)
            minute = '{0:06b}'.format(dt_obj.minute)
            seconds = '{0:05b}'.format(int(dt_obj.second / 2))
            to_hex = str(struct.pack('>I', int(year + month + day + hour + minute + seconds, 2)).hex())
            byte_swap = ''.join([to_hex[i:i+2] for i in range(0, len(to_hex), 2)][::-1])
            self.out_fat = ''.join([byte_swap[i:i+4] for i in range(0, len(byte_swap), 4)][::-1])
            ts_output = str("{}\t\t{}".format(ts_type, self.out_fat))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_fat = ts_output = False
        return self.out_fat, ts_output

    def from_msdos(self):
        """Convert an MS-DOS timestamp to a date"""
        reason = "[!] MS-DOS 32-bit timestamps are 8 hex characters (4 bytes)"
        ts_type = self.ts_types['msdos']
        try:
            if not len(msdos) == 8 or not all(char in hexdigits for char in msdos):
                self.in_msdos = indiv_output = combined_output = False
                pass
            else:
                swap = ''.join([msdos[i:i+2] for i in range(0, len(msdos), 2)][::-1])
                binary = '{0:032b}'.format(int(swap, 16))
                stamp = [binary[:7], binary[7:11], binary[11:16], binary[16:21], binary[21:27], binary[27:32]]
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
                   or dos_sec not in range(0, 60)\
                   or dos_day not in range(1, monthrange(dos_year, dos_month)[1]):
                    self.in_msdos = indiv_output = combined_output = False
                else:
                    dt_obj = dt(dos_year, dos_month, dos_day, dos_hour, dos_min, dos_sec)
                    self.in_msdos = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {} Local".format(ts_type, self.in_msdos))
                    combined_output = str("{}{}\t{} Local{}".format(self.left_color, ts_type, self.in_msdos, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_msdos = indiv_output = combined_output = False
        return self.in_msdos, indiv_output, combined_output, reason

    def to_msdos(self):
        """Convert a date to an MS-DOS timestamp"""
        ts_type = self.ts_types['msdos']
        try:
            dt_obj = duparser.parse(timestamp)
            year = '{0:07b}'.format(dt_obj.year - 1980)
            month = '{0:04b}'.format(dt_obj.month)
            day = '{0:05b}'.format(dt_obj.day)
            hour = '{0:05b}'.format(dt_obj.hour)
            minute = '{0:06b}'.format(dt_obj.minute)
            seconds = '{0:05b}'.format(int(dt_obj.second / 2))
            hexval = str(struct.pack('>I', int(year + month + day + hour + minute + seconds, 2)).hex())
            self.out_msdos = ''.join([hexval[i:i+2] for i in range(0, len(hexval), 2)][::-1])
            ts_output = str("{}\t{}".format(ts_type, self.out_msdos))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_msdos = ts_output = False
        return self.out_msdos, ts_output

    def from_systime(self):
        """Convert a Microsoft 128-bit SYSTEMTIME timestamp to a date"""
        reason = "[!] Microsoft 128-bit SYSTEMTIME timestamps are 32 hex characters (16 bytes)"
        ts_type = self.ts_types['systemtime']
        try:
            if not len(systime) == 32 or not all(char in hexdigits for char in systime):
                self.in_systemtime = indiv_output = combined_output = False
                pass
            else:
                to_le = ''.join([systime[i:i+2] for i in range(0, len(systime), 2)][::-1])
                converted = [to_le[i:i + 4] for i in range(0, len(to_le), 4)][::-1]
                stamp = []
                for i in converted:
                    dec = int(i, 16)
                    stamp.append(dec)
                dt_obj = dt(stamp[0], stamp[1], stamp[3], stamp[4], stamp[5], stamp[6], stamp[7]*1000)
                self.in_systemtime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_systemtime))
                combined_output = str("{}{}\t{} UTC{}".format(self.left_color, ts_type, self.in_systemtime, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_systemtime = indiv_output = combined_output = False
        return self.in_systemtime, indiv_output, combined_output, reason

    def to_systime(self):
        """Convert a date to a Microsoft 128-bit SYSTEMTIME timestamp"""
        ts_type = self.ts_types['systemtime']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            micro = int(dt_obj.microsecond / 1000)
            tz_shift = dt_obj.timestamp() - int(dt_tz)
            add_micro = (tz_shift * 1000) + micro
            convert_to_seconds = add_micro / 1000
            new_dt_obj = dt.fromtimestamp(convert_to_seconds)
            full_date = new_dt_obj.strftime('%Y, %m, %w, %d, %H, %M, %S, ' + str(micro))
            stamp = []
            """ Will leave the following here for temporary Python 2 compatibility """
            if sys.version_info >= (3, 0):
                for value in full_date.split(','):
                    stamp.append(hexlify(struct.pack('<H', int(value))).decode('utf8'))
            elif sys.version_info < (3, 0):
                for value in full_date.split(','):
                    stamp.append(hexlify(struct.pack('<H', int(value))))
            self.out_systemtime = ''.join(stamp)
            ts_output = str("{}\t{}".format(ts_type, self.out_systemtime))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_systemtime = ts_output = False
        return self.out_systemtime, ts_output

    def from_filetime(self):
        """Convert a Microsoft FILETIME timestamp to a date"""
        reason = "[!] Microsoft FILETIME timestamps are 2 sets of 8 hex characters (4 bytes), separated by a colon"
        ts_type = self.ts_types['filetime']
        try:
            if not (":" in ft) or not (all(char in hexdigits for char in ft[0:8]) and all(char in hexdigits for char in ft[9:])):
                self.in_filetime = indiv_output = combined_output = False
                pass
            else:
                part2, part1 = [int(h, base=16) for h in ft.split(':')]
                converted_time = struct.unpack('>Q', struct.pack('>LL', part1, part2))[0]
                if converted_time >= 1e+18:
                    self.in_filetime = indiv_output = combined_output = False
                    pass
                else:
                    dt_obj = dt.utcfromtimestamp(float(converted_time - self.epoch_active) / self.hundreds_nano)
                    self.in_filetime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {} UTC".format(ts_type, self.in_filetime))
                    combined_output = str("{}{}\t{} UTC{}".format(self.left_color, ts_type, self.in_filetime, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_filetime = indiv_output = combined_output = False
        return self.in_filetime, indiv_output, combined_output, reason

    def to_filetime(self):
        """Convert a date to a Microsoft FILETIME timestamp"""
        ts_type = self.ts_types['filetime']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            minus_epoch = dt_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + ((minus_epoch.seconds - int(dt_tz)) * 1000000) + (minus_epoch.days * 86400000000)
            indiv_output = str(struct.pack(">Q", int(calculated_time*10)).hex())
            self.out_filetime = str(indiv_output[8:]) + ":" + str(indiv_output[:8])
            ts_output = str("{}\t{}".format(ts_type, self.out_filetime))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_filetime = ts_output = False
        return self.out_filetime, ts_output

    def from_hotmail(self):
        """Convert a Microsoft Hotmail timestamp to a date"""
        reason = "[!] Microsoft Hotmail timestamps are 2 sets of 8 hex characters (4 bytes), separated by a colon"
        ts_type = self.ts_types['hotmail']
        try:
            if ":" not in hotmail or not (all(char in hexdigits for char in hotmail[0:8]) and all(char in hexdigits for char in hotmail[9:])):
                self.in_hotmail = indiv_output = combined_output = False
                pass
            else:
                hotmail_replace = hotmail.replace(':', '')
                byte_swap = ''.join([hotmail_replace[i:i+2] for i in range(0, len(hotmail_replace), 2)][::-1])
                part2 = int(byte_swap[:8], base=16)
                part1 = int(byte_swap[8:], base=16)
                converted_time = struct.unpack('>Q', struct.pack('>LL', part1, part2))[0]
                if converted_time >= 1e+18:
                    self.in_hotmail = indiv_output = combined_output = False
                    pass
                else:
                    dt_obj = dt.utcfromtimestamp(float(converted_time - self.epoch_active) / self.hundreds_nano)
                    self.in_hotmail = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {} UTC".format(ts_type, self.in_hotmail))
                    combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_hotmail, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_hotmail = indiv_output = combined_output = False
        return self.in_hotmail, indiv_output, combined_output, reason

    def to_hotmail(self):
        """Convert a date to a Microsoft Hotmail timestamp"""
        ts_type = self.ts_types['hotmail']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            minus_epoch = dt_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + ((minus_epoch.seconds - int(dt_tz)) * 1000000) + (minus_epoch.days * 86400000000)
            indiv_output = str(struct.pack(">Q", int(calculated_time*10)).hex())
            byte_swap = ''.join([indiv_output[i:i+2] for i in range(0, len(indiv_output), 2)][::-1])
            self.out_hotmail = str(byte_swap[8:]) + ":" + str(byte_swap[:8])
            ts_output = str("{}\t\t{}".format(ts_type, self.out_hotmail))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_hotmail = ts_output = False
        return self.out_hotmail, ts_output

    def from_prtime(self):
        """Convert a Mozilla PRTime timestamp to a date"""
        reason = "[!] Mozilla PRTime timestamps are 16 digits"
        ts_type = self.ts_types['prtime']
        try:
            if not len(pr) == 16 or not pr.isdigit():
                self.in_prtime = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_1970 + timedelta(microseconds=int(pr))
                self.in_prtime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_prtime))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_prtime, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_prtime = indiv_output = combined_output = False
        return self.in_prtime, indiv_output, combined_output, reason

    def to_prtime(self):
        """Convert a date to Mozilla's PRTime timestamp"""
        ts_type = self.ts_types['prtime']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_prtime = str(int(((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz)) * 1000000))
            ts_output = str("{}\t\t\t{}".format(ts_type, self.out_prtime))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_prtime = ts_output = False
        return self.out_prtime, ts_output

    def from_ole_auto(self):
        """Convert an OLE Automation timestamp to a date"""
        reason = "[!] OLE Automation timestamps are 2 integers, separated by a dot. The left is 5 digits, the right is between 9-12 digits"
        ts_type = self.ts_types['ole_auto']
        try:
            if "." not in auto or not ((len(auto.split(".")[0]) == 5) and (len(auto.split(".")[1]) in range(9, 13))) or not ''.join(auto.split(".")).isdigit():
                self.in_ole_auto = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_1899 + timedelta(days=float(auto))
                self.in_ole_auto = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_ole_auto))
                combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_ole_auto, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ole_auto = indiv_output = combined_output = False
        return self.in_ole_auto, indiv_output, combined_output, reason

    def to_ole_auto(self):
        """Convert a date to an OLE Automation timestamp"""
        ts_type = self.ts_types['ole_auto']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_ole_auto = "{0:.12f}".format(((dt_obj - self.epoch_1899).total_seconds() - int(dt_tz)) / 86400)
            ts_output = str("{}\t\t{}".format(ts_type, self.out_ole_auto))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_ole_auto = ts_output = False
        return self.out_ole_auto, ts_output

    def from_ms1904(self):
        """Convert a Microsoft Excel 1904 timestamp to a date"""
        reason = "[!] Microsoft Excel 1904 timestamps are 2 integers, separated by a dot. The left is 5 digits, the right is between 9-12 digits"
        ts_type = self.ts_types['ms1904']
        try:
            if "." not in ms1904 or not ((len(ms1904.split(".")[0]) == 5) and (len(ms1904.split(".")[1]) in range(9, 13))) or not ''.join(ms1904.split(".")).isdigit():
                self.in_ms1904 = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_1904 + timedelta(days=float(ms1904))
                self.in_ms1904 = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_ms1904))
                combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_ms1904, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ms1904 = indiv_output = combined_output = False
        return self.in_ms1904, indiv_output, combined_output, reason

    def to_ms1904(self):
        """Convert a date to a Microsoft Excel 1904 timestamp"""
        ts_type = self.ts_types['ms1904']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_ms1904 = "{0:.12f}".format(((dt_obj - self.epoch_1904).total_seconds() - int(dt_tz)) / 86400)
            ts_output = str("{}\t\t{}".format(ts_type, self.out_ms1904))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_ms1904 = ts_output = False
        return self.out_ms1904, ts_output

    def from_ios_time(self):
        """Convert an iOS 11 timestamp to a date"""
        reason = "[!] iOS 11 timestamps are typically 15-18 digits"
        ts_type = self.ts_types['iostime']
        try:
            if not len(ios) in range(15, 19) or not ios.isdigit():
                self.in_iostime = indiv_output = combined_output = False
                pass
            else:
                dt_obj = (int(ios) / int(self.nano_2001)) + 978307200
                self.in_iostime = dt.utcfromtimestamp(dt_obj).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {} UTC".format(ts_type, self.in_iostime))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_iostime, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_iostime = indiv_output = combined_output = False
        return self.in_iostime, indiv_output, combined_output, reason

    def to_ios_time(self):
        """Convert a date to an iOS 11 timestamp"""
        ts_type = self.ts_types['iostime']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_iostime = str(int(((dt_obj - self.epoch_2001).total_seconds() - int(dt_tz)) * self.nano_2001))
            ts_output = str("{}\t\t\t{}".format(ts_type, self.out_iostime))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_iostime = ts_output = False
        return self.out_iostime, ts_output

    def from_sym_time(self):
        """Convert a Symantec 6-byte hex timestamp to a date"""
        reason = "[!] Symantec 6-byte hex timestamps are 12 hex characters"
        ts_type = self.ts_types['symtime']
        try:
            if not len(sym) == 12 or not all(char in hexdigits for char in sym):
                self.in_symtime = indiv_output = combined_output = False
                pass
            else:
                hex_to_dec = [int(sym[i:i+2], 16) for i in range(0, len(sym), 2)]
                hex_to_dec[0] = hex_to_dec[0] + 1970
                hex_to_dec[1] = hex_to_dec[1] + 1
                dt_obj = dt(hex_to_dec[0], hex_to_dec[1], hex_to_dec[2], hex_to_dec[3], hex_to_dec[4], hex_to_dec[5])
                self.in_symtime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_symtime))
                combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_symtime, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_symtime = indiv_output = combined_output = False
        return self.in_symtime, indiv_output, combined_output, reason

    def to_sym_time(self):
        """Convert a date to Symantec's 6-byte hex timestamp"""
        ts_type = self.ts_types['symtime']
        try:
            dt_obj = duparser.parse(timestamp)
            sym_year = '{0:x}'.format(dt_obj.year - 1970).zfill(2)
            sym_month = '{0:x}'.format(dt_obj.month - 1).zfill(2)
            sym_day = '{0:x}'.format(dt_obj.day).zfill(2)
            sym_hour = '{0:x}'.format(dt_obj.hour).zfill(2)
            sym_minute = '{0:x}'.format(dt_obj.minute).zfill(2)
            sym_second = '{0:x}'.format(dt_obj.second).zfill(2)
            self.out_symtime = sym_year + sym_month + sym_day + sym_hour + sym_minute + sym_second
            ts_output = str("{}\t\t{}".format(ts_type, self.out_symtime))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_symtime = ts_output = False
        return self.out_symtime, ts_output

    def from_gps_time(self):
        """Convert a GPS timestamp to a date (involves leap seconds)"""
        reason = "[!] GPS timestamps are 10 digits"
        ts_type = self.ts_types['gpstime']
        try:
            if not len(gps) == 10 or not gps.isdigit():
                self.in_gpstime = indiv_output = combined_output = False
                pass
            else:
                leapseconds = self.leapseconds
                gps_stamp = self.epoch_1980 + timedelta(seconds=(float(gps)))
                tai_convert = gps_stamp + timedelta(seconds=19)
                epoch_convert = (tai_convert - self.epoch_1970).total_seconds()
                check_date = dt.utcfromtimestamp(epoch_convert)
                for entry in leapseconds:
                    check = self.date_range(leapseconds.get(entry)[0], leapseconds.get(entry)[1], check_date)
                    if check is True:
                        variance = entry
                    else:
                        variance = 0
                gps_out = check_date - timedelta(seconds=variance)
                self.in_gpstime = gps_out.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_gpstime))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_gpstime, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_gpstime = indiv_output = combined_output = False
        return self.in_gpstime, indiv_output, combined_output, reason

    def to_gps_time(self):
        """Convert a date to a GPS timestamp (involves leap seconds)"""
        ts_type = self.ts_types['gpstime']
        try:
            leapseconds = self.leapseconds
            check_date = duparser.parse(timestamp)
            if hasattr(check_date.tzinfo, '_offset'):
                dt_tz = check_date.tzinfo._offset.total_seconds()
                check_date = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            for entry in leapseconds:
                check = self.date_range(leapseconds.get(entry)[0], leapseconds.get(entry)[1], check_date)
                if check is True:
                    variance = entry
                else:
                    variance = 0
            leap_correction = check_date + timedelta(seconds=variance)
            epoch_shift = leap_correction - self.epoch_1970
            gps_stamp = (dt.utcfromtimestamp(epoch_shift.total_seconds()) - self.epoch_1980).total_seconds() - 19
            gps_stamp = int(gps_stamp) - int(dt_tz)
            self.out_gpstime = str(gps_stamp)
            ts_output = str("{}\t\t\t{}".format(ts_type, self.out_gpstime))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_gpstime = ts_output = False
        return self.out_gpstime, ts_output

    def from_eitime(self):
        """Convert a Google ei URL timestamp"""
        reason = "[!] Google ei URL timestamps contain only URL-safe base64 characters: [A-Z][a-z][0-9][=-_]"
        ts_type = self.ts_types['eitime']
        try:
            URLSAFE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_'
            if not all(char in URLSAFE_CHARS for char in eitime):
                self.in_eitime = indiv_output = combined_output = False
                pass
            else:
                padding_check = (len(eitime) % 4)
                if padding_check != 0:
                    padding_reqd = (4 - padding_check)
                    result_eitime = eitime + (padding_reqd * '=')
                else:
                    result_eitime = eitime
                try:
                    decoded_eitime = base64.urlsafe_b64decode(result_eitime).hex()[:8]
                    unix_timestamp, = struct.unpack("<L", unhexlify(decoded_eitime))
                    self.in_eitime = dt.utcfromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{}\t\t\t{}".format(ts_type, self.in_eitime))
                    combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_eitime, self.right_color))
                except base64.binascii.Error:
                    self.in_eitime = indiv_output = combined_output = False
                    pass
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_eitime = indiv_output = combined_output = False
        return self.in_eitime, indiv_output, combined_output, reason

    def to_eitime(self):
        """ Try to convert a value to an ei URL timestamp"""
        ts_type = self.ts_types['eitime']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            unix_time = int((dt_obj - self.epoch_1970).total_seconds() + int(dt_tz))
            unix_hex = struct.pack("<L", unix_time)
            urlsafe_encode = base64.urlsafe_b64encode(unix_hex)
            self.out_eitime = urlsafe_encode.decode(encoding="UTF-8").strip("=")
            ts_output = str("{}\t\t\t{}".format(ts_type, self.out_eitime))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_eitime = ts_output = False
        return self.out_eitime, ts_output

    def from_bplist(self):
        """Convert a Binary Plist timestamp to a date"""
        reason = "[!] Binary Plist timestamps are 9 digits"
        ts_type = self.ts_types['bplist']
        try:
            if not len(bplist) == 9 or not bplist.isdigit():
                self.in_bplist = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_2001 + timedelta(seconds=float(bplist))
                self.in_bplist = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_bplist))
                combined_output = str("{}{}\t\t{} UTC{}".format(self.left_color, ts_type, self.in_bplist, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_bplist = indiv_output = combined_output = False
        return self.in_bplist, indiv_output, combined_output, reason

    def to_bplist(self):
        """Convert a date to a Binary Plist timestamp"""
        ts_type = self.ts_types['bplist']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_bplist = str(int((dt_obj - self.epoch_2001).total_seconds()) - int(dt_tz))
            ts_output = str("{}\t\t{}".format(ts_type, self.out_bplist))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
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
                '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f',
                '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25',
                '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41',
                '42', '43', '44', '45', '46', '47', '48', '80', '81', '82', '83', '84', '85', '86', '87', '88',
                '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98',
                '99', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'b0', 'b1', 'b2', 'b3', 'b4',
                'b5', 'b6', 'b7', 'b8', 'b9', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8'
                ]
            tz_check = gsm[12:14][::-1].lower()
            if not len(gsm) == 14 or not all(char in hexdigits for char in gsm) or tz_check not in tz_in_range:
                self.in_gsm = indiv_output = combined_output = False
                pass
            else:
                swap = [gsm[i:i+2] for i in range(0, len(gsm), 2)]
                for value in swap[:]:
                    le = value[::-1]
                    swap.remove(value)
                    swap.append(le)
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
                    dt_tz = " UTC+" + str(dt_tz)
                else:
                    dt_tz = " UTC" + str(dt_tz)
                self.in_gsm = str((dt(dt_year, dt_month, dt_day, dt_hour, dt_min, dt_sec).strftime('%Y-%m-%d %H:%M:%S.%f')) + dt_tz)
                indiv_output = str("{} {}".format(ts_type, self.in_gsm))
                combined_output = str("{}{}\t\t\t{}{}".format(self.left_color, ts_type, self.in_gsm, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_gsm = indiv_output = combined_output = False
        return self.in_gsm, indiv_output, combined_output, reason

    def to_gsm(self):
        """Convert a timestamp to a GSM timestamp"""
        ts_type = self.ts_types['gsm']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
            else:
                dt_tz = 0
            if dt_tz == 0:
                hex_tz = '{:02d}'.format(0)
            elif dt_tz < 0:
                dt_tz = dt_tz / 3600
                conversion = str('{:02d}'.format(int(abs(dt_tz)) * 4))
                conversion_list = []
                for char in range(len(conversion)):
                    conversion_list.append(conversion[char])
                high_order = '{0:04b}'.format(int(conversion_list[0]))
                low_order = '{0:04b}'.format(int(conversion_list[1]))
                high_order = '{0:04b}'.format(int(high_order, 2) + 8)
                hex_tz = hex(int((high_order + low_order), 2)).lstrip('0x').upper()
            else:
                dt_tz = dt_tz / 3600
                conversion = str(int(dt_tz) * 4)
                conversion_list = []
                for char in range(len(conversion)):
                    conversion_list.append(conversion[char])
                high_order = '{0:04b}'.format(int(conversion_list[0]))
                low_order = '{0:04b}'.format(int(conversion_list[1]))
                hex_tz = hex(int((high_order + low_order), 2)).lstrip('0x').upper()
            date_list = [str(dt_obj.year - 2000),
                         '{:02d}'.format(dt_obj.month),
                         '{:02d}'.format(dt_obj.day),
                         '{:02d}'.format(dt_obj.hour),
                         '{:02d}'.format(dt_obj.minute),
                         '{:02d}'.format(dt_obj.second), hex_tz]
            date_value_swap = []
            for value in date_list[:]:
                be = value[::-1]
                date_value_swap.append(be)
            self.out_gsm = ''.join(date_value_swap)
            ts_output = str("{}\t\t\t{}".format(ts_type, self.out_gsm))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_gsm = ts_output = False
        return self.out_gsm, ts_output

    def from_vm(self):
        """Convert from a .vmsd createTimeHigh/createTimeLow timestamp"""
        reason = "[!] VMSD timestamps are a 6-digit \'High\' value followed by a signed/unsigned integer at least 9 digits"
        ts_type = self.ts_types['vm']
        try:
            if "," not in vm:
                self.in_vm = indiv_output = combined_output = False
                pass
            else:
                cTimeHigh = int(vm.split(',')[0])
                cTimeLow = int(vm.split(',')[1])
                vmsd = float((cTimeHigh * 2**32) + struct.unpack('I', struct.pack('i', cTimeLow))[0]) / 1000000
                if vmsd >= 1e+13:
                    self.in_vm = indiv_output = combined_output = False
                    pass
                else:
                    self.in_vm = dt.utcfromtimestamp(vmsd).strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("{} {}".format(ts_type, self.in_vm))
                    combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_vm, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_vm = indiv_output = combined_output = False
        return self.in_vm, indiv_output, combined_output, reason

    def to_vm(self):
        """Convert date to a .vmsd createTime* value"""
        ts_type = self.ts_types['vm']
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            unix_seconds = (int((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))*1000000)
            createTimeHigh = int(float(unix_seconds) / 2**32)
            unpacked_int = unix_seconds - (createTimeHigh * 2**32)
            createTimeLow = struct.unpack('i', struct.pack('I', unpacked_int))[0]
            self.out_vm = str(createTimeHigh) + ',' + str(createTimeLow)
            ts_output = str("{}\t\t\t{}".format(ts_type, self.out_vm))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_vm = ts_output = False
        return self.out_vm, ts_output

    def from_tiktok(self):
        """Convert a TikTok URL value to a date/time"""
        reason = "[!] TikTok timestamps are 19 digits long"
        ts_type = self.ts_types['tiktok']
        try:
            if len(str(tiktok)) < 19 or not tiktok.isdigit():
                self.in_tiktok = indiv_output = combined_output = False
                pass
            else:
                unix_ts = (int(tiktok) >> 32)
                self.in_tiktok = dt.utcfromtimestamp(float(unix_ts)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_tiktok))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_tiktok, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_tiktok = indiv_output = combined_output = False
        return self.in_tiktok, indiv_output, combined_output, reason

    def from_twitter(self):
        """Convert a Twitter URL value to a date/time"""
        reason = "[!] Twitter timestamps are 18 digits or longer"
        ts_type = self.ts_types['twitter']
        try:
            if len(str(twitter)) < 18 or not twitter.isdigit():
                self.in_twitter = indiv_output = combined_output = False
                pass
            else:
                unix_ts = (int(twitter) >> 22) + 1288834974657
                self.in_twitter = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_twitter))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_twitter, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_twitter = indiv_output = combined_output = False
        return self.in_twitter, indiv_output, combined_output, reason

    def from_discord(self):
        """Convert a Discord URL value to a date/time"""
        reason = "[!] Discord timestamps are 18 digits or longer"
        ts_type = self.ts_types['discord']
        try:
            if len(str(discord)) < 18 or not discord.isdigit():
                self.in_discord = indiv_output = combined_output = False
                pass
            else:
                unix_ts = (int(discord) >> 22) + 1420070400000
                self.in_discord = dt.utcfromtimestamp(float(unix_ts) / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_discord))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_discord, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_discord = indiv_output = combined_output = False
        return self.in_discord, indiv_output, combined_output, reason

    def from_ksuid(self):
        """Extract a timestamp from a KSUID value"""
        reason = "[!] KSUID values are 27 characters"
        ts_type = self.ts_types['ksuid']
        try:
            KSUIDCHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
            if len(str(ksuid)) != 27 or not all(char in KSUIDCHARS for char in ksuid):
                self.in_ksuid = indiv_output = combined_output = False
                pass
            else:
                length, i, v = len(ksuid), 0, 0
                ba = bytearray()
                for val in ksuid:
                    v += KSUIDCHARS.index(val) * (62 ** (length - (i + 1)))
                    i += 1
                while v > 0:
                    ba.append(v & 0xFF)
                    v //= 256
                ba.reverse()
                ts_bytes = bytes(ba)[0:4]
                unix_ts = int.from_bytes(ts_bytes, 'big', signed=False) + 1400000000
                self.in_ksuid = dt.utcfromtimestamp(float(unix_ts)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_ksuid))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_ksuid, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ksuid = indiv_output = combined_output = False
        return self.in_ksuid, indiv_output, combined_output, reason

    def from_mastodon(self):
        """Convert a Mastodon value to a date/time"""
        reason = "[!] Mastodon timestamps are 18 digits or longer"
        ts_type = self.ts_types['mastodon']
        try:
            if len(str(tiktok)) < 18 or not mastodon.isdigit():
                self.in_mastodon = indiv_output = combined_output = False
                pass
            else:
                unix_ts = (int(mastodon) >> 16)
                self.in_mastodon = dt.utcfromtimestamp(float(unix_ts) /1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_mastodon))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_mastodon, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_mastodon = indiv_output = combined_output = False
        return self.in_mastodon, indiv_output, combined_output, reason

    def from_metasploit(self):
        """Convert a Metasploit Payload UUID value to a date/time"""
        reason = "[!] Metasploit Payload UUID's are at least 22 chars and base64 urlsafe encoded"
        ts_type = self.ts_types['metasploit']
        try:
            URLSAFE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_'
            format = '8sBBBBBBBB'
            if len(str(meta)) < 22 or not all(char in URLSAFE_CHARS for char in meta):
                self.in_metasploit = indiv_output = combined_output = False
                pass
            else:
                b64decoded = base64.urlsafe_b64decode(meta[0:22] + '==')
                if len(b64decoded) < struct.calcsize(format):
                    raise Exception
                puid, xor1, xor2, platform_xored, architecture_xored, ts1_xored, ts2_xored, ts3_xored, ts4_xored = struct.unpack(format, b64decoded)
                unix_ts = struct.unpack('>I', bytes([ts1_xored ^ xor1, ts2_xored ^ xor2, ts3_xored ^ xor1, ts4_xored ^ xor2]))[0]
                self.in_metasploit = dt.utcfromtimestamp(float(unix_ts)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_metasploit))
                combined_output = str("{}{}\t{} UTC{}".format(self.left_color, ts_type, self.in_metasploit, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_metasploit = indiv_output = combined_output = False
        return self.in_metasploit, indiv_output, combined_output, reason

    def from_sony(self):
        """Convert a Sonyflake value to a date/time"""
        reason = "[!] Sonyflake values are 15 hex characters"
        ts_type = self.ts_types['sony']
        try:
            if len(str(sony)) != 15 or not all(char in hexdigits for char in sony):
                self.in_sony = indiv_output = combined_output = False
                pass
            else:
                dec_value = int(sony, 16)
                ts_value = dec_value >> 24
                unix_ts = (ts_value + 140952960000) * 10
                self.in_sony = dt.utcfromtimestamp(float(unix_ts) /1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("{} {}".format(ts_type, self.in_sony))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_sony, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_sony = indiv_output = combined_output = False
        return self.in_sony, indiv_output, combined_output, reason

    def from_uuid(self):
        """Convert a UUID value to date/time"""
        reason = "[!] UUID's are in the format 00000000-0000-0000-0000-000000000000"
        ts_type = self.ts_types['uu']
        try:
            uuid_lower = uu.lower()
            UUID_REGEX = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
            if not bool(UUID_REGEX.match(uuid_lower)):
                self.in_uuid = indiv_output = combined_output = False
                pass
            else:
                u = uuid.UUID(uuid_lower)
                if u.version == 1:
                    unix_ts = int((u.time / 10000) - 12219292800000)
                    self.in_uuid = dt.utcfromtimestamp(float(unix_ts) /1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
                else:
                    pass
                indiv_output = str("{} {}".format(ts_type, self.in_uuid))
                combined_output = str("{}{}\t\t\t{} UTC{}".format(self.left_color, ts_type, self.in_uuid, self.right_color))
        except Exception:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_uuid = indiv_output = combined_output = False
        return self.in_uuid, indiv_output, combined_output, reason

    def date_range(self, start, end, check_date):
        """Check if date is in range of start and end, return True if it is"""
        if start <= end:
            return start <= check_date <= end
        else:
            return start <= check_date or check_date <= end

    def from_all(self):
        """Output all processed timestamp values"""
        """Find date from provided timestamp"""
        this_year = int(dt.now().strftime('%Y'))
        states = []
        print('\nGuessing Date from Timestamp: ' + sys.argv[2] + '\r')
        print('Outputs which do not result in a date/time value are not displayed.\r')
        print('{}Most likely results (results within +/- 5 years) are highlighted.\n{}'.format(self.left_color, self.right_color))
        for func in self.ts_funcs:
            result, indiv_output, combined_output, reason = func()
            states.append(result)
            if isinstance(result, str):
                if int(duparser.parse(result).strftime('%Y')) in range(this_year - 5, this_year + 5):
                    print(combined_output)
                else:
                    print(combined_output.strip(self.left_color).strip(self.right_color))
        if all([state is False for state in states]):
            print('No valid dates found. Check your input and try again.')
        print('\r')

    def timestamp_output(self):
        """Output all processed dates from timestamp values"""
        for func in self.date_funcs:
            result, ts_output = func()
            if isinstance(result, str):
                print(ts_output)
        print('\r')


if __name__ == '__main__':
    now = dt.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    arg_parse = argparse.ArgumentParser(description='Time Decoder and Converter v' + str(__version__), formatter_class=argparse.RawTextHelpFormatter)
    arg_parse.add_argument('--unix', metavar='', help='convert from Unix Seconds')
    arg_parse.add_argument('--umil', metavar='', help='convert from Unix Milliseconds')
    arg_parse.add_argument('--wh', metavar='', help='convert from Windows 64-bit Hex BE')
    arg_parse.add_argument('--whle', metavar='', help='convert from Windows 64-bit Hex LE')
    arg_parse.add_argument('--chrome', metavar='', help='convert from Google Chrome time')
    arg_parse.add_argument('--active', metavar='', help='convert from Active Directory value')
    arg_parse.add_argument('--uhbe', metavar='', help='convert from Unix Hex 32-bit BE')
    arg_parse.add_argument('--uhle', metavar='', help='convert from Unix Hex 32-bit LE')
    arg_parse.add_argument('--cookie', metavar='', help='convert from Windows Cookie Date (Low Value,High Value)')
    arg_parse.add_argument('--oleb', metavar='', help='convert from Windows OLE 64-bit BE - remove 0x and spaces!\n- Example from SRUM: 0x40e33f5d 0x97dfe8fb should be 40e33f5d97dfe8fb')
    arg_parse.add_argument('--olel', metavar='', help='convert from Windows OLE 64-bit LE')
    arg_parse.add_argument('--mac', metavar='', help='convert from Mac Absolute Time')
    arg_parse.add_argument('--hfsdec', metavar='', help='convert from Mac OS/HFS+ Decimal Time')
    arg_parse.add_argument('--hfsbe', metavar='', help='convert from HFS(+) BE times (HFS = Local, HFS+ = UTC)')
    arg_parse.add_argument('--hfsle', metavar='', help='convert from HFS(+) LE times (HFS = Local, HFS+ = UTC)')
    arg_parse.add_argument('--fat', metavar='', help='convert from FAT Date + Time (wFat)')
    arg_parse.add_argument('--msdos', metavar='', help='convert from 32-bit MS-DOS time - result is Local Time')
    arg_parse.add_argument('--systime', metavar='', help='convert from 128-bit SYSTEMTIME')
    arg_parse.add_argument('--ft', metavar='', help='convert from FILETIME timestamp')
    arg_parse.add_argument('--hotmail', metavar='', help='convert from a Hotmail timestamp')
    arg_parse.add_argument('--pr', metavar='', help='convert from Mozilla\'s PRTime')
    arg_parse.add_argument('--auto', metavar='', help='convert from OLE Automation Date format')
    arg_parse.add_argument('--ms1904', metavar='', help='convert from MS Excel 1904 Date format')
    arg_parse.add_argument('--ios', metavar='', help='convert from iOS 11 timestamp')
    arg_parse.add_argument('--sym', metavar='', help='convert from Symantec\'s 12-byte AV timestamp')
    arg_parse.add_argument('--gps', metavar='', help='convert from a GPS timestamp')
    arg_parse.add_argument('--eitime', metavar='', help='convert from a Google EI URL timestamp')
    arg_parse.add_argument('--bplist', metavar='', help='convert from an iOS Binary Plist timestamp')
    arg_parse.add_argument('--gsm', metavar='', help='convert from a GSM timestamp')
    arg_parse.add_argument('--vm', metavar='', help='convert from a VMWare Snapshot (.vmsd) timestamp - enter as "high value,low value"')
    arg_parse.add_argument('--tiktok', metavar='', help='convert from a TikTok URL value')
    arg_parse.add_argument('--twitter', metavar='', help='convert from a Twitter URL value')
    arg_parse.add_argument('--discord', metavar='', help='convert from a Discord URL value')
    arg_parse.add_argument('--ksuid', metavar='', help='convert from a KSUID value')
    arg_parse.add_argument('--mastodon', metavar='', help='convert from a Mastodon URL value')
    arg_parse.add_argument('--meta', metavar='', help='convert from a Metasploit Payload UUID')
    arg_parse.add_argument('--sony', metavar='', help='convert from a Sonyflake URL value')
    arg_parse.add_argument('--uu', metavar='', help='convert from a UUID: 00000000-0000-0000-0000-000000000000')
    arg_parse.add_argument('--guess', metavar='', help='guess timestamp and output all reasonable possibilities')
    arg_parse.add_argument('--timestamp', metavar='DATE', help='convert date to every timestamp - enter date as \"YYYY-MM-DD HH:MM:SS.f\" in 24h fmt.\n- Without argument gives current date/time', nargs='?', const=now)
    arg_parse.add_argument('--version', '-v', action='version', version='%(prog)s ' + str(__version__))
    args = arg_parse.parse_args()
    all_args = vars(args)
    if args.guess:
        local_args = {}
        for each_arg in all_args:
            local_args[each_arg] = all_args[each_arg]
        for each_local in local_args:
            local_args[each_local] = args.guess
        locals().update(local_args)
        timestamp = None
    else:
        locals().update(all_args)

    td = TimeDecoder()
    td.run()
