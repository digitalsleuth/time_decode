#!/usr/bin/env python3
"""
This application is designed to decode timestamps into human-readable date/times and vice-versa
Additional information regarding the source of the timestamp formats and associated equations
will be provided in the docstrings below.
TO DO:
    Re-evaluate error handling.
    MSDOS and FAT timestamps both need method for accepting time offset

GPS Ref: http://www.leapsecond.com/java/gpsclock.htm
Leap Seconds: https://www.nist.gov/pml/time-and-frequency-division/leap-seconds-faqs
              http://hpiers.obspm.fr/eop-pc/index.php?index=TAI-UTC_tab&lang=en
Microsoft DateTime: https://docs.microsoft.com/en-us/dotnet/api/system.datetime?view=netframework-4.8
Microsoft Time: https://docs.microsoft.com/en-ca/windows/win32/sysinfo/time
Microsoft 1904 Timestamp: https://docs.microsoft.com/en-us/office/troubleshoot/excel/1900-and-1904-date-system
Microsoft OLE Automation Date (OADate): https://docs.microsoft.com/en-us/dotnet/api/system.datetime.tooadate?view=netframework-4.8
MSDOS wFatDate wFatTime DosDate: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime
Microsoft FILETIME: https://support.microsoft.com/en-ca/help/188768/info-working-with-the-filetime-structure
Microsoft Active Directory/LDAP Timestamp: https://docs.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp
bplist timestamp: https://developer.apple.com/documentation/corefoundation/cfabsolutetime
                  https://developer.apple.com/documentation/foundation/nsdate
GSM Timestamps: https://en.wikipedia.org/wiki/GSM_03.40
                http://seven-bit-forensics.blogspot.com/2014/02/decoding-gsmsms-timestamps.html

"""
from datetime import datetime as dt, timedelta
import struct
from binascii import hexlify, unhexlify
from string import hexdigits
import argparse
import sys
from dateutil import parser as duparser
import base64
from colorama import init
init(autoreset=True)

__author__ = 'Corey Forman'
__date__ = '1 Jul 2020'
__version__ = '2.3'
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
        self.ts_funcs = [self.from_unix_sec, self.from_unix_milli, self.from_win_64_hex, self.from_win_64_hexle, self.from_chrome, self.from_ad,
                 self.from_unix_hex_32be, self.from_unix_hex_32le, self.from_cookie, self.from_ole_be, self.from_ole_le, self.from_mac,
                 self.from_hfs_dec, self.from_hfs_be, self.from_hfs_le, self.from_msdos, self.from_fat, self.from_systime, self.from_filetime,
                 self.from_prtime, self.from_ole_auto, self.from_ms1904, self.from_ios_time, self.from_sym_time, self.from_gps_time,
                 self.from_eitime, self.from_bplist, self.from_gsm]
        self.date_funcs = [self.to_unix_sec, self.to_unix_milli, self.to_win_64_hex, self.to_win_64_hexle, self.to_chrome, self.to_ad, self.to_unix_hex_32be,
                           self.to_unix_hex_32le, self.to_cookie, self.to_ole_be, self.to_ole_le, self.to_mac, self.to_hfs_dec, self.to_hfs_be, self.to_hfs_le,
                           self.to_msdos, self.to_fat, self.to_systime, self.to_filetime, self.to_prtime, self.to_ole_auto, self.to_ms1904, self.to_ios_time,
                           self.to_sym_time, self.to_gps_time, self.to_eitime, self.to_bplist, self.to_gsm]
        self.in_unix_sec = self.in_unix_milli = self.in_windows_hex_64 = self.in_windows_hex_le = self.in_chrome = self.in_ad = self.in_unix_hex_32 = self.in_unix_hex_32le = self.in_cookie = self.in_ole_be = self.in_ole_le = self.in_mac = self.in_hfs_dec = self.in_hfs_be = self.in_hfs_le = self.in_fat = self.in_msdos = self.in_systemtime = self.in_filetime = self.in_prtime = self.in_ole_auto = self.in_ms1904 = self.in_iostime = self.in_symtime = self.in_gpstime = self.in_eitime = self.in_bplist = self.in_gsm = None
        self.out_unix_sec = self.out_unix_milli = self.out_windows_hex_64 = self.out_windows_hex_le = self.out_chrome = self.out_adtime = self.out_unix_hex_32 = self.out_unix_hex_32le = self.out_cookie = self.out_ole_be = self.out_ole_le = self.out_mac = self.out_hfs_dec = self.out_hfs_be = self.out_hfs_le = self.out_fat = self.out_msdos = self.out_systemtime = self.out_filetime = self.out_prtime = self.out_ole_auto = self.out_ms1904 = self.out_iostime = self.out_symtime = self.out_gpstime = self.out_eitime = self.out_bplist = self.out_gsm = None
        self.leapseconds = {
        10:[dt(1972,1,1), dt(1972,7,1)],
        11:[dt(1972,7,1), dt(1973,1,1)],
        12:[dt(1973,1,1), dt(1974,1,1)],
        13:[dt(1974,1,1), dt(1975,1,1)],
        14:[dt(1975,1,1), dt(1976,1,1)],
        15:[dt(1976,1,1), dt(1977,1,1)],
        16:[dt(1977,1,1), dt(1978,1,1)],
        17:[dt(1978,1,1), dt(1979,1,1)],
        18:[dt(1979,1,1), dt(1980,1,1)],
        19:[dt(1980,1,1), dt(1981,7,1)],
        20:[dt(1981,7,1), dt(1982,7,1)],
        21:[dt(1982,7,1), dt(1983,7,1)],
        22:[dt(1983,7,1), dt(1985,7,1)],
        23:[dt(1985,7,1), dt(1988,1,1)],
        24:[dt(1988,1,1), dt(1990,1,1)],
        25:[dt(1990,1,1), dt(1991,1,1)],
        26:[dt(1991,1,1), dt(1992,7,1)],
        27:[dt(1992,7,1), dt(1993,7,1)],
        28:[dt(1993,7,1), dt(1994,7,1)],
        29:[dt(1994,7,1), dt(1996,1,1)],
        30:[dt(1996,1,1), dt(1997,7,1)],
        31:[dt(1997,7,1), dt(1999,1,1)],
        32:[dt(1999,1,1), dt(2006,1,1)],
        33:[dt(2006,1,1), dt(2009,1,1)],
        34:[dt(2009,1,1), dt(2012,7,1)],
        35:[dt(2012,7,1), dt(2015,7,1)],
        36:[dt(2015,7,1), dt(2017,1,1)],
        37:[dt(2017,1,1), dt.now() - timedelta(seconds=37)]
        }
        # There have been no further leapseconds since 2017,1,1 at the __date__ of this script
        # which is why the leapseconds end with a dt.now object to valid/relevant timestamp output.
        self.left_color = "\033[1;31m"
        self.right_color = "\033[1;m"

    def run(self):
        """Process arguments and errors"""
        if len(sys.argv[1:]) == 0:
            arg_parse.print_usage()
            arg_parse.exit()
        try:
            if args.unix:
                result, indiv_output, combined_output, reason = self.from_unix_sec()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.umil:
                result, indiv_output, combined_output, reason = self.from_unix_milli()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.wh:
                result, indiv_output, combined_output, reason = self.from_win_64_hex()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.whle:
                result, indiv_output, combined_output, reason = self.from_win_64_hexle()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.chrome:
                result, indiv_output, combined_output, reason = self.from_chrome()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.active:
                result, indiv_output, combined_output, reason = self.from_ad()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.uhbe:
                result, indiv_output, combined_output, reason = self.from_unix_hex_32be()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.uhle:
                result, indiv_output, combined_output, reason = self.from_unix_hex_32le()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.cookie:
                result, indiv_output, combined_output, reason = self.from_cookie()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.oleb:
                result, indiv_output, combined_output, reason = self.from_ole_be()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.olel:
                result, indiv_output, combined_output, reason = self.from_ole_le()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.mac:
                result, indiv_output, combined_output, reason = self.from_mac()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.hfsdec:
                result, indiv_output, combined_output, reason = self.from_hfs_dec()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.hfsbe:
                result, indiv_output, combined_output, reason = self.from_hfs_be()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.hfsle:
                result, indiv_output, combined_output, reason = self.from_hfs_le()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.fat:
                result, indiv_output, combined_output, reason = self.from_fat()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.msdos:
                result, indiv_output, combined_output, reason = self.from_msdos()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.sys:
                result, indiv_output, combined_output, reason = self.from_systime()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.ft:
                result, indiv_output, combined_output, reason = self.from_filetime()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.pr:
                result, indiv_output, combined_output, reason = self.from_prtime()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.auto:
                result, indiv_output, combined_output, reason = self.from_ole_auto()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.ms1904:
                result, indiv_output, combined_output, reason = self.from_ms1904()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.ios:
                result, indiv_output, combined_output, reason = self.from_ios_time()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.sym:
                result, indiv_output, combined_output, reason = self.from_sym_time()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.gps:
                result, indiv_output, combined_output, reason = self.from_gps_time()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.eitime:
                result, indiv_output, combined_output, reason = self.from_eitime()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.bplist:
                result, indiv_output, combined_output, reason = self.from_bplist()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.gsm:
                result, indiv_output, combined_output, reason = self.from_gsm()
                if indiv_output == False:
                    print(reason)
                else:
                    print(indiv_output)
            elif args.timestamp:
                self.to_timestamps()
            elif args.guess:
                self.from_all()
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))

    def to_timestamps(self):
        """Convert provided date to all timestamps"""
        print ('\nConverting Date: ' + timestamp + '\n')
        for func in self.date_funcs:
            func()
        self.timestamp_output()

    def from_unix_sec(self):
        """Convert Unix Seconds value to a date"""
        reason = "[!] Unix seconds timestamp is 10 digits in length"
        try:
            if not (len(unix) == 10) or not (unix.isdigit()):
                self.in_unix_sec = indiv_output = combined_output = False
                pass
            else:
                self.in_unix_sec = dt.utcfromtimestamp(float(unix)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Unix Seconds: " + self.in_unix_sec + " UTC")
                combined_output = str("\033[1;31mUnix Seconds:\t\t\t"  + self.in_unix_sec + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_unix_sec = indiv_output = combined_output = False
        return self.in_unix_sec, indiv_output, combined_output, reason

    def to_unix_sec(self):
        """Convert date to a Unix Seconds value"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_unix_sec = str(int((dt_obj - self.epoch_1970).total_seconds()) - int(dt_tz))
            ts_output = str("Unix Seconds:\t\t\t" + self.out_unix_sec)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_unix_sec = ts_output = False
        return self.out_unix_sec, ts_output

    def from_unix_milli(self):
        """Convert Unix Millisecond value to a date"""
        reason = "[!] Unix milliseconds timestamp is 13 digits in length"
        try:
            if not (len(umil) == 13) or not (umil.isdigit()):
                self.in_unix_milli = indiv_output = combined_output = False
                pass
            else:
                self.in_unix_milli = dt.utcfromtimestamp(float(umil) / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Unix Milliseconds: " + self.in_unix_milli + " UTC")
                combined_output = str("\033[1;31mUnix Milliseconds:\t\t"  + self.in_unix_milli + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_unix_milli = indiv_output = combined_output = False
        return self.in_unix_milli, indiv_output, combined_output, reason

    def to_unix_milli(self):
        """Convert date to a Unix Millisecond value"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_unix_milli = str((int((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))*1000))
            ts_output = str("Unix Milliseconds:\t\t" + self.out_unix_milli)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_unix_milli = ts_output = False
        return self.out_unix_milli, ts_output

    def from_win_64_hex(self):
        """Convert a Windows 64 Hex Big-Endian value to a date"""
        reason = "[!] Windows 64-bit Hex Big-Endian timestamp is 16 hex characters (8 bytes)"
        try:
            if not (len(wh) == 16) or not (all(char in hexdigits for char in wh)):
                self.in_windows_hex_64 = indiv_output = combined_output = False
                pass
            else:
                base10_microseconds = int(wh, 16) / 10
                dt_obj = self.epoch_1601 + timedelta(microseconds=base10_microseconds)
                self.in_windows_hex_64 = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Windows 64-bit Hex BE: " + self.in_windows_hex_64 + " UTC")
                combined_output = str("\033[1;31mWindows 64-bit Hex BE:\t\t"  + self.in_windows_hex_64 + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_windows_hex_64 = indiv_output = combined_output = False
        return self.in_windows_hex_64, indiv_output, combined_output, reason

    def to_win_64_hex(self):
        """Convert a date to a Windows 64 Hex Big-Endian value"""
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
            ts_output = str("Windows 64-bit Hex BE:\t\t" + self.out_windows_hex_64)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_windows_hex_64 = ts_output = False
        return self.out_windows_hex_64, ts_output

    def from_win_64_hexle(self):
        """Convert a Windows 64 Hex Little-Endian value to a date"""
        reason = "[!] Windows 64-bit Hex Little-Endian timestamp is 16 hex characters (8 bytes)"
        try:
            if not (len(whle) == 16) or not (all(char in hexdigits for char in whle)):
                self.in_windows_hex_le = indiv_output = combined_output = False
                pass
            else:
                indiv_output = combined_output = False
                endianness_change, = struct.unpack("<Q", unhexlify(whle))
                converted_time = endianness_change / 10
                try:
                    dt_obj = self.epoch_1601 + timedelta(microseconds=converted_time)
                    self.in_windows_hex_le = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("Windows 64-bit Hex LE: " + self.in_windows_hex_le + " UTC")
                    combined_output = str("\033[1;31mWindows 64-bit Hex LE:\t\t"  + self.in_windows_hex_le + " UTC\033[1;m".format())
                except OverflowError:
                    pass
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_windows_hex_le = indiv_output = combined_output = False
        return self.in_windows_hex_le, indiv_output, combined_output, reason

    def to_win_64_hexle(self):
        """Convert a date to a Windows 64 Hex Little-Endian value"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            minus_epoch = dt_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + ((minus_epoch.seconds - int(dt_tz)) * 1000000) + (minus_epoch.days * 86400000000)
            self.out_windows_hex_le = str(struct.pack("<Q", int(calculated_time*10)).hex())[2:].zfill(16)
            ts_output = str("Windows 64-bit Hex LE:\t\t" + self.out_windows_hex_le)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_windows_hex_le = ts_output = False
        return self.out_windows_hex_le, ts_output

    def from_chrome(self):
        """Convert a Chrome Timestamp/Webkit Value to a date"""
        reason = "[!] Chrome/Webkit timestamp is 17 digits"
        try:
            if not (len(chrome) == 17) or not (chrome.isdigit()):
                self.in_chrome = indiv_output = combined_output = False
                pass
            else:
                delta = timedelta(microseconds=int(chrome))
                converted_time = self.epoch_1601 + delta
                self.in_chrome = converted_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Google Chrome Time: " + self.in_chrome + " UTC")
                combined_output = str("\033[1;31mGoogle Chrome:\t\t\t"  + self.in_chrome + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_chrome = indiv_output = combined_output = False
        return self.in_chrome, indiv_output, combined_output, reason

    def to_chrome(self):
        """Convert a date to a Chrome Timestamp/Webkit value"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            chrome_time = ((dt_obj - self.epoch_1601).total_seconds() - int(dt_tz))* 1000000
            self.out_chrome = str(int(chrome_time))
            ts_output = str("Google Chrome:\t\t\t" + self.out_chrome)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_chrome = ts_output = False
        return self.out_chrome, ts_output

    def from_ad(self):
        """Convert an Active Directory/LDAP timestamp to a date"""
        reason = "[!] Active Directory/LDAP timestamps are 18 digits"
        try:
            if not (len(active) == 18) or not (active.isdigit()):
                self.in_ad = indiv_output = combined_output = False
                pass
            else:
                dt_obj = dt.utcfromtimestamp((float(active) - self.epoch_active) / self.hundreds_nano)
                self.in_ad = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Active Directory Timestamp: " + self.in_ad + " UTC")
                combined_output = str("\033[1;31mActive Directory/LDAP dt:\t"  + self.in_ad + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ad = indiv_output = combined_output = False
        return self.in_ad, indiv_output, combined_output, reason

    def to_ad(self):
        """Convert a date to an Active Directory/LDAP timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            tz_shift = int((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))
            self.out_adtime = str(int(tz_shift * self.hundreds_nano + self.epoch_active))
            ts_output = str("Active Directory/LDAP dt:\t" + self.out_adtime)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_adtime = ts_output = False
        return self.out_adtime, ts_output

    def from_unix_hex_32be(self):
        """Convert a Unix Hex 32-bit Big-Endian timestamp to a date"""
        reason = "[!] Unix Hex 32-bit Big-Endian timestamps are 8 hex characters (4 bytes)"
        try:
            if not (len(uhbe) == 8) or not (all(char in hexdigits for char in uhbe)):
                self.in_unix_hex_32 = indiv_output = combined_output = False
                pass
            else:
                to_dec = int(uhbe, 16)
                self.in_unix_hex_32 = dt.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Unix Hex 32-bit BE: " + self.in_unix_hex_32 + " UTC")
                combined_output = str("\033[1;31mUnix Hex 32-bit BE:\t\t" + self.in_unix_hex_32 + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_unix_hex_32 = indiv_output = combined_output = False
        return self.in_unix_hex_32, indiv_output, combined_output, reason

    def to_unix_hex_32be(self):
        """Convert a date to a Unix Hex 32-bit Big-Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            unix_time = int((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))
            self.out_unix_hex_32 = str(struct.pack(">L", unix_time).hex())
            ts_output = str("Unix Hex 32-bit BE:\t\t" + self.out_unix_hex_32)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_unix_hex_32 = ts_output = False
        return self.out_unix_hex_32, ts_output

    def from_unix_hex_32le(self):
        """Convert a Unix Hex 32-bit Little-Endian timestamp to a date"""
        reason = "[!] Unix Hex 32-bit Little-Endian timestamps are 8 hex characters (4 bytes)"
        try:
            if not (len(uhle) == 8) or not (all(char in hexdigits for char in uhle)):
                self.in_unix_hex_32le = indiv_output = combined_output = False
                pass
            else:
                to_dec = struct.unpack("<L", unhexlify(uhle))[0]
                self.in_unix_hex_32le = dt.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Unix Hex 32-bit LE: " + self.in_unix_hex_32le + " UTC")
                combined_output = str("\033[1;31mUnix Hex 32-bit LE:\t\t"  + self.in_unix_hex_32le + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_unix_hex_32le = indiv_output = combined_output = False
        return self.in_unix_hex_32le, indiv_output, combined_output, reason

    def to_unix_hex_32le(self):
        """Convert a date to a Unix Hex 32-bit Little-Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            unix_time = int((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))
            self.out_unix_hex_32le = str(struct.pack("<L", unix_time).hex())
            ts_output = str("Unix Hex 32-bit LE:\t\t" + self.out_unix_hex_32le)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_unix_hex_32le = ts_output = False
        return self.out_unix_hex_32le, ts_output

    def from_cookie(self):
        """Convert an Internet Explorer timestamp to a date"""
        reason = "[!] Internet Explorer Cookie timestamps (txt cookies) consist of 2 integers values. Must be input with a comma between them."
        try:
            if not ("," in cookie) or not (cookie.split(",")[0].isdigit() and cookie.split(",")[1].isdigit()):
                self.in_cookie = indiv_output = combined_output = False
                pass
            else:
                low, high = [int(h, base=10) for h in cookie.split(',')]
                calc = 10**-7 * (high * 2**32 + low) - 11644473600
                dt_obj = dt.utcfromtimestamp(calc)
                self.in_cookie = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Windows Cookie Date: " + self.in_cookie + " UTC")
                combined_output = str("\033[1;31mWindows Cookie Date:\t\t"  + self.in_cookie + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_cookie = indiv_output = combined_output = False
        return self.in_cookie, indiv_output, combined_output, reason

    def to_cookie(self):
        """Convert a date to Internet Explorer timestamp values"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            unix = int((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz))
            high = int(((unix + 11644473600) * 10**7) / 2**32)
            low = int((unix + 11644473600) * 10**7) - (high * 2**32)
            self.out_cookie = str(low) + ',' + str(high)
            ts_output = str("Windows Cookie Date:\t\t" + self.out_cookie)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_cookie = ts_output = False
        return self.out_cookie, ts_output

    def from_ole_be(self):
        """Convert an OLE Big-Endian timestamp to a date"""
        reason = "[!] OLE Big-Endian timestamps are 16 hex characters (8 bytes)"
        try:
            if not (len(oleb) == 16) or not (all(char in hexdigits for char in oleb)):
                self.in_ole_be = indiv_output = combined_output = False
                pass
            else:
                delta = struct.unpack('>d', struct.pack('>Q', int(oleb, 16)))[0]
                dt_obj = self.epoch_1899 + timedelta(days=delta)
                self.in_ole_be = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Windows OLE 64-bit double BE: " + self.in_ole_be + " UTC")
                combined_output = str("\033[1;31mWindows OLE 64-bit double BE:\t"  + self.in_ole_be + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ole_be = indiv_output = combined_output = False
        return self.in_ole_be, indiv_output, combined_output, reason

    def to_ole_be(self):
        """Convert a date to an OLE Big-Endian timestamp"""
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
            ts_output = str("Windows OLE 64-bit double BE:\t" + self.out_ole_be)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_ole_be = ts_output = False
        return self.out_ole_be, ts_output

    def from_ole_le(self):
        """Convert an OLE Little-Endian timestamp to a date"""
        reason = "[!] OLE Little-Endian timestamps are 16 hex characters (8 bytes)"
        try:
            if not (len(olel) == 16) or not (all(char in hexdigits for char in olel)):
                self.in_ole_le = indiv_output = combined_output = False
                pass
            else:
                to_le = hexlify(struct.pack('<Q', int(olel, 16)))
                delta = struct.unpack('>d', struct.pack('>Q', int(to_le, 16)))[0]
                dt_obj = self.epoch_1899 + timedelta(days=delta)
                self.in_ole_le = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Windows OLE 64-bit double LE: " + self.in_ole_le + " UTC")
                combined_output = str("\033[1;31mWindows OLE 64-bit double LE:\t"  + self.in_ole_le + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ole_le = indiv_output = combined_output = False
        return self.in_ole_le, indiv_output, combined_output, reason

    def to_ole_le(self):
        """Convert a date to an OLE Little-Endian timestamp"""
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
            ts_output = str("Windows OLE 64-bit double LE:\t" + self.out_ole_le)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_ole_le = ts_output = False
        return self.out_ole_le, ts_output

    def from_mac(self):
        """Convert a Mac Absolute timestamp to a date - Also used for Safari plist timestamps"""
        reason = "[!] Mac Absolute timestamps are 9 digits, commonly followed by a decimal and up to 6 digits for milliseconds"
        try:
            if not ("." in mac) or not ((len(mac.split(".")[0]) == 9) and (len(mac.split(".")[1]) in range(0,7))) or not (''.join(mac.split(".")).isdigit()):
                self.in_mac = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_2001 + timedelta(seconds=float(mac))
                self.in_mac = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Mac Absolute Time: " + self.in_mac + " UTC")
                combined_output = str("\033[1;31mMac Absolute Time:\t\t"  + self.in_mac + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_mac = indiv_output = combined_output = False
        return self.in_mac, indiv_output, combined_output, reason

    def to_mac(self):
        """Convert a date to a Mac Absolute timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_mac = str(int((dt_obj - self.epoch_2001).total_seconds() - int(dt_tz)))
            ts_output = str("Mac Absolute Time:\t\t" + self.out_mac)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_mac = ts_output = False
        return self.out_mac, ts_output

    def from_hfs_dec(self):
        """Convert a Mac OS/HFS+ Decimal Timestamp to a date"""
        reason = "[!] Mac OS/HFS+ Decimal timestamps are 10 digits"
        try:
            if not (len(hfsdec) == 10) or not (hfsdec.isdigit()) or not (int(hfsdec) >= 2082844800):
                self.in_hfs_dec = indiv_output = combined_output = False
                pass
            else:
                self.in_hfs_dec = dt.utcfromtimestamp(float(int(hfsdec) - self.hfs_dec_subtract)).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Mac OS/HFS+ Decimal Date: " + self.in_hfs_dec + " UTC")
                combined_output = str("\033[1;31mMac OS/HFS+ Decimal Time:\t"  + self.in_hfs_dec + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_hfs_dec = indiv_output = combined_output = False
        return self.in_hfs_dec, indiv_output, combined_output, reason

    def to_hfs_dec(self):
        """Convert a date to a Mac OS/HFS+ Decimal Timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_hfs_dec = str(int((dt_obj - self.epoch_1904).total_seconds() - int(dt_tz)))
            ts_output = str("Mac OS/HFS+ Decimal Time:\t" + self.out_hfs_dec)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_hfs_dec = ts_output = False
        return self.out_hfs_dec, ts_output

    def from_hfs_be(self):
        """Convert an HFS/HFS+ Big-Endian timestamp to a date (HFS+ is in UTC)"""
        reason = "[!] HFS/HFS+ Big-Endian timestamps are 8 hex characters (4 bytes)"
        try:
            if not (len(hfsbe) == 8) or not (all(char in hexdigits for char in hfsbe)):
                self.in_hfs_be = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_1904 + timedelta(seconds=int(hfsbe, 16))
                self.in_hfs_be = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("HFS/HFS+ 32-bit Hex BE: " + self.in_hfs_be + " HFS Local / HFS+ UTC")
                combined_output = str("\033[1;31mHFS/HFS+ 32-bit Hex BE:\t\t"  + self.in_hfs_be + " HFS Local / HFS+ UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_hfs_be = indiv_output = combined_output = False
        return self.in_hfs_be, indiv_output, combined_output, reason

    def to_hfs_be(self):
        """Convert a date to an HFS/HFS+ Big-Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            conv = int((dt_obj - self.epoch_1904).total_seconds() - int(dt_tz))
            self.out_hfs_be = '{0:08x}'.format(conv)
            ts_output = str("HFS/HFS+ 32-bit Hex BE:\t\t" + self.out_hfs_be)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_hfs_be = ts_output = False
        return self.out_hfs_be, ts_output

    def from_hfs_le(self):
        """Convert an HFS/HFS+ Little-Endian timestamp to a date (HFS+ is in UTC)"""
        reason = "[!] HFS/HFS+ Little-Endian timestamps are 8 hex characters (4 bytes)"
        try:
            if not (len(hfsle) == 8) or not (all(char in hexdigits for char in hfsle)):
                self.in_hfs_le = indiv_output = combined_output = False
                pass
            else:
                to_le = struct.unpack('>I', struct.pack('<I', int(hfsle, 16)))[0]
                dt_obj = self.epoch_1904 + timedelta(seconds=to_le)
                self.in_hfs_le = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("HFS/HFS+ 32 big Hex LE: " + self.in_hfs_le + " HFS Local / HFS+ UTC")
                combined_output = str("\033[1;31mHFS/HFS+ 32-bit Hex LE:\t\t"  + self.in_hfs_le + " HFS Local / HFS+ UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_hfs_le = indiv_output = combined_output = False
        return self.in_hfs_le, indiv_output, combined_output, reason

    def to_hfs_le(self):
        """Convert a date to an HFS/HFS+ Little-Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            conv = int((dt_obj - self.epoch_1904).total_seconds() - int(dt_tz))
            self.out_hfs_le = str(struct.pack('<I', conv).hex())
            ts_output = str("HFS/HFS+ 32-bit Hex LE:\t\t" + self.out_hfs_le)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_hfs_le = ts_output = False
        return self.out_hfs_le, ts_output

    def from_fat(self):
        """Convert an MS-DOS wFatDate wFatTime timestamp to a date"""
        reason = "[!] MS-DOS wFatDate wFatTime timestamps are 8 hex characters (4 bytes)"
        try:
            if not (len(fat) == 8) or not (all(char in hexdigits for char in fat)):
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
                stamp[0] = stamp[0] + 1980
                stamp[5] = stamp[5] * 2
                dt_obj = dt(stamp[0], stamp[1], stamp[2], stamp[3], stamp[4], stamp[5])
                self.in_fat = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("FAT Date + Time: " + self.in_fat + " Local")
                combined_output = str("\033[1;31mFAT Date + Time:\t\t"  + self.in_fat + " Local\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_fat = indiv_output = combined_output = False
        return self.in_fat, indiv_output, combined_output, reason

    def to_fat(self):
        """Convert a date to an MS-DOS wFatDate wFatTime timestamp"""
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
            ts_output = str("FAT Date + Time:\t\t" + self.out_fat)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_fat = ts_output = False
        return self.out_fat, ts_output

    def from_msdos(self):
        """Convert an MS-DOS timestamp to a date"""
        reason = "[!] MS-DOS 32-bit timestamps are 8 hex characters (4 bytes)"
        try:
            if not (len(msdos) == 8) or not (all(char in hexdigits for char in msdos)):
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
                stamp[0] = stamp[0] + 1980
                stamp[5] = stamp[5] * 2
                dt_obj = dt(stamp[0], stamp[1], stamp[2], stamp[3], stamp[4], stamp[5])
                self.in_msdos = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("MS-DOS 32-bit Hex Value: " + self.in_msdos + " Local")
                combined_output = str("\033[1;31mMS-DOS 32-bit Hex Value:\t"  + self.in_msdos + " Local\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_msdos = indiv_output = combined_output = False
        return self.in_msdos, indiv_output, combined_output, reason

    def to_msdos(self):
        """Convert a date to an MS-DOS timestamp"""
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
            ts_output = str("MS-DOS 32-bit Hex Value:\t" + self.out_msdos)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_msdos = ts_output = False
        return self.out_msdos, ts_output

    def from_systime(self):
        """Convert a Microsoft 128-bit SYSTEMTIME timestamp to a date"""
        reason = "[!] Microsoft 128-bit SYSTEMTIME timestamps are 32 hex characters (16 bytes)"
        try:
            if not (len(systime) == 32) or not (all(char in hexdigits for char in systime)):
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
                indiv_output = str("Microsoft 128-bit SYSTEMTIME: " + self.in_systemtime + " UTC")
                combined_output = str("\033[1;31mMicrosoft 128-bit SYSTEMTIME:\t"  + self.in_systemtime + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_systemtime = indiv_output = combined_output = False
        return self.in_systemtime, indiv_output, combined_output, reason

    def to_systime(self):
        """Convert a date to a Microsoft 128-bit SYSTEMTIME timestamp"""
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
            ts_output = str("Microsoft 128-bit SYSTEMTIME:\t" + self.out_systemtime)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_systemtime = ts_output = False
        return self.out_systemtime, ts_output

    def from_filetime(self):
        """Convert a Microsoft FILETIME timestamp to a date"""
        reason = "[!] Microsoft FILETIME timestamps are 2 sets of 8 hex characters (4 bytes), separated by a colon"
        try:
            if not (":" in ft) or not (all(char in hexdigits for char in ft[0:8]) and all(char in hexdigits for char in ft[9:])):
                self.in_filetime = indiv_output = combined_output = False
                pass
            else:
                part2, part1 = [int(h, base=16) for h in ft.split(':')]
                converted_time = struct.unpack('>Q', struct.pack('>LL', part1, part2))[0]
                dt_obj = dt.utcfromtimestamp(float(converted_time - self.epoch_active) / self.hundreds_nano)
                self.in_filetime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Microsoft FILETIME time: " + self.in_filetime + " UTC")
                combined_output = str("\033[1;31mMicrosoft FILETIME time:\t"  + self.in_filetime + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_filetime = indiv_output = combined_output = False
        return self.in_filetime, indiv_output, combined_output, reason

    def to_filetime(self):
        """Convert a date to a Microsoft FILETIME timestamp"""
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
            ts_output = str("Microsoft FILETIME time:\t" + self.out_filetime)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_filetime = ts_output = False
        return self.out_filetime, ts_output

    def from_prtime(self):
        """Convert a Mozilla PRTime timestamp to a date"""
        reason = "[!] Mozilla PRTime timestamps are 16 digits"
        try:
            if not (len(pr) == 16) or not (pr.isdigit()):
                self.in_prtime = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_1970 + timedelta(microseconds=int(pr))
                self.in_prtime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Mozilla PRTime: " + self.in_prtime + " UTC")
                combined_output = str("\033[1;31mMozilla PRTime:\t\t\t"  + self.in_prtime + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_prtime = indiv_output = combined_output = False
        return self.in_prtime, indiv_output, combined_output, reason

    def to_prtime(self):
        """Convert a date to Mozilla's PRTime timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_prtime = str(int(((dt_obj - self.epoch_1970).total_seconds() - int(dt_tz)) * 1000000))
            ts_output = str("Mozilla PRTime:\t\t\t" + self.out_prtime)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_prtime = ts_output = False
        return self.out_prtime, ts_output

    def from_ole_auto(self):
        """Convert an OLE Automation timestamp to a date"""
        reason = "[!] OLE Automation timestamps are 2 integers, separated by a dot. The left is 5 digits, the right is between 9-12 digits"
        try:
            if not ("." in auto) or not ((len(auto.split(".")[0]) == 5) and (len(auto.split(".")[1]) in range(9,13))) or not (''.join(auto.split(".")).isdigit()):
                self.in_ole_auto = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_1899 + timedelta(days=float(auto))
                self.in_ole_auto = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("OLE Automation Date: " + self.in_ole_auto + " UTC")
                combined_output = str("\033[1;31mOLE Automation Date:\t\t"  + self.in_ole_auto + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ole_auto = indiv_output = combined_output = False
        return self.in_ole_auto, indiv_output, combined_output, reason

    def to_ole_auto(self):
        """Convert a date to an OLE Automation timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_ole_auto = "{0:.12f}".format(((dt_obj - self.epoch_1899).total_seconds() - int(dt_tz)) / 86400)
            ts_output = str("OLE Automation Date:\t\t" + self.out_ole_auto)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_ole_auto = ts_output = False
        return self.out_ole_auto, ts_output

    def from_ms1904(self):
        """Convert a Microsoft Excel 1904 timestamp to a date"""
        reason = "[!] Microsoft Excel 1904 timestamps are 2 integers, separated by a dot. The left is 5 digits, the right is between 9-12 digits"
        try:
            if not ("." in ms1904) or not ((len(ms1904.split(".")[0]) == 5) and (len(ms1904.split(".")[1]) in range(9,13))) or not (''.join(ms1904.split(".")).isdigit()):
                self.in_ms1904 = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_1904 + timedelta(days=float(ms1904))
                self.in_ms1904 = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("MS Excel 1904 Date: " + self.in_ms1904 + " UTC")
                combined_output = str("\033[1;31mMS Excel 1904 Date:\t\t" + self.in_ms1904 + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_ms1904 = indiv_output = combined_output = False
        return self.in_ms1904, indiv_output, combined_output, reason

    def to_ms1904(self):
        """Convert a date to a Microsoft Excel 1904 timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_ms1904 = "{0:.12f}".format(((dt_obj - self.epoch_1904).total_seconds() - int(dt_tz)) / 86400)
            ts_output = str("MS Excel 1904 Date:\t\t" + self.out_ms1904)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_ms1904 = ts_output = False
        return self.out_ms1904, ts_output

    def from_ios_time(self):
        """Convert an iOS 11 timestamp to a date"""
        reason = "[!] iOS 11 timestamps are typically 15-18 digits"
        try:
            if not (len(ios) in range(15,19)) or not (ios.isdigit()):
                self.in_iostime = indiv_output = combined_output = False
                pass
            else:
                dt_obj = (int(ios) / int(self.nano_2001)) + 978307200
                self.in_iostime = dt.utcfromtimestamp(dt_obj).strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("iOS 11 Date: " + self.in_iostime + " UTC")
                combined_output = str("\033[1;31miOS 11 Date:\t\t\t"  + self.in_iostime + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_iostime = indiv_output = combined_output = False
        return self.in_iostime, indiv_output, combined_output, reason

    def to_ios_time(self):
        """Convert a date to an iOS 11 timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_iostime = str(int(((dt_obj - self.epoch_2001).total_seconds() - int(dt_tz)) * self.nano_2001))
            ts_output = str("iOS 11 Date:\t\t\t" + self.out_iostime)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_iostime = ts_output = False
        return self.out_iostime, ts_output

    def from_sym_time(self):
        """Convert a Symantec 6-byte hex timestamp to a date"""
        reason = "[!] Symantec 6-byte hex timestamps are 12 hex characters"
        try:
            if not (len(sym) == 12) or not (all(char in hexdigits for char in sym)):
                self.in_symtime = indiv_output = combined_output = False
                pass
            else:
                hex_to_dec = [int(sym[i:i+2], 16) for i in range(0, len(sym), 2)]
                hex_to_dec[0] = hex_to_dec[0] + 1970
                hex_to_dec[1] = hex_to_dec[1] + 1
                dt_obj = dt(hex_to_dec[0], hex_to_dec[1], hex_to_dec[2], hex_to_dec[3], hex_to_dec[4], hex_to_dec[5])
                self.in_symtime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("Symantec AV Timestamp: " + self.in_symtime)
                combined_output = str("\033[1;31mSymantec AV timestamp:\t\t"  + self.in_symtime + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_symtime = indiv_output = combined_output = False
        return self.in_symtime, indiv_output, combined_output, reason

    def to_sym_time(self):
        """Convert a date to Symantec's 6-byte hex timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            sym_year = '{0:x}'.format(dt_obj.year - 1970).zfill(2)
            sym_month = '{0:x}'.format(dt_obj.month - 1).zfill(2)
            sym_day = '{0:x}'.format(dt_obj.day).zfill(2)
            sym_hour = '{0:x}'.format(dt_obj.hour).zfill(2)
            sym_minute = '{0:x}'.format(dt_obj.minute).zfill(2)
            sym_second = '{0:x}'.format(dt_obj.second).zfill(2)
            self.out_symtime = sym_year + sym_month + sym_day + sym_hour + sym_minute + sym_second
            ts_output = str("Symantec AV time:\t\t" + self.out_symtime)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_symtime = ts_output = False
        return self.out_symtime, ts_output

    def date_range(self, start, end, check_date):
        """Check if date is in range of start and end, return True if it is"""
        if start <= end:
            return start <= check_date <= end
        else:
            return start <= check_date or check_date <= end

    def from_gps_time(self):
        """Convert a GPS timestamp to a date (involves leap seconds)"""
        reason = "[!] GPS timestamps are 10 digits"
        try:
            if not (len(gps) == 10) or not (gps.isdigit()):
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
                    if check == True:
                        variance = entry
                    else:
                        variance = 0
                gps_out = check_date - timedelta(seconds=variance)
                self.in_gpstime = gps_out.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("GPS Timestamp: " + self.in_gpstime)
                combined_output = str("\033[1;31mGPS timestamp:\t\t\t"  + self.in_gpstime + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_gpstime = indiv_output = combined_output = False
        return self.in_gpstime, indiv_output, combined_output, reason

    def to_gps_time(self):
        """Convert a date to a GPS timestamp (involves leap seconds)"""
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
                if check == True:
                    variance = entry
                else:
                    variance = 0
            leap_correction = check_date + timedelta(seconds=variance)
            epoch_shift = leap_correction - self.epoch_1970
            gps_stamp = (dt.utcfromtimestamp(epoch_shift.total_seconds()) - self.epoch_1980).total_seconds() - 19
            gps_stamp = int(gps_stamp) - int(dt_tz)
            self.out_gpstime = str(gps_stamp)
            ts_output = str("GPS time:\t\t\t" + self.out_gpstime)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_gpstime = ts_output = False
        return self.out_gpstime, ts_output

    def from_eitime(self):
        """Convert a Google ei URL timestamp"""
        reason = "[!] Google ei URL timestamps contain only URL-safe base64 characters: [A-Z][a-z][0-9][=-_]"
        try:
            urlsafe_chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_'
            if not (all(char in urlsafe_chars for char in eitime)):
                self.in_eitime = indiv_output = combined_output = False
                pass
            else:
                padding_check = (len(eitime)%4)
                if padding_check != 0:
                    padding_reqd = (4 - padding_check)
                    result_eitime = eitime + (padding_reqd * '=')
                else:
                    result_eitime = eitime
                try:
                    decoded_eitime = base64.urlsafe_b64decode(result_eitime).hex()[:8]
                    unix_timestamp, = struct.unpack("<L", unhexlify(decoded_eitime))
                    self.in_eitime = dt.utcfromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
                    indiv_output = str("Google URL EI Timestamp: " + self.in_eitime)
                    combined_output = str("\033[1;31mGoogle EI URL timestamp:\t" + self.in_eitime + " UTC\033[1;m".format())
                except base64.binascii.Error as e:
                    self.in_eitime = indiv_output = combined_output = False
                    pass
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_eitime = indiv_output = combined_output = False
        return self.in_eitime, indiv_output, combined_output, reason

    def to_eitime(self):
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
            ts_output = str("Google EI time:\t\t\t" + self.out_eitime)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_eitime = ts_output = False
        return self.out_eitime, ts_output

    def from_bplist(self):
        """Convert a Binary Plist timestamp to a date"""
        reason = "[!] Binary Plist timestamps are 9 digits"
        try:
            if not (len(bplist) == 9) or not (bplist.isdigit()):
                self.in_bplist = indiv_output = combined_output = False
                pass
            else:
                dt_obj = self.epoch_2001 + timedelta(seconds=float(bplist))
                self.in_bplist = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
                indiv_output = str("iOS Binary Plist Timestamp: " + self.in_bplist)
                combined_output = str("\033[1;31miOS Binary Plist timestamp:\t" + self.in_bplist + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_bplist = indiv_output = combined_output = False
        return self.in_bplist, indiv_output, combined_output, reason

    def to_bplist(self):
        """Convert a date to a Binary Plist timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            if hasattr(dt_obj.tzinfo, '_offset'):
                dt_tz = dt_obj.tzinfo._offset.total_seconds()
                dt_obj = duparser.parse(timestamp, ignoretz=True)
            else:
                dt_tz = 0
            self.out_bplist = str(int((dt_obj - self.epoch_2001).total_seconds()) - int(dt_tz))
            ts_output = str("iOS Binary Plist time:\t\t" + self.out_bplist)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_bplist = ts_output = False
        return self.out_bplist, ts_output

    def from_gsm(self):
        """Convert a GSM timestamp to a date"""
        reason = "[!] GSM timestamps are 14 hex characters (7 bytes)"
        try:
            # The last byte of the GSM timestamp is a hex representation of the timezone.
            # If the timezone bitwise operation on this byte results in a timezone offset
            # of less than -12 or greater than 12, then the value is incorrect.
            # The values in tz_in_range are hex bytes which return proper timezones.
            tz_in_range = ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8']
            tz_check = gsm[12:14][::-1].lower()
            if not (len(gsm) == 14) or not (all(char in hexdigits for char in gsm)) or not (tz_check in tz_in_range):
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
                if dt_year in range(0, 20):
                    dt_year = dt_year + 2000
                if dt_tz == 0:
                    dt_tz = " UTC"
                elif dt_tz > 0:
                    dt_tz = " UTC+" + str(dt_tz)
                else:
                    dt_tz = " UTC" + str(dt_tz)
                self.in_gsm = str((dt(dt_year, dt_month, dt_day, dt_hour, dt_min, dt_sec).strftime('%Y-%m-%d %H:%M:%S.%f')) + dt_tz)
                indiv_output = str("GSM Timestamp: " + self.in_gsm)
                combined_output = str("\033[1;31mGSM Timestamp:\t\t\t"  + self.in_gsm + " UTC\033[1;m".format())
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.in_gsm = indiv_output = combined_output = False
        return self.in_gsm, indiv_output, combined_output, reason

    def to_gsm(self):
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
                hex_tz = hex(int((high_order + low_order),2)).lstrip('0x').upper()
            else:
                dt_tz = dt_tz / 3600
                conversion = str(int(dt_tz) *4)
                conversion_list = []
                for char in range(len(conversion)):
                    conversion_list.append(conversion[char])
                high_order = '{0:04b}'.format(int(conversion_list[0]))
                low_order = '{0:04b}'.format(int(conversion_list[1]))
                hex_tz = hex(int((high_order + low_order),2)).lstrip('0x').upper()
            date_list = [str(dt_obj.year - 2000), '{:02d}'.format(dt_obj.month), '{:02d}'.format(dt_obj.day), '{:02d}'.format(dt_obj.hour), '{:02d}'.format(dt_obj.minute), '{:02d}'.format(dt_obj.second), hex_tz]
            date_value_swap = []
            for value in date_list[:]:
                be = value[::-1]
                date_value_swap.append(be)
            self.out_gsm = ''.join(date_value_swap)
            ts_output = str("GSM time:\t\t\t" + self.out_gsm)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(str(exc_type) + " - " + str(exc_obj) + " - line " + str(exc_tb.tb_lineno))
            self.out_gsm = ts_output = False
        return self.out_gsm, ts_output

    def from_all(self):
        """Output all processed timestamp values"""
        """Find date from provided timestamp"""
        this_year = int(dt.now().strftime('%Y'))
        states = []
        inputs = (self.in_unix_sec, self.in_unix_milli, self.in_windows_hex_64, self.in_windows_hex_le, self.in_chrome, self.in_ad, self.in_unix_hex_32, self.in_unix_hex_32le, self.in_cookie, self.in_ole_be, self.in_ole_le, self.in_mac, self.in_hfs_dec, self.in_hfs_be, self.in_hfs_le, self.in_msdos, self.in_fat, self.in_systemtime, self.in_filetime, self.in_prtime, self.in_ole_auto, self.in_ms1904, self.in_iostime, self.in_symtime, self.in_gpstime, self.in_eitime, self.in_bplist, self.in_gsm)
        print ('\nGuessing Date from Timestamp: ' + sys.argv[2] + '\r')
        print ('Outputs which do not result in a date/time value are not displayed.\r')
        print ('\033[1;31mMost likely results (results within +/- 5 years) are highlighted.\n\033[1;m'.format())
        for func in self.ts_funcs:
            result, indiv_output, combined_output, reason = func()
            states.append(result)
            if isinstance(result, str):
                if int(duparser.parse(result).strftime('%Y')) in range(this_year -5, this_year +5):
                    print(combined_output)
                else:
                    print(combined_output.strip(self.left_color).strip(self.right_color))
        if all([ state == False for state in states ]) :
            print ('No valid dates found. Check your input and try again.')
        print ('\r')

    def timestamp_output(self):
        """Output all processed dates from timestamp values"""
        for func in self.date_funcs:
            result, ts_output = func()
            if isinstance(result, str):
                print(ts_output)
        print('\r')

if __name__ == '__main__':
    now = dt.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    arg_parse = argparse.ArgumentParser(description='Time Decoder and Converter')
    arg_parse.add_argument('--unix', metavar='<value>', help='convert from Unix Seconds')
    arg_parse.add_argument('--umil', metavar='<value>', help='convert from Unix Milliseconds')
    arg_parse.add_argument('--wh', metavar='<value>', help='convert from Windows 64-bit Hex BE')
    arg_parse.add_argument('--whle', metavar='<value>', help='convert from Windows 64-bit Hex LE')
    arg_parse.add_argument('--chrome', metavar='<value>', help='convert from Google Chrome time')
    arg_parse.add_argument('--active', metavar='<value>', help='convert from Active Directory value')
    arg_parse.add_argument('--uhbe', metavar='<value>', help='convert from Unix Hex 32-bit BE')
    arg_parse.add_argument('--uhle', metavar='<value>', help='convert from Unix Hex 32-bit LE')
    arg_parse.add_argument('--cookie', metavar='<value>', help='convert from Windows Cookie Date (Low Value,High Value)')
    arg_parse.add_argument('--oleb', metavar='<value>', help='convert from Windows OLE 64-bit BE - remove 0x and spaces! Example from SRUM: 0x40e33f5d 0x97dfe8fb should be 40e33f5d97dfe8fb')
    arg_parse.add_argument('--olel', metavar='<value>', help='convert from Windows OLE 64-bit LE')
    arg_parse.add_argument('--mac', metavar='<value>', help='convert from Mac Absolute Time')
    arg_parse.add_argument('--hfsdec', metavar='<value>', help='convert from Mac OS/HFS+ Decimal Time')
    arg_parse.add_argument('--hfsbe', metavar='<value>', help='convert from HFS(+) BE times (HFS = Local, HFS+ = UTC)')
    arg_parse.add_argument('--hfsle', metavar='<value>', help='convert from HFS(+) LE times (HFS = Local, HFS+ = UTC)')
    arg_parse.add_argument('--fat', metavar='<value>', help='convert from FAT Date + Time (wFat)')
    arg_parse.add_argument('--msdos', metavar='<value>', help='convert from 32-bit MS-DOS time - result is Local Time')
    arg_parse.add_argument('--sys', metavar='<value>', help='convert from 128-bit SYSTEMTIME')
    arg_parse.add_argument('--ft', metavar='<value>', help='convert from FILETIME timestamp')
    arg_parse.add_argument('--pr', metavar='<value>', help='convert from Mozilla\'s PRTime')
    arg_parse.add_argument('--auto', metavar='<value>', help='convert from OLE Automation Date format')
    arg_parse.add_argument('--ms1904', metavar='<value>', help='convert from MS Excel 1904 Date format')
    arg_parse.add_argument('--ios', metavar='<value>', help='convert from iOS 11 Timestamp')
    arg_parse.add_argument('--sym', metavar='<value>', help='convert Symantec\'s 12-byte AV Timestamp')
    arg_parse.add_argument('--gps', metavar='<value>', help='convert from a GPS Timestamp')
    arg_parse.add_argument('--eitime', metavar='<value>', help='convert from a Google EI URL Timestamp')
    arg_parse.add_argument('--bplist', metavar='<value>', help='convert from an iOS Binary Plist Timestamp')
    arg_parse.add_argument('--gsm', metavar='<value>', help='convert from a GSM Timestamp')
    arg_parse.add_argument('--guess', metavar='<value>', help='guess timestamp and output all reasonable possibilities')
    arg_parse.add_argument('--timestamp', metavar='DATE', help='convert date to every timestamp - enter date as \"Y-M-D HH:MM:SS.m\" in 24h fmt - without argument gives current date/time', nargs='?', const=now)
    arg_parse.add_argument('--version', '-v', action='version', version='%(prog)s ' +str(__version__))
    args = arg_parse.parse_args()
    guess = args.guess; unix = args.unix; umil = args.umil; wh = args.wh; whle = args.whle; chrome = args.chrome; active = args.active; uhbe = args.uhbe; uhle = args.uhle; cookie = args.cookie; oleb = args.oleb; olel = args.olel; mac = args.mac; hfsdec = args.hfsdec; hfsbe = args.hfsbe; hfsle = args.hfsle; fat = args.fat; msdos = args.msdos; systime = args.sys; ft = args.ft; pr = args.pr; auto = args.auto; ms1904 = args.ms1904; ios = args.ios; sym = args.sym; gps = args.gps; timestamp = args.timestamp; eitime = args.eitime; bplist = args.bplist; gsm = args.gsm
    if args.guess:
        unix = umil = wh = whle = chrome = active = uhbe = uhle = cookie = oleb = olel = mac = hfsdec = hfsbe = hfsle = fat = msdos = systime = ft = pr = auto = ms1904 = ios = sym = gps = eitime = bplist = gsm = guess

    td = TimeDecoder()
    td.run()
