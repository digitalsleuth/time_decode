#!/usr/bin/env python
"""
This application is designed to decode timestamps into human-readable date/times and vice-versa
Additional information regarding the source of the timestamp formats and associated equations
will be provided inline with the docstrings for each module.

GPS Ref: http://www.leapsecond.com/java/gpsclock.htm
Leap Seconds: https://www.nist.gov/pml/time-and-frequency-division/leap-seconds-faqs
              http://hpiers.obspm.fr/eop-pc/index.php?index=TAI-UTC_tab&lang=en
Microsoft 1904 Timestamp: https://docs.microsoft.com/en-us/office/troubleshoot/excel/1900-and-1904-date-system

"""
from datetime import datetime as dt, timedelta
import struct
from binascii import hexlify, unhexlify
import argparse
import sys
from os import environ
from dateutil import parser as duparser
import base64
from colorama import init
init(autoreset=True)

__author__ = 'Corey Forman'
__date__ = '9 Jan 2020'
__version__ = '1.1'
__description__ = 'Python CLI Date Time Conversion Tool'

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
        self.epoch_as_filetime = 116444736000000000
        self.hfs_dec_subtract = 2082844800

        self.in_unix_sec = self.in_unix_milli = self.in_windows_hex_64 = self.in_windows_hex_le = self.in_chrome = self.in_ad = self.in_unix_hex_32 = self.in_unix_hex_32le = self.in_cookie = self.in_ole_be = self.in_ole_le = self.in_mac = self.in_hfs_dec = self.in_hfs_be = self.in_hfs_le = self.in_msdos = self.in_fat = self.in_systemtime = self.in_filetime = self.in_prtime = self.in_ole_auto = self.in_ms1904 = self.in_iostime = self.in_symtime = self.in_gpstime = self.in_eitime = self.in_bplist = None
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
        37:[dt(2017,1,1), dt.now()]
        }

    def run(self):
        """Process arguments and errors"""
        if len(sys.argv[1:]) == 0:
            arg_parse.print_help()
            arg_parse.exit()

        try:
            if args.unix:
                self.from_unix_sec()
                print ("Unix Seconds: " + self.in_unix_sec + " UTC")
            elif args.umil:
                self.from_unix_milli()
                print ("Unix Milliseconds: " + self.in_unix_milli + " UTC")
            elif args.wh:
                self.from_win_64_hex()
                print ("Windows 64 bit Hex BE: " + self.in_windows_hex_64 + " UTC")
            elif args.whle:
                self.from_win_64_hexle()
                print ("Windows 64 bit Hex LE: " + self.in_windows_hex_le + " UTC")
            elif args.goog:
                self.from_chrome()
                print ("Google Chrome Time: " + self.in_chrome + " UTC")
            elif args.active:
                self.from_ad()
                print ("Active Directory Timestamp: " + self.in_ad + " UTC")
            elif args.uhbe:
                self.from_unix_hex_32be()
                print ("Unix Hex 32 bit BE: " + self.in_unix_hex_32 + " UTC")
            elif args.uhle:
                self.from_unix_hex_32le()
                print ("Unix Hex 32 bit LE: " + self.in_unix_hex_32le + " UTC")
            elif args.cookie:
                self.from_cookie()
                print ("Windows Cookie Date: " + self.in_cookie + " UTC")
            elif args.oleb:
                self.from_ole_be()
                print ("Windows OLE 64 bit double BE: " + self.in_ole_be + " UTC")
            elif args.olel:
                self.from_ole_le()
                print ("Windows OLE 64 bit double LE: " + self.in_ole_le + " UTC")
            elif args.mac:
                self.from_mac()
                print ("Mac Absolute Time: " + self.in_mac + " UTC")
            elif args.hfsdec:
                self.from_hfs_dec()
                print ("Mac OS/HFS+ Decimal Date: " + self.in_hfs_dec + " UTC")
            elif args.hfsbe:
                self.from_hfs_be()
                print ("HFS/HFS+ 32 bit Hex BE: " + self.in_hfs_be + " HFS Local / HFS+ UTC")
            elif args.hfsle:
                self.from_hfs_le()
                print ("HFS/HFS+ 32 big Hex LE: " + self.in_hfs_le + " HFS Local / HFS+ UTC")
            elif args.msdos:
                self.from_msdos()
                print ("MS-DOS 32 bit Hex Value: " + self.in_msdos + " Local")
            elif args.fat:
                self.from_fat()
                print ("FAT Date + Time: " + self.in_fat + " Local")
            elif args.sys:
                self.from_systime()
                print ("Microsoft 128 bit SYSTEMTIME: " + self.in_systemtime + " UTC")
            elif args.ft:
                self.from_filetime()
                print ("Microsoft FILETIME/LDAP time: " + self.in_filetime + " UTC")
            elif args.pr:
                self.from_prtime()
                print ("Mozilla PRTime: " + self.in_prtime + " UTC")
            elif args.auto:
                self.from_ole_auto()
                print ("OLE Automation Date: " + self.in_ole_auto + " UTC")
            elif args.ms1904:
                self.from_ms1904()
                print ("MS Excel 1904 Date: " + self.in_ms1904 + " UTC")
            elif args.ios:
                self.from_ios_time()
                print ("iOS 11 Date: " + self.in_iostime)
            elif args.sym:
                self.from_sym_time()
                print ("Symantec AV Timestamp: " + self.in_symtime)
            elif args.gps:
                self.from_gps_time()
                print ("GPS Timestamp: " + self.in_gpstime)
            elif args.eitime:
                self.from_eitime()
                print ("Google URL EI Timestamp: " + self.in_eitime)
            elif args.bplist:
                self.from_bplist()
                print ("iOS Binary Plist Timestamp: " + self.in_bplist)
            elif args.gsm:
                self.from_gsm()
                print ("GSM Timestamp: " + self.in_gsm)
            elif args.timestamp:
                self.to_timestamps()
            elif args.guess:
                self.from_all()
        except Exception as e:
            print(str(type(e)) + "," + str(e))

    def from_all(self):
        """Find date from provided timestamp"""
        print ('\nGuessing Date from Timestamp: ' + sys.argv[2] + '\r')
        print ('Outputs which do not result in a date/time value are not displayed.\r')
        print ('\033[1;31mMost likely results (results within +/- 5 years) are highlighted.\n\033[1;m'.format())
        self.from_unix_sec()
        self.from_unix_milli()
        self.from_win_64_hex()
        self.from_win_64_hexle()
        self.from_chrome()
        self.from_ad()
        self.from_unix_hex_32be()
        self.from_unix_hex_32le()
        self.from_cookie()
        self.from_ole_be()
        self.from_ole_le()
        self.from_mac()
        self.from_hfs_dec()
        self.from_hfs_be()
        self.from_hfs_le()
        self.from_msdos()
        self.from_fat()
        self.from_systime()
        self.from_filetime()
        self.from_prtime()
        self.from_ole_auto()
        self.from_ms1904()
        self.from_ios_time()
        self.from_sym_time()
        self.from_gps_time()
        self.from_eitime()
        self.from_bplist()
        self.from_gsm()
        self.date_output()
        print ('\r')

    def to_timestamps(self):
        """Convert provided date to all timestamps"""
        print ('\nConverting Date: ' + timestamp + '\n')
        self.to_unix_sec()
        self.to_unix_milli()
        self.to_win_64_hex()
        self.to_win_64_hexle()
        self.to_chrome()
        self.to_ad()
        self.to_unix_hex_32be()
        self.to_unix_hex_32le()
        self.to_cookie()
        self.to_ole_be()
        self.to_ole_le()
        self.to_mac()
        self.to_hfs_dec()
        self.to_hfs_be()
        self.to_hfs_le()
        self.to_msdos()
        self.to_fat()
        self.to_systime()
        self.to_filetime()
        self.to_prtime()
        self.to_ole_auto()
        self.to_ms1904()
        self.to_ios_time()
        self.to_sym_time()
        self.to_gps_time()
        self.to_bplist()
        self.to_gsm()
        self.timestamp_output()
        print ('\r')

    def from_unix_sec(self):
        """Convert Unix Seconds value to a date"""
        try:
            self.in_unix_sec = dt.utcfromtimestamp(float(unix)).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_unix_sec = False
        return self.in_unix_sec

    def to_unix_sec(self):
        """Convert date to a Unix Seconds value"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_unix_sec = str(int((dt_obj - self.epoch_1970).total_seconds()))
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_unix_sec = False
        return self.out_unix_sec

    def from_unix_milli(self):
        """Convert Unix Millisecond value to a date"""
        try:
            self.in_unix_milli = dt.utcfromtimestamp(float(umil) / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_unix_milli = False
        return self.in_unix_milli

    def to_unix_milli(self):
        """Convert date to a Unix Millisecond value"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_unix_milli = str(int((dt_obj - self.epoch_1970).total_seconds()*1000))
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_unix_milli = False
        return self.out_unix_milli

    def from_win_64_hex(self):
        """Convert a Windows 64 Hex Big-Endian value to a date"""
        try:
            base10_microseconds = int(wh, 16) / 10
            dt_obj = self.epoch_1601 + timedelta(microseconds=base10_microseconds)
            self.in_windows_hex_64 = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_windows_hex_64 = False
        return self.in_windows_hex_64

    def to_win_64_hex(self):
        """Convert a date to a Windows 64 Hex Big-Endian value"""
        try:
            dt_obj = duparser.parse(timestamp)
            minus_epoch = dt_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
            self.out_windows_hex_64 = str(hex(int(calculated_time)*10))[2:].zfill(16)
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_windows_hex_64 = False
        return self.out_windows_hex_64

    def from_win_64_hexle(self):
        """Convert a Windows 64 Hex Little-Endian value to a date"""
        try:
            converted_time = struct.unpack("<Q", unhexlify(whle))[0]
            dt_obj = self.epoch_1601 + timedelta(microseconds=converted_time /10)
            self.in_windows_hex_le = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_windows_hex_le = False
        return self.in_windows_hex_le

    def to_win_64_hexle(self):
        """Convert a date to a Windows 64 Hex Little-Endian value"""
        try:
            dt_obj = duparser.parse(timestamp)
            minus_epoch = dt_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
            self.out_windows_hex_le = str(hexlify(struct.pack("<Q", int(calculated_time*10))))[2:].zfill(16).strip("'")
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_windows_hex_le = False
        return self.out_windows_hex_le

    def from_chrome(self):
        """Convert a Chrome Timestamp/Webkit Value to a date"""
        try:
            delta = timedelta(microseconds=int(goog))
            converted_time = self.epoch_1601 + delta
            self.in_chrome = converted_time.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_chrome = False
        return self.in_chrome

    def to_chrome(self):
        """Convert a date to a Chrome Timestamp/Webkit value"""
        try:
            dt_obj = duparser.parse(timestamp)
            chrome_time = (dt_obj - self.epoch_1601).total_seconds() * 1000000
            self.out_chrome = str(int(chrome_time))
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_chrome = False
        return self.out_chrome

    def from_ad(self):
        """Convert an Active Directory timestamp to a date"""
        try:
            part2, part1 = [int(h, base=16) for h in active.split(':')]
            converted_time = struct.unpack('>Q', struct.pack('>LL', part1, part2))[0]
            dt_obj = dt.utcfromtimestamp(float(converted_time - self.epoch_as_filetime) / self.hundreds_nano)
            self.in_ad = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_ad = False
        return self.in_ad

    def to_ad(self):
        """Convert a date to an Active Directory timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            minus_epoch = dt_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
            output = hexlify(struct.pack(">Q", int(calculated_time*10)))
            self.out_active_directory_time = str(output[8:]).strip("'b").strip("'") + ":" + str(output[:8]).strip("'b").strip("'")
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_active_directory_time = False
        return self.out_active_directory_time

    def from_unix_hex_32be(self):
        """Convert a Unix Hex 32 bit Big-Endian timestamp to a date"""
        try:
            to_dec = int(uhbe, 16)
            self.in_unix_hex_32 = dt.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_unix_hex_32 = False
        return self.in_unix_hex_32

    def to_unix_hex_32be(self):
        """Convert a date to a Unix Hex 32 bit Big-Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_unix_hex_32 = str(hexlify(struct.pack(">L", int((dt_obj - self.epoch_1970).total_seconds())))).strip("b'").strip("'")
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_unix_hex_32 = False
        return self.out_unix_hex_32

    def from_unix_hex_32le(self):
        """Convert a Unix Hex 32 bit Little-Endian timestamp to a date"""
        try:
            to_dec = struct.unpack("<L", unhexlify(uhle))[0]
            self.in_unix_hex_32le = dt.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_unix_hex_32le = False
        return self.in_unix_hex_32le

    def to_unix_hex_32le(self):
        """Convert a date to a Unix Hex 32 bit Little-Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_unix_hex_32le = str(hexlify(struct.pack("<L", int((dt_obj - self.epoch_1970).total_seconds())))).strip("b'").strip("'")
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_unix_hex_32le = False
        return self.out_unix_hex_32le

    def from_cookie(self):
        """Convert an Internet Explorer timestamp to a date"""
        try:
            low, high = [int(h, base=10) for h in cookie.split(',')]
            calc = 10**-7 * (high * 2**32 + low) - 11644473600
            dt_obj = dt.utcfromtimestamp(calc)
            self.in_cookie = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_cookie = False
        return self.in_cookie

    def to_cookie(self):
        """Convert a date to Internet Explorer timestamp values"""
        try:
            dt_obj = duparser.parse(timestamp)
            unix = int((dt_obj - self.epoch_1970).total_seconds())
            high = int(((unix + 11644473600) * 10**7) / 2**32)
            low = int((unix + 11644473600) * 10**7) - (high * 2**32)
            self.out_cookie = str(low) + ',' + str(high)
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_cookie = False
        return self.out_cookie

    def from_ole_be(self):
        """Convert an OLE Big Endian dimestamp to a date"""
        try:
            delta = struct.unpack('>d', struct.pack('>Q', int(oleb, 16)))[0]
            dt_obj = self.epoch_1899 + timedelta(days=delta)
            self.in_ole_be = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_ole_be = False
        return self.in_ole_be

    def to_ole_be(self):
        """Convert a date to an OLE Big Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            delta = (dt_obj - self.epoch_1899).total_seconds() / 86400
            conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
            self.out_ole_be = str(hexlify(struct.pack('>Q', conv))).strip("b'").strip("'")
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_ole_be = False
        return self.out_ole_be

    def from_ole_le(self):
        """Convert an OLE Little Endian timestamp to a date"""
        try:
            to_le = hexlify(struct.pack('<Q', int(olel, 16)))
            delta = struct.unpack('>d', struct.pack('>Q', int(to_le, 16)))[0]
            dt_obj = self.epoch_1899 + timedelta(days=delta)
            self.in_ole_le = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_ole_le = False
        return self.in_ole_le

    def to_ole_le(self):
        """Convert a date to an OLE Little Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            delta = (dt_obj - self.epoch_1899).total_seconds() / 86400
            conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
            self.out_ole_le = str(hexlify(struct.pack('<Q', conv))).strip("b'").strip("'")
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_ole_le = False
        return self.out_ole_le

    def from_mac(self):
        """Convert a Mac Absolute timestamp to a date - Also used for Safari plist timestamps"""
        try:
            dt_obj = self.epoch_2001 + timedelta(seconds=int(mac))
            self.in_mac = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_mac = False
        return self.in_mac

    def to_mac(self):
        """Convert a date to a Mac Absolute timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_mac = str(int((dt_obj - self.epoch_2001).total_seconds()))
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_mac = False
        return self.out_mac

    def from_hfs_dec(self):
        """Convert a Mac OS/HFS+ Decimal Timestamp to a date"""
        try:
            self.in_hfs_dec = dt.utcfromtimestamp(float(int(hfsdec) - self.hfs_dec_subtract)).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_hfs_dec = False
        return self.in_hfs_dec

    def to_hfs_dec(self):
        """Convert a date to a Mac OS/HFS+ Decimal Timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_hfs_dec = str(int((dt_obj - self.epoch_1904).total_seconds()))
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_hfs_dec = False
        return self.out_hfs_dec

    def from_hfs_be(self):
        """Convert an HFS/HFS+ Big Endian timestamp to a date (HFS+ is in UTC)"""
        try:
            dt_obj = self.epoch_1904 + timedelta(seconds=int(hfsbe, 16))
            self.in_hfs_be = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_hfs_be = False
        return self.in_hfs_be

    def to_hfs_be(self):
        """Convert a date to an HFS/HFS+ Big Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            conv = int((dt_obj - self.epoch_1904).total_seconds())
            self.out_hfs_be = '{0:08x}'.format(conv)
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_hfs_be = False
        return self.out_hfs_be

    def from_hfs_le(self):
        """Convert an HFS/HFS+ Little Endian timestamp to a date (HFS+ is in UTC)"""
        try:
            to_le = struct.unpack('>I', struct.pack('<I', int(hfsle, 16)))[0]
            dt_obj = self.epoch_1904 + timedelta(seconds=to_le)
            self.in_hfs_le = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_hfs_le = False
        return self.in_hfs_le

    def to_hfs_le(self):
        """Convert a date to an HFS/HFS+ Little Endian timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            conv = int((dt_obj - self.epoch_1904).total_seconds())
            self.out_hfs_le = str(hexlify(struct.pack('<I', conv))).strip("b'").strip("'")
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_hfs_le = False
        return self.out_hfs_le

    def from_fat(self):
        """Convert an MS-DOS wFatDate wFatTime timestamp to a date"""
        try:
            byte_swap = [fat[i:i+2] for i in range(0, len(fat), 2)]
            to_le = byte_swap[1]+byte_swap[0]+byte_swap[3]+byte_swap[2]
            binary_conv = int(to_le, 16)
            binary = '{0:032b}'.format(binary_conv)
            stamp = [binary[:7], binary[7:11], binary[11:16], binary[16:21], binary[21:27], binary[27:32]]
            for binary in stamp[:]:
                dec = int(binary, 2)
                stamp.remove(binary)
                stamp.append(dec)
            stamp[0] = stamp[0] + 1980
            stamp[5] = stamp[5] * 2
            dt_obj = dt(stamp[0], stamp[1], stamp[2], stamp[3], stamp[4], stamp[5])
            self.in_fat = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_fat = False
        return self.in_fat

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
            to_hex = str(hexlify(struct.pack('>I', int(year + month + day + hour + minute + seconds, 2)))).strip("b'").strip("'")
            byte_swap = ''.join([to_hex[i:i+2] for i in range(0, len(to_hex), 2)][::-1])
            self.out_fat = ''.join([byte_swap[i:i+4] for i in range(0, len(byte_swap), 4)][::-1])
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_fat = False
        return self.out_fat

    def from_msdos(self):
        """Convert an MS-DOS timestamp to a date"""
        try:
            swap = ''.join([msdos[i:i+2] for i in range(0, len(msdos), 2)][::-1])
            binary_conv = int(swap, 16)
            binary = '{0:032b}'.format(binary_conv)
            stamp = [binary[:7], binary[7:11], binary[11:16], binary[16:21], binary[21:27], binary[27:32]]
            for val in stamp[:]:
                dec = int(val, 2)
                stamp.remove(val)
                stamp.append(dec)
            stamp[0] = stamp[0] + 1980
            stamp[5] = stamp[5] * 2
            dt_obj = dt(stamp[0], stamp[1], stamp[2], stamp[3], stamp[4], stamp[5])
            self.in_msdos = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_msdos = False
        return self.in_msdos

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
            hexval = str(hexlify(struct.pack('>I', int(year + month + day + hour + minute + seconds, 2)))).strip("b'").strip("'")
            self.out_msdos = ''.join([hexval[i:i+2] for i in range(0, len(hexval), 2)][::-1])
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_msdos = False
        return self.out_msdos

    def from_systime(self):
        """Convert a Microsoft 128 bit SYSTEMTIME timestamp to a date"""
        try:
            to_le = str(hexlify(unhexlify(systime)[::-1])).strip("b'").strip("'")
            converted = [to_le[i:i + 4] for i in range(0, len(to_le), 4)][::-1]
            stamp = []
            for i in converted:
                dec = int(i, 16)
                stamp.append(dec)
            dt_obj = dt(stamp[0], stamp[1], stamp[3], stamp[4], stamp[5], stamp[6], stamp[7]*1000)
            self.in_systemtime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_systemtime = False
        return self.in_systemtime

    def to_systime(self):
        """Convert a date to a Microsoft 128 bit SYSTEMTIME timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            micro = int(dt_obj.microsecond / 1000)
            full_date = dt_obj.strftime('%Y, %m, %w, %d, %H, %M, %S, ' + str(micro))
            stamp = []
            if sys.version_info >= (3, 0):
                for value in full_date.split(','):
                    stamp.append(hexlify(struct.pack('<H', int(value))).decode('utf8'))
            elif sys.version_info < (3, 0):
                for value in full_date.split(','):
                    stamp.append(hexlify(struct.pack('<H', int(value))))
            self.out_systemtime = ''.join(stamp)
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_systemtime = False
        return self.out_systemtime

    def from_filetime(self):
        """Convert a Microsoft FILETIME/LDAP timestamp to a date"""
        try:
            dt_obj = dt.utcfromtimestamp((float(ft) - self.epoch_as_filetime) / self.hundreds_nano)
            self.in_filetime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_filetime = False
        return self.in_filetime

    def to_filetime(self):
        """Convert a date to a Microsoft FILETIME/LDAP timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_filetime = str(int((dt_obj - self.epoch_1970).total_seconds() * self.hundreds_nano + self.epoch_as_filetime))
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_filetime = False
        return self.out_filetime

    def from_prtime(self):
        """Convert a Mozilla PRTime timestamp to a date"""
        try:
            dt_obj = self.epoch_1970 + timedelta(microseconds=int(pr))
            self.in_prtime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_prtime = False
        return self.in_prtime

    def to_prtime(self):
        """Convert a date to Mozilla's PRTime timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_prtime = str(int((dt_obj - self.epoch_1970).total_seconds() * 1000000))
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_prtime = False
        return self.out_prtime

    def from_ole_auto(self):
        """Convert an OLE Automation timestamp to a date"""
        try:
            dt_obj = self.epoch_1899 + timedelta(days=float(auto))
            self.in_ole_auto = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_ole_auto = False
        return self.in_ole_auto

    def to_ole_auto(self):
        """Convert a date to an OLE Automation timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_ole_auto = "{0:.12f}".format((dt_obj - self.epoch_1899).total_seconds() / 86400)
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_ole_auto = False
        return self.out_ole_auto

    def from_ms1904(self):
        """Convert a Microsoft Excel 1904 timestamp to a date"""
        """https://docs.microsoft.com/en-us/office/troubleshoot/excel/1900-and-1904-date-system"""
        try:
            dt_obj = self.epoch_1904 + timedelta(days=float(ms1904))
            self.in_ms1904 = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_ms1904 = False
        return self.in_ms1904

    def to_ms1904(self):
        """Convert a date to a Microsoft Excel 1904 timestamp"""
        try:
           dt_obj = duparser.parse(timestamp)
           self.out_ms1904 = "{0:.12f}".format((dt_obj - self.epoch_1904).total_seconds() / 86400)
        except Exception as e:
           print(str(type(e)) + "," + str(e))
           self.out_ms1904 = False
        return self.out_ms1904

    def from_ios_time(self):
        """Convert an iOS 11 timestamp to a date"""
        try:
            dt_obj = (int(ios) / int(self.nano_2001)) + 978307200
            self.in_iostime = dt.utcfromtimestamp(dt_obj).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_iostime = False
        return self.in_iostime

    def to_ios_time(self):
        """Convert a date to an iOS 11 timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_iostime = str(int(((dt_obj - self.epoch_2001).total_seconds()) * self.nano_2001))
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_iostime = False
        return self.out_iostime

    def from_sym_time(self):
        """Convert a Symantec 12-byte hex timestamp to a date"""
        try:
            hex_to_dec = [int(sym[i:i+2], 16) for i in range(0, len(sym), 2)]
            hex_to_dec[0] = hex_to_dec[0] + 1970
            hex_to_dec[1] = hex_to_dec[1] + 1
            dt_obj = dt(hex_to_dec[0], hex_to_dec[1], hex_to_dec[2], hex_to_dec[3], hex_to_dec[4], hex_to_dec[5])
            self.in_symtime = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_symtime = False
        return self.in_symtime

    def to_sym_time(self):
        """Convert a date to Symantec's 12-byte hex timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            sym_year = '{0:x}'.format(dt_obj.year - 1970).zfill(2)
            sym_month = '{0:x}'.format(dt_obj.month - 1).zfill(2)
            sym_day = '{0:x}'.format(dt_obj.day).zfill(2)
            sym_hour = '{0:x}'.format(dt_obj.hour).zfill(2)
            sym_minute = '{0:x}'.format(dt_obj.minute).zfill(2)
            sym_second = '{0:x}'.format(dt_obj.second).zfill(2)
            self.out_symtime = sym_year + sym_month + sym_day + sym_hour + sym_minute + sym_second
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_symtime = False
        return self.out_symtime

    def date_range(self, start, end, check_date):
        """Check if date is in range of start and end, return True if it is"""
        if start <= end:
            return start <= check_date <= end
        else:
            return start <= check_date or check_date <= end

    def from_gps_time(self):
        """Convert a GPS timestamp to a date (involves leap seconds)"""
        try:
            leapseconds = self.leapseconds
            gps_stamp = self.epoch_1980 + timedelta(seconds=(float(gps)))
            tai_convert = gps_stamp + timedelta(seconds=19)
            epoch_convert = (tai_convert - self.epoch_1970).total_seconds()
            check_date = dt.utcfromtimestamp(epoch_convert)
            for entry in leapseconds:
                check = self.date_range(leapseconds.get(entry)[0], leapseconds.get(entry)[1], check_date)
                if check == True:
                    variance = entry
            gps_out = check_date - timedelta(seconds=variance)
            self.in_gpstime = gps_out.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_gpstime = False
        return self.in_gpstime

    def to_gps_time(self):
        """Convert a date to a GPS timestamp (involves leap seconds)"""
        try:
            leapseconds = self.leapseconds
            check_date = duparser.parse(timestamp)
            for entry in leapseconds:
                check = self.date_range(leapseconds.get(entry)[0], leapseconds.get(entry)[1], check_date)
                if check == True:
                    variance = entry
            leap_correction = check_date + timedelta(seconds=variance)
            epoch_shift = leap_correction - self.epoch_1970
            gps_stamp = (dt.utcfromtimestamp(epoch_shift.total_seconds()) - self.epoch_1980).total_seconds() - 19
            self.out_gpstime = str(gps_stamp)
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_gpstime = False
        return self.out_gpstime

    def from_eitime(self):
        """Convert a Google ei URL timestamp"""
        try:
            padding_check = (len(eitime)%4)
            if padding_check != 0:
                padding_reqd = (4 - padding_check)
                result_eitime = eitime + (padding_reqd * '=')
            else:
                result_eitime = eitime
            decoded_eitime = base64.urlsafe_b64decode(result_eitime)
            if sys.version_info.major == 2:
                unix_timestamp = ord(decoded_eitime[0]) + ord(decoded_eitime[1])*256 + ord(decoded_eitime[2])*(256**2) + ord(decoded_eitime[3])*(256**3)
            elif sys.version_info.major == 3:
                unix_timestamp = decoded_eitime[0] + decoded_eitime[1]*256 + decoded_eitime[2]*(256**2) + decoded_eitime[3]*(256**3)
            self.in_eitime = dt.utcfromtimestamp(float(unix_timestamp)).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_eitime = False
        return self.in_eitime

    """
    def to_eitime(self): A reminder to add this
    """
    def from_bplist(self):
        """Convert a Binary Plist timestamp to a date"""
        try:
            dt_obj = self.epoch_2001 + timedelta(seconds=float(bplist))
            self.in_bplist = dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_bplist = False
        return self.in_bplist

    def to_bplist(self):
        """Convert a date to a Binary Plist timestamp"""
        try:
            dt_obj = duparser.parse(timestamp)
            self.out_bplist = str((dt_obj - self.epoch_2001).total_seconds())
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.out_bplist = False
        return self.out_bplist

    def from_gsm(self):
        try:
            swap = [gsm[i:i+2] for i in range(0, len(gsm), 2)]
            for value in swap[:]:
                le = value[::-1]
                swap.remove(value)
                swap.append(le)
            tz = '{0:8b}'.format(int(swap[6], 16))
            if int(tz[0]) == 1:
                utc_offset = -int(str(int(tz[1:4], 2)) + str(int(tz[4:8], 2))) * 0.25
            elif int(tz[0]) == 0:
                utc_offset = int(str(int(tz[0:4], 2)) + str(int(tz[4:8], 2))) * 0.25
            swap[6] = utc_offset
            for string in swap[:]:
                swap.remove(string)
                swap.append(int(string))
            if swap[0] in range(0, 20):
                swap[0] = swap[0] + 2000
            self.in_gsm = str(dt(swap[0], swap[1], swap[2], swap[3], swap[4], swap[5]).strftime('%Y-%m-%d %H:%M:%S')) + " UTC" +  str(swap[6])
        except Exception as e:
            print(str(type(e)) + "," + str(e))
            self.in_gsm = False
        return self.in_gsm

    def to_gsm(self):
        try:
            dt_obj = duparser.parse(timestamp)
            tz = dt_obj.tzinfo._offset.total_seconds()
            if tz == 0:
                hex_tz = '{:02d}'.format(0)
            if tz < 0:
                tz = tz / 3600
                conversion = str(int(abs(tz)) * 4)
                conversion_list = []
                for char in range(len(conversion)):
                    conversion_list.append(conversion[char])
                high_order = '{0:04b}'.format(int(conversion_list[0]))
                low_order = '{0:04b}'.format(int(conversion_list[1]))
                high_order = '{0:04b}'.format(int(high_order, 2) + 8)
                hex_tz = hex(int((high_order + low_order),2)).lstrip('0x').upper()
            else:
                tz = tz / 3600
                conversion = str(int(tz) *4)
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
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(exc_type, exc_tb.tb_lineno)
            print(str(type(e)) + "," + str(e) + " At line no: " + str(exc_tb.tb_lineno))
            self.out_gsm = False
        return self.out_gsm

    def date_output(self):
        """Output all processed timestamp values"""
        inputs = (self.in_unix_sec, self.in_unix_milli, self.in_windows_hex_64, self.in_windows_hex_le, self.in_chrome, self.in_ad, self.in_unix_hex_32, self.in_unix_hex_32le, self.in_cookie, self.in_ole_be, self.in_ole_le, self.in_mac, self.in_hfs_dec, self.in_hfs_be, self.in_hfs_le, self.in_msdos, self.in_fat, self.in_systemtime, self.in_filetime, self.in_prtime, self.in_ole_auto, self.in_iostime, self.in_symtime, self.in_gpstime, self.in_eitime, self.in_bplist)
        this_year = int(dt.now().strftime('%Y'))
        if isinstance(self.in_unix_sec, str):
            if int(duparser.parse(self.in_unix_sec).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mUnix Seconds:\t\t\t"  + self.in_unix_sec + " UTC\033[1;m".format())
            else:
                print ("Unix Seconds:\t\t\t"  + self.in_unix_sec + " UTC")

        if isinstance(self.in_unix_milli, str):
            if int(duparser.parse(self.in_unix_milli).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mUnix Milliseconds:\t\t"  + self.in_unix_milli + " UTC\033[1;m".format())
            else:
                print ("Unix Milliseconds:\t\t" + self.in_unix_milli + " UTC")

        if isinstance(self.in_windows_hex_64, str):
            if int(duparser.parse(self.in_windows_hex_64).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mWindows 64 bit Hex BE:\t\t"  + self.in_windows_hex_64 + " UTC\033[1;m".format())
            else:
                print ("Windows 64 bit Hex BE:\t\t" + self.in_windows_hex_64 + " UTC")

        if isinstance(self.in_windows_hex_le, str):
            if int(duparser.parse(self.in_windows_hex_le).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mWindows 64 bit Hex LE:\t\t"  + self.in_windows_hex_le + " UTC\033[1;m".format())
            else:
                print ("Windows 64 bit Hex LE:\t\t" + self.in_windows_hex_le + " UTC")

        if isinstance(self.in_chrome, str):
            if int(duparser.parse(self.in_chrome).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mGoogle Chrome:\t\t\t"  + self.in_chrome + " UTC\033[1;m".format())
            else:
                print ("Google Chrome:\t\t\t" + self.in_chrome + " UTC")

        if isinstance(self.in_ad, str):
            if int(duparser.parse(self.in_ad).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mActive Directory dt:\t\t"  + self.in_ad + " UTC\033[1;m".format())
            else:
                print ("Active Directory dt:\t\t" + self.in_ad + " UTC")

        if isinstance(self.in_unix_hex_32, str):
            if int(duparser.parse(self.in_unix_hex_32).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mUnix Hex 32 bit BE:\t\t" + self.in_unix_hex_32 + " UTC\033[1;m".format())
            else:
                print ("Unix Hex 32 bit BE:\t\t" + self.in_unix_hex_32 + " UTC")

        if isinstance(self.in_unix_hex_32le, str):
            if int(duparser.parse(self.in_unix_hex_32le).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mUnix Hex 32 bit LE:\t\t"  + self.in_unix_hex_32le + " UTC\033[1;m".format())
            else:
                print ("Unix Hex 32 bit LE:\t\t" + self.in_unix_hex_32le + " UTC")

        if isinstance(self.in_cookie, str):
            if int(duparser.parse(self.in_cookie).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mWindows Cookie Date:\t\t"  + self.in_cookie + " UTC\033[1;m".format())
            else:
                print ("Windows Cookie Date:\t\t" + self.in_cookie + " UTC")

        if isinstance(self.in_ole_be, str):
            if int(duparser.parse(self.in_ole_be).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mWindows OLE 64 bit double BE:\t"  + self.in_ole_be + " UTC\033[1;m".format())
            else:
                print ("Windows OLE 64 bit double BE:\t" + self.in_ole_be + " UTC")

        if isinstance(self.in_ole_le, str):
            if int(duparser.parse(self.in_ole_le).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mWindows OLE 64 bit double LE:\t"  + self.in_ole_le + " UTC\033[1;m".format())
            else:
                print ("Windows OLE 64 bit double LE:\t" + self.in_ole_le + " UTC")

        if isinstance(self.in_mac, str):
            if int(duparser.parse(self.in_mac).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mMac Absolute Time:\t\t"  + self.in_mac + " UTC\033[1;m".format())
            else:
                print ("Mac Absolute Time:\t\t" + self.in_mac + " UTC")

        if isinstance(self.in_hfs_dec, str):
            if int(duparser.parse(self.in_hfs_dec).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mMac OS/HFS+ Decimal Time:\t"  + self.in_hfs_dec + " UTC\033[1;m".format())
            else:
                print ("Mac OS/HFS+ Decimal Time:\t" + self.in_hfs_dec + " UTC")

        if isinstance(self.in_hfs_be, str):
            if int(duparser.parse(self.in_hfs_be).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mHFS/HFS+ 32 bit Hex BE:\t\t"  + self.in_hfs_be + " HFS Local / HFS+ UTC\033[1;m".format())
            else:
                print ("HFS/HFS+ 32 bit Hex BE:\t\t" + self.in_hfs_be + " HFS Local / HFS+ UTC")

        if isinstance(self.in_hfs_le, str):
            if int(duparser.parse(self.in_hfs_le).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mHFS/HFS+ 32 bit Hex LE:\t\t"  + self.in_hfs_le + " HFS Local / HFS+ UTC\033[1;m".format())
            else:
                print ("HFS/HFS+ 32 bit Hex LE:\t\t" + self.in_hfs_le + " HFS Local / HFS+ UTC")

        if isinstance(self.in_msdos, str):
            if int(duparser.parse(self.in_msdos).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mMS-DOS 32 bit Hex Value:\t"  + self.in_msdos + " Local\033[1;m".format())
            else:
                print ("MS-DOS 32 bit Hex Value:\t" + self.in_msdos + " Local")

        if isinstance(self.in_fat, str):
            if int(duparser.parse(self.in_fat).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mFAT Date + Time:\t\t"  + self.in_fat + " Local\033[1;m".format())
            else:
                print ("FAT Date + Time:\t\t" + self.in_fat + " Local")

        if isinstance(self.in_systemtime, str):
            if int(duparser.parse(self.in_systemtime).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mMicrosoft 128 bit SYSTEMTIME:\t"  + self.in_systemtime + " UTC\033[1;m".format())
            else:
                print ("Microsoft 128 bit SYSTEMTIME:\t" + self.in_systemtime + " UTC")

        if isinstance(self.in_filetime, str):
            if int(duparser.parse(self.in_filetime).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mMicrosoft FILETIME/LDAP time:\t"  + self.in_filetime + " UTC\033[1;m".format())
            else:
                print ("Microsoft FILETIME/LDAP time:\t" + self.in_filetime + " UTC")

        if isinstance(self.in_prtime, str):
            if int(duparser.parse(self.in_prtime).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mMozilla PRTime:\t\t\t"  + self.in_prtime + " UTC\033[1;m".format())
            else:
                print ("Mozilla PRTime:\t\t\t" + self.in_prtime + " UTC")

        if isinstance(self.in_ole_auto, str):
            if int(duparser.parse(self.in_ole_auto).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mOLE Automation Date:\t\t"  + self.in_ole_auto + " UTC\033[1;m".format())
            else:
                print ("OLE Automation Date:\t\t" + self.in_ole_auto + " UTC")

        if isinstance(self.in_ms1904, str):
            if int(duparser.parse(self.in_ms1904).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mMS Excel 1904 Date:\t\t" + self.in_ms1904 + " UTC\033[1;m".format())
            else:
                print ("MS Excel 1904 Date:\t\t" + self.in_ms1904 + " UTC")

        if isinstance(self.in_iostime, str):
            if int(duparser.parse(self.in_iostime).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31miOS 11 Date:\t\t\t"  + self.in_iostime + " \033[1;m".format())
            else:
                print ("iOS 11 Date:\t\t\t" + self.in_iostime)

        if isinstance(self.in_symtime, str):
            if int(duparser.parse(self.in_symtime).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mSymantec AV timestamp:\t\t"  + self.in_symtime + " UTC\033[1;m".format())
            else:
                print ("Symantec AV timestamp:\t\t" + self.in_symtime + " UTC")

        if isinstance(self.in_gpstime, str):
            if int(duparser.parse(self.in_gpstime).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mGPS timestamp:\t\t\t"  + self.in_gpstime + " UTC\033[1;m".format())
            else:
                print ("GPS timestamp:\t\t\t" + self.in_gpstime + " UTC")

        if isinstance(self.in_eitime, str):
            if int(duparser.parse(self.in_eitime).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mGoogle EI URL timestamp:\t" + self.in_eitime + " UTC\033[1;m".format())
            else:
                print ("Google EI URL timestamp:\t" + self.in_eitime + " UTC")

        if isinstance(self.in_bplist, str):
            if int(duparser.parse(self.in_bplist).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31miOS Binary Plist timestamp:\t" + self.in_bplist + " UTC\033[1;m".format())
            else:
                print ("iOS Binary Plist timestamp:\t" + self.in_bplist + " UTC")

        if isinstance(self.in_gsm, str):
            if int(duparser.parse(self.in_gsm).strftime('%Y')) in range(this_year -5, this_year +5):
                print ("\033[1;31mGSM Timestamp:\t\t\t"  + self.in_gsm + " UTC\033[1;m".format())
            else:
                print ("GSM Timestamp:\t\t\t" + self.in_gsm)

        if all([ values == False for values in inputs ]) :
            print ('No valid dates found. Check your input and try again.')

    def timestamp_output(self):
        """Output all processed dates from timestamp values"""
        if isinstance(self.out_unix_sec, str):
            print ("Unix Seconds:\t\t\t" + self.out_unix_sec)

        if isinstance(self.out_unix_milli, str):
            print ("Unix Milliseconds:\t\t" + self.out_unix_milli)

        if isinstance(self.out_windows_hex_64, str):
            print ("Windows 64 bit Hex BE:\t\t" + self.out_windows_hex_64)

        if isinstance(self.out_windows_hex_le, str):
            print ("Windows 64 bit Hex LE:\t\t" + self.out_windows_hex_le)

        if isinstance(self.out_chrome, str):
            print ("Google Chrome:\t\t\t" + self.out_chrome)

        if isinstance(self.out_active_directory_time, str):
            print ("Active Directory dt:\t\t" + self.out_active_directory_time)

        if isinstance(self.out_unix_hex_32, str):
            print ("Unix Hex 32 bit BE:\t\t" + self.out_unix_hex_32)

        if isinstance(self.out_unix_hex_32le, str):
            print ("Unix Hex 32 bit LE:\t\t" + self.out_unix_hex_32le)

        if isinstance(self.out_cookie, str):
            print ("Windows Cookie Date:\t\t" + self.out_cookie)

        if isinstance(self.out_ole_be, str):
            print ("Windows OLE 64 bit double BE:\t" + self.out_ole_be)

        if isinstance(self.out_ole_le, str):
            print ("Windows OLE 64 bit double LE:\t" + self.out_ole_le)

        if isinstance(self.out_mac, str):
            print ("Mac Absolute Time:\t\t" + self.out_mac)

        if isinstance(self.out_hfs_dec, str):
            print ("Mac OS/HFS+ Decimal Time:\t" + self.out_hfs_dec)

        if isinstance(self.out_hfs_be, str):
            print ("HFS/HFS+ 32 bit Hex BE:\t\t" + self.out_hfs_be)

        if isinstance(self.out_hfs_le, str):
            print ("HFS/HFS+ 32 bit Hex LE:\t\t" + self.out_hfs_le)

        if isinstance(self.out_msdos, str):
            print ("MS-DOS 32 bit Hex Value:\t" + self.out_msdos)

        if isinstance(self.out_fat, str):
            print ("FAT Date + Time:\t\t" + self.out_fat)

        if isinstance(self.out_systemtime, str):
            print ("Microsoft 128 bit SYSTEMTIME:\t" + self.out_systemtime)

        if isinstance(self.out_filetime, str):
            print ("Microsoft FILETIME/LDAP time:\t" + self.out_filetime)

        if isinstance(self.out_prtime, str):
            print ("Mozilla PRTime:\t\t\t" + self.out_prtime)

        if isinstance(self.out_ole_auto, str):
            print ("OLE Automation Date:\t\t" + self.out_ole_auto)

        if isinstance(self.out_ms1904, str):
            print ("MS Excel 1904 Date:\t\t" + self.out_ms1904)

        if isinstance(self.out_iostime, str):
            print ("iOS 11 Date:\t\t\t" + self.out_iostime)

        if isinstance(self.out_symtime, str):
            print ("Symantec AV time:\t\t" + self.out_symtime)

        if isinstance(self.out_gpstime, str):
            print ("GPS time:\t\t\t" + self.out_gpstime)

        if isinstance(self.out_bplist, str):
            print ("iOS Binary Plist time:\t\t" + self.out_bplist)

        if isinstance(self.out_gsm, str):
            print ("GSM time:\t\t\t" + self.out_gsm)

if __name__ == '__main__':
    now = dt.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    arg_parse = argparse.ArgumentParser(description='Time Decoder and Converter', epilog='If logging is enabled, see time_decoder.log in current users home dir.')
    arg_parse.add_argument('--unix', metavar='<value>', help='convert from Unix Seconds', required=False)
    arg_parse.add_argument('--umil', metavar='<value>', help='convert from Unix Milliseconds', required=False)
    arg_parse.add_argument('--wh', metavar='<value>', help='convert from Windows 64 bit Hex BE', required=False)
    arg_parse.add_argument('--whle', metavar='<value>', help='convert from Windows 64 bit Hex LE', required=False)
    arg_parse.add_argument('--goog', metavar='<value>', help='convert from Google Chrome time', required=False)
    arg_parse.add_argument('--active', metavar='<value>', help='convert from Active Directory value', required=False)
    arg_parse.add_argument('--uhbe', metavar='<value>', help='convert from Unix Hex 32 bit BE', required=False)
    arg_parse.add_argument('--uhle', metavar='<value>', help='convert from Unix Hex 32 bit LE', required=False)
    arg_parse.add_argument('--cookie', metavar='<value>', help='convert from Windows Cookie Date (Low Value,High Value)', required=False)
    arg_parse.add_argument('--oleb', metavar='<value>', help='convert from Windows OLE 64 bit BE - remove 0x and spaces! Example from SRUM: 0x40e33f5d 0x97dfe8fb should be 40e33f5d97dfe8fb', required=False)
    arg_parse.add_argument('--olel', metavar='<value>', help='convert from Windows OLE 64 bit LE', required=False)
    arg_parse.add_argument('--mac', metavar='<value>', help='convert from Mac Absolute Time', required=False)
    arg_parse.add_argument('--hfsdec', metavar='<value>', help='convert from Mac OS/HFS+ Decimal Time', required=False)
    arg_parse.add_argument('--hfsbe', metavar='<value>', help='convert from HFS(+) BE times (HFS = Local, HFS+ = UTC)', required=False)
    arg_parse.add_argument('--hfsle', metavar='<value>', help='convert from HFS(+) LE times (HFS = Local, HFS+ = UTC)', required=False)
    arg_parse.add_argument('--msdos', metavar='<value>', help='convert from 32 bit MS-DOS time - result is Local Time', required=False)
    arg_parse.add_argument('--fat', metavar='<value>', help='convert from FAT Date + Time (wFat)', required=False)
    arg_parse.add_argument('--sys', metavar='<value>', help='convert from 128 bit SYSTEMTIME', required=False)
    arg_parse.add_argument('--ft', metavar='<value>', help='convert from FILETIME/LDAP timestamp', required=False)
    arg_parse.add_argument('--pr', metavar='<value>', help='convert from Mozilla\'s PRTime', required=False)
    arg_parse.add_argument('--auto', metavar='<value>', help='convert from OLE Automation Date format', required=False)
    arg_parse.add_argument('--ms1904', metavar='<value>', help='convert from MS Excel 1904 Date format', required=False)
    arg_parse.add_argument('--ios', metavar='<value>', help='convert from iOS 11 Timestamp', required=False)
    arg_parse.add_argument('--sym', metavar='<value>', help='convert Symantec\'s 12-byte AV Timestamp', required=False)
    arg_parse.add_argument('--gps', metavar='<value>', help='convert from a GPS Timestamp', required=False)
    arg_parse.add_argument('--eitime', metavar='<value>', help='convert from a Google EI URL Timestamp', required=False)
    arg_parse.add_argument('--bplist', metavar='<value>', help='convert from an iOS Binary Plist Timestamp', required=False)
    arg_parse.add_argument('--gsm', metavar='<value>', help='convert from a GSM Timestamp', required=False)
    arg_parse.add_argument('--guess', metavar='<value>', help='guess timestamp and output all reasonable possibilities', required=False)
    arg_parse.add_argument('--timestamp', metavar='DATE', help='convert date to every timestamp - enter date as \"Y-M-D HH:MM:SS.m\" in 24h fmt - without argument gives current date/time', required=False, nargs='?', const=now)
    arg_parse.add_argument('--version', '-v', action='version', version='%(prog)s' +str(__version__))
    args = arg_parse.parse_args()
    guess = args.guess; unix = args.unix; umil = args.umil; wh = args.wh; whle = args.whle; goog = args.goog; active = args.active; uhbe = args.uhbe; uhle = args.uhle; cookie = args.cookie; oleb = args.oleb; olel = args.olel; mac = args.mac; hfsdec = args.hfsdec; hfsbe = args.hfsbe; hfsle = args.hfsle; msdos = args.msdos; fat = args.fat; systime = args.sys; ft = args.ft; pr = args.pr; auto = args.auto; ms1904 = args.ms1904; ios = args.ios; sym = args.sym; gps = args.gps; timestamp = args.timestamp; eitime = args.eitime; bplist = args.bplist; gsm = args.gsm
    if args.guess:
        unix = umil = wh = whle = goog = active = uhbe = uhle = cookie = oleb = olel = mac = hfsdec = hfsbe = hfsle = msdos = fat = systime = ft = pr = auto = ms1904 = ios = sym = gps = eitime = bplist = gsm = guess

    td = TimeDecoder()
    td.run()
