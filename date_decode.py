#!/usr/bin/env python
"""
This application is designed to decode timestamps into human-readable date/times and vice-versa
Additional information regarding the source of the timestamp formats and associated equations
will be provided inline with the docstrings for each module.
"""
from datetime import datetime, timedelta
import logging
import struct
from binascii import hexlify, unhexlify
import argparse
import sys
from dateutil import parser as duparser

__author__ = 'Corey Forman'
__date__ = '2 Jul 17'
__version__ = '0.31'
__description__ = 'Python CLI Date Time Conversion Tool'

class DateDecoder(object):
    """Run the decoding class"""
    def __init__(self):
        self.epoch_1601 = datetime(1601, 1, 1)
        self.epoch_1899 = datetime(1899, 12, 30, 0, 0, 0)
        self.epoch_1904 = datetime(1904, 1, 1)
        self.epoch_1970 = datetime(1970, 1, 1)
        self.epoch_2001 = datetime(2001, 1, 1)
        self.hundreds_nano = 10000000
        self.nano_2001 = 1000000000
        self.epoch_as_filetime = 116444736000000000

    def run(self):
        """Process arguments and log errors"""
        if len(sys.argv[1:]) == 0:
            arg_parse.print_help()
            arg_parse.exit()
        logging.info('Launching Date Decode')
        logging.info('Processing Timestamp: ' + sys.argv[2])
        logging.info('Input Time Format: ' + sys.argv[1])
        logging.info('Starting Date Decoder v.' +str(__version__))
        if args.unix:
            try:
                self.convert_unix_sec()
                print ("Unix Seconds: " + self.proc_unix_sec + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.umil:
            try:
                self.convert_unix_milli()
                print ("Unix Milliseconds: " + self.proc_unix_milli + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.wh:
            try:
                self.convert_win_64_hex()
                print ("Windows 64 bit Hex BE: " + self.proc_windows_hex_64 + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.whle:
            try:
                self.convert_win_64_hexle()
                print ("Windows 64 bit Hex LE: " + self.proc_windows_hex_le + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.goog:
            try:
                self.convert_chrome_timestamps()
                print ("Google Chrome Time: " + self.proc_chrome_time + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.active:
            try:
                self.convert_ad_datetime()
                print ("Active Directory Timestamp: " + self.proc_ad_time + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.uhbe:
            try:
                self.convert_unix_hex_32be()
                print ("Unix Hex 32 bit BE: " + self.proc_unix_hex_32 + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.uhle:
            try:
                self.convert_unix_hex_32le()
                print ("Unix Hex 32 bit LE: " + self.proc_unix_hex_32le + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.cookie:
            try:
                self.convert_cookie()
                print ("Windows Cookie Date: " + self.proc_cookie + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.oleb:
            try:
                self.convert_ole_be()
                print ("Windows OLE 64 bit double BE: " + self.proc_ole_be + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.olel:
            try:
                self.convert_ole_le()
                print ("Windows OLE 64 bit double LE: " + self.proc_ole_le + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.mac:
            try:
                self.convert_mac()
                print ("Mac Absolute Time: " + self.proc_mac + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.hfsbe:
            try:
                self.convert_hfs_be()
                print ("HFS/HFS+ 32 bit Hex BE: " + self.proc_hfs_be + " HFS Local / HFS+ UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.hfsle:
            try:
                self.convert_hfs_le()
                print ("HFS/HFS+ 32 big Hex LE: " + self.proc_hfs_le + " HFS Local / HFS+ UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.msdos:
            try:
                self.convert_msdos()
                print ("MS-DOS 32 bit Hex Value: " + self.proc_msdos + " Local")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.fat:
            try:
                self.convert_fat_dt()
                print ("FAT Date + Time: " + self.proc_fat_dt + " Local")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.sys:
            try:
                self.convert_systime()
                print ("Microsoft 128 bit SYSTEMTIME: " + self.proc_systemtime + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.ft:
            try:
                self.convert_filetime()
                print ("Microsoft FILETIME/LDAP time: " + self.proc_filetime + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.pr:
            try:
                self.convert_prtime()
                print ("Mozilla PRTime: " + self.proc_prtime + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.auto:
            try:
                self.convert_ole_auto()
                print ("OLE Automation Date: " + self.proc_ole_auto + " UTC")
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.ios:
            try:
                self.convert_ios_time()
                print ("iOS 11 beta Date: " + self.proc_iostime)
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.sym:
            try:
                self.convert_sym_time()
                print ("Symantec AV Timestamp: " + self.proc_symtime)
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.timestamp:
            try:
                self.to_timestamps()
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))
        elif args.guess:
            try:
                self.convert_all()
            except Exception as e:
                logging.error(str(type(e)) + "," + str(e))

    def convert_all(self):
        """Find date from provided timestamp"""
        print ('\nGuessing Date from Timestamp\n')

        self.convert_unix_sec()
        self.convert_unix_milli()
        self.convert_win_64_hex()
        self.convert_win_64_hexle()
        self.convert_chrome_timestamps()
        self.convert_ad_datetime()
        self.convert_unix_hex_32be()
        self.convert_unix_hex_32le()
        self.convert_cookie()
        self.convert_ole_be()
        self.convert_ole_le()
        self.convert_mac()
        self.convert_hfs_be()
        self.convert_hfs_le()
        self.convert_msdos()
        self.convert_fat_dt()
        self.convert_systime()
        self.convert_filetime()
        self.convert_prtime()
        self.convert_ole_auto()
        self.convert_ios_time()
        self.convert_sym_time()
        self.output()
        print ('\r')

    def to_timestamps(self):
        """Convert provided date to all timestamps"""
        print ('\nGuessing Timestamp From Date\n')

        self.to_unix_sec()
        self.to_unix_milli()
        self.to_win_64_hex()
        self.to_win_64_hexle()
        self.to_chrome_timestamps()
        self.to_ad_datetime()
        self.to_unix_hex_32be()
        self.to_unix_hex_32le()
        self.to_cookie()
        self.to_ole_be()
        self.to_ole_le()
        self.to_mac()
        self.to_hfs_be()
        self.to_hfs_le()
        self.to_msdos()
        self.to_fat_dt()
        self.to_systime()
        self.to_filetime()
        self.to_prtime()
        self.to_ole_auto()
        self.to_ios_time()
        self.to_sym_time()
        self.date_output()
        print ('\r')

    def convert_unix_sec(self):
        """Convert Unix Seconds value to a date"""
        try:
            self.proc_unix_sec = datetime.utcfromtimestamp(float(sys.argv[2])).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_unix_sec = 'N/A'

    def to_unix_sec(self):
        "Convert date to a Unix Seconds value"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            self.out_unix_sec = str(int((datetime_obj - self.epoch_1970).total_seconds()))
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_unix_sec = 'N/A'

    def convert_unix_milli(self):
        """Convert Unix Millisecond value to a date"""
        try:
            self.proc_unix_milli = datetime.utcfromtimestamp(float(sys.argv[2]) / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_unix_milli = 'N/A'

    def to_unix_milli(self):
        """Convert date to a Unix Millisecond value"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            self.out_unix_milli = str(int((datetime_obj - self.epoch_1970).total_seconds()*1000))
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_unix_milli = 'N/A'

    def convert_win_64_hex(self):
        """Convert a Windows 64 Hex Big-Endian value to a date"""
        try:
            base10_microseconds = int(sys.argv[2], 16) / 10
            datetime_obj = self.epoch_1601 + timedelta(microseconds=base10_microseconds)
            self.proc_windows_hex_64 = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_windows_hex_64 = 'N/A'

    def to_win_64_hex(self):
        """Convert a date to a Windows 64 Hex Big-Endian value"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            minus_epoch = datetime_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
            self.out_windows_hex_64 = str(hex(int(calculated_time)*10))[2:].zfill(16)
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_windows_hex_64 = 'N/A'

    def convert_win_64_hexle(self):
        """Convert a Windows 64 Hex Little-Endian value to a date"""
        try:
            converted_time = struct.unpack("<Q", unhexlify(sys.argv[2]))[0]
            datetime_obj = self.epoch_1601 + timedelta(microseconds=converted_time /10)
            self.proc_windows_hex_le = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_windows_hex_le = 'N/A'

    def to_win_64_hexle(self):
        """Convert a date to a Windows 64 Hex Little-Endian value"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            minus_epoch = datetime_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
            self.out_windows_hex_le = str(hexlify(struct.pack("<Q", int(calculated_time*10))))[2:].zfill(16).strip("'")
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_windows_hex_le = 'N/A'

    def convert_chrome_timestamps(self):
        """Convert a Chrome Timestamp/Webkit Value to a date"""
        try:
            delta = timedelta(microseconds=int(sys.argv[2]))
            converted_time = self.epoch_1601 + delta
            self.proc_chrome_time = converted_time.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_chrome_time = 'N/A'

    def to_chrome_timestamps(self):
        """Convert a date to a Chrome Timestamp/Webkit value"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            chrome_time = (datetime_obj - self.epoch_1601).total_seconds() * 1000000
            self.out_chrome_time = str(int(chrome_time))
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_chrome_time = 'N/A'

    def convert_ad_datetime(self):
        """Convert an Active Directory timestamp to a date"""
        try:
            part2, part1 = [int(h, base=16) for h in sys.argv[2].split(':')]
            converted_time = struct.unpack('>Q', struct.pack('>LL', part1, part2))[0]
            datetime_obj = datetime.utcfromtimestamp(float(converted_time - self.epoch_as_filetime) / self.hundreds_nano)
            self.proc_ad_time = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_ad_time = 'N/A'

    def to_ad_datetime(self):
        """Convert a date to an Active Directory timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            minus_epoch = datetime_obj - self.epoch_1601
            calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
            output = hexlify(struct.pack(">Q", int(calculated_time*10)))
            self.out_active_directory_time = str(output[8:]).strip("'b").strip("'") + ":" + str(output[:8]).strip("'b").strip("'")
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_active_directory_time = 'N/A'

    def convert_unix_hex_32be(self):
        """Convert a Unix Hex 32 bit Big-Endian timestamp to a date"""
        try:
            to_dec = int(sys.argv[2], 16)
            self.proc_unix_hex_32 = datetime.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_unix_hex_32 = 'N/A'

    def to_unix_hex_32be(self):
        """Convert a date to a Unix Hex 32 bit Big-Endian timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            self.out_unix_hex_32 = str(hexlify(struct.pack(">L", int((datetime_obj - self.epoch_1970).total_seconds())))).strip("b'").strip("'")
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_unix_hex_32 = 'N/A'

    def convert_unix_hex_32le(self):
        """Convert a Unix Hex 32 bit Little-Endian timestamp to a date"""
        try:
            to_dec = struct.unpack("<L", unhexlify(sys.argv[2]))[0]
            self.proc_unix_hex_32le = datetime.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_unix_hex_32le = 'N/A'

    def to_unix_hex_32le(self):
        """Convert a date to a Unix Hex 32 bit Little-Endian timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            self.out_unix_hex_32le = str(hexlify(struct.pack("<L", int((datetime_obj - self.epoch_1970).total_seconds())))).strip("b'").strip("'")
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_unix_hex_32le = 'N/A'

    def convert_cookie(self):
        """Convert an Internet Explorer timestamp to a date"""
        try:
            low, high = [int(h, base=10) for h in sys.argv[2].split(',')]
            calc = 10**-7 * (high * 2**32 + low) - 11644473600
            datetime_obj = datetime.utcfromtimestamp(calc)
            self.proc_cookie = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_cookie = 'N/A'

    def to_cookie(self):
        """Convert a date to Internet Explorer timestamp values"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            unix = int((datetime_obj - self.epoch_1970).total_seconds())
            high = int(((unix + 11644473600) * 10**7) / 2**32)
            low = int((unix + 11644473600) * 10**7) - (high * 2**32)
            self.out_cookie = str(low) + ',' + str(high)
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_cookie = 'N/A'

    def convert_ole_be(self):
        """Convert an OLE Big Endian dimestamp to a date"""
        try:
            delta = struct.unpack('>d', struct.pack('>Q', int(sys.argv[2], 16)))[0]
            datetime_obj = self.epoch_1899 + timedelta(days=delta)
            self.proc_ole_be = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_ole_be = 'N/A'

    def to_ole_be(self):
        """Convert a date to an OLE Big Endian timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            delta = (datetime_obj - self.epoch_1899).total_seconds() / 86400
            conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
            self.out_ole_be = str(hexlify(struct.pack('>Q', conv))).strip("b'").strip("'")
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_ole_be = 'N/A'

    def convert_ole_le(self):
        """Convert an OLE Little Endian timestamp to a date"""
        try:
            to_le = hexlify(struct.pack('<Q', int(sys.argv[2], 16)))
            delta = struct.unpack('>d', struct.pack('>Q', int(to_le, 16)))[0]
            datetime_obj = self.epoch_1899 + timedelta(days=delta)
            self.proc_ole_le = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_ole_le = 'N/A'

    def to_ole_le(self):
        """Convert a date to an OLE Little Endian timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            delta = (datetime_obj - self.epoch_1899).total_seconds() / 86400
            conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
            self.out_ole_le = str(hexlify(struct.pack('<Q', conv))).strip("b'").strip("'")
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_ole_le = 'N/A'

    def convert_mac(self):
        """Convert a Mac Absolute timestamp to a date - Also used for Safari plist timestamps"""
        try:
            datetime_obj = self.epoch_2001 + timedelta(seconds=int(sys.argv[2]))
            self.proc_mac = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_mac = 'N/A'

    def to_mac(self):
        """Convert a date to a Mac Absolute timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            self.out_mac = str(int((datetime_obj - self.epoch_2001).total_seconds()))
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_mac = 'N/A'

    def convert_hfs_be(self):
        """Convert an HFS/HFS+ Big Endian timestamp to a date (HFS+ is in UTC)"""
        try:
            datetime_obj = self.epoch_1904 + timedelta(seconds=int(sys.argv[2], 16))
            self.proc_hfs_be = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_hfs_be = 'N/A'

    def to_hfs_be(self):
        """Convert a date to an HFS/HFS+ Big Endian timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            conv = int((datetime_obj - self.epoch_1904).total_seconds())
            self.out_hfs_be = '{0:08x}'.format(conv)
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_hfs_be = 'N/A'

    def convert_hfs_le(self):
        """Convert an HFS/HFS+ Little Endian timestamp to a date (HFS+ is in UTC)"""
        try:
            to_le = struct.unpack('>I', struct.pack('<I', int(sys.argv[2], 16)))[0]
            datetime_obj = self.epoch_1904 + timedelta(seconds=to_le)
            self.proc_hfs_le = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_hfs_le = 'N/A'

    def to_hfs_le(self):
        """Convert a date to an HFS/HFS+ Little Endian timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            conv = int((datetime_obj - self.epoch_1904).total_seconds())
            self.out_hfs_le = str(hexlify(struct.pack('<I', conv))).strip("b'").strip("'")
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_hfs_le = 'N/A'

    def convert_fat_dt(self):
        """Convert an MS-DOS wFatDate wFatTime timestamp to a date"""
        try:
            byte_swap = [sys.argv[2][i:i+2] for i in range(0, len(sys.argv[2]), 2)]
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
            datetime_obj = datetime(stamp[0], stamp[1], stamp[2], stamp[3], stamp[4], stamp[5])
            self.proc_fat_dt = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_fat_dt = 'N/A'

    def to_fat_dt(self):
        """Convert a date to an MS-DOS wFatDate wFatTime timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            year = '{0:07b}'.format(datetime_obj.year - 1980)
            month = '{0:04b}'.format(datetime_obj.month)
            day = '{0:05b}'.format(datetime_obj.day)
            hour = '{0:05b}'.format(datetime_obj.hour)
            minute = '{0:06b}'.format(datetime_obj.minute)
            seconds = '{0:05b}'.format(int(datetime_obj.second / 2))
            to_hex = str(hexlify(struct.pack('>I', int(year + month + day + hour + minute + seconds, 2)))).strip("b'").strip("'")
            byte_swap = ''.join([to_hex[i:i+2] for i in range(0, len(to_hex), 2)][::-1])
            self.out_fat_dt = ''.join([byte_swap[i:i+4] for i in range(0, len(byte_swap), 4)][::-1])
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_fat_dt = 'N/A'

    def convert_msdos(self):
        """Convert an MS-DOS timestamp to a date"""
        try:
            swap = ''.join([sys.argv[2][i:i+2] for i in range(0, len(sys.argv[2]), 2)][::-1])
            binary_conv = int(swap, 16)
            binary = '{0:032b}'.format(binary_conv)
            stamp = [binary[:7], binary[7:11], binary[11:16], binary[16:21], binary[21:27], binary[27:32]]
            for val in stamp[:]:
                dec = int(val, 2)
                stamp.remove(val)
                stamp.append(dec)
            stamp[0] = stamp[0] + 1980
            stamp[5] = stamp[5] * 2
            datetime_obj = datetime(stamp[0], stamp[1], stamp[2], stamp[3], stamp[4], stamp[5])
            self.proc_msdos = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_msdos = 'N/A'

    def to_msdos(self):
        """Convert a date to an MS-DOS timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            year = '{0:07b}'.format(datetime_obj.year - 1980)
            month = '{0:04b}'.format(datetime_obj.month)
            day = '{0:05b}'.format(datetime_obj.day)
            hour = '{0:05b}'.format(datetime_obj.hour)
            minute = '{0:06b}'.format(datetime_obj.minute)
            seconds = '{0:05b}'.format(int(datetime_obj.second / 2))
            hexval = str(hexlify(struct.pack('>I', int(year + month + day + hour + minute + seconds, 2)))).strip("b'").strip("'")
            self.out_msdos = ''.join([hexval[i:i+2] for i in range(0, len(hexval), 2)][::-1])
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_msdos = 'N/A'

    def convert_systime(self):
        """Convert a Microsoft 128 bit SYSTEMTIME timestamp to a date"""
        try:
            to_le = str(hexlify(unhexlify(sys.argv[2])[::-1])).strip("b'").strip("'")
            converted = [to_le[i:i + 4] for i in range(0, len(to_le), 4)][::-1]
            stamp = []
            for i in converted:
                dec = int(i, 16)
                stamp.append(dec)
            datetime_obj = datetime(stamp[0], stamp[1], stamp[3], stamp[4], stamp[5], stamp[6], stamp[7]*1000)
            self.proc_systemtime = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_systemtime = 'N/A'

    def to_systime(self):
        """Convert a date to a Microsoft 128 bit SYSTEMTIME timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            micro = int(datetime_obj.microsecond / 1000)
            full_date = datetime_obj.strftime('%Y, %m, %w, %d, %H, %M, %S, ' + str(micro))
            stamp = []
            if sys.version_info >= (3, 0):
                for value in full_date.split(','):
                    stamp.append(hexlify(struct.pack('<H', int(value))).decode('utf8'))
            elif sys.version_info < (3, 0):
                for value in full_date.split(','):
                    stamp.append(hexlify(struct.pack('<H', int(value))))
            self.out_systemtime = ''.join(stamp)
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_systemtime = 'N/A'

    def convert_filetime(self):
        """Convert a Microsoft FILETIME/LDAP timestamp to a date"""
        try:
            datetime_obj = datetime.utcfromtimestamp((float(sys.argv[2]) - self.epoch_as_filetime) / self.hundreds_nano)
            self.proc_filetime = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_filetime = 'N/A'

    def to_filetime(self):
        """Convert a date to a Microsoft FILETIME/LDAP timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            self.out_filetime = str(int((datetime_obj - self.epoch_1970).total_seconds() * self.hundreds_nano + self.epoch_as_filetime))
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_filetime = 'N/A'

    def convert_prtime(self):
        """Convert a Mozilla PRTime timestamp to a date"""
        try:
            datetime_obj = self.epoch_1970 + timedelta(microseconds=int(sys.argv[2]))
            self.proc_prtime = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_prtime = 'N/A'

    def to_prtime(self):
        """Convert a date to Mozilla's PRTime timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            self.out_prtime = str(int((datetime_obj - self.epoch_1970).total_seconds() * 1000000))
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_prtime = 'N/A'

    def convert_ole_auto(self):
        """Convert an OLE Automation timestamp to a date"""
        try:
            datetime_obj = self.epoch_1899 + timedelta(days=float(sys.argv[2]))
            self.proc_ole_auto = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_ole_auto = 'N/A'

    def to_ole_auto(self):
        """Convert a date to an OLE Automation timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            self.out_ole_auto = "{0:.12f}".format((datetime_obj - self.epoch_1899).total_seconds() / 86400)
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_ole_auto = 'N/A'

    def convert_ios_time(self):
        """Convert an iOS 11 (beta) timestamp to a date"""
        try:
            datetime_obj = (int(sys.argv[2]) / int(self.nano_2001)) + 978307200
            self.proc_iostime = datetime.utcfromtimestamp(datetime_obj).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_iostime = 'N/A'

    def to_ios_time(self):
        """Convert a date to an iOS 11 (beta) timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            self.out_iostime = str(int(((datetime_obj - self.epoch_2001).total_seconds()) * self.nano_2001))
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_iostime = 'N/A'

    def convert_sym_time(self):
        """Convert a Symantec 12-byte hex timestamp to a date"""
        try:
            hex_to_dec = [int(sys.argv[2][i:i+2], 16) for i in range(0, len(sys.argv[2]), 2)]
            hex_to_dec[0] = hex_to_dec[0] + 1970
            hex_to_dec[1] = hex_to_dec[1] + 1
            datetime_obj = datetime(hex_to_dec[0], hex_to_dec[1], hex_to_dec[2], hex_to_dec[3], hex_to_dec[4], hex_to_dec[5])
            self.proc_symtime = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.proc_symtime = 'N/A'

    def to_sym_time(self):
        """Convert a date to Symantec's 12-byte hex timestamp"""
        try:
            datetime_obj = duparser.parse(sys.argv[2])
            sym_year = '{0:x}'.format(datetime_obj.year - 1970).zfill(2)
            sym_month = '{0:x}'.format(datetime_obj.month - 1).zfill(2)
            sym_day = '{0:x}'.format(datetime_obj.day).zfill(2)
            sym_hour = '{0:x}'.format(datetime_obj.hour).zfill(2)
            sym_minute = '{0:x}'.format(datetime_obj.minute).zfill(2)
            sym_second = '{0:x}'.format(datetime_obj.second).zfill(2)
            self.out_symtime = sym_year + sym_month + sym_day + sym_hour + sym_minute + sym_second
        except Exception as e:
            logging.error(str(type(e)) + "," + str(e))
            self.out_symtime = 'N/A'

    def output(self):
        """Output all processed timestamp values"""
        if isinstance(self.proc_unix_sec, str):
            print ("Unix Seconds: "  + self.proc_unix_sec + " UTC")

        if isinstance(self.proc_unix_milli, str):
            print ("Unix Milliseconds: " + self.proc_unix_milli + " UTC")

        if isinstance(self.proc_windows_hex_64, str):
            print ("Windows 64 bit Hex BE: " + self.proc_windows_hex_64 + " UTC")

        if isinstance(self.proc_windows_hex_le, str):
            print ("Windows 64 bit Hex LE: " + self.proc_windows_hex_le + " UTC")

        if isinstance(self.proc_chrome_time, str):
            print ("Google Chrome: " + self.proc_chrome_time + " UTC")

        if isinstance(self.proc_ad_time, str):
            print ("Active Directory DateTime: " + self.proc_ad_time + " UTC")

        if isinstance(self.proc_unix_hex_32, str):
            print ("Unix Hex 32 bit BE: " + self.proc_unix_hex_32 + " UTC")

        if isinstance(self.proc_unix_hex_32le, str):
            print ("Unix Hex 32 bit LE: " + self.proc_unix_hex_32le + " UTC")

        if isinstance(self.proc_cookie, str):
            print ("Windows Cookie Date: " + self.proc_cookie + " UTC")

        if isinstance(self.proc_ole_be, str):
            print ("Windows OLE 64 bit double BE: " + self.proc_ole_be + " UTC")

        if isinstance(self.proc_ole_le, str):
            print ("Windows OLE 64 bit double LE: " + self.proc_ole_le + " UTC")

        if isinstance(self.proc_mac, str):
            print ("Mac Absolute Time: " + self.proc_mac + " UTC")

        if isinstance(self.proc_hfs_be, str):
            print ("HFS/HFS+ 32 bit Hex BE: " + self.proc_hfs_be + " HFS Local / HFS+ UTC")

        if isinstance(self.proc_hfs_le, str):
            print ("HFS/HFS+ 32 bit Hex LE: " + self.proc_hfs_le + " HFS Local / HFS+ UTC")

        if isinstance(self.proc_msdos, str):
            print ("MS-DOS 32 bit Hex Value: " + self.proc_msdos + " Local")

        if isinstance(self.proc_fat_dt, str):
            print ("FAT Date + Time: " + self.proc_fat_dt + " Local")

        if isinstance(self.proc_systemtime, str):
            print ("Microsoft 128 bit SYSTEMTIME: " + self.proc_systemtime + " UTC")

        if isinstance(self.proc_filetime, str):
            print ("Microsoft FILETIME/LDAP time: " + self.proc_filetime + " UTC")

        if isinstance(self.proc_prtime, str):
            print ("Mozilla PRTime: " + self.proc_prtime + " UTC")

        if isinstance(self.proc_ole_auto, str):
            print ("OLE Automation Date: " + self.proc_ole_auto + " UTC")

        if isinstance(self.proc_iostime, str):
            print ("iOS 11 beta Date: " + self.proc_iostime)

        if isinstance(self.proc_symtime, str):
            print ("Symantec AV timestamp: " + self.proc_symtime + " UTC")
        
    def date_output(self):
        """Output all processed dates from timestamp values"""
        if isinstance(self.out_unix_sec, str):
            print ("Unix Seconds: " + self.out_unix_sec)

        if isinstance(self.out_unix_milli, str):
            print ("Unix Milliseconds: " + self.out_unix_milli)

        if isinstance(self.out_windows_hex_64, str):
            print ("Windows 64 bit Hex BE: " + self.out_windows_hex_64)

        if isinstance(self.out_windows_hex_le, str):
            print ("Windows 64 bit Hex LE: " + self.out_windows_hex_le)

        if isinstance(self.out_chrome_time, str):
            print ("Google Chrome: " + self.out_chrome_time)

        if isinstance(self.out_active_directory_time, str):
            print ("Active Directory DateTime: " + self.out_active_directory_time)

        if isinstance(self.out_unix_hex_32, str):
            print ("Unix Hex 32 bit BE: " + self.out_unix_hex_32)

        if isinstance(self.out_unix_hex_32le, str):
            print ("Unix Hex 32 bit LE: " + self.out_unix_hex_32le)

        if isinstance(self.out_cookie, str):
            print ("Windows Cookie Date: " + self.out_cookie)

        if isinstance(self.out_ole_be, str):
            print ("Windows OLE 64 bit double BE: " + self.out_ole_be)

        if isinstance(self.out_ole_le, str):
            print ("Windows OLE 64 bit double LE: " + self.out_ole_le)

        if isinstance(self.out_mac, str):
            print ("Mac Absolute Time: " + self.out_mac)

        if isinstance(self.out_hfs_be, str):
            print ("HFS/HFS+ 32 bit Hex BE: " + self.out_hfs_be)

        if isinstance(self.out_hfs_le, str):
            print ("HFS/HFS+ 32 bit Hex LE: " + self.out_hfs_le)

        if isinstance(self.out_msdos, str):
            print ("MS-DOS 32 bit Hex Value: " + self.out_msdos)

        if isinstance(self.out_fat_dt, str):
            print ("FAT Date + Time: " + self.out_fat_dt)

        if isinstance(self.out_systemtime, str):
            print ("Microsoft 128 bit SYSTEMTIME: " + self.out_systemtime)

        if isinstance(self.out_filetime, str):
            print ("Microsoft FILETIME/LDAP time: " + self.out_filetime)

        if isinstance(self.out_prtime, str):
            print ("Mozilla PRTime: " + self.out_prtime)

        if isinstance(self.out_ole_auto, str):
            print ("OLE Automation Date: " + self.out_ole_auto)

        if isinstance(self.out_iostime, str):
            print ("iOS 11 beta Date: " + self.out_iostime)

        if isinstance(self.out_symtime, str):
            print ("Symantec AV time: " + self.out_symtime)

if __name__ == '__main__':
    arg_parse = argparse.ArgumentParser(description="Date Decode Time Converter", epilog="For errors and logging, see decoder.log")
    arg_parse.add_argument('--unix', metavar='<value>', help='convert from Unix Seconds', required=False)
    arg_parse.add_argument('--umil', metavar='<value>', help='convert from Unix Milliseconds', required=False)
    arg_parse.add_argument('--wh', metavar='<value>', help='convert from Windows 64 bit Hex BE', required=False)
    arg_parse.add_argument('--whle', metavar='<value>', help='convert from Windows 64 bit Hex LE', required=False)
    arg_parse.add_argument('--goog', metavar='<value>', help='convert from Google Chrome time', required=False)
    arg_parse.add_argument('--active', metavar='<value>', help='convert from Active Directory DateTime', required=False)
    arg_parse.add_argument('--uhbe', metavar='<value>', help='convert from Unix Hex 32 bit BE', required=False)
    arg_parse.add_argument('--uhle', metavar='<value>', help='convert from Unix Hex 32 bit LE', required=False)
    arg_parse.add_argument('--cookie', metavar='<value>', help='convert from Windows Cookie Date (Low Value,High Value)', required=False)
    arg_parse.add_argument('--oleb', metavar='<value>', help='convert from Windows OLE 64 bit BE - remove 0x and spaces!\n Example from SRUM: 0x40e33f5d 0x97dfe8fb should be 40e33f5d97dfe8fb', required=False)
    arg_parse.add_argument('--olel', metavar='<value>', help='convert from Windows OLE 64 bit LE', required=False)
    arg_parse.add_argument('--mac', metavar='<value>', help='convert from Mac Absolute Time', required=False)
    arg_parse.add_argument('--hfsbe', metavar='<value>', help='convert from HFS/HFS+ BE times (HFS is Local, HFS+ is UTC)', required=False)
    arg_parse.add_argument('--hfsle', metavar='<value>', help='convert from HFS/HFS+ LE times (HFS is Local, HFS+ is UTC)', required=False)
    arg_parse.add_argument('--msdos', metavar='<value>', help='convert from 32 bit MS-DOS time - result is Local Time', required=False)
    arg_parse.add_argument('--fat', metavar='<value>', help='convert from FAT Date + Time (wFat)', required=False)
    arg_parse.add_argument('--sys', metavar='<value>', help='convert from 128 bit SYSTEMTIME', required=False)
    arg_parse.add_argument('--ft', metavar='<value>', help='convert from FILETIME/LDAP timestamp', required=False)
    arg_parse.add_argument('--pr', metavar='<value>', help='convert from Mozilla\'s PRTime', required=False)
    arg_parse.add_argument('--auto', metavar='<value>', help='convert from OLE Automation Date format', required=False)
    arg_parse.add_argument('--ios', metavar='<value>', help='convert from iOS 11 beta Timestamp', required=False)
    arg_parse.add_argument('--sym', metavar='<value>', help='convert Symantec\'s 12-byte AV Timestamp', required=False)
    arg_parse.add_argument('--guess', metavar='<value>', help='guess timestamp and output all possibilities', required=False)
    arg_parse.add_argument('--timestamp', metavar='<date>', help='convert date to all timestamps. enter date as \'Y-M-D HH:MM:SS.m\' in 24h fmt', required=False)
    arg_parse.add_argument('--version', '-v', action='version', version='%(prog)s' +str(__version__))
    args = arg_parse.parse_args()

    logger_output = 'decoder.log'
    logging.basicConfig(filename=logger_output, level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(funcName)s | %(message)s', filemode='a')
    logging.debug('System ' + sys.platform)
    logging.debug('Version ' + sys.version)
    dd = DateDecoder()
    dd.run()
