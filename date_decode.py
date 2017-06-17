#!/usr/bin/env python
from dateutil import parser as duparser
from datetime import datetime, timedelta
import logging
import struct
from binascii import hexlify, unhexlify
import argparse
import sys

__author__='Corey Forman'
__date__='17 Jun 17'
__version__='0.3'
__description__='Python CLI Date Time Conversion Tool'

class DateDecoder(object):
  def __init__(self):
    self.epoch_1601 = 11644473600000000
    self.epoch_1970 = datetime(1970,1,1)
    self.epoch_2001 = datetime(2001,1,1)
    self.hundreds_nano = 10000000
    self.epoch_as_filetime = 116444736000000000
    self.epoch_1899 = datetime(1899,12,30,0,0,0)
    self.epoch_1904 = datetime(1904,1,1)

  def run(self):
    if len(sys.argv[1:])==0:
      argparse.print_help()
      argparse.exit()
    logging.info('Launching Date Decode')
    logging.info('Processing Timestamp: ' + sys.argv[2])
    logging.info('Input Time Format: ' + sys.argv[1])
    logging.info('Starting Date Decoder v.' +str(__version__))
    if args.unix:
      try:
        self.convertUnixSeconds()
        print ("Unix Seconds: " + self.processed_unix_seconds + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.umil:
      try:
        self.convertUnixMilli()
        print ("Unix Milliseconds: " + self.processed_unix_milli + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.wh:
      try:
        self.convertWindows64Hex()
        print ("Windows 64 bit Hex BE: " + self.processed_windows_hex_64 + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.whle:
      try:
        self.convertWindows64HexLE()
        print ("Windows 64 bit Hex LE: " + self.processed_windows_hex_le + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))   
    elif args.goog:
      try:
        self.convertChromeTimestamps()      
        print ("Google Chrome Time: " + self.processed_chrome_time + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.active:
      try:
        self.convertActiveDirectory_DateTime()
        print ("Active Directory Timestamp: " + self.processed_active_directory_time + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.uhbe:
      try: 
        self.convertUnixHex32BE()
        print ("Unix Hex 32 bit BE: " + self.processed_unix_hex_32 + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.uhle:
      try:
        self.convertUnixHex32LE()
        print ("Unix Hex 32 bit LE: " + self.processed_unix_hex_32le + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.cookie:
      try:
        self.convertCookieDate()
        print ("Windows Cookie Date: " + self.processed_cookie + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.oleb:
      try:
        self.convertOleBE()
        print ("Windows OLE 64 bit double BE: " + self.processed_ole_be + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.olel:
      try:
        self.convertOleLE()
        print ("Windows OLE 64 bit double LE: " + self.processed_ole_le + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.mac:
      try:
        self.convertMac()
        print ("Mac Absolute Time: " + self.processed_mac + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.hfsbe:
      try:
        self.convertHfsBE()
        print ("HFS/HFS+ 32 bit Hex BE: " + self.processed_hfs_be + " HFS Local / HFS+ UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.hfsle:
      try:
        self.convertHfsLE()
        print ("HFS/HFS+ 32 big Hex LE: " + self.processed_hfs_le + " HFS Local / HFS+ UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.msdos:
      try:
        self.convertMsdos()
        print ("MS-DOS 32 bit Hex Value: " + self.processed_msdos + " Local")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.fat:
      try:
        self.convertFatDateTime()
        print ("FAT Date + Time: " + self.processed_fat_dt + " Local")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.sys:
      try:
        self.convertSystime()
        print ("Microsoft 128 bit SYSTEMTIME: " + self.processed_systemtime + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.ft:
      try:
        self.convertFiletime()
        print ("Microsoft FILETIME/LDAP time: " + self.processed_filetime + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))    
    elif args.pr:
      try:
        self.convertPrtime()
        print ("Mozilla PRTime: " + self.processed_prtime + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.auto:
      try:
        self.convertOleAutomation()
        print ("OLE Automation Date: " + self.processed_ole_auto + " UTC")
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.timestamp:
      try:
        self.toTimestamps()
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))
    elif args.guess:
      try:
        self.convertAll()
      except Exception as e:
        logging.error(str(type(e)) + "," + str(e))

  def convertAll(self):
    print ('\nGuessing Date from Timestamp\n')

    self.convertUnixSeconds()
    self.convertUnixMilli()
    self.convertWindows64Hex()
    self.convertWindows64HexLE()
    self.convertChromeTimestamps()
    self.convertActiveDirectory_DateTime()
    self.convertUnixHex32BE()
    self.convertUnixHex32LE()
    self.convertCookieDate()
    self.convertOleBE()
    self.convertOleLE()
    self.convertMac()
    self.convertHfsBE()
    self.convertHfsLE()
    self.convertMsdos()
    self.convertFatDateTime()
    self.convertSystime()
    self.convertFiletime()
    self.convertPrtime()
    self.convertOleAutomation()
    self.output()
    print ('\r')

  def toTimestamps(self):
    print ('\nGuessing Timestamp From Date\n')
 
    self.toUnixSeconds()
    self.toUnixMilli()
    self.toWindows64Hex()
    self.toWindows64HexLE()
    self.toChromeTimestamps()
    self.toActiveDirectory_DateTime()
    self.toUnixHex32BE()
    self.toUnixHex32LE()
    self.toCookieDate()
    self.toOleBE()
    self.toOleLE()
    self.toMac()
    self.toHfsBE()
    self.toHfsLE()
    self.toMsdos()
    self.toFatDateTime()
    self.toSystime()
    self.toFiletime()
    self.toPrtime()
    self.toOleAutomation()
    self.dateOutput()
    print ('\r')

  def convertUnixSeconds(self):
    try:
      self.processed_unix_seconds = datetime.utcfromtimestamp(float(sys.argv[2])).strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_unix_seconds = 'N/A'

  def toUnixSeconds(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      self.output_unix_seconds = str(int((datetime_obj - self.epoch_1970).total_seconds()))
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_unix_seconds = 'N/A'

  def convertUnixMilli(self):
    try:
      self.processed_unix_milli = datetime.utcfromtimestamp(float(sys.argv[2]) / 1000.0).strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_unix_milli = 'N/A'

  def toUnixMilli(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      self.output_unix_milli = str(int((datetime_obj - self.epoch_1970).total_seconds()*1000))
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_unix_milli = 'N/A'

  def convertWindows64Hex(self):
    try:
      base10_microseconds = int(sys.argv[2], 16) / 10
      datetime_obj = datetime(1601,1,1) + timedelta(microseconds=base10_microseconds)
      self.processed_windows_hex_64 = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_windows_hex_64 = 'N/A'

  def toWindows64Hex(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      minus_epoch = datetime_obj - datetime(1601,1,1,0,0,0)
      calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
      self.output_windows_hex_64 = str(hex(int(calculated_time)*10))[2:].zfill(16)
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_windows_hex_64 = 'N/A'

  def convertWindows64HexLE(self):
    try:
      converted_time = struct.unpack("<Q", unhexlify(sys.argv[2]))[0]
      datetime_obj = datetime(1601,1,1,0,0,0) + timedelta(microseconds=converted_time /10)
      self.processed_windows_hex_le = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_windows_hex_le = 'N/A'

  def toWindows64HexLE(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      minus_epoch = datetime_obj - datetime(1601,1,1,0,0,0)
      calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
      self.output_windows_hex_le = str(hexlify(struct.pack("<Q",int(calculated_time*10))))[2:].zfill(16).strip("'")
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_windows_hex_le = 'N/A'

  def convertChromeTimestamps(self):
    try:
      converted_time = datetime.fromtimestamp((float(sys.argv[2])-self.epoch_1601)/1000000)
      self.processed_chrome_time = converted_time.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_chrome_time = 'N/A'

  def toChromeTimestamps(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      chrome_time = (datetime_obj - self.epoch_1970).total_seconds()*1000000 + self.epoch_1601
      self.output_chrome_time = str(int(chrome_time))
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_chrome_time = 'N/A'

  def convertActiveDirectory_DateTime(self):
    try:
      part2, part1 = [int(h, base=16) for h in sys.argv[2].split(':')]
      converted_time = struct.unpack('>Q', struct.pack('>LL', part1, part2))[0]
      datetime_obj = datetime.utcfromtimestamp((converted_time - self.epoch_as_filetime) / self.hundreds_nano)
      self.processed_active_directory_time = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_active_directory_time = 'N/A'

  def toActiveDirectory_DateTime(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      minus_epoch = datetime_obj - datetime(1601,1,1,0,0,0)
      calculated_time = minus_epoch.microseconds + (minus_epoch.seconds * 1000000) + (minus_epoch.days * 86400000000)
      output = hexlify(struct.pack(">Q", int(calculated_time*10)))
      self.output_active_directory_time = str(output[8:]).strip("'b").strip("'") + ":" + str(output[:8]).strip("'b").strip("'")
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_active_directory_time = 'N/A'

  def convertUnixHex32BE(self):
    try:
      to_dec = int(sys.argv[2], 16)
      self.processed_unix_hex_32 = datetime.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_unix_hex_32 = 'N/A'

  def toUnixHex32BE(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      self.output_unix_hex_32 = str(hexlify(struct.pack(">L", int((datetime_obj - self.epoch_1970).total_seconds())))).strip("b'").strip("'")
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_unix_hex_32 = 'N/A'

  def convertUnixHex32LE(self):
    try:
      to_dec = struct.unpack("<L", unhexlify(sys.argv[2]))[0]
      self.processed_unix_hex_32le = datetime.utcfromtimestamp(float(to_dec)).strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_unix_hex_32le = 'N/A'

  def toUnixHex32LE(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      self.output_unix_hex_32le = str(hexlify(struct.pack("<L", int((datetime_obj - self.epoch_1970).total_seconds())))).strip("b'").strip("'")
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_unix_hex_32le = 'N/A'

  def convertCookieDate(self):
    try:
      low, high = [int(h, base=10) for h in sys.argv[2].split(',')]
      calc = 10**-7 * (high * 2**32 + low) - 11644473600
      datetime_obj = datetime.utcfromtimestamp(calc)
      self.processed_cookie = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_cookie = 'N/A'

  def toCookieDate(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      unix = int((datetime_obj - self.epoch_1970).total_seconds())
      high = int(((unix + 11644473600) * 10**7) / 2**32)
      low = int((unix + 11644473600) * 10**7) - (high * 2**32)
      self.output_cookie = str(low) + ',' + str(high)
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_cookie = 'N/A'

  def convertOleBE(self):
    try:
      delta = struct.unpack('>d',struct.pack('>Q', int(sys.argv[2], 16)))[0]
      datetime_obj = self.epoch_1899 + timedelta(days=delta)
      self.processed_ole_be = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_ole_be = 'N/A'

  def toOleBE(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      delta = (datetime_obj - self.epoch_1899).total_seconds() / 86400
      conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
      self.output_ole_be = str(hexlify(struct.pack('>Q', conv))).strip("b'").strip("'")
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_ole_be = 'N/A'

  def convertOleLE(self):
    try:
      to_le = hexlify(struct.pack('<Q', int(sys.argv[2],16)))
      delta = struct.unpack('>d',struct.pack('>Q', int(to_le, 16)))[0]
      datetime_obj = self.epoch_1899 + timedelta(days=delta)
      self.processed_ole_le = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_ole_le = 'N/A'

  def toOleLE(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      delta = (datetime_obj - self.epoch_1899).total_seconds() / 86400
      conv = struct.unpack('<Q', struct.pack('<d', delta))[0]
      self.output_ole_le = str(hexlify(struct.pack('<Q', conv))).strip("b'").strip("'")
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_ole_le = 'N/A'

  def convertMac(self):
    try:
      datetime_obj = self.epoch_2001 + timedelta(seconds=int(sys.argv[2]))
      self.processed_mac = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_mac = 'N/A'

  def toMac(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      self.output_mac = str(int((datetime_obj - self.epoch_2001).total_seconds()))
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_mac = 'N/A'

  def convertHfsBE(self):
    try:
      datetime_obj = self.epoch_1904 + timedelta(seconds=int(sys.argv[2],16))
      self.processed_hfs_be = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_hfs_be = 'N/A'

  def toHfsBE(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      conv = int((datetime_obj - self.epoch_1904).total_seconds())
      self.output_hfs_be = '{0:08x}'.format(conv)
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_hfs_be = 'N/A'

  def convertHfsLE(self):
    try:
      to_le = struct.unpack('>I',struct.pack('<I', int(sys.argv[2], 16)))[0]
      datetime_obj = self.epoch_1904 + timedelta(seconds=to_le)
      self.processed_hfs_le = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_hfs_le = 'N/A'

  def toHfsLE(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      conv = int((datetime_obj - self.epoch_1904).total_seconds())
      self.output_hfs_le = str(hexlify(struct.pack('<I', conv))).strip("b'").strip("'")
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_hfs_le = 'N/A'

  def convertFatDateTime(self):
    try:
      byte_swap = [sys.argv[2][i:i+2] for i in range(0, len(sys.argv[2]), 2)]
      to_le = byte_swap[1]+byte_swap[0]+byte_swap[3]+byte_swap[2]
      bin_conv = int(to_le, 16)
      bin = '{0:032b}'.format(bin_conv)
      ts = [bin[:7], bin[7:11], bin[11:16], bin[16:21], bin[21:27], bin[27:32]]
      for bin in ts[:]:
        dec = int(bin, 2)
        ts.remove(bin)
        ts.append(dec)
      ts[0] = ts[0] + 1980
      ts[5] = ts[5] * 2
      datetime_obj = datetime(ts[0], ts[1], ts[2], ts[3], ts[4], ts[5])
      self.processed_fat_dt = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_fat_dt = 'N/A'

  def toFatDateTime(self):
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
      self.output_fat_dt = ''.join([byte_swap[i:i+4] for i in range(0, len(byte_swap), 4)][::-1])
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_fat_dt = 'N/A'  

  def convertMsdos(self):
    try:
      swap = ''.join([sys.argv[2][i:i+2] for i in range(0, len(sys.argv[2]), 2)][::-1])
      bin_conv = int(swap, 16)
      bin = '{0:032b}'.format(bin_conv)
      ts = [bin[:7], bin[7:11], bin[11:16], bin[16:21], bin[21:27], bin[27:32]]
      for val in ts[:]:
        dec = int(val, 2)
        ts.remove(val)
        ts.append(dec)
      ts[0] = ts[0] + 1980
      ts[5] = ts[5] * 2
      datetime_obj = datetime(ts[0], ts[1], ts[2], ts[3], ts[4], ts[5])
      self.processed_msdos = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_msdos = 'N/A'

  def toMsdos(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      year = '{0:07b}'.format(datetime_obj.year - 1980)
      month = '{0:04b}'.format(datetime_obj.month)
      day = '{0:05b}'.format(datetime_obj.day)
      hour = '{0:05b}'.format(datetime_obj.hour)
      minute = '{0:06b}'.format(datetime_obj.minute)
      seconds = '{0:05b}'.format(int(datetime_obj.second / 2))
      hexval = str(hexlify(struct.pack('>I', int(year + month + day + hour + minute + seconds, 2)))).strip("b'").strip("'")
      self.output_msdos = ''.join([hexval[i:i+2] for i in range(0, len(hexval),2)][::-1])
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_msdos = 'N/A'

  def convertSystime(self):
    try:
      from_be = sys.argv[2].decode('hex')
      to_le = from_be[::-1].encode('hex')
      t = [to_le[i:i + 4] for i in range(0, len(to_le), 4)][::-1]
      ts = []
      for i in t:
        dec = int(i, 16)
        ts.append(dec)
      datetime_obj = datetime(ts[0], ts[1], ts[3], ts[4], ts[5], ts[6], ts[7]*1000)
      self.processed_systemtime = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_systemtime = 'N/A'

  def toSystime(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      micro = int(datetime_obj.microsecond / 1000)
      full_date = datetime_obj.strftime('%Y, %m, %w, %d, %H, %M, %S, ' + str(micro))
      ts = []
      if sys.version_info >= (3,0):
        for value in full_date.split(','):
          ts.append(hexlify(struct.pack('<H', int(value))).decode('utf8'))
      elif sys.version_info < (3,0):
        for value in full_date.split(','):
          ts.append(hexlify(struct.pack('<H', int(value))))
      self.output_systemtime = ''.join(ts)
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_systemtime = 'N/A'

  def convertFiletime(self):
    try:
      datetime_obj = datetime.utcfromtimestamp((float(sys.argv[2]) - self.epoch_as_filetime) / self.hundreds_nano)
      self.processed_filetime = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_filetime = 'N/A'

  def toFiletime(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      self.output_filetime = str(int((datetime_obj - self.epoch_1970).total_seconds() * self.hundreds_nano + self.epoch_as_filetime))
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_filetime = 'N/A'

  def convertPrtime(self):
    try:
      datetime_obj = self.epoch_1970 + timedelta(microseconds=int(sys.argv[2]))
      self.processed_prtime = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_prtime = 'N/A'      

  def toPrtime(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      self.output_prtime = str(int((datetime_obj - self.epoch_1970).total_seconds() * 1000000))
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_prtime = 'N/A'  

  def convertOleAutomation(self):
    try:
      datetime_obj = self.epoch_1899 + timedelta(days=float(sys.argv[2]))
      self.processed_ole_auto = datetime_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.processed_ole_auto = 'N/A'

  def toOleAutomation(self):
    try:
      datetime_obj = duparser.parse(sys.argv[2])
      self.output_ole_auto = "{0:.12f}".format((datetime_obj - self.epoch_1899).total_seconds() / 86400)
    except Exception as e:
      logging.error(str(type(e)) + "," + str(e))
      self.output_ole_auto = 'N/A'

  def output(self):
    if isinstance(self.processed_unix_seconds, str):
      print ("Unix Seconds: "  + self.processed_unix_seconds)

    if isinstance(self.processed_unix_milli, str):
      print ("Unix Milliseconds: " + self.processed_unix_milli)

    if isinstance(self.processed_windows_hex_64, str):
      print ("Windows 64 bit Hex BE: " + self.processed_windows_hex_64)

    if isinstance(self.processed_windows_hex_le, str):
      print ("Windows 64 bit Hex LE: " + self.processed_windows_hex_le)

    if isinstance(self.processed_chrome_time, str):
      print ("Google Chrome: " + self.processed_chrome_time)

    if isinstance(self.processed_active_directory_time, str):
      print ("Active Directory DateTime: " + self.processed_active_directory_time)

    if isinstance(self.processed_unix_hex_32, str):
      print ("Unix Hex 32 bit BE: " + self.processed_unix_hex_32)

    if isinstance(self.processed_unix_hex_32le, str):
      print ("Unix Hex 32 bit LE: " + self.processed_unix_hex_32le)

    if isinstance(self.processed_cookie, str):
      print ("Windows Cookie Date: " + self.processed_cookie)

    if isinstance(self.processed_ole_be, str):
      print ("Windows OLE 64 bit double BE: " + self.processed_ole_be)

    if isinstance(self.processed_ole_le, str):
      print ("Windows OLE 64 bit double LE: " + self.processed_ole_le)

    if isinstance(self.processed_mac, str):
      print ("Mac Absolute Time: " + self.processed_mac)

    if isinstance(self.processed_hfs_be, str):
      print ("HFS/HFS+ 32 bit Hex BE: " + self.processed_hfs_be)

    if isinstance(self.processed_hfs_le, str):
      print ("HFS/HFS+ 32 bit Hex LE: " + self.processed_hfs_le)

    if isinstance(self.processed_msdos, str):
      print ("MS-DOS 32 bit Hex Value: " + self.processed_msdos)

    if isinstance(self.processed_fat_dt, str):
      print ("FAT Date + Time: " + self.processed_fat_dt)

    if isinstance(self.processed_systemtime, str):
      print ("Microsoft 128 bit SYSTEMTIME: " + self.processed_systemtime)

    if isinstance(self.processed_filetime, str):
      print ("Microsoft FILETIME/LDAP time: " + self.processed_filetime)

    if isinstance(self.processed_prtime, str):
      print ("Mozilla PRTime: " + self.processed_prtime)

    if isinstance(self.processed_ole_auto, str):
      print ("OLE Automation Date: " + self.processed_ole_auto)

  def dateOutput(self):
    if isinstance(self.output_unix_seconds, str):
      print ("Unix Seconds: " + self.output_unix_seconds)

    if isinstance(self.output_unix_milli, str):
      print ("Unix Milliseconds: " + self.output_unix_milli)

    if isinstance(self.output_windows_hex_64, str):
      print ("Windows 64 bit Hex BE: " + self.output_windows_hex_64)

    if isinstance(self.output_windows_hex_le, str):
      print ("Windows 64 bit Hex LE: " + self.output_windows_hex_le)

    if isinstance(self.output_chrome_time, str):
      print ("Google Chrome: " + self.output_chrome_time)

    if isinstance(self.output_active_directory_time, str):
      print ("Active Directory DateTime: " + self.output_active_directory_time)

    if isinstance(self.output_unix_hex_32, str):
      print ("Unix Hex 32 bit BE: " + self.output_unix_hex_32)

    if isinstance(self.output_unix_hex_32le, str):
      print ("Unix Hex 32 bit LE: " + self.output_unix_hex_32le)

    if isinstance(self.output_cookie, str):
      print ("Windows Cookie Date: " + self.output_cookie)

    if isinstance(self.output_ole_be, str):
      print ("Windows OLE 64 bit double BE: " + self.output_ole_be)

    if isinstance(self.output_ole_le, str):
      print ("Windows OLE 64 bit double LE: " + self.output_ole_le)

    if isinstance(self.output_mac, str):
      print ("Mac Absolute Time: " + self.output_mac)

    if isinstance(self.output_hfs_be, str):
      print ("HFS/HFS+ 32 bit Hex BE: " + self.output_hfs_be)

    if isinstance(self.output_hfs_le, str):
      print ("HFS/HFS+ 32 bit Hex LE: " + self.output_hfs_le)

    if isinstance(self.output_msdos, str):
      print ("MS-DOS 32 bit Hex Value: " + self.output_msdos)

    if isinstance(self.output_fat_dt, str):
      print ("FAT Date + Time: " + self.output_fat_dt)

    if isinstance(self.output_systemtime, str):
      print ("Microsoft 128 bit SYSTEMTIME: " + self.output_systemtime)

    if isinstance(self.output_filetime, str):
      print ("Microsoft FILETIME/LDAP time: " + self.output_filetime)

    if isinstance(self.output_prtime, str):
      print ("Mozilla PRTime: " + self.output_prtime)

    if isinstance(self.output_ole_auto, str):
      print ("OLE Automation Date: " + self.output_ole_auto)


if __name__ == '__main__':
  argparse = argparse.ArgumentParser(description="Date Decode Time Converter", epilog="For errors and logging, see decoder.log")
  argparse.add_argument('--unix', metavar='<value>', help='convert from Unix Seconds', required=False)
  argparse.add_argument('--umil', metavar='<value>', help='convert from Unix Milliseconds', required=False)
  argparse.add_argument('--wh', metavar='<value>', help='convert from Windows 64 bit Hex BE', required=False)
  argparse.add_argument('--whle', metavar='<value>', help='convert from Windows 64 bit Hex LE', required=False)
  argparse.add_argument('--goog', metavar='<value>', help='convert from Google Chrome time', required=False)
  argparse.add_argument('--active', metavar='<value>', help='convert from Active Directory DateTime', required=False)
  argparse.add_argument('--uhbe', metavar='<value>', help='convert from Unix Hex 32 bit BE', required=False)
  argparse.add_argument('--uhle', metavar='<value>', help='convert from Unix Hex 32 bit LE', required=False)
  argparse.add_argument('--cookie', metavar='<value>', help='convert from Windows Cookie Date (Low Value,High Value)', required=False)
  argparse.add_argument('--oleb', metavar='<value>', help='convert from Windows OLE 64 bit BE - remove 0x and spaces!\n Example from SRUM: 0x40e33f5d 0x97dfe8fb should be 40e33f5d97dfe8fb', required=False)
  argparse.add_argument('--olel', metavar='<value>', help='convert from Windows OLE 64 bit LE', required=False)
  argparse.add_argument('--mac', metavar='<value>', help='convert from Mac Absolute Time', required=False)
  argparse.add_argument('--hfsbe', metavar='<value>', help='convert from HFS/HFS+ BE times (HFS is Local, HFS+ is UTC)', required=False)
  argparse.add_argument('--hfsle', metavar='<value>', help='convert from HFS/HFS+ LE times (HFS is Local, HFS+ is UTC)', required=False)
  argparse.add_argument('--msdos', metavar='<value>', help='convert from 32 bit MS-DOS time - result is Local Time', required=False)
  argparse.add_argument('--fat', metavar='<value>', help='convert from FAT Date + Time (wFat)', required=False)
  argparse.add_argument('--sys', metavar='<value>', help='convert from 128 bit SYSTEMTIME', required=False)
  argparse.add_argument('--ft', metavar='<value>', help='convert from FILETIME/LDAP timestamp', required=False)
  argparse.add_argument('--pr', metavar='<value>', help='convert from Mozilla\'s PRTime', required=False)
  argparse.add_argument('--auto', metavar='<value>', help='convert from OLE Automation Date format', required=False)
  argparse.add_argument('--guess', metavar='<value>', help='guess timestamp and output all possibilities', required=False)
  argparse.add_argument('--timestamp', metavar='<date>', help='convert date to all timestamps. enter date as \'Y-M-D HH:MM:SS.m\' in 24h fmt', required=False)
  argparse.add_argument('--version', '-v', action='version', version='%(prog)s' +str( __version__))
  args = argparse.parse_args()

  log_path = 'decoder.log'
  logging.basicConfig(filename=log_path, level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(funcName)s | %(message)s', filemode='a')
  logging.debug('System ' + sys.platform)
  logging.debug('Version ' + sys.version)
  dd = DateDecoder()
  dd.run()
