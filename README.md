# Time Decode
A timestamp and date decoder. 
Compatible with Python 3.x.
(can be compatible with Python 2.7x with minor changes)

I noticed a lack of timestamp conversion utilities in a number of different linux systems. Since I happen to use linux in my day-to-day work I thought this would help.

This was developed with the Digital Forensics field in mind, so all of the testing has been done with the up-to-date SIFT Kit from SANS.
If you have any questions, suggestions, helpful thoughts of any kind, please feel free to drop me a line.

# Requirements
For python3, dateutil does not come pre-installed as a module. It will need to be installed manually:

`sudo apt-get install python3-dateutil` or `pip install python-dateutil`

# Install
`pip3 install time-decode` or `pip3 install git+https://github.com/digitalsleuth/time_decode`

This python script provides the following conversions from existing timestamps:

- Unix Seconds
- Unix Milliseconds
- Windows 64 bit Hex (in Big Endian)
- Windows 64 bit Hex (in Little Endian)
- Google Chrome Time
- Active Directory/LDAP time
- Unix Hex 32 bit (in Big Endian)
- Unix Hex 32 bit (in Little Endian)
- Cookie Time (Low Value,High Value)
- Windows OLE 64 bit double (in Big Endian)
- Windows OLE 64 bit double (in Little Endian)
- Mac Absolute Time
- Mac OS/HFS+ Decimal Time
- HFS/HFS+ Time (in Big Endian)
- HFS/HFS+ Time (in Little Endian)
- MS-DOS 32 bit Hex
- MS-DOS FAT Date + Time
- Microsoft 128 bit SYSTEMTIME
- Microsoft FILETIME
- Mozilla PRTime
- OLE Automation Date/Time
- iOS 11 Date/Time
- Symantec AV timestamp
- GPS timestamps
- Google EI URL timestamp (thanks to http://cheeky4n6monkey.blogspot.com/2014/10/google-eid.html)
- iOS Binary Plist (Mac Absolute + milli/nano seconds)
- GSM Timestamps
- Virtual Machine Snapshot timestamp (vmsd createTimeHigh / createTimeLow)

Note that HFS times are in Local Time, where HFS+ times are in UTC. MS-DOS 32 bit Hex values and MS-DOS FAT Date+Time are also in Local Time of the source generating the timestamp. All other times, unless expressly mentioned, are in UTC.

I have added a feature to 'guess' in what format the timestamp is that you've provided. This will run the timestamp you provide against all methods, and provide an output if human-readable.
There is also the ability to convert a date-time to all of the aforementioned timestamps. Simply use the following command:

`time_decode.py --timestamp "2017-06-02 13:14:15.678"`
or for timezones use:
`time_decode.py --timestamp "2017-06-02 13:14:15 -5"`

The date/time you enter should be in the "YYYY-mm-dd HH:MM:SS.sss" format with the double-quote included, but does not require milli/micro/nano seconds to work. (Double-quote required for Windows Python)
If anyone has any other timestamps they think should be added to this tool, please let me know.
