![PyPI - Version](https://img.shields.io/pypi/v/time_decode?logo=python&label=Latest%20pypi%20Release&labelColor=white)

# Time Decode
A Python 3 timestamp and date decoder/encoder. 

I noticed a lack of timestamp conversion utilities in a number of different linux systems. Since I happen to use linux in my day-to-day work I thought this would help.

This was developed with the Digital Forensics field in mind, so all of the testing has been done with the up-to-date SIFT Kit from SANS.
If you have any questions, suggestions, helpful thoughts of any kind, please feel free to drop me a line.

# Requirements
For python3, dateutil does not come pre-installed as a module. It will need to be installed manually:

`sudo apt-get install python3-dateutil` or `python3 -m pip install python-dateutil`

# Install
`python3 -m pip install time-decode` or `python3 -m pip install git+https://github.com/digitalsleuth/time_decode`

This python script provides the following conversions from existing timestamps:

- 128-bit SYSTEMTIME
- 32-bit MS-DOS time, result is Local
- Active Directory value
- Apache Cookie
- Apple Biome 64-bit decimal format
- Apple Biome hex format
- Bitwise decimal 10-digit
- BPlist (as NSDate)
- Cocoa Core (as NSDate)
- DHCP6 DUID
- Discord URL
- exFAT
- FAT Date + Time (wFat)
- FILETIME
- GMail Boundary
- GMail Message ID
- Google Chrome value
- Google EI URL (thanks to http://cheeky4n6monkey.blogspot.com/2014/10/google-eid.html)
- GPS
- GSM
- HFS(+) BE, HFS Local, HFS+ UTC
- HFS(+) LE, HFS Local, HFS+ UTC
- Hotmail
- iOS 11+ (as NSDate)
- KSUID 27-character
- KSUID 9-digit
- LEB128 hex value
- Mac Absolute Time (as NSDate)
- Mac OS/HFS+ Decimal Time
- Mastodon URL
- Metasploit Payload UUID
- Motorola's 6-byte
- Mozilla's PRTime
- MS Excel 1904 Date
- .NET DateTime
- Nokia 4-byte
- Nokia 4-byte LE
- Nokia S40 7-byte
- Nokia S40 7-byte LE
- OLE Automation Date
- S32 Encoded (Bluesky Social timestamp)
- Samsung/LG 4-byte
- Sonyflake URL (Sony version of Twitter Snowflake)
- Symantec's 6-byte AV
- TikTok URL
- Twitter URL
- Unix Hex 32-bit BE
- Unix Hex 32-bit LE
- Unix Milliseconds
- Unix Seconds
- UUID
- VMWare Snapshot (.vmsd)
- Windows 64-bit Hex BE
- Windows 64-bit Hex LE
- Windows Cookie Date (Low,High)
- Windows OLE 64-bit BE (SRUM as well)
- Windows OLE 64-bit LE

Note that HFS times are in Local Time, where HFS+ times are in UTC. MS-DOS 32 bit Hex values and MS-DOS FAT Date+Time are also in Local Time of the source generating the timestamp. All other times, unless expressly mentioned, are in UTC.

I have added a feature to 'guess' in what format the timestamp is that you've provided. This will run the timestamp you provide against all methods, and provide an output if human-readable.
There is also the ability to convert a date-time to all of the aforementioned timestamps. Simply use the following command:

`time-decode --timestamp "2023-04-27 16:14:15.678"`
or for timezones use:
`time-decode --timestamp "2023-04-27 16:14:15 -5"`

The date/time you enter should be in the "YYYY-mm-dd HH:MM:SS.sss" format with the double-quote included, but does not require milli/micro/nano seconds to work. (Double-quote required for Windows Python)
If anyone has any other timestamps they think should be added to this tool, please let me know.

References/Sources for all material can also be found in the docstrings in the python script.
