# Time Decode
![PyPI - Version](https://img.shields.io/pypi/v/time_decode?logo=python&label=Latest%20pypi%20Release&labelColor=white)

A Python 3 timestamp and date decoder/encoder. 

I noticed a lack of timestamp conversion utilities in a number of different linux systems. Since I happen to use linux in my day-to-day work I thought this would help.

This was developed with the Digital Forensics field in mind, so all of the testing has been done on Windows, macOS, and Linux.
If you have any questions, suggestions, helpful thoughts of any kind, please feel free to drop me a line.

# Requirements
All requirements will get installed automatically when following the below install methods. The additional packages which get installed are:

# Install
`python3 -m pip install time-decode` or `python3 -m pip install git+https://github.com/digitalsleuth/time_decode`

This python script provides the following conversions from existing timestamps:

```
┌───────────────────────────────┬──────────────────────────────────────────────────────────────────────────────┬──────────────────────────────────────────┬────────────────┐
│ Type                          │ Format                                                                       │ Example                                  │ Argument       │
├───────────────────────────────┼──────────────────────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼────────────────┤
│ Active Directory/LDAP         │ Active Directory/LDAP timestamps are 18 digits                               │ 133908455300649390                       │ --active       │
│ Apache Cookie Hex time        │ Apache Cookie hex timestamps are 13 hex characters long                      │ 63450e689882b                            │ --apache       │
│ Apple Biome 64-bit decimal    │ Apple Biome 64-bit decimal is 19 digits in length                            │ 4739726202305531884                      │ --biome64      │
│ Apple Biome hex time          │ Apple Biome Hex value is 8 bytes (16 chars) long                             │ 41c6e3de6d084fec                         │ --biomehex     │
│ Apple NSDate - bplist / Cocoa │ Apple NSDates (bplist) are 9 digits in length                                │ 768064730                                │ --bplist       │
│ Apple NSDate - iOS 11+        │ Apple NSDates (iOS) are 15-19 digits in length                               │ 768064730064939008                       │ --iostime      │
│ Apple NSDate - Mac Absolute   │ Apple NSDates (Mac) are 9 digits '.' 6 digits                                │ 768064730.064939                         │ --mac          │
│ Apple NSDate - All            │ Apple NSDates are 9, 9.6, or 15-19 digits in length                          │ 704656778.285777                         │ --nsdate       │
│ Binary Coded Decimal          │ Binary Coded Decimal timestamps are 12 digits in length                      │ 250506232221                             │ --bcd          │
│ BitDate time                  │ BitDate (Samsung/LG) timestamps are 8 hex characters                         │ d223957e                                 │ --bitdate      │
│ Bitwise Decimal time          │ Bitwise Decimal timestamps are 10 digits                                     │ 2123703250                               │ --bitdec       │
│ DHCPv6 DUID time              │ DHCPv6 DUID values are at least 14 bytes long                                │ 000100012faa41da000000000000             │ --dhcp6        │
│ Discord time                  │ Discord timestamps are 18 digits or longer                                   │ 1102608904745127937                      │ --discord      │
│ DVR (WFS / DHFS) File System  │ DVR timestamps are 4 bytes                                                   │ 00F0063F                                 │ --dvr          │
│ exFAT time                    │ exFAT 32-bit timestamps are 8 hex characters (4 bytes)                       │ 5aa47a59                                 │ --exfat        │
│ FAT Date + Time               │ FAT (MS-DOS wFatDate wFatTime) timestamps are 8 hex characters (4 bytes)     │ a45a597a                                 │ --fat          │
│ GMail Boundary time           │ GMail Boundary values are 28 hex chars                                       │ 00000000000089882b063450e600             │ --gbound       │
│ GMail Message ID time         │ GMail Message ID values are 16 hex chars or 19 digits (IMAP)                 │ 1969be0e7d000000                         │ --gmsgid       │
│ Google Chrome                 │ Google Chrome/Webkit timestamp is 17 digits                                  │ 13390845530064940                        │ --chrome       │
│ Google EI time                │ Google ei timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_    │ WoUXaA                                   │ --eitime       │
│ Google GCLID time             │ Google GCLID timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_ │ CKSDxc_qhLkCFQyk4AodO24Arg               │ --gclid        │
│ Google VED time               │ Google VED timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_   │ 0ahUKEwilufv7joqNAxW3nYkEHd0vMyIQ4dUDCA8 │ --ved          │
│ GPS time                      │ GPS timestamps are 10 digits                                                 │ 1430407111                               │ --gps          │
│ GSM time                      │ GSM timestamps are 14 hex characters (7 bytes)                               │ 52504051810500                           │ --gsm          │
│ HFS+ Decimal Time             │ HFS+ Decimal timestamps are 10 digits                                        │ 3829216730                               │ --hfsdec       │
│ HFS/HFS+ 32-bit Hex BE        │ HFS/HFS+ Big-Endian timestamps are 8 hex characters (4 bytes)                │ e43d35da                                 │ --hfsbe        │
│ HFS/HFS+ 32-bit Hex LE        │ HFS/HFS+ Little-Endian timestamps are 8 hex characters (4 bytes)             │ da353de4                                 │ --hfsle        │
│ Julian Date decimal           │ Julian Date decimal values are 7 digits, a decimal, and up to 10 digits      │ 2460800.1380787035                       │ --juliandec    │
│ Julian Date hex               │ Julian Date hex values are 14 characters (7 bytes)                           │ 258c80524d235b                           │ --julianhex    │
│ KSUID Decimal                 │ KSUID decimal timestamps are 9 digits in length                              │ 346371930                                │ --ksdec        │
│ KSUID Alpha-numeric           │ KSUID values are 27 alpha-numeric characters                                 │ 2PChRqPZDwT9m2gBDLd5uy7XNTr              │ --ksalnum      │
│ LEB128 Hex time               │ LEB128 Hex timestamps are variable-length and even-length                    │ d0cf83dfe932                             │ --leb128hex    │
│ LinkedIn Activity time        │ LinkedIn Activity timestamps contain only digits                             │ 7324176984442343424                      │ --linkedin     │
│ Mastodon time                 │ Mastodon timestamps are 18 digits or longer                                  │ 114450230804480000                       │ --mastodon     │
│ Metasploit Payload UUID       │ Metasploit Payload UUID's are at least 22 chars and base64 urlsafe encoded   │ 4PGoVGYmx8l6F3sVI4Rc8g                   │ --metasploit   │
│ Microsoft .NET DateTime Ticks │ Microsoft .NET DateTime Ticks values are 18 digits                           │ 638819687300649472                       │ --dotnet       │
│ Microsoft 128-bit SYSTEMTIME  │ Microsoft 128-bit SYSTEMTIME timestamps are 32 hex characters (16 bytes)     │ e9070500000004000f00120032004000         │ --systemtime   │
│ Microsoft DTTM Date           │ Microsoft DTTM timestamps are 4 bytes                                        │ 8768f513                                 │ --dttm         │
│ Microsoft Excel 1904 Date     │ Microsoft Excel 1904 timestamps are 2 ints, separated by a dot               │ 44319.638079455312                       │ --ms1904       │
│ Microsoft Hotmail time        │ Microsoft Hotmail timestamps are 2x 8 hex chars (4 bytes) colon separated    │ 07bddb01:aed19dd6                        │ --hotmail      │
│ Microsoft MS-DOS 32-bit Hex   │ Microsoft MS-DOS 32-bit timestamps are 8 hex characters (4 bytes)            │ 597aa45a                                 │ --msdos        │
│ Motorola time                 │ Motorola 6-byte hex timestamps are 12 hex characters                         │ 3705040f1232                             │ --moto         │
│ Mozilla PRTime                │ Mozilla PRTime timestamps are 16 digits                                      │ 1746371930064939                         │ --prtime       │
│ Nokia time                    │ Nokia 4-byte hex timestamps are 8 hex characters                             │ d19d0f5a                                 │ --nokia        │
│ Nokia time LE                 │ Nokia 4-byte hex timestamps are 8 hex characters                             │ 5a0f9dd1                                 │ --nokiale      │
│ Nokia S40 time                │ Nokia 7-byte hex timestamps are 14 hex characters                            │ 07e905040f1232                           │ --ns40         │
│ Nokia S40 time LE             │ Nokia 7-byte hex timestamps are 14 hex characters                            │ e90705040f1232                           │ --ns40le       │
│ S32 Encoded (Bluesky) time    │ S32 encoded (Bluesky) timestamps are 9 characters long                       │ 3muhy3twk                                │ --s32          │
│ Semi-Octet decimal            │ Semi-Octet decimal values are 12 or 14 digits long                           │ 525040518105                             │ --semioctet    │
│ Sonyflake time                │ Sonyflake values are 15 hex characters                                       │ 65dd4bb89000001                          │ --sony         │
│ Symantec AV time              │ Symantec 6-byte hex timestamps are 12 hex characters                         │ 3704040f1232                             │ --symantec     │
│ TikTok time                   │ TikTok timestamps are 19 digits long                                         │ 7228142017547750661                      │ --tiktok       │
│ Twitter time                  │ Twitter timestamps are 18 digits or longer                                   │ 1189581422684274688                      │ --twitter      │
│ ULID time                     │ ULID timestamp contains only Base32 characters                               │ 01JTDY1SYGCZWCBPCSEBHV1DW2               │ --ulid         │
│ Unix Hex 32-bit BE            │ Unix Hex 32-bit Big-Endian timestamps are 8 hex characters (4 bytes)         │ 6817855a                                 │ --unixhex32be  │
│ Unix Hex 32-bit LE            │ Unix Hex 32-bit Little-Endian timestamps are 8 hex characters (4 bytes)      │ 5a851768                                 │ --unixhex32le  │
│ Unix Milliseconds hex         │ Unix Milliseconds hex timestamp is 12 hex characters (6 bytes)               │ 01969be0e7d0                             │ --unixmillihex │
│ Unix Milliseconds             │ Unix milliseconds timestamp is 13 digits in length                           │ 1746371930064                            │ --unixmilli    │
│ Unix Seconds                  │ Unix seconds timestamp is 10 digits in length                                │ 1746371930                               │ --unixsec      │
│ UUID time                     │ UUIDs are in the format 00000000-0000-0000-0000-000000000000                 │ d93026f0-e857-11ed-a05b-0242ac120003     │ --uuid         │
│ VMSD time                     │ VMSD values are a 6-digit value and a signed/unsigned int at least 9 digits  │ 406608,-427259264                        │ --vm           │
│ Windows Cookie Date           │ Windows Cookie times consist of 2 ints, entered with a comma between them    │ 3600017664,31177991                      │ --cookie       │
│ Windows FILETIME BE           │ Windows FILETIME Hex Big-Endian timestamp is 16 hex characters (8 bytes)     │ 01dbbd07d69dd1ae                         │ --filetimebe   │
│ Windows FILETIME LE           │ Windows FILETIME Hex Little-Endian timestamp is 16 hex characters (8 bytes)  │ aed19dd607bddb01                         │ --filetimele   │
│ Windows FILETIME (Low:High)   │ Windows FILETIME Low:High times are 2x 8 hex chars (4 bytes) colon separated │ d69dd1ae:01dbbd07                        │ --filetimelohi │
│ Windows OLE Automation Date   │ Windows OLE Automation timestamps are 2 ints, separated by a dot             │ 45781.638079455312                       │ --oleauto      │
│ Windows OLE 64-bit hex BE     │ Windows OLE Big-Endian timestamps are 16 hex characters (8 bytes)            │ 40e65ab46b259b1a                         │ --olebe        │
│ Windows OLE 64-bit hex LE     │ Windows OLE Little-Endian timestamps are 16 hex characters (8 bytes)         │ 1a9b256bb45ae640                         │ --olele        │
└───────────────────────────────┴──────────────────────────────────────────────────────────────────────────────┴──────────────────────────────────────────┴────────────────┘
* BE = Big-Endian / LE = Little-Endian
```

Note that HFS times are in Local Time, where HFS+ times are in UTC. MS-DOS 32 bit Hex values and MS-DOS FAT Date+Time are also in Local Time of the source generating the timestamp. All other times, unless expressly mentioned, are in UTC.

I have added a feature to 'guess' in what format the timestamp is that you've provided. This will run the timestamp you provide against all methods, and provide an output if human-readable.
There is also the ability to convert a date-time to all of the aforementioned timestamps. Simply use the following command:

`time-decode --timestamp "2017-06-02 13:14:15.678"`
or for timezones use:
`time-decode --timestamp "2017-06-02 13:14:15+02:00"`

The date/time you enter should be in the "YYYY-mm-dd HH:MM:SS.fff" where `.fff` is the millisecond value. (Double-quote required for Windows Python)
If anyone has any other timestamps they think should be added to this tool, please let me know.

References/Sources for all material can also be found in the REFERENCES.md documentation.
