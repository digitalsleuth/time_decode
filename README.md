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

To use the GUI (`--gui` or `time-decode-gui`), include the `gui` extra which adds PyQt6:

`python3 -m pip install "time-decode[gui]"`

This python script provides the following conversions from existing timestamps:

```
┌───────────────────────────────┬───────────────────────────────────────────────────────────────────────────────────┬──────────────────────────────────────────┬────────────────┐
│ Type                          │ Format                                                                            │ Example                                  │ Argument       │
├───────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────┼──────────────────────────────────────────┼────────────────┤
│ Active Directory/LDAP         │ Active Directory/LDAP timestamps are up to 19 digits                              │ 133908455300649390                       │ --active       │
│ Apache Cookie Hex time        │ Apache Cookie hex timestamps are up to 15 hex characters long                     │ 63450e689882b                            │ --apache       │
│ APFS time                     │ APFS timestamps are 16 hex characters (8 bytes), little-endian                    │ f8e73b89045c3c18                         │ --apfs         │
│ Apple Biome 64-bit decimal    │ Apple Biome 64-bit decimal is up to 20 digits in length                           │ 4739726202305531884                      │ --biome64      │
│ Apple Biome Hex time          │ Apple Biome Hex value is 8 bytes (16 chars) long                                  │ 41c6e3de6d084fec                         │ --biomehex     │
│ Apple NSDate - All            │ Apple NSDates are up to 12, up to 12.6, or 15-18 digits in length                 │ 704656778.285777                         │ --nsdate       │
│ Apple NSDate - bplist / Cocoa │ Apple NSDates (bplist) are up to 12 digits in length                              │ 768064730                                │ --bplist       │
│ Apple NSDate - iOS 11+        │ Apple NSDates (iOS) are 15-18 digits in length                                    │ 768064730064939008                       │ --iostime      │
│ Apple NSDate - Mac Absolute   │ Apple NSDates (Mac) are up to 12 digits '.' up to 6 digits                        │ 768064730.064939                         │ --mac          │
│ AWS X-Ray trace ID time       │ AWS X-Ray trace IDs are in the format 1-00000000-000000000000000000000000         │ 1-6817855a-a006649127e371903a2de979      │ --xray         │
│ Binary Coded Decimal          │ Binary Coded Decimal timestamps are 12 digits in length                           │ 250506232221                             │ --bcd          │
│ BitDate time                  │ BitDate (Samsung/LG) timestamps are 8 hex characters                              │ d223957e                                 │ --bitdate      │
│ Bitwise Decimal time          │ Bitwise Decimal timestamps are up to 10 digits                                    │ 2123703250                               │ --bitdec       │
│ Bluesky TID time              │ Bluesky TIDs are 13 characters, from 234567a-z                                    │ 3loe5ncn43f5v                            │ --tid          │
│ Btrfs inode time              │ Btrfs inode times are 24 hex characters little-endian                             │ 5a85176800000000f8e3de03                 │ --btrfs        │
│ CDMA SMS time                 │ CDMA SMS times are 12 digits (6 BCD bytes)                                        │ 990712151030                             │ --cdma         │
│ cuid time                     │ cuid values are 25 characters, starting with c                                    │ cma9sr9ao0000k2w9b3qzd5r6                │ --cuid         │
│ DHCPv6 DUID time              │ DHCPv6 DUID values are at least 14 bytes long                                     │ 000100012faa41da000000000000             │ --dhcp6        │
│ Discord time                  │ Discord timestamps are up to 20 digits                                            │ 1102608904745127937                      │ --discord      │
│ DVR (WFS / DHFS) File System  │ DVR timestamps are 4 bytes                                                        │ 654D7595                                 │ --dvr          │
│ exFAT time                    │ exFAT 32-bit timestamps are 8 hex characters (4 bytes)                            │ 5aa47a59                                 │ --exfat        │
│ exFAT time with extras        │ exFAT times with extras are 12 hex characters                                     │ 5aa47a590700                             │ --exfatext     │
│ ext4 inode time               │ ext4 inode times are 8 hex characters                                             │ 6817855a:0f7b8fe0                        │ --ext4         │
│ Facebook cookie time          │ Facebook _fbp/_fbc values are in the format fb.1.0000000000000.0000000000         │ fb.1.1746371930064.1116446470            │ --fbcookie     │
│ FAT Date + Time               │ FAT (MS-DOS wFatDate wFatTime) timestamps are 8 hex characters (4 bytes)          │ a45a597a                                 │ --fat          │
│ Firebase Push ID time         │ Firebase Push IDs are 20 characters, from A-Za-z0-9-_                             │ -OPQsDUF7Gkq3VtZb0Xa                     │ --firebase     │
│ Garmin FIT time               │ Garmin FIT timestamps are 1 to 10 digits, seconds since 1989-12-31                │ 1115306330                               │ --garmin       │
│ GMail Boundary time           │ GMail Boundary values are 28 hex chars                                            │ 00000000000089882b063450e600             │ --gbound       │
│ GMail Message ID time         │ GMail Message ID values are 6-17 hex chars or 19 digits (IMAP)                    │ 1969be0e7d000000                         │ --gmsgid       │
│ Google Analytics cookie time  │ Google Analytics _ga/_gid values are in the format GA1.2.0000000000.0000000000    │ GA1.2.1033914209.1746371930              │ --gacookie     │
│ Google Chrome                 │ Google Chrome/Webkit timestamp is up to 18 digits                                 │ 13390845530064940                        │ --chrome       │
│ Google EI time                │ Google ei timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_         │ WoUXaA                                   │ --eitime       │
│ Google GCLID time             │ Google GCLID timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_      │ CKSDxc_qhLkCFQyk4AodO24Arg               │ --gclid        │
│ Google VED time               │ Google VED timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_        │ 0ahUKEwilufv7joqNAxW3nYkEHd0vMyIQ4dUDCA8 │ --ved          │
│ GPS time                      │ GPS timestamps are up to 12 digits                                                │ 1430407111                               │ --gps          │
│ GSM time                      │ GSM timestamps are 14 hex characters (7 bytes)                                    │ 52504051810500                           │ --gsm          │
│ HFS / HFS+ 32-bit Hex BE      │ HFS / HFS+ Big-Endian timestamps are 8 hex characters (4 bytes)                   │ e43d35da                                 │ --hfsbe        │
│ HFS / HFS+ 32-bit Hex LE      │ HFS / HFS+ Little-Endian timestamps are 8 hex characters (4 bytes)                │ da353de4                                 │ --hfsle        │
│ HFS+ Decimal Time             │ HFS+ Decimal timestamps are up to 12 digits                                       │ 3829216730                               │ --hfsdec       │
│ Horolog Time                  │ Horolog timestamps are two whole numbers separated by a comma (days, seconds)     │ 67637,80193                              │ --horolog      │
│ Instagram time                │ Instagram IDs are up to 20 digits                                                 │ 3625152955542620216                      │ --instagram    │
│ ISO 9660 recording date       │ ISO 9660 recording dates are 14 hex characters (7 bytes)                          │ 7d05040f123200                           │ --iso9660      │
│ JET LogTime                   │ JET LogTime values are 8 bytes, one byte for each YY-MM-DD HH:MM:SS and 2 fillers │ 343a0d17037b0000                         │ --logtime      │
│ Julian Date decimal           │ Julian Date decimal values are 7 digits '.' up to 10 digits                       │ 2460800.1380787035                       │ --juliandec    │
│ Julian Date hex               │ Julian Date hex values are 14 characters (7 bytes)                                │ 258c80524d235b                           │ --julianhex    │
│ KSUID Alpha-numeric           │ KSUID values are 27 alpha-numeric characters                                      │ 2PChRqPZDwT9m2gBDLd5uy7XNTr              │ --ksalnum      │
│ KSUID Decimal                 │ KSUID decimal timestamps are up to 10 digits in length                            │ 346371930                                │ --ksdec        │
│ LEB128 Hex time               │ LEB128 Hex timestamps are variable-length and even-length                         │ d0cf83dfe932                             │ --leb128hex    │
│ LinkedIn Activity time        │ LinkedIn Activity timestamps contain only digits                                  │ 7324176984442343424                      │ --linkedin     │
│ Mars Sol Date time            │ Mars Sol Date time values are up to 7 digits '.' 1 or more digits                 │ 54103.12581                              │ --mars         │
│ Mastodon time                 │ Mastodon timestamps are up to 20 digits                                           │ 114450230804480000                       │ --mastodon     │
│ MATLAB datenum                │ MATLAB datenum values are up to 7 digits, optionally '.' up to 15 digits          │ 739741.638079455312                      │ --matlab       │
│ Matroska/WebM time            │ Matroska/WebM dates are up to 19 digits                                           │ 768064730064939000                       │ --matroska     │
│ Metasploit Payload UUID       │ Metasploit Payload UUID's are at least 22 chars and base64 urlsafe encoded        │ 4PGoVGYmx8l6F3sVI4Rc8g                   │ --metasploit   │
│ Microsoft .NET Ticks          │ Microsoft .NET Ticks values are up to 19 digits                                   │ 638819687300649472                       │ --dotnet       │
│ Microsoft .NET ToBinary       │ Microsoft .NET ToBinary values are up to 19 digits                                │ 5250505705728037294                      │ --dotnetbin    │
│ Microsoft 128-bit SYSTEMTIME  │ Microsoft 128-bit SYSTEMTIME timestamps are 32 hex characters (16 bytes)          │ e9070500000004000f00120032004000         │ --systemtime   │
│ Microsoft DTTM date           │ Microsoft DTTM timestamps are 4 bytes                                             │ 8768f513                                 │ --dttm         │
│ Microsoft Excel 1904 date     │ Microsoft Excel 1904 timestamps are up to 7 digits '.' up to 15 digits            │ 44319.638079455312                       │ --ms1904       │
│ Microsoft Hotmail time        │ Microsoft Hotmail timestamps are 2x 8 hex chars (4 bytes) colon separated         │ 07bddb01:aed19dd6                        │ --hotmail      │
│ Microsoft MS-DOS 32-bit Hex   │ Microsoft MS-DOS 32-bit timestamps are 8 hex characters (4 bytes)                 │ 597aa45a                                 │ --msdos        │
│ Microsoft SQL Server date     │ Microsoft SQL Server date values are 16 hex characters                            │ 0000b2d300fc5d78                         │ --mssql        │
│ Microsoft SQL Server date LE  │ Microsoft SQL Server date LE values are 16 hex characters                         │ 785dfc00d3b20000                         │ --mssqlle      │
│ Modified Julian Date          │ Modified Julian Dates are up to 7 digits, optionally '.' up to 15 digits          │ 60799.638079455312                       │ --mjd          │
│ MongoDB ObjectId time         │ MongoDB ObjectIds are 24 hex characters (12 bytes)                                │ 6817855a1b2c3d4e5f607182                 │ --objectid     │
│ Motorola time                 │ Motorola 6-byte hex timestamps are 12 hex characters                              │ 3705040f1232                             │ --moto         │
│ Mozilla PRTime                │ Mozilla PRTime timestamps are up to 18 digits                                     │ 1746371930064939                         │ --prtime       │
│ MySQL DATETIME                │ MySQL DATETIME values are 10 hex characters, then 2, 4 or 6 more for a fraction   │ 99b688f4b200fdab                         │ --mysql        │
│ Nokia S40 time                │ Nokia 7-byte hex timestamps are 14 hex characters                                 │ 07e905040f1232                           │ --ns40         │
│ Nokia S40 time LE             │ Nokia 7-byte hex timestamps are 14 hex characters                                 │ e90705040f1232                           │ --ns40le       │
│ Nokia time                    │ Nokia 4-byte hex timestamps are 8 hex characters                                  │ d19d0f5a                                 │ --nokia        │
│ Nokia time LE                 │ Nokia 4-byte hex timestamps are 8 hex characters                                  │ 5a0f9dd1                                 │ --nokiale      │
│ NTP 64-bit hex                │ NTP 64-bit timestamps are 16 hex characters (8 bytes)                             │ ebc203da109fd7a1                         │ --ntp64        │
│ NTP time                      │ NTP timestamps are up to 12 digits, optionally '.' up to 30 digits                │ 3981841662.020607                        │ --ntp          │
│ Oracle DATE                   │ Oracle DATE values are 14 hex characters (7 bytes) or 7 comma separated numbers   │ 787d0504101333                           │ --oracle       │
│ Parquet INT96 time            │ Parquet INT96 timestamps are 24 hex characters (12 bytes)                         │ f8e7eff723320000808c2500                 │ --int96        │
│ pcap record time              │ pcap record times are 16 hex characters: seconds, microseconds, little-endian     │ 5a851768abfd0000                         │ --pcap         │
│ pcap record time BE           │ pcap record times are 16 hex characters: seconds, microseconds, big-endian        │ 6817855a0000fdab                         │ --pcapbe       │
│ PostgreSQL timestamp          │ PostgreSQL timestamp values are up to 19 digits                                   │ 799687130064939                          │ --postgres     │
│ PostgreSQL timestamp hex BE   │ PostgreSQL timestamp hex BE values are 16 hex characters                          │ 0002d74fab51a82b                         │ --postgresbe   │
│ PostgreSQL timestamp hex LE   │ PostgreSQL timestamp hex LE values are 16 hex characters                          │ 2ba851ab4fd70200                         │ --postgresle   │
│ QuickTime/MP4 time            │ QuickTime/MP4 times are 8 hex characters (4 bytes) or 16 hex characters (8 bytes) │ e43d35da                                 │ --quicktime    │
│ S32 Encoded (Bluesky) time    │ S32 encoded (Bluesky) timestamps are 9 characters long                            │ 3muhy3twk                                │ --s32          │
│ SAS date                      │ SAS date values are up to 7 digits                                                │ 23865                                    │ --sasdate      │
│ SAS datetime                  │ SAS datetime values are up to 12 digits, optionally '.' up to 9 digits            │ 2061991130.064939                        │ --sas          │
│ Semi-Octet decimal            │ Semi-Octet decimal values are 12 digits long                                      │ 525040518105                             │ --semioctet    │
│ Sonyflake time                │ Sonyflake values are up to 16 hex characters                                      │ 65dd4bb89000001                          │ --sony         │
│ SPSS date                     │ SPSS date values are up to 12 digits, optionally '.' up to 9 digits               │ 13965751130.064939                       │ --spss         │
│ Star Trek TNG Stardate        │ Star Trek TNG Stardates are up to 7 digits, optionally '.' up to 6 digits         │ 41153.7                                  │ --stardatetng  │
│ Star Trek TOS Stardate        │ Star Trek TOS Stardates are up to 8 digits, optionally '.' up to 6 digits         │ 1312.4                                   │ --stardatetos  │
│ Stata %tc time                │ Stata %tc values are up to 15 digits                                              │ 2061991130064                            │ --stata        │
│ Symantec AV time              │ Symantec 6-byte hex timestamps are 12 hex characters                              │ 3704040f1232                             │ --symantec     │
│ Symbian time                  │ Symbian time values are up to 18 digits, microseconds since the year 0            │ 63913591130064939                        │ --symbian      │
│ TAI Milliseconds              │ TAI (International Atomic Time) values (based on ms) are up to 15 digits          │ 1599755800000                            │ --taimilli     │
│ TAI Seconds                   │ TAI (International Atomic Time) values (based on sec) are up to 12 digits         │ 1599755800                               │ --tai          │
│ TAI64N time                   │ TAI64N labels are 24 hex characters, optionally with a leading '@'                │ 400000006817856403dee3f8                 │ --tai64n       │
│ tar header time               │ tar header times are 1 to 12 octal digits                                         │ 15005702532                              │ --tar          │
│ Telegram MTProto ID time      │ Telegram MTProto message IDs are up to 20 digits                                  │ 7500610326281312160                      │ --telegram     │
│ TikTok time                   │ TikTok timestamps are up to 20 digits long                                        │ 7228142017547750661                      │ --tiktok       │
│ Twitter time                  │ Twitter timestamps are up to 20 digits                                            │ 1189581422684274688                      │ --twitter      │
│ UDF timestamp                 │ UDF timestamps are 24 hex characters (12 bytes)                                   │ 0118e90705040f1232063127                 │ --udf          │
│ UEFI EFI_TIME                 │ UEFI EFI_TIME values are 32 hex characters (16 bytes)                             │ e90705040f123200f8e3de03ff070000         │ --efitime      │
│ ULID time                     │ ULID timestamp contains only Base32 characters                                    │ 01JTDY1SYGCZWCBPCSEBHV1DW2               │ --ulid         │
│ Unix Days                     │ Unix days timestamp is up to 7 digits in length                                   │ 20212                                    │ --unixdays     │
│ Unix Hex 32-bit BE            │ Unix Hex 32-bit Big-Endian timestamps are 8 hex characters (4 bytes)              │ 6817855a                                 │ --unixhex32be  │
│ Unix Hex 32-bit LE            │ Unix Hex 32-bit Little-Endian timestamps are 8 hex characters (4 bytes)           │ 5a851768                                 │ --unixhex32le  │
│ Unix Milliseconds             │ Unix milliseconds timestamp is 1 to 15 digits in length                           │ 1746371930064                            │ --unixmilli    │
│ Unix Milliseconds hex         │ Unix Milliseconds hex timestamp is up to 12 hex characters (6 bytes)              │ 01969be0e7d0                             │ --unixmillihex │
│ Unix Nanoseconds              │ Unix nanoseconds timestamp is up to 21 digits in length                           │ 1746371930064939000                      │ --unixnano     │
│ Unix Seconds                  │ Unix seconds timestamp is up to 12 digits in length                               │ 1746371930                               │ --unixsec      │
│ Unix Seconds with fraction    │ Unix seconds with a fraction are up to 12 digits '.' up to 9 digits               │ 1746371930.064939                        │ --unixsecfrac  │
│ UUID time                     │ UUIDs are in the format 00000000-0000-0000-0000-000000000000                      │ d93026f0-e857-11ed-a05b-0242ac120003     │ --uuid         │
│ UUID v6 time                  │ UUID v6 values are in the format 00000000-0000-6000-8000-000000000000             │ 1f028fb1-4e09-61ae-8c4f-0342ac120003     │ --uuid6        │
│ UUID v7 time                  │ UUID v7 values are in the format 00000000-0000-7000-8000-000000000000             │ 01969be0-e7d0-7a3c-9b2e-5f60718293a4     │ --uuid7        │
│ VMSD time                     │ VMSD values are two signed whole numbers separated by a comma                     │ 406608,-427259264                        │ --vm           │
│ Windows Cookie Date           │ Windows Cookie times consist of 2 ints, entered with a comma between them         │ 3600017664,31177991                      │ --cookie       │
│ Windows FILETIME (Low|High)   │ Windows FILETIME Low|High times are 8 hex chars, a colon, and up to 8 hex chars   │ d69dd1ae:01dbbd07                        │ --filetimelohi │
│ Windows FILETIME BE           │ Windows FILETIME Hex Big-Endian timestamp is 16 hex characters (8 bytes)          │ 01dbbd07d69dd1ae                         │ --filetimebe   │
│ Windows FILETIME LE           │ Windows FILETIME Hex Little-Endian timestamp is 16 hex characters (8 bytes)       │ aed19dd607bddb01                         │ --filetimele   │
│ Windows OLE 64-bit hex BE     │ Windows OLE Big-Endian timestamps are 16 hex characters (8 bytes)                 │ 40e65ab46b259b1a                         │ --olebe        │
│ Windows OLE 64-bit hex LE     │ Windows OLE Little-Endian timestamps are 16 hex characters (8 bytes)              │ 1a9b256bb45ae640                         │ --olele        │
│ Windows OLE Automation Date   │ Windows OLE Automation timestamps are up to 7 digits '.' up to 15 digits          │ 45781.638079455312                       │ --oleauto      │
│ XFS bigtime                   │ XFS bigtime values are 16 hex characters (8 bytes), big-endian                    │ 3609c104893be7f8                         │ --xfsbig       │
│ XFS inode time                │ XFS inode times are 16 hex characters big-endian                                  │ 6817855a03dee3f8                         │ --xfs          │
│ xid time                      │ xid values are 20 characters, 0-9 and a-v                                         │ d0boaml1mb1t9pfm0sc0                     │ --xid          │
└───────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────┴──────────────────────────────────────────┴────────────────┘
* BE = Big-Endian / LE = Little-Endian
```

Note that HFS times are in Local Time, where HFS+ times are in UTC. MS-DOS 32 bit Hex values and MS-DOS FAT Date+Time are also in Local Time of the source generating the timestamp. All other times, unless expressly mentioned, are in UTC.

I have added a feature to 'guess' in what format the timestamp is that you've provided. This will run the timestamp you provide against all methods, and provide an output if human-readable. Dates that cannot be shown in a `--tz` time zone, such as a date at the very start or end of the calendar, are left out.
There is also the ability to convert a date-time to all of the aforementioned timestamps. Simply use the following command:

`time-decode --timestamp "2017-06-02 13:14:15.678"`
or for timezones use:
`time-decode --timestamp "2017-06-02 13:14:15+02:00"`

The date/time you enter should be in the "YYYY-mm-dd HH:MM:SS.fff" where `.fff` is the millisecond value. (Double-quote required for Windows Python)
To convert a date/time to a single timestamp format, add `--to` and provide the date/time as the value of that format's argument:

`time-decode --to --unixmilli "2017-06-02 13:14:15.678"`

To convert the current date/time instead, use `--now` (or `-n`) in place of a value. With `--tz`, the current time in that time zone is used:

`time-decode --to --unixmilli --now`

`--nsdate` stands for the three Apple NSDate formats (`--bplist`, `--mac` and `--iostime`), which all count from 2001-01-01 UTC. When decoding, it tries each and shows whichever one fits the value. With `--to`, it gives all three:

`time-decode --nsdate 768064730.064939`

`time-decode --to --nsdate "2025-05-06 23:22:21.123456"`

If anyone has any other timestamps they think should be added to this tool, please let me know.

References/Sources for all material can also be found in the REFERENCES.md documentation.
