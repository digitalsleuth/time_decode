# Date Decode
A timestamp and date decoder written in python 2.x

I noticed a lack of timestamp conversion utilities in a number of different linux systems. Since I happen to use linux in my day-to-day work I thought this would help.
I took a small part of the formatting for this from the Packt Publishing Learning Python for Forensics, but the rest of this was my own machination.

This was developed with the Digital Forensics field in mind, so all of the testing has been done with the up-to-date SIFT Kit from SANS.
If you have any questions, suggestions, helpful thoughts of any kind, please feel free to drop me a line.

Note: You will notice several commented sections in the existing code. I am working on adding the capability of converting a formatted Date/Time to the timestamp of your choice. It is still a work in progress.

This python script provides the following conversions from existing timestamps:

- Unix Seconds
- Unix Milliseconds
- Windows Filetime 64 bit (in Big Endian)
- Windows Filetime 64 bit (in Little Endian)
- Google Chrome Time
- Active Directory time
- Unix Hex 32 bit (in Big Endian)
- Unix Hex 32 bit (in Little Endian)
- Cookie Time (Low Value,High Value)
- Windows OLE 64 bit double (in Big Endian)
- Windows OLE 64 bit double (in Little Endian)
- Mac Absolute Time
- HFS/HFS+ Time (in Big Endian)
- HFS/HFS+ Time (in Little Endian)
- MS-DOS 32 bit Hex
- Microsoft 128 bit SYSTEMTIME
- Mozilla PRTime
- OLE Automation Date/Time

Note that HFS times are in Local Time, where HFS+ times are in UTC. MS-DOS 32 bit Hex values are also in Local time. All other times, unless expressly mentioned, are in UTC.

I have added an additional feature to 'guess' in what format the timestamp is that you've provided. This will run the timestamp you provide against all methods, and provide an output if human-readable.
If anyone has any other timestamps they think should be added to this tool, please let me know.

Moving forward, this tool will also be capable of converting TO these timestamps as well as from. 
