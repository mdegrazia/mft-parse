# mft-parse
Tool to parse the output of MFTDump.exe to bodyfile format
Parses the output of mftdump.exe from the Standard Format to bodyfile format

Grab mftdump.exe from #http://malware-hunters.net/all-downloads/
Tested with version 2012-09-13 MFTDump V.1.3.0

First, create an mftdump output file using the tool downloaded from malware-hunters using the syntax:
mftdump.exe C:/path/to/$mft /o C:/path/to/mft_output.txt

Then run this tool over the mft_output.txt to create a bodyfile
parse_mftdump.py C:/path/to/mft_output.txt >> C:/path/to/bodyfile.txt

Check out my blog post on MFT parser testing here: http://az4n6.blogspot.com/2015/09/whos-your-master-mft-parsers-reviewed.html

