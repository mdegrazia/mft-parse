#parse_mftdump v.1.1
#Mari DeGrazia
#
#
#Parses the output of mftdump.exe from the Standard Format to bodyfile format
#Grab mftdump.exe from #http://malware-hunters.net/all-downloads/
#Tested with version 2012-09-13 MFTDump V.1.3.0
#
#First, create and mftdump output file with mftdump.exe downloaded from malware-hunters using the syntax:
#	mftdump.exe C:/path/to/$mft /o C:/path/to/mft_output.txt
#
#Then run this tool over the mft_output.txt to create a bodyfile
#	parse_mftdump.py C:/path/to/mft_output.txt >> C:/path/to/bodyfile.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can view the GNU General Public License at <http://www.gnu.org/licenses/>
#
# Use at your own risk!
import csv
import time
import calendar
import argparse

parser =  argparse.ArgumentParser(description='This will parse the output of mftdump.exe to bodyfile format\n1)Run mftdump using the following syntax:\n mftdump.exe C:/path/to/$mft /o C:/path/to/mft_output.txt\n 2)Run this tool over the mft dump output file')
parser.add_argument('-f', '--file', dest="mftdump_file",help="Path to mftdump.exe output file",required=True)
args = parser.parse_args()
mftfile = args.mftdump_file

def toEpoch(date_string):
	#use calendar.timegm as the date_string passed is in UTC
	epoch = calendar.timegm(time.strptime(date_string, "%Y-%m-%d %H:%M:%S"))
	return epoch 
count = 0

with open(mftfile) as tsvfile:
	tsvreader = csv.reader(tsvfile, delimiter="\t")
	for line in tsvreader:
		if count is not 0:
			deleted = line[1]
			filename = line[4]
			siCreateTimeUTC=toEpoch(line[5])
			siAccessTimeUTC=toEpoch(line[6])
			siModTimeUTC=toEpoch(line[7])
			siMFTModTimeUTC=toEpoch(line[8])
			FNCreateTimeUTC=toEpoch(line[13])
			FNAccessTimeUTC=toEpoch(line[14])
			FNModTimeUTC=toEpoch(line[15])
			FNMFTModTimeUTC=toEpoch(line[16])
			
			ActualSize=line[9]
			fullPath = line[12]
			hostname = line[20]
		
			if deleted is "1":
				fullPath = fullPath + "(DELETED)"
			#bodyfile format; http://wiki.sleuthkit.org/index.php?title=Body_file
			#MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
						
			print "|" + fullPath + "|||||" + str(ActualSize) + "|" + str(siAccessTimeUTC) + "|" + str(siModTimeUTC) + "|" + str(siMFTModTimeUTC) + "|" +  str(siCreateTimeUTC)
			print "|" + fullPath + "(FILENAME)|||||" + str(ActualSize) + "|" + str(FNAccessTimeUTC) + "|" + str(FNModTimeUTC) + "|" + str(FNMFTModTimeUTC) + "|" +  str(FNCreateTimeUTC)	
	
		else:
			count =+1
