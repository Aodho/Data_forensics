#! /bin/python

from hurry.filesize import size
from sets import Set

import binascii
import sys
import csv
import codecs
import struct


filesystem_type = {"00": "Unknown or Empty",
              "01": "12-bit FAT",
              "04": "16-bit FAT (< 32MB)",
              "05": "Extended MS-DOS Partition",
              "06": "FAT-16 (32MB to 2GB)",
              "07": "NTFS",
              "0B": "FAT-32 (CHS)",
              "0C": "FAT-32 (LBA)",
              "0E": "FAT-16 (LBA)"}

SECTOR_SIZE = 512

def bytes_to_KB(b):
    return (b / 1024)

def sectors_to_mega(sectors):
    return (sectors * 512)/ 1024 / 1024

class DiskExplorer():
    def __init__(self, filepath):
        self.filepath = filepath

    def read_disk(self, address, reading_partition=True, reading_volume=False):
        """ Search into the disk at given address find and return bytes of information """

        disk_data = ""
        find_address = int(address)
        read_range = 0

        if reading_partition:
            find_address = address # if reading a partition just seek to address.
            read_range = 16 # Partition table entries are 16 bytes
        else:
            find_address = address * SECTOR_SIZE # if reading volume info multiply address by sector size
            read_range = 73 # NTFS Volume information is within in the BPB and extended BPB fields.

        with open(self.filepath, "rb") as f:
            f.seek(find_address) # seek to sector address
            byte = f.read(read_range) # read bytes and convert to hex
            disk_data = binascii.hexlify(byte).upper()

        return disk_data

    def toBigEndian(self, hexString):
        """ Convert hexString to Big-Endian Format """
        swapByteOrder = ""
        character = ""
        lastpos = 0
        for x in xrange(0, len(hexString) + 2, 2):
            character = hexString[lastpos:x] # Take 2 bytes (character)
            swapByteOrder = character + swapByteOrder # Move to end of string
            lastpos = x
        return swapByteOrder

    def get_partition_type(self, fs_type):
        """ Return partition type """
        for t in filesystem_type:
            if t in filesystem_type.keys():
                return filesystem_type[fs_type]

    def get_partition_data(self):
        """ Pick out relevant partition data """
        # first partition is at 0x1BE, convert this to decimal value
        # seek that amount into the file, read the 16 bytes
        # and that is the MBR record for the partition
        # 0x1CE -> 446 - 1st partition
        # 0x1BE -> 462 - 2nd partition
        # 0x1DE -> 478 - 3rd partition
        # 0x1FE -> 494 - 4th partition

        partitions = [446, 462, 478, 494]
        partition_info = []

        part_number = 1
        part_data = []
        part_flag = ""
        part_type = ""
        part_start_address = ""
        part_size = ""

        # For each VISIBLE partition, pull out required information
        for p in partitions:
            part_info = self.read_disk(p,True,False) # get partition information

            # get flag, type, start sector address and size in hex
            part_flag = self.toBigEndian(part_info[:2] + '0x')
            part_type = self.toBigEndian(part_info[8:10] + '0x')
            part_start_address = self.toBigEndian(part_info[16:24] + '0x')
            part_size = self.toBigEndian(part_info[24:34] + '0x')

            # above variables formatted for nice output later
            part_type_string = "(" + self.get_partition_type(part_info[8:10]) + ")"
            part_address_string = "(" + str(int(self.toBigEndian(part_info[16:24]), 16)) + ")"
            part_size_string = "(" + str(int(self.toBigEndian(part_info[24:34]), 16)) + ")"

            # if the partition type is 0x00, it is unassigned
            # Don't add to list of visible partitions, otherwise do
            if part_type != "0x00":
              part_data.append({"Partition #": part_number,
                             "Flag": part_flag,
                             "Type": part_type,
                             "Sector Start Address": part_start_address,
                             "Flag_string": part_flag,
                             "Type_string": part_type_string,
                             "Sector Start Address_string": part_address_string,
                             "Partition Size": part_size,
                             "Partition Size_string": part_size_string, })
            part_number += 1


        return part_data

    def get_NTFS_volume_data(self, volume_num, address):
        """ Get Information on NTFS Volume"""

        volume_data = self.read_disk(address, False, True) # Get NTFS BPB and Extended BPB code.

        bytes_per_sector = int(self.toBigEndian(volume_data[22:26]), 16)
        sectors_per_cluster = int(self.toBigEndian(volume_data[26:28]), 16)
        media_descriptor = int(self.toBigEndian(volume_data[42:44]), 16)
        total_sectors = int(self.toBigEndian(volume_data[80:94]), 16)
        MFT_cluster_location = int(self.toBigEndian(volume_data[96:110]), 16)
        MFT_copy_cluster_location = int(self.toBigEndian(volume_data[112:126]), 16)
        clusters_per_MFT_record = int(self.toBigEndian(volume_data[128:130]), 16)
        clusters_per_index_buffer = int(self.toBigEndian(volume_data[136:138]), 16)
        volume_serial_number = volume_data[144:160]

        print  "\nbytes_per_sector: ",  bytes_per_sector
        print  "sectors_per_cluster: ",  sectors_per_cluster
        print  "media_descriptor: ",  media_descriptor
        print  "total_sectors: ",  total_sectors
        print  "MFT_cluster_location: ",  MFT_cluster_location
        print  "MFT_copy_cluster_location: ",  MFT_copy_cluster_location
        print  "clusters_per_MFT_record: ",  clusters_per_MFT_record
        print  "clusters_per_index_buffer: ",  clusters_per_index_buffer
        print  "volume_serial_number: ",  volume_serial_number, "\n"

        ntfs_volume_data = {"volume_num": volume_num,
                         "bytes_per_sector" : bytes_per_sector,
                         "sectors_per_cluster" : sectors_per_cluster,
                         "MFT_cluster_location" : MFT_cluster_location}

        return ntfs_volume_data

    def display_disk_info(self):
        """ Outputs the Layout and Structure of the disk """
        part_data = self.get_partition_data()

        volume_data = []

        print "##########################\n",
        print "***** PARTITION INFO *****"
        print "##########################\n"
        print "Number of Visible Partitions:", len(part_data), "\n"
        read_parts = False

        for i in xrange(len(part_data)):
            print "Partition #", part_data[i].get("Partition #")
            print "Start Sector Address:", part_data[i].get("Sector Start Address"), part_data[i].get("Sector Start Address_str")
            print "Partition Size:", int(part_data[i].get("Partition Size"),16),"Sectors"
            print "Size in MegaBytes (Approximately):", size(int(part_data[i].get("Partition Size"),16) * SECTOR_SIZE)
            print "File System Type:", part_data[i].get("Type"), part_data[i].get("Type_str"), "\n"

        for i in xrange(len(part_data)):
            vol_sec_address = int(part_data[i].get("Sector Start Address"),16)  # Get NTFS volume address in decimal
            print "#######################################"
            print "***** VOLUME INFO FOR PARTITION %i *****" % i
            print "#######################################"
            NTFS_volume_data = self.get_NTFS_volume_data(i, vol_sec_address)
            volume_data.append(NTFS_volume_data)
            #print

        return part_data, volume_data

def analyse_partition(raw_mbr):
        partition = {}
        partition["boot_flag"] = struct.unpack('>b',raw_mbr[0:1])[0]
        partition["begin_chs"] = int(reverse_bytes(binascii.hexlify(raw_mbr[1:3])),16)
        partition["type"] = struct.unpack('>b',raw_mbr[4])[0]
        partition["end_chs"] = int(reverse_bytes(binascii.hexlify(raw_mbr[5:8])),16)
        partition["start_LBA"] = struct.unpack('i',raw_mbr[8:12])[0]
        partition["size_in_sectors"] = struct.unpack('i',raw_mbr[12:16])[0]  # partition["size_in_sectors"] = int(reverse_bytes(binascii.hexlify(mbr[12:16])),16)
        return partition

def reverse_bytes(b):
    new = ""
    for x in range(-1, -len(b), -2):
        new += b[x-1] + b[x]
    return new

def analyse_volume(raw_vol, first_sector):
        volume = {}
        volume["no_sectors_per_cluster"] = struct.unpack('>b',raw_vol[13])[0]
        volume["size_reserved_area_clusters"] = int(reverse_bytes(binascii.hexlify(raw_vol[14:16])),16)
        volume["size_of_each_fat_sectors"] = int(reverse_bytes(binascii.hexlify(raw_vol[22:24])),16)
        volume["no_of_fat_copies" ] = struct.unpack('>b', raw_vol[16])[0]
        volume["fat_area_size"] = volume["size_of_each_fat_sectors"] \
        * volume["no_of_fat_copies"]
        volume["max_no_root_dir"] = int(reverse_bytes(binascii.hexlify(raw_vol[17:19])),16)
        entry_size = 32
        volume["root_dir_size"] = (volume["max_no_root_dir"]*entry_size)/512
        volume["cluster_size"] = volume["no_sectors_per_cluster"] * 512
        volume["DA_address"] = first_sector  + volume["size_reserved_area_clusters"]\
        + volume["fat_area_size"]
        volume["cluster2_address"] = volume["DA_address"] + volume["root_dir_size"]
        print "no_sectors_per_cluster", volume["no_sectors_per_cluster"]
        print "size_reserved_area_clusters", volume["size_reserved_area_clusters"]
        print "size fat sector", volume["size_of_each_fat_sectors"]
        print "no_of_fat_copies", volume["no_of_fat_copies"]
        print "fat_area_size", volume["fat_area_size"]
        print "max_no_root_dir", volume["max_no_root_dir"]
        print "Root Dir Size", volume["root_dir_size"]
        print "cluster_size", volume["cluster_size"]
        print "DA_address", volume["DA_address"]
        print "cluster#2_address", volume["cluster2_address"]
        return volume

def analayse_dir_entry(raw_dir_entry):
        print "\n****************DIR_ENTRY*****************\n"
        att_type = {"128":"READ_ONLY","64":"HIDDEN","32":"SYSTEM_FILE","16":"VOL_LABEL"\
        ,"8":"DIRECTORY","4":"ARCHIVE","15":"LONG_FILE_NAME"}

        d = {}
        d["deleted"] = False

        if binascii.hexlify(raw_dir_entry[0]) == "e5":
                print "!!!!!!!!!DELETED!!!!!!!!!!!"
                d["deleted"] = True

        d["filename"] = raw_dir_entry[0:11]
        d["filename"] = binascii.hexlify(d["filename"]).decode("hex")
        d["attributes"] = int(reverse_bytes(binascii.hexlify(raw_dir_entry[11])),16)
        d["starting_cluster"] = int(reverse_bytes(binascii.hexlify(raw_dir_entry[26:28])),16)
        d["size"] =  int(reverse_bytes(binascii.hexlify(raw_dir_entry[28:32])),16)

        try:
                print "This is a ", att_type[str(d["attributes"])]
        except:
                print "Not a valid DIRECTORY"
        print "filename", d["filename"]
        print "attributes", d["attributes"]
        print "starting_cluster", d["starting_cluster"]
        print "size", d["size"], " Bytes"
        print "size", bytes_to_KB(int(d["size"])), " KiloBytes"

def analayse_dir_entry_for_del_files(raw_dir_entry, cluster2_address, no_sectors_per_cluster):
        d = {}
        att_type = {"128":"READ_ONLY","64":"HIDDEN","32":"SYSTEM_FILE","16":"VOL_LABEL","8":"DIRECTORY","4":"ARCHIVE","15":"LONG_FILE_NAME"}
        detected = False
        if binascii.hexlify(raw_dir_entry[0]) == "e5":
                print "!!!!!!!!!DELETED!!!!!!!!!!!"
                d["deleted"] = True
                detected = True
                d["filename"] = raw_dir_entry[0:11]
                d["filename"] = binascii.hexlify(d["filename"]).decode("hex")
                d["attributes"] = int(reverse_bytes(binascii.hexlify(raw_dir_entry[11])),16)
                d["starting_cluster"] = int(reverse_bytes(binascii.hexlify(raw_dir_entry[26:28])),16)
                d["size"] =  int(reverse_bytes(binascii.hexlify(raw_dir_entry[28:32])),16)
                d["CSA"] = ((cluster2_address) + (d["starting_cluster" ]-2) * 8)
                print "deleted files name", d["filename"]
                try:
                        print "This is a ", att_type[str(d["attributes"])]
                except:
                        print "not a valid entry"
                        print str(d["attributes"])

                print "starting_cluster", d["starting_cluster"]
                print "size", d["size"], " Bytes"
                print "size", bytes_to_KB(int(d["size"])), " KiloBytes"
                print "Cluster sector address - CSA", d["CSA"]
                return d, detected

def main(argv):
    parseMFT = False
    volume_no = 0
    file_path = argv[1]
    sys.stdout = open("output.txt", "w")
    disk_explorer = DiskExplorer(file_path)
    partition_info, volume_info = disk_explorer.display_disk_info() # Default usage - Get partition information from MBR (Master Boot Record)

    with open(argv[1], "rb") as f:
    	print "\n$$$$$$$$$$$$$$$$$$$$-DIRECTORY_LISTING ANALYSIS-$$$$$$$$$$$$$$$$$$$$$$"
    	f.seek(446)
        mbr =  f.read(16 + 16 + 16 + 16)
        start = 0
        analysed_parts = []
        volume1 = f.read(510) #510 -- removed layout of fat volume
        for i in [16,32,48,64]:
                analysed_parts.append(analyse_partition(mbr[start:i]))
                start = i
        counter = 0
        for i in range(4):
                if not  analysed_parts[i]["type"] == 0:
                        counter = counter + 1

        f.seek(0)
        vol1_sector_addr = int(analysed_parts[0]["start_LBA"]) * 512
        f.seek(vol1_sector_addr)
        volume1 = f.read(510) #510 -- removed layout of fat volume
        if not int(analysed_parts[0]["type"]) ==  4:
            vol1_info = analyse_volume(volume1, int(analysed_parts[0]["start_LBA"]))
        else:
            print "First Partition is not fat-16"
        f.seek(0)
    	root_dir_sector_address = vol1_info["DA_address"]
    	f.seek(root_dir_sector_address * 512)
    	s = vol1_info["root_dir_size"]
    	vol1_d1 = f.read(s)
    	analayse_dir_entry(vol1_d1)
    	starting_address = (root_dir_sector_address * 512)
    	loop = True
    	add = 32
    	while(loop):
            	f.seek(0)
            	f.seek(((root_dir_sector_address )* 512) + add)
            	temp = f.read(32)
            	if binascii.hexlify(temp[0]) == "00":
                    	loop = False
                    	break
            	analayse_dir_entry(temp)
            	add = add + 32

        print "\n########################CHECK DELELETED FILES##############################\n"
        starting_address = (root_dir_sector_address * 512)
        loop = True
        add = 0
        while(loop):
                f.seek(0)
                f.seek(((root_dir_sector_address )* 512) + add)
                temp = f.read(32)
                if binascii.hexlify(temp[0]) == "00":
                        loop = False
                        break
                status = analayse_dir_entry_for_del_files(temp,vol1_info["cluster2_address"], vol1_info["no_sectors_per_cluster"])
                if not status == None:
                        break
                add = add + 32
        DELETED_ENTRY = status[0]
        csa = DELETED_ENTRY["CSA"]
        deleted_entry_address = csa * 512
        f.seek(0)
        f.seek(deleted_entry_address)
        deleted_contents = f.read(16)
        print "\n\ndeleted first 16 Bytes Content"
        print "----------------------------------"
        print binascii.hexlify(deleted_contents).decode("hex")
        print "----------------------------------"
        print "\nPROGRAM TERMINATING SUCCESSFULLY"

if __name__ == '__main__':
    main(sys.argv)

