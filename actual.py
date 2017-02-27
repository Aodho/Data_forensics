#! /bin/python

from hurry.filesize import size
from sets import Set

import binascii
import sys
import csv
import codecs
import struct

reload(sys)  
sys.setdefaultencoding('utf16')

# Map the bytes to attribute type
ATTRIBUTE_TYPES = {"10000000": "$STANDARD_INFORMATION",
                   "20000000": "$ATTRIBUTE_LIST",
                   "30000000": "$FILE_NAME",
                   "40000000": "$VOLUME_VERSION",
                   "40000000": "$OBJECT_ID",
                   "50000000": "$SECURITY_DESCRIPTOR",
                   "60000000": "$VOLUME_NAME",
                   "70000000": "$VOLUME_INFORMATION",
                   "80000000": "$DATA",
                   "90000000": "$INDEX_ROOT",
                   "A0000000": "$INDEX_ALLOCATION",
                   "B0000000": "$BITMAP",
                   "C0000000": "$SYMBOLIC_LINK",
                   "C0000000": "$REPARSE_POINT",
                   "D0000000": "$EA_INFORMATION",
                   "E0000000": "$EA",
                   "F0000000": "$PROPERTY_SET",
                   "100000000": "$LOGGED_UTILITY_STREAM"}

# Map the bytes to record type
FILE_FLAGS = {"0": "Deleted",
              "1": "Record in Use",
              "2": "Directory",
              "3": "Directory in Use"}

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

class DiskExplorer():
    def __init__(self, filepath):
        self.filepath = filepath

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

    def read_FAT_partition_data(self):
        """ Read 16 byte partition information from disk """

        with open(self.filepath, "rb") as f:
            # first partition is at 0x1BE, convert this to decimal value
            # seek that amount into the file, read the 16 bytes
            # and that is the MBR record for the partition
            # 0x1CE -> 446 - 1st partition
            # 0x1BE -> 462 - 2nd partition
            # 0x1DE -> 478 - 3rd partition
            # 0x1FE -> 494 - 4th partition
            partitions = [446, 462, 478, 494]
            part_info = []

            for partition in partitions:
                part = ""
                f.seek(partition)

                for x in xrange(1, 17):
                    byte = f.read(1)
                    part = part + str(binascii.hexlify(byte).upper())

                part_info.append(part)

        return part_info

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

    def get_FAT_partition_data(self):
        part_info = self.read_FAT_partition_data()
        partition_info = self.get_partition_info(part_info)

        return partition_info

    def get_partition_info(self, partition_info):
        """ Pick out relavant partition information """

        j = 1
        p_info = []
        p_flag = ""
        p_type = ""
        p_start_addr = ""
        p_size = ""

        for i in partition_info:
            p_flag = self.toBigEndian(i[:2] + '0x')
            p_type = self.toBigEndian(i[8:10] + '0x') + "(" + self.get_partition_type(i[8:10]) + ")"
            p_start_addr = self.toBigEndian(i[16:24] + '0x') + " (" + str(int(self.toBigEndian(i[16:24]), 16)) + ") "
            p_size = self.toBigEndian(i[24:34] + '0x') + " (" + str(int(self.toBigEndian(i[24:34]), 16)) + ")"

            p_info.append({"Partition #": j,
                           "Flag": p_flag,
                           "Type": p_type,
                           "Sector Start Address": p_start_addr,
                           "Partition Size": p_size
                       })
            j += 1

        return p_info

    def get_FAT_volume_data(self, address):

        # take address in deciaml
        res_area_sector = int(address[12:14])

        # create address of sector we need to seek to
        sector_address = res_area_sector * SECTOR_SIZE

        vol_info = []

        with open(self.filepath, "rb") as f:
            f.seek(sector_address)
            for i in xrange(2):
                part = ""
                for x in xrange(1, 17):
                    byte = f.read(1)
                    part = part + str(binascii.hexlify(byte).upper())

                vol_info.append(part)

        # Reserved Area size in Sectors 0Eh - 2 bytes
        reserved_area_size = int(self.toBigEndian(vol_info[0][-4:]), 16)

        # FAT size in Sector 16h, 17h  - 1 word
        fat_size = int(self.toBigEndian(vol_info[1][12:16]), 16)

        # No. of FATs 10h - 1 byte
        num_fats = int(self.toBigEndian(vol_info[1][:2]), 16)

        # FAT Area = (No. of FATs * FAT size in secors)
        fat_area_size =  fat_size * num_fats

        # No. of root dir entries 11h - 1 word
        num_root_dirs = int(self.toBigEndian(vol_info[1][2:6]),16)

        # always 32 bytes for a FAT volume
        dir_entry_size = 32

        # Root dir size in sectors
        root_dir_size = (num_root_dirs * dir_entry_size) / SECTOR_SIZE

        # No. of sectors per cluster 0D - 1 byte
        num_sectors = int(self.toBigEndian(vol_info[0][-6: -4]),16)

        DA_address = res_area_sector + reserved_area_size + fat_area_size
        cluster_2_addr = DA_address + root_dir_size
        print "##################################\n",
        print "***** FAT Volume information *****"
        print "##################################\n"
	print "Number of sectors per cluster:", num_sectors
        print "Fat size:", fat_size
        print "Fat area size:", fat_area_size
        print "size of root directory:", root_dir_size
        print "Cluster #2 location:", cluster_2_addr, "(" + str(cluster_2_addr), "to", str(cluster_2_addr + num_sectors) + ")"
	print

        return {"First sector of Disk": 0,
                "First sector of Reserved Area": res_area_sector,
                "First sector of FAT Area": res_area_sector + reserved_area_size,
                "First sector of Data Area": DA_address,
                "Cluster #2 location": cluster_2_addr }

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

        return part_data, volume_data

    def get_del_file_info(self, root_dir_address, first_cluster):

        file_name = ""
        file_size = 0
        start_cluster = ""

        root_dir_address = int(root_dir_address)

        # create address of sector we need to seek to
        sector_address = root_dir_address * SECTOR_SIZE

        found_deleted = False
        with open(self.filepath, "rb") as f:
            f.seek(0)
            f.seek(sector_address)
            while found_deleted != True:
                part = ""
                byte = f.read(32)
                # read a byte, if a deleted file, get file info
                if binascii.hexlify(byte).upper()[:2] == "E5":
                    found_deleted = True

                    file_name = binascii.hexlify(byte).upper()[:22].decode("hex")
                    start_cluster = self.toBigEndian(binascii.hexlify(byte[-6:-4])).upper()
                    file_size = int(self.toBigEndian(binascii.hexlify(byte[-4:])).upper(), 16)
                    print "\n#########################"
                    print "***** Deleted Files *****"
                    print "#########################"
		    print
                    print "File Name:", file_name
                    print "File Size:", size(file_size)
                    print "Cluster Address:", start_cluster + "h or", str(int(start_cluster,16)) + "d"
                else:
                    # seek to next file in root directory
                    f.read(32)
                    continue

            # Calculate cluster sector address
            file_cluster_addr = int(int(first_cluster) + ((int(start_cluster,16) - 2) * 8))

            # Seek to deleted file on disk
            f.seek(file_cluster_addr * SECTOR_SIZE)

            # read 16 bytes of information
            file_data = f.read(16)
            print "*****Contents of File*****"
            print file_data
	    print
	    print

    def get_attribute_type(self, attr_types):
        """ Return partition type """
        for t in ATTRIBUTE_TYPES:
            if t in ATTRIBUTE_TYPES.keys():
                return ATTRIBUTE_TYPES[attr_types]

    def get_disk_data(self, address, bytes_to_read):
        """ Seek to given address and read the amount of bytes given """

        with open(self.filepath, "rb") as f:
            # seek to sector address
            print"Address in get disk data:", address
            f.seek(address)

            # read bytes and convert to hex
            byte = f.read(bytes_to_read)
            disk_data = binascii.hexlify(byte).upper()

        return disk_data

    def get_MFT_info(self, address):
        """ Parse the Master File Table and get record information """

        hasFiles = True
        record_num = 0
        rows = []
        filename = ""

        # If a mft record doesn't have these values defaulted, it will error out
        dos_permis = 0
        filename_flags = 0
        parent_dir_ref = 0
	count = 1
        # Parse MFT until no more files left or we reach a BAD file
        while hasFiles:
            print
	    print "#########################\n",
            print "***** MTF FILE: %i *****" %count
            print "#########################\n"
            mft_record = self.get_disk_data(address, 1024)
            record_num += 1
            print "magic number:", mft_record[0:8].decode("hex")
            if mft_record[0:8].decode("hex") != "FILE":
                # terminate
                hasFiles = False

            update_sequence_offset  = int(self.toBigEndian(mft_record[8:12]), 16)
            fixup_entries_array = int(self.toBigEndian(mft_record[12:16]), 16)
            offset_to_first_attribute = int(self.toBigEndian(mft_record[40:44]), 16)
            mft_record_flags = str(int(self.toBigEndian(mft_record[44:48]), 16))
            used_mft_size = int(self.toBigEndian(mft_record[48:56]), 16)
            allocated_mft_size = int(self.toBigEndian(mft_record[56:64]), 16)
            reference_to_base_file = int(self.toBigEndian(mft_record[64:80]), 16)
            first_attr_offset = int(self.toBigEndian(mft_record[40:44]), 16) * 2

            print "update sequence offset:",                update_sequence_offset
            print "Entries in Fixup Array:",                fixup_entries_array
            print "Offset to first attribute:",             first_attr_offset/2, "bytes"
            print "Offset to first attribute in hex:",      offset_to_first_attribute
            # This tells me that the file is deleted or in use
            print "Flags:",                                 mft_record_flags
            print "Used size of MFT entry:",                used_mft_size
            print "Allocated size of MFT entry:",           allocated_mft_size
            print

            total_offset = first_attr_offset
            # Must go to the first attribute offset

            read_attributes = True
            isFile = True
	    counter = 1;
            while read_attributes:
                type_id        = ATTRIBUTE_TYPES.get(mft_record[total_offset : total_offset + 8],"Unknown attribute")
                attr_length    = int(self.toBigEndian(mft_record[total_offset + 8: total_offset + 16]), 16)
                form_code      = self.toBigEndian(mft_record[total_offset + 16 : total_offset + 18])
                offset_to_name = self.toBigEndian(mft_record[total_offset + 20 : total_offset + 24])
                attr_id        = self.toBigEndian(mft_record[total_offset + 28 : total_offset + 30])

                print "###################################"
                print "***** ATTRIBUTE %i INFORMATION *****"% counter
                print "###################################"
		print
                print "Attribute Type is:",  type_id
                print "Attribute Lengh is:", attr_length
                print "Offset to Name:",     offset_to_name
                print "Attribute is:", "Resident" if form_code == "00" else "Non-Resident"

                # Depending on which type, depends on how much of the record to read into
                file_record_hdr = ""

                if form_code == "00":
                    # resident attribute
                    file_record_hdr = mft_record[total_offset: total_offset + 44 ]
                    # These are for resident attributes ONLY
                    content_size = int(self.toBigEndian(file_record_hdr[32:40]), 16)
                    offset_to_content = int(self.toBigEndian(file_record_hdr[40:44]), 16) * 2

                    print "Attribute ID:",      attr_id
                    print "Content Size:",      content_size
                    print "Offset to Content:", offset_to_content
                else:
                    # non resident attribute
                    file_record_hdr = mft_record[total_offset: total_offset + 128 ]

                    # These are for non-resident
                    starting_VCN          = self.toBigEndian(file_record_hdr[32:48])
                    ending_VCN            = self.toBigEndian(file_record_hdr[48:64])
                    offset_to_runlist     = self.toBigEndian(file_record_hdr[64:68])
                    allocated_size        = self.toBigEndian(file_record_hdr[76:92])
                    actual_size           = self.toBigEndian(file_record_hdr[92:108])

                    print "Attribute ID:",                             attr_id
                    print "starting Virtual Cluster Number: ",         starting_VCN
                    print "ending Virtual Cluster Number: ",           ending_VCN
                    print "offset_to_runlist: ",                       offset_to_runlist
                    print "allocated_size: ",                          allocated_size
                    print "actual_size: ",                             actual_size

                file_record = mft_record[total_offset: total_offset + attr_length * 2]

                print "\n=================================\n"
                print "Bytes for current file attribute:\n"
                print file_record
                print "\n=================================\n"

                if not type_id == "$STANDARD_INFORMATION":
		    read_attributes= False

                # Update the offset after reading current attribute
                total_offset += attr_length * 2
		counter = counter + 1

            # Move address to next MFT entry
            address += 1024
	    count = count + 1

def main(argv):
    parseMFT = False
    volume_no = 2
    file_path = argv[1]
    sys.stdout = open("output.txt", "w")
    disk_explorer = DiskExplorer(file_path)
    p_info = disk_explorer.get_FAT_partition_data()
    vol_info = disk_explorer.get_FAT_volume_data(p_info[0].get("Sector Start Address"))
    partition_info, volume_info = disk_explorer.display_disk_info() # Default usage - Get partition information from MBR (Master Boot Record)
    disk_explorer.get_del_file_info(vol_info.get("First sector of Data Area"),vol_info.get("Cluster #2 location"))
    mft_cluster_location = volume_info[volume_no].get("MFT_cluster_location")
    sectors_per_cluster = volume_info[volume_no].get("sectors_per_cluster")
    mft_logical_addr = mft_cluster_location * sectors_per_cluster
    mft_physical_addr = 0
    mft_physical_addr = int(partition_info[volume_no].get("Sector Start Address"),16)
    mft_physical_addr += mft_logical_addr
    mft_physical_addr = mft_physical_addr * SECTOR_SIZE
    print "######################################\n",
    print "***** NTFS SUPPORTED INFORMATION *****"
    print "######################################\n"
    print "MFT Physical Sector Number:", mft_physical_addr / SECTOR_SIZE
    print "Logical address:",mft_logical_addr
    print "Sector address:",int(partition_info[volume_no].get("Sector Start Address"),16)
    disk_explorer.get_MFT_info(mft_physical_addr)

if __name__ == '__main__':
    main(sys.argv)



