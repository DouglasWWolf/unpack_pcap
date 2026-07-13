//=============================================================================
// unpack_pcap - A tool for unpacking a PCAP file into RAM
//
// Author: D. Wolf
//
//
//  Ver    Date     Who  What
//-----------------------------------------------------------------------------
//  1.0  11-Jul-26  DWW  Initial creation
//=============================================================================
#define SOFTWARE_REV "1.0"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <cstdint>
#include "PhysMem.h"

using namespace std;

PhysMem  RAM;
FILE*    ifile;
uint32_t packets = 0;
uint32_t packet_cycles = 0;
uint32_t ram_records   = 0;


struct 
{
    uint64_t    size     = 0x100000000;
    uint64_t    addr     = 0x100000000;
    string      filename = "";
} config;


void execute();
void parseCommandLine(const char** argv);


//=============================================================================
// main() - Execution starts here
//=============================================================================
int main(int argc, const char** argv)
{

    parseCommandLine(argv);

    try
    {
        execute();
    }
    catch(const std::exception& e)
    {
        printf("%s\n", e.what());
        exit(1);
    }
}
//=============================================================================



//=============================================================================
// showHelp() - Displays some help-text and exits the program
//=============================================================================
void showHelp()
{
    printf("unpack_pcap v%s\n", SOFTWARE_REV);
    printf("unpack_pcap [-addr <n>] [-size <n>] <filename>\n");
    exit(1);
}
//=============================================================================



//=============================================================================
// parseCommandLine() - Parses the command line parameters
//=============================================================================
void parseCommandLine(const char** argv)
{
    int i=1;
    const char* ptr;

    while (argv[i])
    {
        // Fetch the next token from the command line
        string token = argv[i++];

        if (token == "-size")
        {
            ptr = argv[i++];
            if (ptr == nullptr) showHelp();
            config.size = strtoul(ptr, 0, 0);
            if (config.size < 1) showHelp();
            continue;
        }

        else if (token == "-addr")
        {
            ptr = argv[i++];
            if (ptr == nullptr) showHelp();
            config.addr = strtoul(ptr, 0, 0);
            if (config.addr < 0x100000000) showHelp();
            continue;
        }

        else if (token == "-help")
        {
            showHelp();
        }

        // If this is an unrecognized command-line switch, complain
        else if (token[0] == '-')
        {
            printf("invalid command line switch.\n");
            showHelp();            
        }

        // Store the filename 
        if (config.filename == "") 
        {
            config.filename = token;
            continue;
        }

        // We had an unexpected parameter on the command line
        showHelp();
    }

    // If the user didn't give us a filename, show the help
    if (config.filename == "") showHelp();
}
//=============================================================================

//=============================================================================
// This goes at the very top of our data in RAM.  The reads this in to 
// determine whether it's looking at a real PCAP structure, and to determine
// how to configure itself
//=============================================================================
#pragma pack(push, 1)
struct
{
    uint64_t magic;
    uint32_t ram_records;
    uint32_t packet_cycles;
    uint8_t  filler[46];
} playback_params;
#pragma pack(push, 1)
//=============================================================================

//=============================================================================
// This is the header of a PCAP file
//=============================================================================
#pragma pack(push, 1)
struct pcap_header_t
{
    uint32_t    magic_number;
    uint16_t    major_version;
    uint16_t    minor_version;
    uint32_t    reserved1;
    uint32_t    reserved2;
    uint32_t    snaplen;
    uint32_t    link_type;
} pcap_header;
#pragma pack(pop)
//=============================================================================


//=============================================================================
// This is a PCAP packet
//=============================================================================
#pragma pack(push, 1)
struct pcap_packet_t
{
    uint32_t    ts_seconds;
    uint32_t    ts_nanoseconds;
    uint32_t    length1;
    uint32_t    length2;
};
#pragma pack(pop)
//=============================================================================


//=============================================================================
// This is a PCAP packet
//=============================================================================
#pragma pack(push, 1)
struct ram_header_t
{
    uint64_t    magic = 0xDEADBEEFDEADBEEFULL;
    uint16_t    length;
    uint8_t     filler[54];
} ram_header;
#pragma pack(pop)
//=============================================================================



//=============================================================================
// analyze_file() - Find out how many 64-byte records this will will take
//                  in RAM and as transmitted packets
//
// On Exit: packets       = The number of packets in the file
//          packet_cycles = # of 64-byte data-cycles of packet data
//=============================================================================
void analyze_file()
{
    pcap_packet_t packet;

    // Find the current position of the file
    auto sof = ftell(ifile);

    // Spin through the input pcap file, one packet at a time
    while (fread(&packet, 1, sizeof(packet), ifile) == sizeof(packet))
    {
        // Count the number of packets in the file
        ++packets;

        // This is the packet length
        uint32_t length = packet.length1;

        // How many data-cycles will this packet occupy?
        uint32_t cycles = (length / 64) + ((length & 63) != 0);

        // Keep track of how many data-cycles this fill will require
        packet_cycles = packet_cycles + cycles;
 
        // Skip over the packet data
        fseek(ifile, length, SEEK_CUR);
    }

    // Restore the original position of the file
    fseek(ifile, sof, SEEK_SET);
}
//=============================================================================


//=============================================================================
// write_packets_to_ram() - Writes the PCAP data to RAM
//=============================================================================
void write_packets_to_ram(unsigned char* ptr)
{
    pcap_packet_t packet;

    // Write a block of playback-parameters into the first block of RAM
    // The FPGA will fetch this prior to fetching packets
    playback_params.magic         = 0x3141592653589793ULL;
    playback_params.ram_records   = ram_records;
    playback_params.packet_cycles = packet_cycles;
    memcpy(ptr, &playback_params, sizeof(playback_params));
    ptr += 4096;

    // Spin through the input pcap file, one packet at a time
    while (fread(&packet, 1, sizeof(packet), ifile) == sizeof(packet))
    {
        // This is the packet length
        uint32_t length = packet.length1;

        // Write the header to RAM
        ram_header.length = length;
        memcpy(ptr, &ram_header, sizeof(ram_header));
        ptr += sizeof(ram_header);
        
        // How many bytes of padding will this packet need to get 
        // to a multiple of 64 bytes?
        uint32_t padding =  64 - (length & 63);

        // Read the packet data from the file into RAM
        if (fread(ptr, 1, length, ifile) != length)
        {
            fprintf(stderr, "read from file %s failed!\n", config.filename.c_str());
            exit(1);
        }
        ptr += length;

        // If we need to add padding, make it so
        if (padding < 64)
        {
            memset(ptr, 0, padding);
            ptr += padding;            
        }
    }
};
//=============================================================================


//=============================================================================
// execute() - Creates a PCAP file from a bank of RAM on the FPGA board
//=============================================================================
void execute()
{
    // Get a string pointer to the filename
    const char* fn = config.filename.c_str();

    // Open the input file
    ifile = fopen(fn, "r");
    if (ifile == nullptr) 
    {
        fprintf(stderr, "file not found: %s\n", fn);
        exit(1);
    }

    // Read the PCAP header    
    size_t n = fread(&pcap_header, 1, sizeof(pcap_header), ifile);
    if (n != sizeof(pcap_header))
    {
        fprintf(stderr, "malformed input file: %s\n", fn);
        exit(1);
    }

    // Make sure this is a PCAP file!
    if (pcap_header.magic_number != 0xA1B2C3D4 && pcap_header.magic_number != 0xA1B23C4D)
    {
        fprintf(stderr, "not a pcap file: %s\n", fn);
        exit(1);
    }

    // Find out how many packets are in the file, and how many data-cycles they require
    analyze_file();

    // Make sure the file isn't empty
    if (packets == 0)
    {
        fprintf(stderr, "empty pcap file: %s\n", fn);
        exit(1);
    }

    // How many 64-byte records in RAM will this require?
    ram_records = packet_cycles + packets;

    // There are 64 records in a 4KB block.  How many blocks will this require?
    // We add 1 at the end to account for the header block we write
    uint32_t blocks = (ram_records / 64) + ((ram_records & 63) != 0) + 1;

    // This is the total amount of required space, in bytes
    uint64_t bytes_required = blocks * 4096;

    // Make sure our data will fit in RAM!
    if (bytes_required > config.size)
    {
        fprintf(stderr, "input file %s requires too much storage\n", fn);
        exit(0);
    }

    // Map RAM
    RAM.map(config.addr, bytes_required);

    // Write the packets to RAM
    write_packets_to_ram(RAM.bptr());

    // We're done with the input file
    fclose(ifile);

    // Tell the user what we've done
    printf("%8u packets unpacked from %s\n", packets, fn);

    // Tell the OS that all is well
    exit(0);
}
//=================================================================================================
