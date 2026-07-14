//=================================================================================================
// PhysMem - A class for mapping physical RAM addresses into userspace
//=================================================================================================
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <string.h>
#include <string>
#include <fstream>
#include "PhysMem.h"
using namespace std;

#define MALFORMED 0xFFFFFFFFFFFFFFFF



//=================================================================================================
// throwRuntime() - Throws a runtime exception
//=================================================================================================
static void throwRuntime(const char* fmt, ...)
{
    char buffer[1024];
    va_list ap;
    va_start(ap, fmt);
    vsprintf(buffer, fmt, ap);
    va_end(ap);

    throw runtime_error(buffer);
}
//=================================================================================================

//=================================================================================================
// This describes a reserved contiguous buffer
//=================================================================================================
struct contig_t
{
    uint64_t    addr;
    uint64_t    size;
};
//=================================================================================================




//=================================================================================================
// parseKMG() - Examines a string for a delimeter, and parses the integer immediately after 
//              the delimeter.  Looks for the character after the digits, expect to find a K, M,
//              or G (meaning Kilo, Mega, or Giga) and returns the parsed value.
//
//              Example:  4G = 0x1_0000_0000
//                        2K = 0x400
//                        3M = 0x30_0000
//
// If the string is malformed in some way, returns -1
//=================================================================================================
static uint64_t parseKMG(const char* ptr)
{
    // Convert the ASCII digits that follow the delimeter to an integer
    int64_t value = strtol(ptr, 0, 0);

    // Skip over all of the ASCII digits
    while (*ptr >= '0' && *ptr <= '9') ++ptr;

    // Return the appropriate scaled integer value
    if (*ptr == 'K') return value * 1024;
    if (*ptr == 'M') return value * 1024 * 1024;
    if (*ptr == 'G') return value * 1024 * 1024 * 1024;

    // If we get here, there wasn't a K, M, or G after the numeric value
    return MALFORMED;
}
//=================================================================================================

//=================================================================================================
// get_contig() - Fetch the geometry of the reserved contiguous buffer
//=================================================================================================
static contig_t get_contig()
{
    string line;
    contig_t contig = {MALFORMED, MALFORMED};

    const char* filename = "/proc/cmdline";

    // Open the specified file.  It will contain a line of ASCII data
    ifstream file(filename);

    // If we couldn't open the file, tell the caller
    if (!file.is_open()) throwRuntime("Can't open %s", filename);
    
    // Fetch the first line of the file
    getline(file, line);

    // Look for "memmap=" in the command line
    const char* memmap = ::strstr(line.c_str(), "memmap=");

    // If we can't find "memmap=", something is awry
    if (memmap == nullptr) throwRuntime("malformed %s", filename);

    // Fetch the value after the '='
    contig.size = parseKMG(memmap + 7);

    // Fetch the value after either a '!' or a '$
    const char* p = strchr(memmap, '$');
    if (p == nullptr) p = strchr(memmap, '!');
    if (p) contig.addr = parseKMG(p+1);

    // If we couldn't parse one of those values, /proc/cmdline is malformed
    if (contig.addr == MALFORMED || contig.size == MALFORMED) throwRuntime("malformed %s", filename);

    // Hand the geometry of the contig buffer to the caller
    return contig;
}
//=================================================================================================






//=================================================================================================
// map() - Maps the specified physical address into user-space
//
// Passed: physAddr = The physical address to map into user-space
//         size     = The size of the region to map, in bytes
//=================================================================================================
void PhysMem::map(uint64_t physAddr, size_t size)
{
    const char* filename;
    int   fd;
    uint64_t base_addr = 0;
    char buffer[200];

    // These are the memory protection flags we'll use when mapping the device into memory
    const int protection = PROT_READ | PROT_WRITE;

    // Unmap any memory we may already have mapped
    unmap();

    // Does /dev/pmem0 exist?
    filename = "/dev/pmem0";
    fd = ::open(filename, O_RDWR| O_SYNC);
    if (fd >= 0)
    {
        auto contig = get_contig();
        base_addr = contig.addr;        
        if (physAddr < contig.addr || physAddr >= (contig.addr + contig.size))
        {
            sprintf
            (
                buffer,
                "can't map 0x%lX: bounds are 0x%lX thru 0x%lX",
                physAddr, contig.addr, contig.addr + contig.size - 1
            );
            throwRuntime(buffer);            
        }
    }

    // If we don't have an open device, use "/dev/mem"
    if (fd < 0)
    {
        filename = "/dev/mem";
        fd = ::open(filename, O_RDWR| O_SYNC);
        base_addr = 0;
    }

    // If that open failed, we're done here
    if (fd < 0) throwRuntime("Can't open %s", filename);

    // Map the memory
    void* ptr = mmap(0, size, protection, MAP_SHARED, fd, physAddr - base_addr);
    
    // We're done with /dev/mem
    ::close(fd);

    // If mapping into user-space failed tell the caller
    if (ptr == MAP_FAILED) throwRuntime("mmap failed");        

    // Otherwise, that mapping succeeded.  Record the userspace address and region size
    userspaceAddr_ = ptr;        
    mappedSize_    = size;
    physicalAddr_  = physAddr;
}
//=================================================================================================



//=================================================================================================
// map() - Automatically maps the region defined with "memmap=" in /proc/cmdline
//=================================================================================================
void PhysMem::map()
{
    const char* filename;
    int   fd = -1;
    uint64_t base_addr = 0;
    
    // These are the memory protection flags we'll use when mapping the device into memory
    const int protection = PROT_READ | PROT_WRITE;

    // Unmap any memory we may already have mapped
    unmap();

    // Find the geometry of the contiguous buffer
    auto contig = get_contig();

    // Does "/dev/pmem0" exist?
    filename = "/dev/pmem0";
    fd = ::open(filename, O_RDWR| O_SYNC);
    if (fd >= 0)
    {
        base_addr = contig.addr;        
    }
    
    // If we still don't have an open device, use /dev/mem
    if (fd < 0)
    {
        filename = "/dev/mem";
        fd = ::open(filename, O_RDWR| O_SYNC);
        base_addr = 0;
    }

    // If that open failed, we're done here
    if (fd < 0) throwRuntime("Can't open %s", filename);

    // Map the memory
    void* ptr = mmap(0, contig.size, protection, MAP_SHARED, fd, contig.addr - base_addr);
    
    // We're done with /dev/mem
    ::close(fd);

    // If mapping into user-space failed tell the caller
    if (ptr == MAP_FAILED) throwRuntime("mmap failed");        

    // Otherwise, that mapping succeeded.  Record the userspace address and region size
    userspaceAddr_ = ptr;        
    mappedSize_    = contig.size;
    physicalAddr_  = contig.addr;
}
//=================================================================================================





//=================================================================================================
// unmap() - Checks to see if physical address space has been mapped into user-space [i.e., there
//           was a succesfull call to 'map()'], and if so, unmaps it
//=================================================================================================
void PhysMem::unmap()
{
    // If we have a valid user-space address, we need to unmap that memory
    if (userspaceAddr_) munmap(userspaceAddr_, mappedSize_);

    // Indicate that we no longer have any memory mapped
    userspaceAddr_ = nullptr;
    mappedSize_    = 0;
}
//=================================================================================================
