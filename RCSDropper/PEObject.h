#ifndef _PEOBJECT_H
#define _PEOBJECT_H

#include "common.h"

#include "tree.hpp"
#include <vector>
#include <iostream>
#include <fstream>
#include <map>
#include <ostream>
#include <string>
using namespace std;

#include "GenericSection.h"

#define PE_MAX_DATA_SECTIONS 64

#define endian_swap4byte(x)			\
	x = ((x & 0x000000FF) << 24) |  \
		((x & 0x0000FF00) << 8)  |  \
		((x & 0x00FF0000) >> 8)  |  \
		((x & 0xFF000000) >> 24)

typedef struct _PE_DOS_HEADER
{
	IMAGE_DOS_HEADER* header;
	std::size_t		  stub_size;
	char*			  stub;
} PEDOSHEADER;

typedef struct _PE_SECTION
{
	IMAGE_SECTION_HEADER* header;
	char*                 data;
} PESECTION;

class GenericSection;
class DropperSection;
class ResourceSection;

class PEObject
{
private:
	std::ifstream _file;
	std::string _filename;
	
	std::size_t  _fileSize;
	char* _rawData;
	
	PEDOSHEADER	      _dosHeader;
	IMAGE_NT_HEADERS  *_ntHeader;
	
	std::vector<GenericSection *> _sections;
	GenericSection *_eofData;
	
	std::size_t _sectionHeadersPaddingSize;
	char* _sectionHeadersPadding;
	
	std::size_t _boundImportTableSize;
	PBYTE _boundImportTable;
	
	DWORD   _oep; // AddressOfEntryPoint
	
	int _exitProcessIndex;
	int _exitIndex;
	
	std::map< std::string, std::map<std::string, DWORD> > _calls;
	
	// this should be removed in favor of the above map
	DWORD _pLoadLibrary;
	DWORD _pGetProcAddress;
	
	bool _hasManifest;
	string _manifest;
	
	bool _parseDOSHeader();
	bool _parseNTHeader();

	// int _findExitProcessIndex();
	// int _findExitIndex();
	int _findCall(std::string& dll, std::string& call);
	
	char * _resolveOffset(DWORD offset) 
	{
		if (offset > _fileSize)
			return NULL;
		return (char *)((DWORD)this->_rawData + offset); 
	}
	
	DWORD _rvaToOffset(DWORD _rva);
	char* _resolveRvaToOffset(DWORD rva) { return rva == 0 ? NULL : (char *)_resolveOffset(_rvaToOffset(rva)); }
	inline DWORD _alignTo( DWORD _size, DWORD _base_size )
	{
		return ( ((_size + _base_size-1) / _base_size) * _base_size );
	}

public:
	PEObject(char* data, std::size_t size);
	virtual ~PEObject(void);
	
	PEDOSHEADER dosHeader() { return _dosHeader; }
	PIMAGE_NT_HEADERS ntHeaders() { return _ntHeader; }
	
	unsigned char* OEPcode;
	size_t OEPCodeSize;
	
	DWORD EntryPoint_RVA() { return _ntHeader->OptionalHeader.AddressOfEntryPoint; }
	DWORD EntryPoint_VA() { return _ntHeader->OptionalHeader.ImageBase + _ntHeader->OptionalHeader.AddressOfEntryPoint; }
	void SetOEP(DWORD oep) { _ntHeader->OptionalHeader.AddressOfEntryPoint = oep; }
	void WriteData(DWORD rva, char * data, size_t size)
	{
		DWORD offset = _rvaToOffset(rva);
		char * ptr = _rawData + offset;
		memcpy(ptr, data, size);
	}
	
	unsigned char* GetOEPCode()
	{
		DWORD oep = _ntHeader->OptionalHeader.AddressOfEntryPoint;
		DWORD offset = _rvaToOffset(oep);
		cout << "OEP " << hex << oep << " @ offset " << hex << offset << endl;
		return (unsigned char*) _rawData + offset;
	}
	
	/*
	void saveOEP()
	{
		DWORD oep = _ntHeader->OptionalHeader.AddressOfEntryPoint;
		DWORD offset = _rvaToOffset(oep);
		cout << "OEP " << oep << " @ offset " << offset << endl;
		memcpy(OEPcode, _rawData + offset, sizeof(OEPcode));
	}
	*/
	
	PCHAR getRawData() { return _rawData; }
	
	bool saveToFile(std::string filename);
	bool parse();
	
	bool hasResources() { return _ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == 0 ? false : true; }
	
	GenericSection* getSection(DWORD directoryEntryID);
	GenericSection* findSection(DWORD rva)
	{
		std::vector<GenericSection*>::iterator iter = _sections.begin();

		for (; iter != _sections.end(); iter++) {
			GenericSection* section = *iter;
			if (rva >= section->VirtualAddress()
				&& rva < section->VirtualAddress() + section->SizeOfRawData())
				return section;
		}

		if (_eofData) 
		{
			if (rva >= _eofData->VirtualAddress() && rva < _eofData->VirtualAddress() + _eofData->SizeOfRawData()) {
				return _eofData;
			}
		}
		
		return NULL;
	}

	void setSection(DWORD directoryEntryID, GenericSection* section)
	{
		_ntHeader->OptionalHeader.DataDirectory[directoryEntryID].VirtualAddress = section->VirtualAddress();
		_ntHeader->OptionalHeader.DataDirectory[directoryEntryID].Size = section->VirtualSize();
	}
	
	bool isAuthenticodeSigned();
	
	DropperSection *createDropperSection(string name);
	
	bool appendSection(GenericSection* section) 
	{
		GenericSection* previousSection = _sections[_sections.size() - 1];
		
		DWORD ptrToRawData = previousSection->PointerToRawData() + previousSection->SizeOfRawData();
		DWORD RVA = previousSection->VirtualAddress() + previousSection->VirtualSize();

		section->SetPointerToRawData( _alignTo( ptrToRawData, _ntHeader->OptionalHeader.FileAlignment ));
		section->SetVirtualAddress( _alignTo( RVA, _ntHeader->OptionalHeader.SectionAlignment ));
		
		section->SetCharacteristics(
			IMAGE_SCN_CNT_INITIALIZED_DATA 
			| IMAGE_SCN_MEM_EXECUTE 
			| IMAGE_SCN_MEM_READ 
			| IMAGE_SCN_MEM_WRITE); 
		
		_sections.push_back(section); 
		return true; 
	}

	int exitProcessIndex() { return _exitProcessIndex; }
	int exitIndex() { return _exitIndex; }
};

#endif /* _PEOBJECT_H */

