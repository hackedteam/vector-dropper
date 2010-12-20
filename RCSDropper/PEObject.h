#ifndef _PEOBJECT_H
#define _PEOBJECT_H

#include <vector>
#include <iostream>
#include <fstream>
#include <map>
#include <ostream>
#include <string>
using namespace std;

#include <boost/scoped_ptr.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
namespace bf = boost::filesystem;

#include "common.h"
#include "tree.hpp"
#include "GenericSection.h"
#include "IATEntry.h"

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

typedef struct RESOURCE_DIRECTORY {
	IMAGE_RESOURCE_DIRECTORY Header;
	IMAGE_RESOURCE_DIRECTORY_ENTRY Entries[1];
} *PRESOURCE_DIRECTORY;

class GenericSection;
class DropperObject;
class ResourceSection;
class ResourceDirectory;

class parsing_error : public std::exception
{
public:
	parsing_error(const std::string& msg) : std::exception(msg.c_str()) {}
};

typedef struct _cavity_t {
	char* ptr;
	DWORD va;
	std::size_t size;
} Cavity;

class PEObject
{
private:	
	//std::fstream _sourceFile;
	//std::fstream _destinationFile;
	
	char* _rawData;
	std::size_t  _fileSize;
	
	PEDOSHEADER	      _dosHeader;
	IMAGE_NT_HEADERS  *_ntHeader;
	
	std::vector<GenericSection *> _sections;
	GenericSection *_eofData;
	
	std::size_t _sectionHeadersPaddingSize;
	char* _sectionHeadersPadding;
	
	std::size_t _boundImportTableSize;
	PBYTE _boundImportTable;
	
	DWORD   _oep; // AddressOfEntryPoint
	
	struct {
		int ExitProcess;
		int exit;
		int _exit;
	} functionIndex;
	
	std::vector< Cavity > _cavities;

	std::map< std::string, std::map<std::string, DWORD> > _calls;
	IATEntries _iat;
	
	struct {
		struct {
			char* ptr;
			DWORD va;
		} stage1;
		struct {
			char* ptr;
			DWORD va;
		} stage2;
	} _hookPointer;
	
	// TODO this should be removed in favor of the above map
	DWORD _pLoadLibrary;
	DWORD _pGetProcAddress;
	
	bool _parseDOSHeader();
	bool _parseNTHeader();
	bool _parseIAT();
	bool _parseResources();
	bool _parseText();
	
	struct {
		ResourceDirectory* dir;
		std::size_t size;
	} _resources;
	
	ResourceDirectory* _scanResources(char const * const data);
	ResourceDirectory* _scanResources(PRESOURCE_DIRECTORY rdRoot, PRESOURCE_DIRECTORY rdToScan, DWORD level);
	bool _updateResource(WCHAR* type, WCHAR* name, LANGID lang, PBYTE data, DWORD size);
	bool _updateResource(WORD type, WCHAR* name, LANGID lang, PBYTE data, DWORD size) 
	{
		return _updateResource(MAKEINTRESOURCEW(type), name, lang, data, size);
	}
	bool _updateResource(WCHAR* type, WORD name, LANGID lang, BYTE* data, DWORD size)
	{
		return _updateResource(type, MAKEINTRESOURCEW(name), lang, data, size);
	}
	bool _updateResource(WORD type, WORD name, LANGID lang, BYTE* data, DWORD size)
	{
		return _updateResource(MAKEINTRESOURCEW(type), MAKEINTRESOURCEW(name), lang, data, size);
	}
	DWORD _sizeOfResources();
	void _setResourceOffsets(ResourceDirectory* resDir, DWORD newResDirAt);
	
	bool _fixManifest();
	std::size_t _writeResources( char* data, DWORD virtualAddress );

	// void _findCavities( GenericSection * const section );
	void _disassembleCode(unsigned char *start, unsigned char *end, unsigned char *ep, int VA);
	
public:
	PEObject(char* data, std::size_t size);
	virtual ~PEObject(void);
	
	unsigned char * atOffset(DWORD offset) 
	{
		if (offset > _fileSize)
			return NULL;
		return (unsigned char *)( ((DWORD)this->_rawData) + offset); 
	}
	
	unsigned char * atRVA(DWORD rva)
	{
		DWORD offset = this->offset(rva);
		if (offset == 0)
			return NULL;
		return rva == 0 ? NULL : (unsigned char *)atOffset(offset);
	}
	
	DWORD offset(DWORD _rva);
	
	std::size_t resourceSize() { return _resources.size; }
	
	DWORD imageBase() { return _ntHeader->OptionalHeader.ImageBase; }
	DWORD fileAlignment() { return _ntHeader->OptionalHeader.FileAlignment; }
	DWORD sectionAlignment() { return _ntHeader->OptionalHeader.SectionAlignment; }
	
	PEDOSHEADER dosHeader() { return _dosHeader; }
	PIMAGE_NT_HEADERS ntHeaders() { return _ntHeader; }
	PIMAGE_DATA_DIRECTORY dataDirectory(DWORD entry) { return &_ntHeader->OptionalHeader.DataDirectory[entry]; }
	
	bool parse();
	bool saveToFile( std::string filename );
	
	DWORD epRVA() { return _ntHeader->OptionalHeader.AddressOfEntryPoint; }
	DWORD epVA() { return _ntHeader->OptionalHeader.ImageBase + _ntHeader->OptionalHeader.AddressOfEntryPoint; }
	void writeData(DWORD rva, char * data, size_t size);
	
	unsigned char* GetOEPCode();
	
	bool hasResources() { return _ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress == 0 ? false : true; }
	
	GenericSection* getSection( DWORD directoryEntryID );
	GenericSection* findSection( DWORD rva );
	
	void setSection( DWORD directoryEntryID, GenericSection* section );
	void setSection( DWORD directoryEntryID, DWORD VirtualAddress, DWORD VirtualSize );
	
	bool isAuthenticodeSigned();
	
	bool embedDropper( bf::path core, bf::path core64, bf::path config, bf::path codec, bf::path driver, bf::path driver64, std::string installDir, bool fixManifest);
	
	IATEntry const & getIATEntry( std::string const dll, std::string const call );
	IATEntry const & getIATEntry( DWORD const rva );
};

#endif /* _PEOBJECT_H */
