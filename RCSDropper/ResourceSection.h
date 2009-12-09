#ifndef _RESOURCESECTION_H
#define _RESOURCESECTION_H

#include <string>
using namespace std;

#include <Windows.h>
#include "GenericSection.h"
#include "ResourceDirectory.h"
#include "ResourceDirectoryEntry.h"
#include "ResourceDataEntry.h"

// Resource directory with entries
typedef struct RESOURCE_DIRECTORY {
	IMAGE_RESOURCE_DIRECTORY Header;
	IMAGE_RESOURCE_DIRECTORY_ENTRY Entries[1];
} *PRESOURCE_DIRECTORY;

#define RALIGN(dwToAlign, dwAlignOn) ((dwToAlign%dwAlignOn == 0) ? dwToAlign : dwToAlign - (dwToAlign%dwAlignOn) + dwAlignOn)

class PEObject;

class ResourceSection
{
private:
	GenericSection _base;
	
	string _manifest;
	bool _hasManifest;
	
	//bool _checkForManifest(IMAGE_SECTION_HEADER* header, char* data);
	//bool _parseResourceDirectory(PIMAGE_RESOURCE_DIRECTORY resDir, LPBYTE resBase, DWORD level, DWORD resType);
	//bool _dumpResourceEntry(PIMAGE_RESOURCE_DIRECTORY_ENTRY resDirEntry, LPBYTE resBase, DWORD level);
	//void _getResourceTypeName(DWORD type, PSTR buffer, UINT cBytes);
	//void _getResourceNameFromId(DWORD id, LPBYTE resourceBase, PSTR buffer, UINT cBytes);
	
	//void _rebuildDirectory( );
	//void _rebuildEntry( );
	//void _rebuildDataEntry( );
	
	ResourceDirectory* _resDir;
	
public:
	
	ResourceSection( GenericSection& base );
	ResourceSection( const ResourceSection& rhs ) 
		: _base(rhs._base), _hasManifest(rhs._hasManifest), _manifest(rhs._manifest)
	{
		cout << __FUNCTION__ << " copy constructor." << endl;
	}
	
	ResourceSection& operator=(const ResourceSection& rhs)
	{
		cout << __FUNCTION__ << " assignment operator." << endl;
		
		if (this == &rhs) return *this;
		
		*this = rhs;
		// static_cast<GenericSection&>(*this) = rhs;
		//_manifest = rhs._manifest;
		//_hasManifest = rhs._hasManifest;
		
		return *this;
	}
	
	virtual ~ResourceSection(void);
	
	GenericSection* GetBase() { return &_base; }
	
	//bool BuildWithManifest();
	//bool CheckForManifest();
	//bool Rebuild(DWORD oldRva, DWORD newRva);
	ResourceDirectory* ScanDirectory();
	
	void SetManifest(string manifest) { _manifest = manifest; }
	
	void SetName(string name) { _base._name = name; }
	
	GenericSection* section() { return &_base; }
	
	ResourceDirectory* ScanDirectory(PRESOURCE_DIRECTORY rdRoot, PRESOURCE_DIRECTORY rdToScan, DWORD level);
	
	PBYTE GetResource(PCHAR type, PCHAR name, LANGID lang);
	size_t GetResourceSize(PCHAR type, PCHAR name, LANGID lang);
	
	bool UpdateResource(char* type, char* name, LANGID lang, PBYTE data, DWORD size);
	bool UpdateResource(WORD type, char* name, LANGID lang, PBYTE data, DWORD size) 
	{
		return UpdateResource(MAKEINTRESOURCE(type), name, lang, data, size);
	}
	bool UpdateResource(char* type, WORD name, LANGID lang, BYTE* data, DWORD size)
	{
		return UpdateResource(type, MAKEINTRESOURCE(name), lang, data, size);
	}
	bool UpdateResource(WORD type, WORD name, LANGID lang, BYTE* data, DWORD size)
	{
		return UpdateResource(MAKEINTRESOURCE(type), MAKEINTRESOURCE(name), lang, data, size);
	}
	
	DWORD SizeOfResources();
	bool WriteResources();
	void SetOffsets(ResourceDirectory* resDir, DWORD newResDirAt);
};

#endif /* _RESOURCESECTION_H */
