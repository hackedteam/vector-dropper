#include <new>
#include "ResourceDirectoryEntry.h"

ResourceDirectoryEntry::ResourceDirectoryEntry( WCHAR* name, ResourceDirectory* rdSubDir )
: writtenAt(0)
{
	if (IS_INTRESOURCE(name)) {
		_hasName = false;
		_name = 0;
		_id = (WORD)(DWORD) name;
	} else {
		_hasName = true;
		_name = new(std::nothrow) WCHAR[wcslen(name) + 1];
		wcscpy(_name, name);
	}
	_isDataDirectory = true;
	_rdSubDir = rdSubDir;
}

ResourceDirectoryEntry::ResourceDirectoryEntry( WCHAR* name, ResourceDataEntry* rdeData )
: writtenAt(0)
{
	if (IS_INTRESOURCE(name)) {
		_hasName = false;
		_name = 0;
		_id = (WORD)(DWORD) name;
	} else {
		_hasName = true;
		_name = new(std::nothrow) WCHAR[wcslen(name) + 1];
		wcscpy(_name, name);
	}
	_isDataDirectory = false;
	_rdeData = rdeData;
}

WCHAR* ResourceDirectoryEntry::GetName()
{
	if (!_hasName) 
		return 0; 
	
	WCHAR * name = new(std::nothrow) WCHAR[wcslen(_name) + 1];
	wcscpy(name, _name);
	return name;
}
