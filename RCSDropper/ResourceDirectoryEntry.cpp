#include <new>
#include "ResourceDirectoryEntry.h"

ResourceDirectoryEntry::ResourceDirectoryEntry( char *name, ResourceDirectory* rdSubDir )
: writtenAt(0)
{
	if (IS_INTRESOURCE(name)) {
		_hasName = false;
		_name = 0;
		_id = (WORD)(DWORD) name;
	} else {
		_hasName = true;
		_name = new(std::nothrow) char[strlen(name) + 1];
		strcpy(_name, name);
	}
	_isDataDirectory = true;
	_rdSubDir = rdSubDir;
}

ResourceDirectoryEntry::ResourceDirectoryEntry( char *name, ResourceDataEntry* rdeData )
: writtenAt(0)
{
	if (IS_INTRESOURCE(name)) {
		_hasName = false;
		_name = 0;
		_id = (WORD)(DWORD) name;
	} else {
		_hasName = true;
		_name = new(std::nothrow) char [strlen(name) + 1];
		strcpy(_name, name);
	}
	_isDataDirectory = false;
	_rdeData = rdeData;
}

char* ResourceDirectoryEntry::GetName()
{
	if (!_hasName) 
		return 0; 
	char * name = new(std::nothrow) char[strlen(_name) + 1]; 
	strcpy(name, _name);
	return name;
}