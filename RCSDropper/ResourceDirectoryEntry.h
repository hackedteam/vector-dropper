#ifndef _RESOURCE_DIRECTORY_ENTRY_H
#define _RESOURCE_DIRECTORY_ENTRY_H

#include "common.h"

class ResourceDirectory;
class ResourceDataEntry;

class ResourceDirectoryEntry
{
public:
	ResourceDirectoryEntry(WCHAR* name, ResourceDirectory* rdSubDir);
	ResourceDirectoryEntry(WCHAR* name, ResourceDataEntry* rdeData);
	virtual ~ResourceDirectoryEntry(void) { if (_name && _hasName) delete [] _name; }

	bool HasName() { return _hasName; }
	WCHAR* GetName();

	int GetNameLength() { return wcslen(_name); }

	WORD GetId() { if (_hasName) return 0; return _id; }

	bool IsDataDirectory() { return _isDataDirectory; }
	ResourceDirectory* GetSubDirectory() { if ( ! _isDataDirectory) return NULL; return _rdSubDir; }
	ResourceDataEntry* GetDataEntry()  { if (_isDataDirectory) return NULL; return _rdeData; }
	
	DWORD writtenAt;
private:
	bool _hasName;
	union {
		WCHAR* _name;
		WORD _id;
	};

	bool _isDataDirectory;
	union {
		ResourceDirectory* _rdSubDir;
		ResourceDataEntry* _rdeData;
	};
};

#endif /* _RESOURCE_DIRECTORY_ENTRY_H */
