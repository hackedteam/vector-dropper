#pragma once

#include <Windows.h>

class ResourceDirectory;
class ResourceDataEntry;

class ResourceDirectoryEntry
{
public:
	ResourceDirectoryEntry(char *name, ResourceDirectory* rdSubDir);

	ResourceDirectoryEntry(char *name, ResourceDataEntry* rdeData);

	virtual ~ResourceDirectoryEntry(void) { if (_name && _hasName) delete [] _name; }

	bool HasName() { return _hasName; }
	char* GetName();

	int GetNameLength() { return strlen(_name); }

	WORD GetId() { if (_hasName) return 0; return _id; }

	bool IsDataDirectory() { return _isDataDirectory; }
	ResourceDirectory* GetSubDirectory() { if ( ! _isDataDirectory) return NULL; return _rdSubDir; }
	ResourceDataEntry* GetDataEntry()  { if (_isDataDirectory) return NULL; return _rdeData; }
	
	DWORD writtenAt;
private:
	bool _hasName;
	union {
		char *_name;
		WORD _id;
	};

	bool _isDataDirectory;
	union {
		ResourceDirectory* _rdSubDir;
		ResourceDataEntry* _rdeData;
	};
};
