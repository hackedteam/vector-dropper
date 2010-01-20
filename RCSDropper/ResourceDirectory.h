#ifndef _RESOURCE_DIRECTORY_H
#define _RESOURCE_DIRECTORY_H

#include "common.h"

#include <vector>
using namespace std;

#define ALIGN(dwToAlign, dwAlignOn) dwToAlign = (dwToAlign%dwAlignOn == 0) ? dwToAlign : dwToAlign - (dwToAlign%dwAlignOn) + dwAlignOn

class ResourceDirectoryEntry;

class ResourceDirectory
{
public:
	ResourceDirectory(PIMAGE_RESOURCE_DIRECTORY prd);
	
	virtual ~ResourceDirectory(void) {}
	
	IMAGE_RESOURCE_DIRECTORY GetInfo() { return _rdDir; }

	ResourceDirectoryEntry* GetEntry(UINT i)
	{
		if (_entries.size() < i)
			return NULL;

		return _entries[i];
	}

	void AddEntry(ResourceDirectoryEntry* entry);
	
	int CountEntries() { return _entries.size(); }
	int Find(WCHAR* name);

	int Find(WORD Id);
	
	DWORD GetSize();
	
	void Destroy();
	
	DWORD writtenAt;
	
private:
	IMAGE_RESOURCE_DIRECTORY _rdDir;
	vector<ResourceDirectoryEntry*> _entries;
};

#endif /* _RESOURCE_DIRECTORY_H */
