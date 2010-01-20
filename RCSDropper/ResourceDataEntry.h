#ifndef _RESOURCE_DATA_ENTRY_H
#define _RESOURCE_DATA_ENTRY_H

#include "common.h"

class ResourceDataEntry
{
public:
	ResourceDataEntry(PBYTE data, DWORD rva, DWORD size, DWORD codePage = 0);
	ResourceDataEntry(DWORD rva, DWORD size, DWORD codePage = 0);
	virtual ~ResourceDataEntry(void);
	
	PBYTE GetData() { return _data; }
	DWORD GetRva() { return _rva; }
	
	void SetAdded(bool added = true) { _added = added; }
	bool IsAdded() { return _added; }
	
	void SetData(PBYTE data, DWORD size) { SetData( data, size, _codePage); }
	void SetData(PBYTE data, DWORD size, DWORD codePage);
	
	DWORD GetSize() { return _size; }
	DWORD GetCodePage() { return _codePage; }

	DWORD writtenAt;

private:
	bool _added;
	DWORD _rva;
	PBYTE _data;
	DWORD _size;
	DWORD _codePage;
};

#endif /* _RESOURCE_DATA_ENTRY_H */
