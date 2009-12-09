#include "ResourceDirectory.h"
#include "ResourceDirectoryEntry.h"
#include "ResourceDataEntry.h"

#include <iostream>

ResourceDirectory::ResourceDirectory( PIMAGE_RESOURCE_DIRECTORY prd ) 
	: _rdDir(*prd), writtenAt(0)
{
	_rdDir.NumberOfIdEntries = 0;
	_rdDir.NumberOfNamedEntries = 0;
}

void ResourceDirectory::AddEntry( ResourceDirectoryEntry* entry )
{
	int i = 0;
	
	if (entry->HasName()) {
		char *entryName = entry->GetName();
		
		//cout << "Adding entry \"" << entryName << "\" ";
		
		for (i = 0; i < _rdDir.NumberOfNamedEntries; i++) {
			char *name = _entries[i]->GetName();
			int cmp = strcmp(name, entryName);
			delete [] name;
			if (cmp == 0) {
				delete [] entryName;
				return;
			}
			if (cmp > 0)
				break;
		}
		delete [] entryName;
		_rdDir.NumberOfNamedEntries++;
		
	} else {
		
		//cout << "Adding entry " << entry->GetId() << " ";
		
		for (i = _rdDir.NumberOfNamedEntries; i < _rdDir.NumberOfNamedEntries + _rdDir.NumberOfIdEntries; i++)
		{
			if (_entries[i]->GetId() == entry->GetId())
				return;
			if (_entries[i]->GetId() > entry->GetId())
				break;
		}
		_rdDir.NumberOfIdEntries++;
	}
	
	//cout << "at position " << i << endl;
	
	_entries.insert(_entries.begin() + i, entry);
}

int ResourceDirectory::Find( char* name )
{
	if (IS_INTRESOURCE(name))
		return Find((WORD)(DWORD)name);
	else
		if (name[0] == '#')
			return Find(WORD(atoi(name + 1)));

	for (UINT i = 0; i < _entries.size(); i++)
	{
		if (_entries[i]->HasName())
			continue;

		char* entryName = _entries[i]->GetName();
		int cmp = strcmp(name, entryName);
		delete [] entryName;

		if (!cmp)
			return i;
	}

	return -1;
}

int ResourceDirectory::Find( WORD Id )
{
	for (UINT i = 0; i < _entries.size(); i++)
	{
		if (_entries[i]->HasName())
			continue;

		if (Id == _entries[i]->GetId())
			return i;
	}
	return -1;
}

DWORD ResourceDirectory::GetSize()
{
	DWORD size = sizeof(IMAGE_RESOURCE_DIRECTORY);
	for (UINT i = 0; i < _entries.size(); i++) {
		size += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
		if (_entries[i]->HasName())
			size += sizeof(IMAGE_RESOURCE_DIR_STRING_U) + (_entries[i]->GetNameLength() + 1) * sizeof(WCHAR);
		if (_entries[i]->IsDataDirectory())
			size += _entries[i]->GetSubDirectory()->GetSize();
		else {
			DWORD aligned = _entries[i]->GetDataEntry()->GetSize();
			ALIGN(aligned, 8);
			size += sizeof(IMAGE_RESOURCE_DATA_ENTRY) + aligned;
		}
	}
	
	return size;
}

void ResourceDirectory::Destroy()
{
	for (UINT i = 0; i < _entries.size(); i++) {
		if (_entries[i]->IsDataDirectory()) {
			_entries[i]->GetSubDirectory()->Destroy();
			delete _entries[i]->GetSubDirectory();
		} else {
			delete _entries[i]->GetDataEntry();
		}
	}
}
