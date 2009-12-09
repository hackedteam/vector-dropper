#include <new>
#include "ResourceDataEntry.h"

ResourceDataEntry::ResourceDataEntry( PBYTE data, DWORD rva, DWORD size, DWORD codePage ) 
	: _data(NULL), _rva(rva), _added(false)
{
	SetData(data, size, codePage);
}

ResourceDataEntry::ResourceDataEntry( DWORD rva, DWORD size, DWORD codePage )
: _data(NULL), _rva(rva), _size(size), _codePage(codePage), _added(false)
{
}

ResourceDataEntry::~ResourceDataEntry( void )
{
	if (_data) 
		delete [] _data;
}

void ResourceDataEntry::SetData( PBYTE data, DWORD size, DWORD codePage )
{	
	_codePage = codePage;
	_size = size;
	
	if (_added == true) {
		_data = new(std::nothrow) BYTE[_size];
		CopyMemory(_data, data, _size);
	} else {
		_data = data; 
	}
}
