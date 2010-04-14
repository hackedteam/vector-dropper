#include "GenericSection.h"
#include "PEObject.h"

GenericSection::GenericSection(PEObject& pe, string name )
: _pe(pe), _data(NULL), _size(0), _allocated(true), _name(name)
{
	_header = new IMAGE_SECTION_HEADER;
	memset(_header, 0 , sizeof(IMAGE_SECTION_HEADER));
	
	memcpy(_header->Name, name.c_str(), name.size() < IMAGE_SIZEOF_SHORT_NAME ? name.size() : IMAGE_SIZEOF_SHORT_NAME);
}

GenericSection::GenericSection(PEObject& pe, string name, IMAGE_SECTION_HEADER* header)
: _pe(pe), _header(header), _data(NULL), _size(0), _allocated(false), _name(name)
{
	memcpy(_header->Name, name.c_str(), name.size() < IMAGE_SIZEOF_SHORT_NAME ? name.size() : IMAGE_SIZEOF_SHORT_NAME);
}

GenericSection::~GenericSection(void)
{
	if (_allocated) {
		if (_header)
			delete _header;
		if (_data)
			delete [] _data;
	}
}

DWORD GenericSection::FileAlignment()
{
	return _pe.fileAlignment();
}

DWORD GenericSection::SectionAlignment()
{
	return _pe.sectionAlignment();
}

void GenericSection::SetData( char const * const data, DWORD size )
{
	cout << __FUNCTION__ << " data = 0x" << hex << (DWORD)data << " size: " << hex << size << endl;
	_header->Misc.VirtualSize = alignTo(size, SectionAlignment());
	_header->SizeOfRawData = alignTo(_header->Misc.VirtualSize, FileAlignment());
	_data = new char[ _header->SizeOfRawData ];
	memset(_data, 0, _header->SizeOfRawData);
	
	cout << __FUNCTION__ << " _data = 0x" << hex << (DWORD)_data << " size: " << hex << _header->SizeOfRawData << endl;
	
	memcpy(_data, data, size);
}
