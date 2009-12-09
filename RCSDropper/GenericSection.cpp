#include "GenericSection.h"
#include "PEObject.h"

GenericSection::GenericSection(PEObject& pe, string name, DWORD FileAlignment )
: _pe(pe), _data(NULL), _size(0), _allocated(true), _fileAlignment(FileAlignment), _name(name)
{
	_header = new IMAGE_SECTION_HEADER;
	ZeroMemory(_header, sizeof(IMAGE_SECTION_HEADER));

	memcpy(_header->Name, name.c_str(), name.size() < IMAGE_SIZEOF_SHORT_NAME ? name.size() : IMAGE_SIZEOF_SHORT_NAME);
}

GenericSection::GenericSection(PEObject& pe, string name, DWORD FileAlignment, IMAGE_SECTION_HEADER* header)
: _pe(pe), _header(header), _data(NULL), _size(0), _allocated(false), _fileAlignment(FileAlignment), _name(name)
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
