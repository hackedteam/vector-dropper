#ifndef _GENERIC_SECTION_H
#define _GENERIC_SECTION_H

#include <iostream>
#include <string>
using namespace std;

#include "common.h"

class PEObject;

class GenericSection
{
protected:
	char* _data;
	size_t _size;
	
	DWORD _fileAlignment;	
	IMAGE_SECTION_HEADER* _header;
	string _name;
	
	bool _allocated;
	bool _eof; // if true, section is EOF data and should not be added to data directories
	
	PEObject& _pe;
	
	friend class ResourceSection;
	
public:
	GenericSection(PEObject& pe, string name, DWORD FileAlignment);
	GenericSection(PEObject& pe, string name, DWORD FileAlignment, IMAGE_SECTION_HEADER* header);
	GenericSection(const GenericSection& rhs)
		: _pe(rhs._pe)
	{
		// cout << __FUNCTION__ << " copy constructor." << endl;

		_size = rhs._size;
		_data = new char[_size];
		memcpy(_data, rhs._data, _size);

		_header = new IMAGE_SECTION_HEADER;
		memcpy(_header, rhs._header, sizeof(IMAGE_SECTION_HEADER));
		
		_name = rhs._name;
		_fileAlignment = rhs._fileAlignment;
		_allocated = rhs._allocated;
	}
	
	GenericSection& operator=(const GenericSection& rhs)
	{
		// cout << __FUNCTION__ << " assignment operator." << endl;

		if (this == &rhs)
			return *this;

		if (_data)
			delete [] _data;
		
		_size = rhs._size;

		if (rhs._data)
		{
			_data = new char[_size];
			memcpy(_data, rhs._data, _size);
		} else {
			_data = NULL;
		}

		_name = rhs._name;
		_fileAlignment = rhs._fileAlignment;
		_allocated = rhs._allocated;
		
		return *this;
	}

	virtual ~GenericSection(void);
	
	DWORD FileAlignment() { return _fileAlignment; }
	
	IMAGE_SECTION_HEADER* Header() { return _header; }
	
	char * data() { return _data; }
	size_t size() { return _size; }
	
	bool isEof() { return _eof; }
	void setEof(bool value) { _eof = value; }
	bool isAllocated() { return _allocated; }
	
	void SetData(char const * const data, DWORD size) { _data = new char[size]; memcpy(_data, data, size); } 
	
	inline DWORD alignTo( DWORD _size, DWORD _base_size )
	{
		return ( ((_size + _base_size-1) / _base_size) * _base_size );
	}
	
	void SetFilePointer(char * ptr, size_t size) { _data = ptr + _header->PointerToRawData; _size = size; }
	
	DWORD PointerToRawData() { return _header->PointerToRawData; }
	DWORD SizeOfRawData() { return _header->SizeOfRawData; }
	DWORD VirtualAddress() { return _header->VirtualAddress; }
	DWORD VirtualSize() { return _header->Misc.VirtualSize; }
	
	void SetPointerToRawData(DWORD ptr) { _header->PointerToRawData = ptr; }
	void SetSizeOfRawData(DWORD size) { _header->SizeOfRawData = size; }
	void SetVirtualAddress(DWORD address) { _header->VirtualAddress = address; }
	void SetVirtualSize(DWORD size) { _header->Misc.VirtualSize = size; }
	
	void SetCharacteristics(DWORD characteristics) { _header->Characteristics = characteristics; }
	void SetName(std::string name) { memcpy(_header->Name, name.c_str(), name.size() < IMAGE_SIZEOF_SHORT_NAME ? name.size() : IMAGE_SIZEOF_SHORT_NAME); }
	string Name() { return string((char*)_header->Name); }
};

#endif /* _GENERIC_SECTION_H */


