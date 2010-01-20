#include <iomanip>
#include "common.h"
#include "Exceptions.h"
#include "ResourceSection.h"
#include "PEObject.h"

char *SzResourceTypes[] =
{
	"???_0",
	"CURSOR",
	"BITMAP",
	"ICON",
	"MENU",
	"DIALOG",
	"STRING",
	"FONTDIR",
	"FONT",
	"ACCELERATORS",
	"RCDATA",
	"MESSAGETABLE",
	"GROUP_CURSOR",
	"???_13",
	"GROUP_ICON",
	"???_15",
	"VERSION"
};

ResourceSection::ResourceSection( GenericSection& base )
: _base(base)
{
}

ResourceSection::~ResourceSection(void)
{
}

#define INDENT do { for (DWORD i = 0; i < level; i++) cout << "\t"; } while (0)

ResourceDirectory* ResourceSection::ScanDirectory( PRESOURCE_DIRECTORY rdRoot, PRESOURCE_DIRECTORY rdToScan, DWORD level )
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
				ScanDirectory(
					rdRoot, 
					PRESOURCE_DIRECTORY(rdToScan->Entries[i].OffsetToDirectory + (PBYTE)rdRoot),
					level + 1
					)
				)
			);
		} else {
			// DATA ENTRY
			
			rde = PIMAGE_RESOURCE_DATA_ENTRY(rdToScan->Entries[i].OffsetToData + (PBYTE)rdRoot);
			GenericSection* section = _base._pe.findSection(rde->OffsetToData);

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
			} else {
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

ResourceDirectory* ResourceSection::ScanDirectory()
{
	PRESOURCE_DIRECTORY rdRoot = PRESOURCE_DIRECTORY(_base._data);
	_resDir = ScanDirectory(rdRoot, rdRoot, 0);
	
	return _resDir;
}

bool ResourceSection::UpdateResource( WCHAR* type, WCHAR* name, LANGID lang, PBYTE data, DWORD size )
{
	ResourceDirectory* nameDir = NULL;
	ResourceDirectory* langDir = NULL;
	ResourceDataEntry* dataEntry = NULL;
	IMAGE_RESOURCE_DIRECTORY rd = {0, /* time(0), */};
	int typeIdx = -1, nameIdx = -1, langIdx = -1;
	
	typeIdx = _resDir->Find(type);
	if (typeIdx > -1) {
		nameDir = _resDir->GetEntry(typeIdx)->GetSubDirectory();
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
			_resDir->AddEntry(new ResourceDirectoryEntry(type, nameDir));
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

PBYTE ResourceSection::GetResource( PCHAR type, PCHAR name, LANGID lang )
{
	ResourceDirectory* nameDir = NULL;
	ResourceDirectory* langDir = NULL;
	ResourceDataEntry* dataEntry = NULL;
	int typeIdx = -1, nameIdx = -1, langIdx = -1;
	
	typeIdx = _resDir->Find((WCHAR*)type);
	if (typeIdx > -1) {
		nameDir = _resDir->GetEntry(typeIdx)->GetSubDirectory();
		nameIdx = nameDir->Find((WCHAR*)name);
		if (nameIdx > -1) {
			langDir = nameDir->GetEntry(nameIdx)->GetSubDirectory();
			langIdx = langDir->Find(lang);
			if (langIdx > -1) {
				dataEntry = langDir->GetEntry(langIdx)->GetDataEntry();
			}
		}
	}
	
	if (dataEntry) {
		PBYTE toReturn = new BYTE[dataEntry->GetSize()];
		memcpy(toReturn, dataEntry->GetData(), dataEntry->GetSize());
		return toReturn;
	}
	
	return NULL;
}

size_t ResourceSection::GetResourceSize( PCHAR type, PCHAR name, LANGID lang )
{
	ResourceDirectory* nameDir = NULL;
	ResourceDirectory* langDir = NULL;
	ResourceDataEntry* dataEntry = NULL;
	int typeIdx = -1, nameIdx = -1, langIdx = -1;

	typeIdx = _resDir->Find((WCHAR*)type);
	if (typeIdx > -1) {
		nameDir = _resDir->GetEntry(typeIdx)->GetSubDirectory();
		nameIdx = nameDir->Find((WCHAR*)name);
		if (nameIdx > -1) {
			langDir = nameDir->GetEntry(nameIdx)->GetSubDirectory();
			langIdx = langDir->Find(lang);
			if (langIdx > -1) {
				dataEntry = langDir->GetEntry(langIdx)->GetDataEntry();
			}
		}
	}

	if (dataEntry) {
		return (size_t) dataEntry->GetSize();
	} else
		return -1;

	return NULL;
}

bool ResourceSection::WriteResources()
{
	DWORD level = 0;

	if (_base._data)
		delete [] _base._data;
	_base._size = SizeOfResources();
	_base._data = new CHAR[_base._size];
	PBYTE seeker = (PBYTE)_base._data;
	
	cout << __FUNCTION__ << endl;
	
	//cout << "[1] seeker base at 0x" << hex << (DWORD)seeker << endl;
	
	queue<ResourceDirectory*> dirs;
	queue<ResourceDataEntry*> dataEntries;
	queue<ResourceDataEntry*> dataEntries2;
	queue<ResourceDirectoryEntry*> strings;
	
	dirs.push(_resDir);
	
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
		
		memcpy(seeker, &rdDir, sizeof(IMAGE_RESOURCE_DIRECTORY));
		crd->writtenAt = DWORD(seeker);
		seeker += sizeof(IMAGE_RESOURCE_DIRECTORY);
		
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
			PIMAGE_RESOURCE_DIRECTORY_ENTRY rDirE = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)seeker;
			memset(rDirE, 0, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
			rDirE->DataIsDirectory = crd->GetEntry(i)->IsDataDirectory();
			rDirE->Id = (crd->GetEntry(i)->HasName()) ? 0 : crd->GetEntry(i)->GetId();
			rDirE->NameIsString = (crd->GetEntry(i)->HasName()) ? 1 : 0;
			
			// CopyMemory(seeker, &rDirE, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
			crd->GetEntry(i)->writtenAt = DWORD(seeker);
			seeker += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
			
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
		PIMAGE_RESOURCE_DATA_ENTRY rDataE = (PIMAGE_RESOURCE_DATA_ENTRY) seeker;
		memset(rDataE, 0, sizeof(IMAGE_RESOURCE_DATA_ENTRY));
		rDataE->OffsetToData = cRDataE->GetRva();
		rDataE->CodePage = cRDataE->GetCodePage();
		rDataE->Size = cRDataE->GetSize();
		
		// CopyMemory(seeker, &rDataE, sizeof(IMAGE_RESOURCE_DATA_ENTRY));
		cRDataE->writtenAt = DWORD(seeker);
		seeker += sizeof(IMAGE_RESOURCE_DATA_ENTRY);
		
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
		
		PIMAGE_RESOURCE_DIRECTORY_ENTRY(cRDirE->writtenAt)->NameOffset = DWORD(seeker) - DWORD(_base._data);
		
		WCHAR* szName = cRDirE->GetName();
		WORD iLen = wcslen(szName) + 1;
		
		*(WORD*)seeker = iLen - 1;
		seeker += sizeof(WORD);
		wmemcpy((WCHAR*)seeker, szName, iLen);
		seeker += iLen * sizeof(WCHAR);
		
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
			memcpy(seeker, data, size);
			PIMAGE_RESOURCE_DATA_ENTRY dataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)cRDataE->writtenAt;
			dataEntry->OffsetToData = (DWORD)((PBYTE)seeker - (PBYTE)_base._data + (PBYTE)_base.VirtualAddress());
			
			//cout << "[7] seeker @ 0x" << hex << (DWORD)seeker;
			
			DWORD increment = RALIGN(cRDataE->GetSize(), 8);
			seeker += increment;
			
			//cout << " incremented by " << dec << increment << " for size " << dec << size << endl;
		}
		
		dataEntries2.pop();
	}
	
	_base._size = (DWORD)seeker - (DWORD)_base._data;
	_base._header->SizeOfRawData = _base._size;
	SetOffsets(_resDir, DWORD(_base._data));
	
	return true;
}

void ResourceSection::SetOffsets( ResourceDirectory* resDir, DWORD newResDirAt )
{
	for (int i = 0; i < resDir->CountEntries(); i++) {
		PIMAGE_RESOURCE_DIRECTORY_ENTRY dirEntry = PIMAGE_RESOURCE_DIRECTORY_ENTRY(resDir->GetEntry(i)->writtenAt);
		if (resDir->GetEntry(i)->IsDataDirectory()) {
			dirEntry->DataIsDirectory = 1;
			dirEntry->OffsetToDirectory = resDir->GetEntry(i)->GetSubDirectory()->writtenAt - newResDirAt;
			SetOffsets(resDir->GetEntry(i)->GetSubDirectory(), newResDirAt);
		}
		else {
			ResourceDataEntry* dataEntry = resDir->GetEntry(i)->GetDataEntry();
			if (dataEntry)
				dirEntry->OffsetToData = dataEntry->writtenAt - newResDirAt;
		}
	}
}

DWORD ResourceSection::SizeOfResources()
{
	DWORD size = 0;

	queue<ResourceDirectory*> dirs;
	queue<ResourceDataEntry*> dataEntries;
	queue<ResourceDataEntry*> dataEntries2;
	queue<ResourceDirectoryEntry*> strings;

	dirs.push(_resDir);
	
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
