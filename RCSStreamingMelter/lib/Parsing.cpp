#include "Common.h"
#include "Events.h"
#include "Parsing.h"
#include "ParsingError.h"


#if 0
sc::result ParseSectionHeaders::react( const EvNewData & ev )
{
	(void) ev;

	DEBUG_MSG(NOTIFY, "new data to offset: %d", availableOffset());
	DEBUG_MSG(NOTIFY, "current offset    : %d", currentOffset());
	
	std::size_t numberOfSections = context<StreamingMelter>().numberOfSections();

	if (current_ > numberOfSections + 1) 
	{
		// we already processed all sections, send padding
		if (availableOffset() > firstSectionDataOffset_) {
			context<StreamingMelter>().complete( firstSectionDataOffset_ - currentOffset() );
			return transit<ParseNativeSections>();
		} else {
			context<StreamingMelter>().complete( availableOffset() - currentOffset() );
			return discard_event();
		}
	}
	
	if (currentOffset() + sizeof(IMAGE_SECTION_HEADER) < availableOffset())
	{
		DEBUG_MSG(NOTIFY, "header %d", current_);
		
		if (current_ < numberOfSections ) {
			// original PE sections
			PIMAGE_SECTION_HEADER header = (PIMAGE_SECTION_HEADER) context<StreamingMelter>().buffer()->data();
			DEBUG_MSG(NOTIFY, "Section %s", string((PCHAR)header->Name));
			
			if (header->PointerToRawData < firstSectionDataOffset_)
				firstSectionDataOffset_ = header->PointerToRawData;
			
			context<StreamingMelter>().addSection(header);
			
		} else {
			// added sections
			if (current_ == (numberOfSections)) 
			{
				// dropper
				DEBUG_MSG(NOTIFY, "Dropper section header.");
			}
			else if (current_ == (numberOfSections + 1))
			{
				// rebuilt resources
				DEBUG_MSG(NOTIFY, "Rebuilt resources section header.");
			}
			else
			{
				// unknown ... we have a problem
				throw parsing_error("Unknown non-original section found.");
			}
		}
		
		context<StreamingMelter>().complete( sizeof(IMAGE_SECTION_HEADER) );
		current_++;
	}
	
	DEBUG_MSG(NOTIFY, "number of sections: %d", context<StreamingMelter>().numberOfSections());
	DEBUG_MSG(NOTIFY, "file alignment    : %d", context<StreamingMelter>().fileAlignment());
	
	// context<StreamingMelter>().complete( availableOffset() - currentOffset() );
	return discard_event();
}
#endif




#if 0
sc::result Defective::react( const EvNewData & ev )
{
	(void) ev;

	DEBUG_MSG(NOTIFY, "new data to offset: %d", availableOffset());
	DEBUG_MSG(NOTIFY, "current offset    : %d", currentOffset());
	
	context<StreamingMelter>().complete( availableOffset() - currentOffset() );
	return discard_event();
}

ParseNativeSections::ParseNativeSections()
	: DataState< ParseNativeSections, Parsing >()
{
}

sc::result ParseNativeSections::react( const EvNewData & ev )
{
	(void) ev;

	DEBUG_MSG(NOTIFY, "new data to offset: %d", availableOffset());
	DEBUG_MSG(NOTIFY, "current offset    : %d", currentOffset());

	DEBUG_MSG(NOTIFY, "Parsing native section");

	context<StreamingMelter>().complete( availableOffset() - currentOffset() );
	return discard_event();
}
#endif
