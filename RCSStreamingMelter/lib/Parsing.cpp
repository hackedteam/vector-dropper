#include "Common.h"
#include "Events.h"
#include "Parsing.h"
#include "ParsingError.h"


#if 0
sc::result ParseSectionHeaders::react( const EvNewData & ev )
{
	(void) ev;

	DBGTRACE("new data to offset: ", availableOffset() , NOTIFY);
	DBGTRACE("current offset    : ", currentOffset(), NOTIFY);
	
	// DBGTRACE("header            :", current_, NOTIFY);
	
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
		DBGTRACE("header ", current_, NOTIFY);
		
		if (current_ < numberOfSections ) {
			// original PE sections
			PIMAGE_SECTION_HEADER header = (PIMAGE_SECTION_HEADER) context<StreamingMelter>().buffer()->data();
			DBGTRACE("Section ", string((PCHAR)header->Name), NOTIFY);
			
			if (header->PointerToRawData < firstSectionDataOffset_)
				firstSectionDataOffset_ = header->PointerToRawData;
			
			context<StreamingMelter>().addSection(header);
			
		} else {
			// added sections
			if (current_ == (numberOfSections)) 
			{
				// dropper
				DBGTRACE("Dropper section header.", "", NOTIFY);
			}
			else if (current_ == (numberOfSections + 1))
			{
				// rebuilt resources
				DBGTRACE("Rebuilt resources section header.", "", NOTIFY);
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
	
	DBGTRACE("number of sections: ", context<StreamingMelter>().numberOfSections(), NOTIFY);
	DBGTRACE("file alignment    : ", context<StreamingMelter>().fileAlignment(), NOTIFY);
	
	// context<StreamingMelter>().complete( availableOffset() - currentOffset() );
	return discard_event();
}
#endif




#if 0
sc::result Defective::react( const EvNewData & ev )
{
	(void) ev;

	DBGTRACE("new data to offset: ", availableOffset() , NOTIFY);
	DBGTRACE("current offset    : ", currentOffset(), NOTIFY);
	
	context<StreamingMelter>().complete( availableOffset() - currentOffset() );
	return discard_event();
}

ParseNativeSections::ParseNativeSections()
	: DataState< ParseNativeSections, Parsing >()
{
	DBGTRACE("constructor.", "", NOTIFY);
}

sc::result ParseNativeSections::react( const EvNewData & ev )
{
	(void) ev;

	DBGTRACE("new data to offset: ", availableOffset() , NOTIFY);
	DBGTRACE("current offset    : ", currentOffset(), NOTIFY);

	DBGTRACE("Parsing native section", "", NOTIFY);

	context<StreamingMelter>().complete( availableOffset() - currentOffset() );
	return discard_event();
}
#endif
