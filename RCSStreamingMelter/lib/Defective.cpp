/*
 * Defective.cpp
 *
 *  Created on: May 3, 2010
 *      Author: daniele
 */

#include "Parsing.h"

sc::result Defective::react( const EvNewData & ev )
{
	(void) ev;

	DEBUG_MSG(D_EXCESSIVE, "new data to offset: %08x", availableOffset());
	DEBUG_MSG(D_EXCESSIVE, "current offset    : %08x", currentOffset());

   std::size_t completedSize = availableOffset() - currentOffset();
   DEBUG_MSG(D_DEBUG, "streaming %d bytes.", completedSize);
	context<StreamingMelter>().complete( completedSize );
	return discard_event();
}

Defective::Defective()
	: DataState< Defective, Parsing >()
 {
	DEBUG_MSG(D_INFO, "streaming rest of data.");
 }
