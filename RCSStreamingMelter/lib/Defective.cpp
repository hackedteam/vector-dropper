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

	DBGTRACE("new data to offset: ", availableOffset() , DEVDEBUG);
	DBGTRACE("current offset    : ", currentOffset(), DEVDEBUG);

	context<StreamingMelter>().complete( availableOffset() - currentOffset() );
	return discard_event();
}

Defective::Defective()
	: DataState< Defective, Parsing >()
 {
	DBGTRACE("constructor.", "", DEVDEBUG);
 }
