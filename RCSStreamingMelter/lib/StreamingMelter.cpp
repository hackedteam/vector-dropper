/*
 * StreamingMelter.cpp
 *
 *  Created on: May 3, 2010
 *      Author: daniele
 */

#include <boost/format.hpp>
#include "StreamingMelter.h"
#include "Common.h"

void StreamingMelter::setRCS(const char* file)
{
	DBGTRACE("Setting RCS   : ", file, NOTIFY);

	try
	{
		RCSDropper* dropper = new RCSDropper(file);
		dropper_.reset(dropper);
	} catch (InvalidCookerVersion& e) {
		std::cout << boost::format("%s has been cooked with RCSCooker version %s, required version is %s") % file % e.effective() % e.required() << std::endl;
		std::cout << "Inserting dummy dropper ..." << std::endl;
		//Dropper* dropper = new DummyDropper();
		//dropper_.reset(dropper);
		throw parsing_error(e.what());
	} catch (std::runtime_error& e) {
		throw parsing_error(e.what());
	}

	DBGTRACE("Raw dropper size ... ", (DWORD) dropper_->size(), NOTIFY);
}
