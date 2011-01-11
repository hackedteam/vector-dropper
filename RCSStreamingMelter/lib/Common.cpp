/*
 * Common.cpp
 *
 *  Created on: May 4, 2010
 *      Author: daniele
 */

#include "Common.h"

#include <cstdarg>
#include <iostream>
#include <sstream>
#include <string>

#include <boost/regex.hpp>

#include <syslog.h>

void debugTrace(char level, const char* message, ...);

static debug_msg_t _debug_fn = debugTrace;

debug_msg_t debug_fn() { return _debug_fn; }
void set_debug_fn( debug_msg_t fn ) { if (!fn) _debug_fn = debugTrace; _debug_fn = fn; }

#if 0
std::string parseFunctionName(std::string text)
{
	// void DataState<Derived, Outer>::preamble() [with Derived = ParseDOSHeader, Outer = Parsing]

	// virtual boost::statechart::result Defective::react(const EvNewData&)
	// virtual void ParseNTHeader::parse()
	const boost::regex templated("^\\w* \\w*<\\w*, \\w*>::(\\w*)\\(\\) \\[with \\w* = (\\w*),.*");
	const boost::regex plain("^(virtual)?\\s?\\w*(::\\w*::\\w*)?\\s?(\\w*)::(\\w*).*");
	boost::cmatch what;

	std::string className = "unknown";
	std::string functionName = "unknown";

	if ( boost::regex_match(text.c_str(), what, templated) ) {
#if 0
		std::cout << "$1 = " << what[1].str() << std::endl;
		std::cout << "$2 = " << what[2].str() << std::endl;
#endif
		className = what[2].str();
		functionName = what[1].str();
	} if ( boost::regex_match(text.c_str(), what, plain) ) {
#if 0
		std::cout << "$1 = " << what[1].str() << std::endl;
		std::cout << "$2 = " << what[2].str() << std::endl;
		std::cout << "$3 = " << what[3].str() << std::endl;
		std::cout << "$4 = " << what[4].str() << std::endl;
#endif
		if ( ! what[3].str().empty())
			className = what[3].str();
		else
			className = what[2].str();
		functionName = what[4].str();
	}

	std::ostringstream ss;
	ss << className << "::" << functionName;
	return ss.str();
}
#endif

void debugTrace_extended(std::string filename, unsigned int line, std::string function, std::string msg, std::string par)
{
	(void) filename;
	std::ostringstream ss;
	bf::path f = __FILE__;
	(void) line;
	(void) function;
	std::string funcPrototype = ""; // parseFunctionName( function );
	ss << /* "[" << funcPrototype << " @ " << line << "] " << */ msg << " " << par;

	syslog(LOG_LOCAL4 | LOG_NOTICE, "%s", ss.str().c_str());
}

void debugTrace(char level, const char* message, ...)
{
	if (level >= DBG_MINPRIO)
		return;

	va_list l;
	va_start(l, message);
        vprintf(message, l);
        printf("\n");

        //vsyslog(LOG_LOCAL4 | LOG_NOTICE, message, l);
	va_end(l);
}

