#ifndef Common_h__
#define Common_h__

#include <iomanip>
#include <iostream>
#include <sstream>

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
namespace bf = boost::filesystem;

#include "../MelterConfig.h"

#ifdef WIN32
#include <Windows.h>
#else
#include "win32types.h"
#endif

enum {
	DEVDEBUG = 1,
	NOTIFY,
	LOW,
	HIGH,
	CRITICAL,
};

#define DBG_MINPRIO DEVDEBUG

#ifdef WIN32
#define __PRETTY_FUNCTION__ __FUNCTION__
#endif

void debugTrace(std::string filename, unsigned int line, std::string function, std::string msg, std::string par);

#ifdef _DEBUG

#define DBGTRACE(msg, par, pri) do { \
		if ( (unsigned int)pri >= (unsigned int)DBG_MINPRIO ) \
		{ \
			std::ostringstream spar; \
			spar << (par); \
			debugTrace(__FILE__, __LINE__, __PRETTY_FUNCTION__, msg, spar.str()); \
		} \
	} while(0)

#define DBGTRACE_HEX(msg, par, pri) do { \
		if ( (unsigned int)pri >= (unsigned int)DBG_MINPRIO ) \
		{ \
			std::ostringstream spar; \
			spar << "0x" << hex << (par); \
			debugTrace(__FILE__, __LINE__, __PRETTY_FUNCTION__, msg, spar.str()); \
		} \
	} while (0)

#define DBGTRACE_BUFFER(pri) do { \
		if ( (unsigned int)pri >= (unsigned int)DBG_MINPRIO ) { \
		std::ostringstream spar; \
		spar << "[ " << ( done() ? "true" : "false" ) << hex \
					<< " trig: " << triggeringOffset() \
		            << " curr: " << currentOffset() \
		            << " need: " << neededBytes() \
		            << " aval: " << availableOffset() \
		            << " ]"; \
		debugTrace(__FILE__, __LINE__, __PRETTY_FUNCTION__, spar.str(), ""); \
		} \
	} while (0)

#else
#define DBGTRACE(msg, par, pri)
#define DBGTRACE_HEX(msg, par, pri)
#define DBGTRACE_BUFFER(pri)
#endif

#endif // Common_h__
