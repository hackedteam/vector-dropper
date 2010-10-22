#ifndef ParsingError_h__
#define ParsingError_h__

#include <boost/shared_ptr.hpp>
#include <boost/statechart/event.hpp>
namespace sc = boost::statechart;

#include <exception>

#include "Common.h"
#include "DataCarrier.h"
#include "Events.h"

class parsing_error : public std::runtime_error
{
public:
	parsing_error(const string& m) throw() : std::runtime_error(m) {}
};

class parsing_exception_translator
{
public:
	template< class Action, class ExceptionEventHandler >
	sc::result operator()(
		Action a, ExceptionEventHandler eh )
	{
		try {
			return a();
		} catch ( const parsing_error & e) {
			return eh( EvParsingFailed() );
		} catch ( const std::exception &e ) {
			// return eh(EvParsingFailed());
		} catch ( ... ) {
			// return eh(EvParsingFailed());
		}

		return a();
	}
};

#endif // ParsingError_h__
