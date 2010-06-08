/*
 * DataState.h
 *
 *  Created on: Apr 27, 2010
 *      Author: daniele
 */

#ifndef DATASTATE_H_
#define DATASTATE_H_

#include <boost/statechart/result.hpp>
#include <boost/statechart/deep_history.hpp>
#include <boost/statechart/custom_reaction.hpp>
#include <boost/statechart/simple_state.hpp>
#include <boost/statechart/transition.hpp>
#include <boost/statechart/in_state_reaction.hpp>
namespace sc = boost::statechart;

#include "Events.h"
#include "StreamingMelter.h"

enum StateResult {
		NEED_MORE_DATA,
		PARSED,
		PROCESSED,
	};

template< class Derived, class Outer >
struct DataState : sc::simple_state< Derived, Outer >
{
public:
	DataState()
		: done_(false), initialized_(false), parsed_(false)
	{
	}

	void feed ( char *data, std::size_t size )
	{
		this.template context<StreamingMelter>().feed(data, size);
		this->post_event( EvNewData() );
	}

	bool isTriggering()
	{
		if ( currentOffset() == triggeringOffset() && isDataAvailable() )
			return true;
		return false;
	}

	bool isDataAvailable()
	{
		return isDataAvailable( neededBytes() );
	}

	bool isDataAvailable(std::size_t bytes)
	{
		if ( availableOffset() - currentOffset() >= bytes )
			return true;
		return false;
	}

	sc::result canSwitchToNext()
	{
		if ( availableOffset() < offsetToNext() ) {
			std::size_t bytes = availableOffset() - currentOffset();
			this->template context<StreamingMelter>().complete( bytes );
			return this->discard_event();
		}

		std::size_t bytes = offsetToNext() - currentOffset();
		this->template context<StreamingMelter>().complete( bytes );
		this->post_event( EvNewData() );
		return transitToNext();
	}

	char* getData()
	{
		char *data = this->template context<StreamingMelter>().buffer()->data();
		if (!data)
				throw parsing_error("Invalid data pointer.");
		return data;
	}

	virtual void init() = 0;
	virtual StateResult parse() = 0;
	virtual StateResult process() { return PROCESSED; };
	virtual sc::result transitToNext() = 0;

	void preamble()
	{
	}

	sc::result react( const EvNewData & ev )
	{
		(void) ev;

		if ( ! initialized() )
		{
			init();
			initialized() = true;
		}

		DBGTRACE_BUFFER(DEVDEBUG);

		if ( done() == false )
		{
			// check if we have enough data
			if ( ! isTriggering() ) {
				// DBGTRACE("NOT TRIGGERING", "", DEVDEBUG);
				return this->discard_event();
			}

			// DBGTRACE("TRIGGERING", "", DEVDEBUG);
			if (!parsed_) {
				if (parse() != PARSED)
					return this->discard_event();
				parsed_ = true;
			}

			if (process() != PROCESSED)
				throw parsing_error("CRITICAL ERROR!!!");

			done() = true;
			// DBGTRACE("offset to next           : ", offsetToNext(), DEVDEBUG);
		}

		// DBGTRACE("running to next state in: ", offsetToNext() - currentOffset(), DEVDEBUG);
		return canSwitchToNext();
	}

	boost::shared_ptr<Chunk> output()
	{
		DBGTRACE("new data to offset: ", this.template context<StreamingMelter>().maxOffset(), NOTIFY);
		return this.template context<StreamingMelter>().output();
	}

	std::size_t currentOffset()
	{
		return this->template context<StreamingMelter>().currentOffset();
	}

	std::size_t availableOffset()
	{
		return this->template context<StreamingMelter>().maxOffset();
	}

	bool done() const { return done_; }
	bool & done() { return done_; }

	std::size_t neededBytes() const { return neededBytes_; }
	std::size_t& neededBytes() { return neededBytes_; }

	std::size_t triggeringOffset() const { return triggeringOffset_; }
	std::size_t& triggeringOffset() { return triggeringOffset_; }

	std::size_t offsetToNext() const { return offsetToNext_; }
	std::size_t& offsetToNext() { return offsetToNext_; }

	bool initialized() const { return initialized_; }
	bool& initialized() { return initialized_; }

	typedef mpl::list<
				sc::custom_reaction<EvNewData>,
				sc::transition<EvParsingFailed, Defective>
			> reactions;

protected:
	std::size_t neededBytes_;
	std::size_t triggeringOffset_;
	std::size_t offsetToNext_;
	bool done_;
	bool initialized_;
	bool parsed_;
};

#endif /* DATASTATE_H_ */
