#ifndef Parsing_h__
#define Parsing_h__

#include <iostream>
#include <limits>
using namespace std;

#include <boost/statechart/result.hpp>
#include <boost/statechart/deep_history.hpp>
#include <boost/statechart/custom_reaction.hpp>
#include <boost/statechart/simple_state.hpp>
#include <boost/statechart/transition.hpp>
#include <boost/statechart/in_state_reaction.hpp>
namespace sc = boost::statechart;

#include <boost/mpl/list.hpp>
namespace mpl = boost::mpl;

#include "Common.h"
#include "Events.h"

#include "StreamingMelter.h"

struct Defective;
struct ParseHeaders;

struct Parsing : sc::simple_state< Parsing, StreamingMelter, mpl::list< sc::deep_history<ParseHeaders> >, sc::has_deep_history > {};

#include "DataState.h"
#include "ParseHeaders.h"
#include "ParseEntryPoint.h"
#include "InjectStage1Trampoline.h"
#include "InjectDropper.h"

#include "Defective.h"
#include "ParsingError.h"

#endif // Parsing_h__
