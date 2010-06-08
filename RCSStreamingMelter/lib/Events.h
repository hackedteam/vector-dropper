#ifndef Events_h__
#define Events_h__

#include <iostream>
#include <string>

#include <boost/shared_ptr.hpp>
#include <boost/statechart/event.hpp>
namespace sc = boost::statechart;

#include "DataCarrier.h"

class Chunk;

struct EvNewData : sc::event< EvNewData > {};

struct EvIdleComplete : sc::event < EvIdleComplete > {};
/*
struct EvNewData : DataCarrier, sc::event< EvNewData > 
{
public:
	EvNewData(boost::shared_ptr<Chunk> c) : DataCarrier(c) {}
};
*/

struct EvParsingEnded : DataCarrier, sc::event< EvParsingEnded > 
{
public:
	EvParsingEnded(boost::shared_ptr<Chunk> c) : DataCarrier(c) {}
};

struct EvSendingEnded : sc::event< EvSendingEnded > {};

struct EvParsingFailed : sc::event< EvParsingFailed >  {};
/*
{
public:
	EvParsingFailed(std::string description, boost::shared_ptr<Chunk> c) : DataCarrier(c), desc_(description) {};
private:
	std::string desc_;
};
*/

#endif // Events_h__
