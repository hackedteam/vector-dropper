/*
 * Defective.h
 *
 *  Created on: Apr 27, 2010
 *      Author: daniele
 */

#ifndef DEFECTIVE_H_
#define DEFECTIVE_H_

struct Defective : DataState< Defective, Parsing >
{
public:
	typedef sc::custom_reaction< EvNewData > reactions;

	sc::result react( const EvNewData & ev );

	Defective();
	~Defective() {}

private:
	void init() {}
	StateResult parse() { return PROCESSED; }
	sc::result transitToNext() { return discard_event(); }
};

#endif /* DEFECTIVE_H_ */
