/*
 * InjectDropper.h
 *
 *  Created on: May 7, 2010
 *      Author: daniele
 */

#ifndef INJECTDROPPER_H_
#define INJECTDROPPER_H_

struct InjectDropper : DataState< InjectDropper, Parsing >
{
public:
	void init();
	StateResult parse();
	StateResult process();
	sc::result transitToNext();

	InjectDropper();
	~InjectDropper();
};

#endif /* INJECTDROPPER_H_ */
