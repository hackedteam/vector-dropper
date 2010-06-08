/*
 * ParseStage1Trampoline.h
 *
 *  Created on: May 7, 2010
 *      Author: daniele
 */

#ifndef PARSESTAGE1TRAMPOLINE_H_
#define PARSESTAGE1TRAMPOLINE_H_

#include <AsmJit.h>

struct InjectStage1Trampoline
	: DataState< InjectStage1Trampoline, Parsing >
{
public:
	void init();
	StateResult parse();
	StateResult process();
	sc::result transitToNext();

	InjectStage1Trampoline();
	~InjectStage1Trampoline();
};

#endif /* PARSESTAGE1TRAMPOLINE_H_ */
