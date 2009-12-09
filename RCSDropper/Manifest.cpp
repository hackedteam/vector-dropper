#include <iostream>
using namespace std;

#include "Manifest.h"
#include "mxml.h"

static std::string default_manifest = 
"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n   <assemblyIdentity\r\n      name=\"Microsoft.Windows.MyCoolApp\"\r\n      processorArchitecture=\"x86\"\r\n      version=\"7.0.10.4165\"\r\n      type=\"win32\"/>\r\n   <description>Application description here</description>\r\n   <dependency>\r\n      <dependentAssembly>\r\n         <assemblyIdentity\r\n            type=\"win32\"\r\n            name=\"Microsoft.Windows.Common-Controls\"\r\n            version=\"6.0.0.0\"\r\n            processorArchitecture=\"x86\"\r\n            publicKeyToken=\"6595b64144ccf1df\"\r\n            language=\"*\"\r\n         />\r\n      </dependentAssembly>\r\n   </dependency>\r\n   <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">\r\n      <security>\r\n         <requestedPrivileges>\r\n            <requestedExecutionLevel\r\n               level=\"highestAvailable\"\r\n               uiAccess=\"False\"/>\r\n         </requestedPrivileges>\r\n      </security>\r\n   </trustInfo>\r\n</assembly>";

string trustInfonode_names[] = {
	"trustInfo",
	"ms_asmv2:trustInfo",
};

Manifest::Manifest()
{
}

Manifest::Manifest(string manifest)
: _manifest(manifest)
{
}

Manifest::~Manifest(void)
{
}

void Manifest::Create()
{
	_manifest = default_manifest;
}

bool Manifest::AddSecurityInfo()
{
	cout << "MANIFEST: " << _manifest << endl;
	
	// parse string
	mxml_node_t* tree = NULL;
	tree = mxmlLoadString(NULL, _manifest.c_str(), MXML_TEXT_CALLBACK);
	
	// look for <trustInfo> trustInfoNode
	mxml_node_t *trustInfoNode = NULL;
	trustInfoNode = mxmlFindElement(tree, tree, "trustInfo", NULL, NULL, MXML_DESCEND);
	if (trustInfoNode == NULL) {
		
		cout << "trustInfo trustInfoNode not found, creating ..." << endl;
		
		// look for <assembly> node
		mxml_node_t *assemblyNode = NULL;
		assemblyNode = mxmlFindElement(tree, tree, "assembly", NULL, NULL, MXML_DESCEND);
		
		mxml_node_t* trustInfoNode = mxmlNewElement(assemblyNode, "trustInfo");
		mxmlElementSetAttr(trustInfoNode, "xmlns", "urn:schemas-microsoft-com:asm.v3");
		
		mxml_node_t* securityNode = mxmlNewElement(trustInfoNode, "security");
		mxml_node_t* requestedPrivilegesNode = mxmlNewElement(securityNode, "requestedPrivileges");
		
		mxml_node_t* requestedExecutionLevelNode = mxmlNewElement(requestedPrivilegesNode, "requestedExecutionLevel");
		mxmlElementSetAttr(requestedExecutionLevelNode, "level", "highestAvailable");
		mxmlElementSetAttr(requestedExecutionLevelNode, "uiAccess", "false");
		
	} else {
		// a <trustInfo> node is found
		// look for <security>

		mxml_node_t *securityNode = NULL;
		securityNode = mxmlFindElement(trustInfoNode, trustInfoNode, "security", NULL, NULL, MXML_DESCEND);
		if (securityNode == NULL) {
			// create <security> node

			mxml_node_t* securityNode = mxmlNewElement(trustInfoNode, "security");
			mxml_node_t* requestedPrivilegesNode = mxmlNewElement(securityNode, "requestedPrivileges");

			mxml_node_t* requestedExecutionLevelNode = mxmlNewElement(requestedPrivilegesNode, "requestedExecutionLevel");
			mxmlElementSetAttr(requestedExecutionLevelNode, "level", "highestAvailable");
			mxmlElementSetAttr(requestedExecutionLevelNode, "uiAccess", "false");
		} else {
			// a <security> node is found
			// look for <requestedPrivileges>

			mxml_node_t *requestedPrivilegesNode = NULL;
			requestedPrivilegesNode = mxmlFindElement(securityNode, securityNode, "requestedPrivileges", NULL, NULL, MXML_DESCEND);
			if (requestedPrivilegesNode == NULL) {
				// create <requestedPrivileges> node
				mxml_node_t* requestedPrivilegesNode = mxmlNewElement(securityNode, "requestedPrivileges");

				mxml_node_t* requestedExecutionLevelNode = mxmlNewElement(requestedPrivilegesNode, "requestedExecutionLevel");
				mxmlElementSetAttr(requestedExecutionLevelNode, "level", "highestAvailable");
				mxmlElementSetAttr(requestedExecutionLevelNode, "uiAccess", "false");
			} else {
				// a <requestedPrivileges> node is found
				// look for <requestedExecutionLevel>

				mxml_node_t *requestedExecutionLevelNode = NULL;
				requestedExecutionLevelNode = mxmlFindElement(securityNode, securityNode, "requestedExecutionLevel", NULL, NULL, MXML_DESCEND);
				if (requestedExecutionLevelNode == NULL) {
					// create <requestedExecutionLevel> node
					mxml_node_t* requestedExecutionLevelNode = mxmlNewElement(requestedPrivilegesNode, "requestedExecutionLevel");
					mxmlElementSetAttr(requestedExecutionLevelNode, "level", "highestAvailable");
					mxmlElementSetAttr(requestedExecutionLevelNode, "uiAccess", "false");
				} else {
					// a <requestedExecutionLevel> node is found
					// check if node attributes are as required

					const char * level = mxmlElementGetAttr(requestedExecutionLevelNode, "level");
					if (level == NULL) {
						mxmlElementSetAttr(requestedExecutionLevelNode, "level", "highestAvailable");
					} else {
						// if attribute level DOES NOT exceed our requirements
						// change it to "highestAvailable" anyway
						if (strcmp(level, "requireAdministrator"))
							mxmlElementSetAttr(requestedExecutionLevelNode, "level", "highestAvailable");
					}

					const char *uiAccess = mxmlElementGetAttr(requestedExecutionLevelNode, "uiAccess");
					if (uiAccess == NULL)
						mxmlElementSetAttr(requestedExecutionLevelNode, "uiAccess", "false");
				}
			}
		}
	}
	
	_manifest = mxmlSaveAllocString(tree, MXML_NO_CALLBACK);
	
	cout << "MANGLED MANIFEST: " << _manifest << endl; 
	
	mxmlDelete(tree);
	
	return true;
}
