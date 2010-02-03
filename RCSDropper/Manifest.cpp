#include <iostream>
using namespace std;

#include <xercesc/dom/DOM.hpp>
#include <xercesc/dom/DOMError.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/PlatformUtils.hpp>
using namespace xercesc;

#include "Manifest.h"

static std::string default_manifest = 
"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n   <assemblyIdentity\r\n      name=\"Microsoft.Windows.MyCoolApp\"\r\n      processorArchitecture=\"x86\"\r\n      version=\"7.0.10.4165\"\r\n      type=\"win32\"/>\r\n   <description>Application description here</description>\r\n   <dependency>\r\n      <dependentAssembly>\r\n         <assemblyIdentity\r\n            type=\"win32\"\r\n            name=\"Microsoft.Windows.Common-Controls\"\r\n            version=\"6.0.0.0\"\r\n            processorArchitecture=\"x86\"\r\n            publicKeyToken=\"6595b64144ccf1df\"\r\n            language=\"*\"\r\n         />\r\n      </dependentAssembly>\r\n   </dependency>\r\n   <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">\r\n      <security>\r\n         <requestedPrivileges>\r\n            <requestedExecutionLevel\r\n               level=\"highestAvailable\"\r\n               uiAccess=\"False\"/>\r\n         </requestedPrivileges>\r\n      </security>\r\n   </trustInfo>\r\n</assembly>";

class MyDOMErrorHandler : public DOMErrorHandler
{
public:

	MyDOMErrorHandler(){};
	~MyDOMErrorHandler(){};

	/** @name The error handler interface */
	bool handleError(const DOMError& domError)
	{
		// Display whatever error message passed from the serializer
		if (domError.getSeverity() == DOMError::DOM_SEVERITY_WARNING)
			XERCES_STD_QUALIFIER cerr << "\nWarning Message: ";
		else if (domError.getSeverity() == DOMError::DOM_SEVERITY_ERROR)
			XERCES_STD_QUALIFIER cerr << "\nError Message: ";
		else
			XERCES_STD_QUALIFIER cerr << "\nFatal Message: ";

		char *msg = XMLString::transcode(domError.getMessage());
		XERCES_STD_QUALIFIER cerr<< msg <<XERCES_STD_QUALIFIER endl;
		XMLString::release(&msg);

		// Instructs the serializer to continue serialization if possible.
		return true;
	}

	void resetErrors(){};

private :
	/* Unimplemented constructors and operators */
	MyDOMErrorHandler(const DOMErrorHandler&);
	void operator=(const DOMErrorHandler&);

};

Manifest::Manifest()
{
}

Manifest::Manifest(string manifest)
: _manifest(manifest)
{
	XMLCh tempStr[100];
	XMLString::transcode("LS", tempStr, 99);
	_impl = DOMImplementationRegistry::getDOMImplementation(tempStr);
	_parser = ((DOMImplementationLS*)_impl)->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	
	// optionally you can set some features on this builder
	_parser->getDomConfig()->setParameter(XMLUni::fgDOMWellFormed, true);
	_parser->getDomConfig()->setParameter(XMLUni::fgDOMValidateIfSchema, true);
	_parser->getDomConfig()->setParameter(XMLUni::fgDOMNamespaces, true);
	_parser->getDomConfig()->setParameter(XMLUni::fgDOMDatatypeNormalization, true);
	_parser->getDomConfig()->setParameter(XMLUni::fgDOMNormalizeCharacters, true);
	
	// optionally you can implement your DOMErrorHandler (e.g. MyDOMErrorHandler)
	// and set it to the builder
	MyDOMErrorHandler* errHandler = new MyDOMErrorHandler();
	_parser->getDomConfig()->setParameter(XMLUni::fgDOMErrorHandler, errHandler);
}

Manifest::~Manifest(void)
{
}

void Manifest::create()
{
	_manifest = default_manifest;
}

bool Manifest::check()
{	
	DOMLSInput* input = _impl->createLSInput();
	input->setEncoding(XMLUni::fgUTF8EncodingString);
	input->setStringData((XMLCh*)_manifest.c_str());
	
	try {
		_doc = _parser->parse(input);
	}
	catch (const XMLException& toCatch) {
		char* message = XMLString::transcode(toCatch.getMessage());
		cout << "Exception message is: \n"
			<< message << "\n";
		XMLString::release(&message);
		return false;
	}
	catch (const DOMException& toCatch) {
		char* message = XMLString::transcode(toCatch.msg);
		cout << "Exception message is: \n"
			<< message << "\n";
		XMLString::release(&message);
		return false;
	}
	catch (...) {
		cout << "Unexpected Exception \n" ;
		return false;
	}
	
	input->release();
	
	if (_doc) {
		XMLCh* tagName = XMLString::transcode("*");
		DOMNodeList* childs = _doc->getElementsByTagName(tagName);
		XMLString::release(&tagName);
		if (childs) {
			int size = childs->getLength();
			
			if (size > 0) {
				for (int i = 0; i < size; i++) {
					DOMNode* node = childs->item(i);
					string nodeName = XMLString::transcode(node->getLocalName());
					cout << "NODE: " << nodeName << endl;
					if (!nodeName.compare("requestedExecutionLevel")) {
						// change attributes
						DOMNamedNodeMap* attributes = node->getAttributes();
						DOMNode* levelNode = attributes->getNamedItem(XMLString::transcode("level"));
						if (levelNode) {
							string level = XMLString::transcode(levelNode->getNodeValue());

							cout << "LEVEL: " << level << endl;

							if (level.compare("highestAvailable") && level.compare("requireAdministrator")) { 
								cout << "Changing level to highestAvailable" << endl;						
								levelNode->setNodeValue(XMLString::transcode("highestAvailable"));
							}
						}

						return true;
					}
				}

				// we have not found a requestedExecutionLevel entry, so add it
				DOMNode *trustInfoNode = createTrustInfo();
				_doc->getDocumentElement()->appendChild(_doc->importNode(trustInfoNode, true));
			}
		}
	}
	
	return true;
}

bool Manifest::initialize()
{
	try {
		XMLPlatformUtils::Initialize();
	}

	catch (const XMLException& toCatch) {
		char* message = XMLString::transcode(toCatch.getMessage());
		cout << "Error during xercesc initialization! : " << endl;
		cout << message << endl;
		XMLString::release(&message);
		return false;
	}
	
	return true;
}

DOMElement* Manifest::createTrustInfo()
{
	DOMImplementation* impl = DOMImplementationRegistry::getDOMImplementation(XMLString::transcode("Range"));
	DOMDocument* doc = impl->createDocument(0, XMLString::transcode("root"), 0);
	DOMElement* root = doc->getDocumentElement();

	DOMElement* trustInfoNode = doc->createElementNS(XMLString::transcode("urn:schemas-microsoft-com:asm.v3"),
		XMLString::transcode("ms_asmv3:trustInfo"));
	root->appendChild(trustInfoNode);

	DOMNode* securityNode = doc->createElement(XMLString::transcode("ms_asmv3:security"));
	trustInfoNode->appendChild(securityNode);

	DOMNode* requestedPrivilegesNode = doc->createElement(XMLString::transcode("ms_asmv3:requestedPrivileges"));
	securityNode->appendChild(requestedPrivilegesNode);

	DOMNode* requestedExecutionLevelNode = doc->createElement(XMLString::transcode("ms_asmv3:requestedExecutionLevel"));
	requestedPrivilegesNode->appendChild(requestedExecutionLevelNode);

	DOMAttr* levelAttr = doc->createAttribute(XMLString::transcode("level"));
	levelAttr->setValue(XMLString::transcode("highestAvailable"));
	((DOMElement*)requestedExecutionLevelNode)->setAttributeNode(levelAttr);

	DOMAttr* uiAccessAttr = doc->createAttribute(XMLString::transcode("uiAccess"));
	uiAccessAttr->setValue(XMLString::transcode("false"));
	((DOMElement*)requestedExecutionLevelNode)->setAttributeNode(uiAccessAttr);

	// optionally, call release() to release the resource associated with the range after done
	DOMRange* range = doc->createRange();
	range->release();

	// no need to release this returned object which is owned by implementation
	DOMNodeList*    nodeList = doc->getElementsByTagName(XMLString::transcode("*"));

	return trustInfoNode;
}

bool Manifest::serialize()
{
	DOMLSSerializer* serializer = ((DOMImplementationLS*)_impl)->createLSSerializer();
	
	// optionally you can set some features on this serializer
	if (serializer->getDomConfig()->canSetParameter(XMLUni::fgDOMWRTDiscardDefaultContent, false))
		serializer->getDomConfig()->setParameter(XMLUni::fgDOMWRTDiscardDefaultContent, false);
	
	if (serializer->getDomConfig()->canSetParameter(XMLUni::fgDOMWRTFormatPrettyPrint, false))
		serializer->getDomConfig()->setParameter(XMLUni::fgDOMWRTFormatPrettyPrint, false);
	
	XMLFormatTarget *formTarget = new MemBufFormatTarget();
	DOMLSOutput* output = ((DOMImplementationLS*)_impl)->createLSOutput();
	output->setByteStream(formTarget);
	output->setEncoding(XMLUni::fgUTF8EncodingString);

	try {
		serializer->write(_doc, output);
	}
	catch (const XMLException& c) {
		char* message = XMLString::transcode(c.getMessage());
		cout << "Exception message is: \n"
			<< message << "\n";
		XMLString::release(&message);
		return false;
	}
	catch (const DOMException& c) {
		char* message = XMLString::transcode(c.msg);
		cout << "Exception message is: \n"
			<< message << "\n";
		XMLString::release(&message);
		return false;
	}
	catch (...) {
		cout << "Unexpected Exception \n" ;
		return false;
	}
	
	_manifest = (char*) ((MemBufFormatTarget*)formTarget)->getRawBuffer();
	
	output->release();
	serializer->release();
	delete formTarget;
	
	return true;
}
