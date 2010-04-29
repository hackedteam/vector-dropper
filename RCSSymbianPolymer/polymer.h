
// Password di cifratura log
#define AES_LOG_PASS_MARK (BYTE *)"3j9WmmDgBqyU270FTid3719g64bP4s52"
#define AES_CONF_PASS_MARK (BYTE *)"Adf5V57gQtyi90wUhpb8Neg56756j87R"
#define AES_PASS_MARK_LEN 32
#define AES_PASS_LEN      16

// Password cifratura canale
#define CHAN_PASS_MARK (BYTE *)"f7Hk0f5usd04apdvqw13F5ed25soV5eD"
#define CHAN_PASS_MARK_LEN 32
#define CHAN_PASS_LEN      16

// 16 byte che identificano univocamente la backdoor (NULL terminato)
#define BACKDOOR_ID_MARK (BYTE *)"av3pVck1gb4eR2d8"
#define BACKDOOR_ID_LEN 16

// Nome del file di configurazione CIFRATO con il primo byte di g_Challenge[]
#define CONFIG_NAME_MARK (BYTE *) L"c3mdX053du1YJ541vqWILrc4Ff71pViL"
#define CONFIG_NAME_MARK_LEN 64
#define CONFIG_FILENAME		      L"cptm511.dql\x00"

#define SIS_UNINST	0
#define SIS_CORE	1

#define ERROR_OUTPUT			-1
#define ERROR_EMBEDDING			-2
#define ERROR_POLYMER			-3
#define ERROR_MANIFEST			-4
#define ERROR_NO_DROPPER		-100
#define ERROR_INVALID_DROPPER	-101
