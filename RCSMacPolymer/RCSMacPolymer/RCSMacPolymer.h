/*
 * RCSMac Polymer
 *  poly engine and binary patcher
 *
 * binary patcher created by Massimo Chiodini on 10/11/2009
 * refactored and fixed by Alfredo 'revenge' Pesoli on 17/11/2009
 *
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */

#define BACKDOOR_ID_MARK      (BYTE *)"av3pVck1gb4eR2d8"
#define BACKDOOR_ID_LEN       16

#define CONF_KEY_MARK         (BYTE *)"Adf5V57gQtyi90wUhpb8Neg56756j87R"
#define LOG_KEY_MARK          (BYTE *)"3j9WmmDgBqyU270FTid3719g64bP4s52"
#define AES_KEY_MARK_LEN      32

#define SIGNATURE_MARK        (BYTE *)"f7Hk0f5usd04apdvqw13F5ed25soV5eD"
#define SIGNATURE_MARK_LEN    32

#define CONFIG_NAME_MARK      (BYTE *)"c3mdX053du1YJ541vqWILrc4Ff71pViL"
#define CONFIG_NAME_MARK_LEN  32

#define CONFIG_FILENAME	      "cptm511.dql\x00"

#define kSuccess              (int)0x00000000
#define kArgError             (int)0xFFFFFF01
#define kPatchLogError        (int)0xFFFFFF02
#define kPatchCnfError        (int)0xFFFFFF03
#define kPatchComError        (int)0xFFFFFF04
#define kPatchBIdError        (int)0xFFFFFF05
#define kPatchFlcError        (int)0xFFFFFF06
#define kMarkError            (int)0xFFFFFF10