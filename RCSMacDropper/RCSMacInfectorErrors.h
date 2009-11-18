#ifndef __RCSMacDropperError_h__
#define __RCSMacDropperError_h__

enum
{
  kFatBinary      = 0,
  kFatSwapBinary  = 1,
  kMachBinary     = 2,
};

enum
{
  kSuccess                = 0,
  kErrorGeneric           = -1,
  kErrorOpenFile          = -2,
  kErrorReadFile          = -3,
  kErrorWriteFile         = -4,
  kErrorCreateFile        = -5,
  kErrorMemoryAllocation  = -6,
  kErrorFileNotSupported  = -50,
};

enum
{
  kInvalidFile          = -1,
  kInvalidFAT           = -2,
  kInvalidMacho         = -3,
};

#endif