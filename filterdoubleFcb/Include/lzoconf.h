/* lzoconf.h -- configuration for the LZO real-time data compression library
 */


#ifndef __LZOCONF_H
#define __LZOCONF_H

#define LZO_VERSION             0x1000


/* LZO requires a conforming <limits.h> */
#include <limits.h>
#if !defined(CHAR_BIT) || (CHAR_BIT != 8)
#  error invalid CHAR_BIT
#endif
#if !defined(UCHAR_MAX) || !defined(UINT_MAX) || !defined(ULONG_MAX)
#  error check your compiler installation
#endif

#ifdef __cplusplus
extern "C" {
#endif


/***********************************************************************
// architecture defines
************************************************************************/

#if defined(__WINDOWS__) || defined(_WINDOWS) || defined(_Windows)
#  define __LZO_WIN
#elif defined(__WIN32__) || defined(_WIN32) || defined(WIN32)
#  define __LZO_WIN
#elif defined(__NT__) || defined(__WINDOWS_386__)
#  define __LZO_WIN
#elif defined(__DOS__) || defined(__MSDOS__) || defined(MSDOS)
#  define __LZO_DOS
#endif

#if (UINT_MAX < 0xffffffffL)
#  if defined(__LZO_WIN)
#    define __LZO_WIN16
#  elif defined(__LZO_DOS)
#    define __LZO_DOS16
#  elif defined(__TOS__)
#    define __LZO_TOS16
#  else
#    error 16 bit target not supported
#  endif
#endif

#if !defined(__LZO_i386)
#  if defined(__LZO_DOS) || defined(__LZO_WIN16)
#    define __LZO_i386
#  elif defined(__i386__) || defined(__386__) || defined(_M_IX86)
#    define __LZO_i386
#  endif
#endif


/***********************************************************************
// integral and pointer types
************************************************************************/

/* Integral types with 32 bits or more */
#if !defined(LZO_UINT32_MAX)
#  if (UINT_MAX >= 0xffffffffL)
     typedef unsigned int       lzo_uint32;
     typedef int                lzo_int32;
#    define LZO_UINT32_MAX      UINT_MAX
#  elif (ULONG_MAX >= 0xffffffffL)
     typedef unsigned long      lzo_uint32;
     typedef long               lzo_int32;
#    define LZO_UINT32_MAX      ULONG_MAX
#  else
#    error lzo_uint32
#  endif
#endif

/* lzo_uint is used like size_t */
#if !defined(LZO_UINT_MAX)
#  if (UINT_MAX >= 0xffffffffL)
     typedef unsigned int       lzo_uint;
     typedef int                lzo_int;
#    define LZO_UINT_MAX        UINT_MAX
#  elif (ULONG_MAX >= 0xffffffffL)
     typedef unsigned long      lzo_uint;
     typedef long               lzo_int;
#    define LZO_UINT_MAX        ULONG_MAX
#  else
#    error lzo_uint
#  endif
#endif



/* no typedef here because of const-pointer issues */
#define lzo_byte                unsigned char 
#define lzo_bytep               unsigned char  *
#define lzo_voidp               void  *
#define lzo_shortp              short *
#define lzo_ushortp             unsigned short  *
#define lzo_uint32p             lzo_uint32  *
#define lzo_int32p              lzo_int32  *
#define lzo_uintp               lzo_uint  *
#define lzo_intp                lzo_int  *
#define lzo_voidpp              lzo_voidp  *
#define lzo_bytepp              lzo_bytep  *
#define lzo_charp               char  *

/* improve code readability */
typedef int lzo_bool;


/***********************************************************************
// function types
************************************************************************/

/* linkage */
#if !defined(__LZO_EXTERN_C)
#  ifdef __cplusplus
#    define __LZO_EXTERN_C      extern "C"
#  else
#    define __LZO_EXTERN_C      extern
#  endif
#endif

/* calling conventions */
#if defined(__LZO_i386) && defined(_MSC_VER)
#    define __LZO_ENTRY         __cdecl
#else
#    define __LZO_ENTRY
#endif


/* DLL export information */
#if !defined(__LZO_EXPORT1)
#  define __LZO_EXPORT1
#endif
#if !defined(__LZO_EXPORT2)
#  define __LZO_EXPORT2
#endif

#if !defined(LZO_PUBLIC)
#  define LZO_PUBLIC(_rettype)  __LZO_EXPORT1 _rettype __LZO_EXPORT2 __LZO_ENTRY
#endif
#if !defined(LZO_EXTERN)
#  define LZO_EXTERN(_rettype)  __LZO_EXTERN_C LZO_PUBLIC(_rettype)
#endif
#if !defined(LZO_PRIVATE)
#  define LZO_PRIVATE(_rettype) static _rettype __LZO_ENTRY
#endif


typedef int
(__LZO_ENTRY *lzo_compress_t)   ( const lzo_byte *src, lzo_uint  src_len,
                                        lzo_byte *dst, lzo_uint *dst_len,
                                        lzo_voidp wrkmem );

typedef int
(__LZO_ENTRY *lzo_decompress_t) ( const lzo_byte *src, lzo_uint  src_len,
                                        lzo_byte *dst, lzo_uint *dst_len,
                                        lzo_voidp wrkmem );

typedef int
(__LZO_ENTRY *lzo_optimize_t)   (       lzo_byte *src, lzo_uint  src_len,
                                        lzo_byte *dst, lzo_uint *dst_len,
                                        lzo_voidp wrkmem );


/* a progress indicator callback function */
typedef void
(__LZO_ENTRY *lzo_progress_callback_t)(lzo_uint,lzo_uint);


/***********************************************************************
// error codes and prototypes
************************************************************************/

/* Error codes for the compression/decompression functions. Negative
 * values are errors, positive values will be used for special but
 * normal events.
 */
#define LZO_E_OK                    0
#define LZO_E_ERROR                 (-1)
#define LZO_E_OUT_OF_MEMORY         (-2)    /* not used right now */
#define LZO_E_NOT_COMPRESSIBLE      (-3)    /* not used right now */
#define LZO_E_INPUT_OVERRUN         (-4)
#define LZO_E_OUTPUT_OVERRUN        (-5)
#define LZO_E_LOOKBEHIND_OVERRUN    (-6)
#define LZO_E_EOF_NOT_FOUND         (-7)
#define LZO_E_INPUT_NOT_CONSUMED    (-8)


/* lzo_init() should be the first function you call.
 * Check the return code !
 *
 * lzo_init() is a macro to allow checking that the library and the
 * compiler's view of various types are consistent.
 */
#define lzo_init() __lzo_init(LZO_VERSION,(int)sizeof(short),(int)sizeof(int),\
    (int)sizeof(long),(int)sizeof(lzo_uint32),(int)sizeof(lzo_uint),\
    (int)sizeof(lzo_voidp),(int)sizeof(lzo_compress_t))
LZO_EXTERN(int) __lzo_init(unsigned,int,int,int,int,int,int,int);

/* version functions (useful for shared libraries) */



/* checksum functions */
LZO_EXTERN(lzo_uint32)
lzo_adler32(lzo_uint32 _adler, const lzo_byte *_buf, lzo_uint _len);


/* misc. */
LZO_EXTERN(int) _lzo_config_check(void);

/* align a char pointer on a boundary that is a multiple of `size' */
LZO_EXTERN(unsigned) __lzo_align_gap(const lzo_voidp _ptr, lzo_uint _size);
#define LZO_ALIGN(_ptr,_size) \
    ((_ptr) + (lzo_uint) __lzo_align_gap((const lzo_voidp)(_ptr),(lzo_uint)(_size)))


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* already included */

