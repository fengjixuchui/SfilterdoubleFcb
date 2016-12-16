#ifndef __LZO_H__
#define __LZO_H__


#include "lzoconf.h"

#ifdef __cplusplus
extern "C" {
#endif


/***********************************************************************
//
************************************************************************/

#define LZO1X_MEM_COMPRESS      ((lzo_uint) (16384L * sizeof(lzo_byte *)))
#define LZO1X_MEM_DECOMPRESS    (0)


/* compression
dst_len only be used as a return value
*/
LZO_EXTERN(int)
lzo1x_compress        ( const lzo_byte *src, lzo_uint  src_len,
                                lzo_byte *dst, lzo_uint *dst_len,
                                lzo_voidp wrkmem );

/* decompression 
 dst_len will be used in both input and output for boundary check
 Input:  the length of *dst buffer
 Output: the length of decompess data
*/

LZO_EXTERN(int)
lzo1x_decompress        ( const lzo_byte *src, lzo_uint  src_len,
                                lzo_byte *dst, lzo_uint *dst_len,
                                lzo_voidp wrkmem /* NOT USED */ );


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* already included */

