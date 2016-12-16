#ifndef _MD5_H_
#define _MD5_H_

#pragma pack(push, 1)

typedef struct _md5_context{
    ULONG total[2];
    ULONG state[4];
    UCHAR buffer[64];
}md5_context;

#pragma pack(pop)


#ifdef __cplusplus
extern "C" {
#endif

void md5_starts( md5_context *ctx);
void md5_update( md5_context *ctx, UCHAR *input, ULONG length );
void md5_finish( md5_context *ctx, UCHAR digest[16] );


//Get  MD5 value[16 bytes] of a string
void GetMD5Value(IN UCHAR *pBuffer, IN ULONG Length,OUT UCHAR *MD5Value);


#ifdef __cplusplus
}
#endif

#endif // _MD5_H


