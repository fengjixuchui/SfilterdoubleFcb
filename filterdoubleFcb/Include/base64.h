#ifndef __BASE64_H__
#define __BASE64_H__

enum {BASE64_OK = 0, BASE64_INVALID};

#define BASE64_ENCODE_OUT_SIZE(s)	(((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s)	(((s)) / 4 * 3)
#ifdef __cplusplus 
extern "C" {
#endif
	/*
	* 带补位符的base64编码
	* end为0不置字符串末尾\0
	*/
	int	base64_encode_with_pad(const unsigned char *in, unsigned int inlen, char *out, int end);

	/*
	* 不带补位符的base64编码
	* end为0不置字符串末尾\0
	*/
	int	base64_encode(const unsigned char *in, unsigned int inlen, char *out, int end);

	/*
	* end为0不置字符串末尾\0
	*/
	int	base64_decode(const char *in, unsigned int inlen, unsigned char *out, int end);

	/*
	* 计算不带补位符的base64解码后的长度
	*/
	int base64_decode_count(int encode_size);

	/*
	* 计算不带补位符的base64编码后的长度
	*/
	int base64_encode_count(int decode_size);

	/*
	* 计算带补位符的base64编码后的长度
	*/
	int base64_encode_count_with_pad(int decode_size);
#ifdef __cplusplus 
}
#endif
#endif /* __BASE64_H__ */

