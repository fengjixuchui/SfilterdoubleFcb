// layerfsd_sdk.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include  <string>


//使用socket接口与驱动通信
#include "UserSocket.h"

/*********************************************************************
*
* Function    :  data_is_available
*
* Description :  Waits for data to arrive on a socket.
*
* Parameters  :
*          1  :  fd = file descriptor of the socket to read
*          2  :  seconds_to_wait = number of seconds after which we give up.
*
* Returns     :  TRUE if data arrived in time,
*                FALSE otherwise.
*
*********************************************************************/
int data_is_available(SOCKET fd, int seconds_to_wait)
{
	char buf[10];
	fd_set rfds;
	struct timeval timeout;
	int n;

	memset(&timeout, 0, sizeof(timeout));
	timeout.tv_sec = seconds_to_wait;

	FD_ZERO(&rfds);

	FD_SET(fd, &rfds);

	n = select(fd+1, &rfds, NULL, NULL, &timeout);

	return ((n == 1) && (1 == recv(fd, buf, 1, MSG_PEEK)));//MSG_PEEK,并不把读取的数据从TCP buffer中删除，下次recv还能读取到
}


/*********************************************************************
*
* Function    :  read_socket
*
* Description :  Read from a TCP/IP socket in a platform independent way.
*
* Parameters  :
*          1  :  fd = file descriptor of the socket to read
*          2  :  buf = pointer to buffer where data will be written
*                Must be >= len bytes long.
*          3  :  len = maximum number of bytes to read
*
* Returns     :  On success, the number of bytes read is returned (zero
*                indicates end of file), and the file position is advanced
*                by this number.  It is not an error if this number is
*                smaller than the number of bytes requested; this may hap-
*                pen for example because fewer bytes are actually available
*                right now (maybe because we were close to end-of-file, or
*                because we are reading from a pipe, or from a terminal,
*                or because read() was interrupted by a signal).  On error,
*                -1 is returned, and errno is set appropriately.  In this
*                case it is left unspecified whether the file position (if
*                any) changes.
*
*********************************************************************/
int read_socket(SOCKET fd, char *buf, int len)
{
	int ret;

	if (len <= 0)
	{
		return(0);
	}

	ret = recv(fd, buf, len, 0);

	return ret;
}

/*********************************************************************
*
* Function    :  write_socket
*
* Description :  Write the contents of buf (for n bytes) to socket fd.
*
* Parameters  :
*          1  :  fd = file descriptor (aka. handle) of socket to write to.
*          2  :  buf = pointer to data to be written.
*          3  :  len = length of data to be written to the socket "fd".
*
* Returns     :  0 on success (entire buffer sent).
*                nonzero on error.
*
*********************************************************************/

int write_socket(SOCKET fd, const char *buf, size_t len)
{
	if (len == 0)
	{
		return 0;
	}

	return (send(fd, buf, (int)len, 0) != (int)len);
}

//make sure the len bytes transfered completely
BOOL safe_send(SOCKET fd, const char *buf, size_t len)
{
	int ret = 0,result = 0;
	if (len == 0)
	{
		return ret;
	}

	try
	{
		result = send(fd, buf, (int)len, 0);

		while (len-result>0)
		{
			result += send(fd,buf+result,(int)(len-result), 0);
		}

		if (len == result)
		{
			ret = 1;
		}
	}catch(...)
	{

	}

	return ret;
}

