// ConsoleApplication1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <WinSock2.h>
#include "pch.h"
#include <iostream>
#include <Windows.h>

#include "layerfsd_sdk.h"
#pragma comment(lib , "ws2_32.lib")


int main()
{
    //std::cout << "Hello World!\n";
	//DWORD size; 
	//DWORD dwSizeLow;
	//PVOID pBuffer = new char[50];
	//DWORD realReadbyte;
	//system("pause");
	//const wchar_t* pFile = L"C:\\1111\\121.txt";
	//auto  hfile  = CreateFile(pFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//if(hfile == INVALID_HANDLE_VALUE)
	//{
	//	//方法一，使用Windows API GetFileSizeEx  
	//	dwSizeLow = GetFileSize(hfile, &size);
	//	//auto  nSize1  = size.QuadPart;
	//}
	//std::cout << "size=" << dwSizeLow << std::endl;
	//system("pause");
	//std::cout << "\读取文件测试";
	////CopyFile(pFile, L"C:\\Users\\Wrench\\Desktop\\121.txt",TRUE);
	//::ReadFile(hfile, pBuffer, 10, &realReadbyte, NULL);
	////std::cout <<"pBuffer="<< *pBuffer <<std::endl;
	//printf("pBuffer=%s\r\n", pBuffer);
	//std::cout << "预关闭文件句柄";
	//system("pause");
	//CloseHandle(hfile);
	//system("pause");
	WSAData wsaData;
	int iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
	ClientMain(NULL);
	getchar();
}
