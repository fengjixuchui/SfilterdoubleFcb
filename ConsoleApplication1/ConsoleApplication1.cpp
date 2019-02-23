// ConsoleApplication1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>

#include <Windows.h>


int main()
{
    //std::cout << "Hello World!\n";
	DWORD size; 
	DWORD dwSizeLow;
	PVOID pBuffer = new char[50];
	DWORD realReadbyte;
	system("pause");
	const wchar_t* pFile = L"C:\\1111\\121.txt";
	auto  hfile  = CreateFile(pFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hfile == INVALID_HANDLE_VALUE)
	{
		//方法一，使用Windows API GetFileSizeEx  
		dwSizeLow = GetFileSize(hfile, &size);
		//auto  nSize1  = size.QuadPart;
	}
	std::cout << "size=" << dwSizeLow << std::endl;
	system("pause");
	std::cout << "\读取文件测试";
	//CopyFile(pFile, L"C:\\Users\\Wrench\\Desktop\\121.txt",TRUE);
	::ReadFile(hfile, pBuffer, 10, &realReadbyte, NULL);
	//std::cout <<"pBuffer="<< *pBuffer <<std::endl;
	printf("pBuffer=%s\r\n", pBuffer);
	std::cout << "预关闭文件句柄";
	system("pause");
	CloseHandle(hfile);
	system("pause");
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
