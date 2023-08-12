/*
Pattern.hpp - From "Image Injection" project

AlSch092 @ github

*/

#pragma once
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <Psapi.h>

BOOL Check(const BYTE* pData, const BYTE* bMask, const char* szMask);
UINT64 FindPattern(BYTE *bMask, char* szMask, UINT64 dwOffset, UINT64 dwStartAddress);
UINT64 FindRemotePattern(const unsigned char* pattern, int length, const wchar_t* procName);