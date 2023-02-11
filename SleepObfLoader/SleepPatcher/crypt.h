#pragma once
#include <Windows.h>

LPBYTE DecryptBlock(LPBYTE lpNewBuffer, DWORD dwBufferSize, DWORD dwTargetKey);