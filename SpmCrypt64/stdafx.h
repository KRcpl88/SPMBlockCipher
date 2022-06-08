// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include <windows.h>
#include "targetver.h"

#include <stdio.h>
#include <memory.h>
#include <tchar.h>
#include <ctime>

// a codebook is a pre-stored initialization state for the sbox which is allready shuffled
// using a codebook can reduce the per stream intialization cost
// the one time cost of creating a codebook is relatively small, its just shuffling an array of short ints



#ifdef _DEBUG
#define DIAGNOSTIC_OUTPUT 1
#define ASSERT(t) {if (!(t)){DebugBreak();}}
#else
#define DIAGNOSTIC_OUTPUT 0
#define ASSERT(t) ;
#endif



// TODO: reference additional headers your program requires here
