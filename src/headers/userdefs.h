#pragma once

#include <stdbool.h>
#include <windows.h>
#include "win32_api.h"

// Declarations
bool InternalIsBadReadPtr (void* p);
int strCmp (const char* s1, const char* s2);
size_t internalstrlen (const char *str);
int internalstrncmp (const char * s1, const char * s2, size_t n );


// Implementations
bool InternalIsBadReadPtr(void* p)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (KERNEL32$VirtualQuery(p, &mbi, sizeof(mbi)))
    {
        DWORD mask = (PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY);
        bool b = !(mbi.Protect & mask);
        // check the page is not a guard page
        if (mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) 
        {
            b = true;
        }

        return b;
    }
    return true;
}

int strCmp(const char* s1, const char* s2)
{
    while(*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

size_t internalstrlen(const char *str)
{
        const char *s;

        for (s = str; *s; ++s)
                ;
        return (s - str);
}

int internalstrncmp( const char * s1, const char * s2, size_t n )
{
    while ( n && *s1 && ( *s1 == *s2 ) )
    {
        ++s1;
        ++s2;
        --n;
    }
    if ( n == 0 )
    {
        return 0;
    }
    else
    {
        return ( *(unsigned char *)s1 - *(unsigned char *)s2 );
    }
}