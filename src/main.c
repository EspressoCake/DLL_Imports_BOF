#include <windows.h>
#include "headers/beacon.h"
#include "headers/syscalls.h"
#include "headers/userdefs.h"
#include "headers/win32_api.h"


// Forward declaration(s) to make CS happy.
void allocatedBufferOutput(formatp* pFormatPStruct, WINBOOL standardOutput);
void getImportedDLLNamesWin32(char* args, int arglength);
void needleGetImportedDLLNamesWin32(char* args, int arglength);


// Implementations
void allocatedBufferOutput(formatp* pFormatPStruct, WINBOOL standardOutput)
{
    char* outputString = NULL;
    int sizeOfObject   = 0;

    outputString = BeaconFormatToString(pFormatPStruct, &sizeOfObject);

    if ( standardOutput == TRUE )
    {
        BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
    } 
    else 
    {
        BeaconOutput(CALLBACK_ERROR, outputString, sizeOfObject);
    }

    BeaconFormatFree(pFormatPStruct);

    return;
}


void getImportedDLLNamesWin32(char* args, int arglength) 
{
    datap parser;
    formatp formatObject;

    char* fileToCreate = NULL;
    char* filterNeedle = NULL;

    int filterAPINames = 0;

    BeaconDataParse(&parser, args, arglength);
    fileToCreate = BeaconDataExtract(&parser, NULL);
    filterAPINames = BeaconDataInt(&parser);
    filterNeedle = BeaconDataExtract(&parser, NULL);

    BeaconFormatAlloc(&formatObject, 64 * 1024);
    BeaconFormatPrintf(&formatObject, "File inquired: %s\n\n", fileToCreate);

    HANDLE hFile = KERNEL32$CreateFileA(fileToCreate, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if ( hFile == INVALID_HANDLE_VALUE )
    {
        BeaconFormatPrintf(&formatObject, "Error in establishing handle to file: %s\n", fileToCreate);
        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    HANDLE hMappedFile = KERNEL32$CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if ( !hMappedFile )
    {
        BeaconFormatPrintf(&formatObject, "Unsuccessful mapping of file.\n");
        BeaconFormatPrintf(&formatObject, "Closing handle to file: ");
        NtClose(hFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    LPVOID fileMapping = KERNEL32$MapViewOfFile(hMappedFile, FILE_MAP_READ, 0, 0, 0);
    if ( !fileMapping )
    {
        BeaconFormatPrintf(&formatObject, "Unsuccessful map view of file.\n");
        allocatedBufferOutput(&formatObject, FALSE);

        NtClose(hMappedFile);
        NtClose(hFile);

        return;
    }

    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)fileMapping;
    if ( imageDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
    {
        BeaconFormatPrintf(&formatObject, "This does not appear to be a valid PE/COFF file, exiting.\n");

        BeaconFormatPrintf(&formatObject, "Unmapping view of section(s): ");
        KERNEL32$UnmapViewOfFile(fileMapping);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to mapped file: ");
        NtClose(hMappedFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to file: ");
        NtClose(hFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    PIMAGE_NT_HEADERS imageNTHeader = (PIMAGE_NT_HEADERS)(((ULONG_PTR)fileMapping) + imageDosHeader->e_lfanew);
    if ( imageNTHeader->Signature != IMAGE_NT_SIGNATURE )
    {
        BeaconFormatPrintf(&formatObject, "Invalid NT headers discovered.\n");

        BeaconFormatPrintf(&formatObject, "Unmapping view of section(s): ");
        KERNEL32$UnmapViewOfFile(fileMapping);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to mapped file: ");
        NtClose(hMappedFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to file: ");
        NtClose(hFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    IMAGE_DATA_DIRECTORY importDirectory = imageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if ( !importDirectory.VirtualAddress || !importDirectory.Size )
    {
        BeaconFormatPrintf(&formatObject, "No import directory found.\n");

        BeaconFormatPrintf(&formatObject, "Unmapping view of section(s):");
        KERNEL32$UnmapViewOfFile(fileMapping);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to mapped file:");
        NtClose(hMappedFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to file:");
        NtClose(hFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((ULONG_PTR)fileMapping) + importDirectory.VirtualAddress);
    
    if ( !InternalIsBadReadPtr((char*)fileMapping + importDirectory.VirtualAddress) )
    {
        BeaconFormatPrintf(&formatObject, "DLL Import(s):\n");
        for ( ; pImportDescriptor->Name; pImportDescriptor++ )
        {
            if ( !InternalIsBadReadPtr((char*)fileMapping + pImportDescriptor->Name) )
            {
                // Debugging to fix...
                if ( filterAPINames )
                {
                    if ( internalstrncmp((char*)fileMapping + pImportDescriptor->Name, filterNeedle, internalstrlen(filterNeedle)) != 0 )
                    {
                        BeaconFormatPrintf(&formatObject, "\t%s\n", (char*)fileMapping + pImportDescriptor->Name);
                    }
                }
                else
                {
                    BeaconFormatPrintf(&formatObject, "\t%s\n", (char*)fileMapping + pImportDescriptor->Name);
                }
            }
        }
    }    

    // Ensure we cleanup anything we have a handle or mapped view of
    BeaconFormatPrintf(&formatObject, "\nUnmapping view of section(s): ");
    KERNEL32$UnmapViewOfFile(fileMapping);
    BeaconFormatPrintf(&formatObject, "\tDone!\n");

    BeaconFormatPrintf(&formatObject, "Closing handle to mapped file: ");
    NtClose(hMappedFile);
    BeaconFormatPrintf(&formatObject, "\tDone!\n");

    BeaconFormatPrintf(&formatObject, "Closing handle to file: ");
    NtClose(hFile);
    BeaconFormatPrintf(&formatObject, "\t\tDone!\n");

    allocatedBufferOutput(&formatObject, TRUE);

    // Return void
    return;
}


void needleGetImportedDLLNamesWin32(char* args, int arglength) 
{
    datap parser;
    formatp formatObject;

    char* fileToCreate;
    char* dllToHunt;

    BeaconFormatAlloc(&formatObject, 64 * 1024);

    BeaconDataParse(&parser, args, arglength);
    fileToCreate = BeaconDataExtract(&parser, NULL);
    dllToHunt    = BeaconDataExtract(&parser, NULL);

    BeaconFormatPrintf(&formatObject, "File inquired: %s\n", fileToCreate);
    BeaconFormatPrintf(&formatObject, "DLL inquired:  %s\n", dllToHunt);

    HANDLE hFile = KERNEL32$CreateFileA(fileToCreate, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if ( hFile == INVALID_HANDLE_VALUE )
    {
        BeaconFormatPrintf(&formatObject, "Error in establishing handle to file: %s\n", fileToCreate);
        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    HANDLE hMappedFile = KERNEL32$CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if ( !hMappedFile )
    {
        BeaconFormatPrintf(&formatObject, "Unsuccessful mapping of file.\n");
        BeaconFormatPrintf(&formatObject, "Closing handle to file: ");
        NtClose(hFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    LPVOID fileMapping = KERNEL32$MapViewOfFile(hMappedFile, FILE_MAP_READ, 0, 0, 0);
    if ( !fileMapping )
    {
        BeaconFormatPrintf(&formatObject, "Unsuccessful map view of file.\n");
        allocatedBufferOutput(&formatObject, FALSE);

        NtClose(hMappedFile);
        NtClose(hFile);

        return;
    }

    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)fileMapping;
    if ( imageDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
    {
        BeaconFormatPrintf(&formatObject, "This does not appear to be a valid PE/COFF file, exiting.\n");

        BeaconFormatPrintf(&formatObject, "Unmapping view of section(s): ");
        KERNEL32$UnmapViewOfFile(fileMapping);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to mapped file: ");
        NtClose(hMappedFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to file: ");
        NtClose(hFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    PIMAGE_NT_HEADERS imageNTHeader = (PIMAGE_NT_HEADERS)(((ULONG_PTR)fileMapping) + imageDosHeader->e_lfanew);
    if ( imageNTHeader->Signature != IMAGE_NT_SIGNATURE )
    {
        BeaconFormatPrintf(&formatObject, "Invalid NT headers discovered.\n");

        BeaconFormatPrintf(&formatObject, "Unmapping view of section(s): ");
        KERNEL32$UnmapViewOfFile(fileMapping);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to mapped file: ");
        NtClose(hMappedFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to file: ");
        NtClose(hFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    IMAGE_DATA_DIRECTORY importDirectory = imageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if ( !importDirectory.VirtualAddress || !importDirectory.Size )
    {
        BeaconFormatPrintf(&formatObject, "No import directory found.\n");

        BeaconFormatPrintf(&formatObject, "Unmapping view of section(s):");
        KERNEL32$UnmapViewOfFile(fileMapping);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to mapped file:");
        NtClose(hMappedFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        BeaconFormatPrintf(&formatObject, "Closing handle to file:");
        NtClose(hFile);
        BeaconFormatPrintf(&formatObject, "Done.\n");

        allocatedBufferOutput(&formatObject, FALSE);

        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(((ULONG_PTR)fileMapping) + importDirectory.VirtualAddress);
    BOOL foundDesiredImport = FALSE;
    
    if ( !InternalIsBadReadPtr((char*)fileMapping + importDirectory.VirtualAddress) )
    {
        BeaconFormatPrintf(&formatObject, "DLL Import(s):\n");
        for ( ; pImportDescriptor->Name; pImportDescriptor++ )
        {
            if ( !InternalIsBadReadPtr((char*)fileMapping + pImportDescriptor->Name) )
            {
                if ( strCmp((char*)fileMapping + pImportDescriptor->Name, dllToHunt) == 0 )
                {
                    foundDesiredImport = TRUE;

                    // Loop through
                    PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)(((ULONG_PTR)fileMapping) + pImportDescriptor->FirstThunk);
                    for ( ; thunkData->u1.AddressOfData; thunkData++ )
                    {
                        unsigned long long rva  = (ULONG_PTR)thunkData - (ULONG_PTR)fileMapping;
                        unsigned long long data = thunkData->u1.AddressOfData;

                        PIMAGE_IMPORT_BY_NAME importedName = (PIMAGE_IMPORT_BY_NAME)(((ULONG_PTR)fileMapping) + data);

                        if ( !InternalIsBadReadPtr(importedName) )
                        {
                            BeaconFormatPrintf(&formatObject, "\t%s\n", (char*)importedName->Name);
                        }
                    }
                }
            }
        }
    }
    
    // Ensure we cleanup anything we have a handle or mapped view of
    BeaconFormatPrintf(&formatObject, "\nUnmapping view of section(s): ");
    KERNEL32$UnmapViewOfFile(fileMapping);
    BeaconFormatPrintf(&formatObject, "\tDone!\n");

    BeaconFormatPrintf(&formatObject, "Closing handle to mapped file: ");
    NtClose(hMappedFile);
    BeaconFormatPrintf(&formatObject, "\tDone!\n");

    BeaconFormatPrintf(&formatObject, "Closing handle to file: ");
    NtClose(hFile);
    BeaconFormatPrintf(&formatObject, "\t\tDone!\n");

    if ( foundDesiredImport == TRUE )
    {
        allocatedBufferOutput(&formatObject, TRUE);
        return;
    }

    allocatedBufferOutput(&formatObject, FALSE);

    // Return void
    return;
}