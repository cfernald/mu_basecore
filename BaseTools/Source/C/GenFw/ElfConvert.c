/** @file
Elf convert solution

Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __GNUC__
#define RUNTIME_FUNCTION  _WINNT_DUP_RUNTIME_FUNCTION
#include <windows.h>
#undef RUNTIME_FUNCTION
#include <io.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>

#include <Common/UefiBaseTypes.h>
#include <IndustryStandard/PeImage.h>

#include "EfiUtilityMsgs.h"

#include "GenFw.h"
#include "ElfConvert.h"
#include "Elf32Convert.h"
#include "Elf64Convert.h"

//
// Result Coff file in memory.
//
UINT8 *mCoffFile = NULL;

//
// COFF relocation data
//
EFI_IMAGE_BASE_RELOCATION *mCoffBaseRel;
UINT16                    *mCoffEntryRel;

//
// Current offset in coff file.
//
UINT32 mCoffOffset;

//
// Offset in Coff file of headers and sections.
//
UINT32 mTableOffset;

//
//mFileBufferSize
//
UINT32 mFileBufferSize;

//
// String table for long section names
//
CHAR8  *mStringTable = NULL;
UINT32 mStringTableSize = 4; // Starts with 4-byte size field

//
//*****************************************************************************
// Common ELF Functions
//*****************************************************************************
//

VOID
CoffAddFixupEntry(
  UINT16 Val
  )
{
  *mCoffEntryRel = Val;
  mCoffEntryRel++;
  mCoffBaseRel->SizeOfBlock += 2;
  mCoffOffset += 2;
}

VOID
CoffAddFixup(
  UINT32 Offset,
  UINT8  Type
  )
{
  if (mCoffBaseRel == NULL
      || mCoffBaseRel->VirtualAddress != (Offset & ~0xfff)) {
    if (mCoffBaseRel != NULL) {
      //
      // Add a null entry (is it required ?)
      //
      CoffAddFixupEntry (0);

      //
      // Pad for alignment.
      //
      if (mCoffOffset % 4 != 0)
        CoffAddFixupEntry (0);
    }

    mCoffFile = realloc (
      mCoffFile,
      mCoffOffset + sizeof(EFI_IMAGE_BASE_RELOCATION) + 2 * MAX_COFF_ALIGNMENT
      );
    if (mCoffFile == NULL) {
      Error (NULL, 0, 4001, "Resource", "memory cannot be allocated!");
    }
    assert (mCoffFile != NULL);
    memset (
      mCoffFile + mCoffOffset, 0,
      sizeof(EFI_IMAGE_BASE_RELOCATION) + 2 * MAX_COFF_ALIGNMENT
      );

    mCoffBaseRel = (EFI_IMAGE_BASE_RELOCATION*)(mCoffFile + mCoffOffset);
    mCoffBaseRel->VirtualAddress = Offset & ~0xfff;
    mCoffBaseRel->SizeOfBlock = sizeof(EFI_IMAGE_BASE_RELOCATION);

    mCoffEntryRel = (UINT16 *)(mCoffBaseRel + 1);
    mCoffOffset += sizeof(EFI_IMAGE_BASE_RELOCATION);
  }

  //
  // Fill the entry.
  //
  CoffAddFixupEntry((UINT16) ((Type << 12) | (Offset & 0xfff)));
}

VOID
CreateSectionHeader (
  const CHAR8 *Name,
  UINT32      Offset,
  UINT32      Size,
  UINT32      Flags
  )
{
  EFI_IMAGE_SECTION_HEADER *Hdr;
  UINT32                   NameLen;
  UINT32                   StringOffset;
  CHAR8                    *NewStringTable;

  Hdr = (EFI_IMAGE_SECTION_HEADER*)(mCoffFile + mTableOffset);

  NameLen = (UINT32)strlen((const char *)Name);

  //
  // Check if the section name is too long. If so, add it to the string table and redirect.
  //
  if (NameLen > EFI_IMAGE_SIZEOF_SHORT_NAME - 1) {
    //
    // Allocate or expand the string table
    //
    StringOffset = mStringTableSize;
    mStringTableSize += NameLen + 1; // +1 for null terminator

    NewStringTable = (CHAR8 *)realloc(mStringTable, mStringTableSize);
    if (NewStringTable == NULL) {
      Error (NULL, 0, 4001, "Resource", "memory cannot be allocated for string table!");
      return;
    }
    mStringTable = NewStringTable;

    //
    // Copy the long name to the string table
    //
    strcpy(mStringTable + StringOffset, Name);

    //
    // Set the section name to "/offset" format
    // The offset is a decimal string representation
    //
    snprintf((char *)Hdr->Name, EFI_IMAGE_SIZEOF_SHORT_NAME, "/%u", StringOffset);
  } else {
    //
    // Name fits in the section header, copy it directly
    //
    strcpy((char *)Hdr->Name, Name);
  }

  Hdr->Misc.VirtualSize = Size;
  Hdr->VirtualAddress = Offset;
  Hdr->SizeOfRawData = Size;
  Hdr->PointerToRawData = Offset;
  Hdr->PointerToRelocations = 0;
  Hdr->PointerToLinenumbers = 0;
  Hdr->NumberOfRelocations = 0;
  Hdr->NumberOfLinenumbers = 0;
  Hdr->Characteristics = Flags;

  mTableOffset += sizeof (EFI_IMAGE_SECTION_HEADER);
}

UINT32
CoffWriteStringTable (
  VOID
  )
{
  UINT32 StringTableFileOffset;

  if (mStringTable == NULL || mStringTableSize <= 4) {
    //
    // No long section names, no string table needed
    //
    return 0;
  }

  //
  // Align the string table on a 4-byte boundary
  //
  if (mCoffOffset % 4 != 0) {
    UINT32 Padding = 4 - (mCoffOffset % 4);
    mCoffFile = realloc(mCoffFile, mCoffOffset + Padding);
    if (mCoffFile == NULL) {
      Error (NULL, 0, 4001, "Resource", "memory cannot be allocated for string table padding!");
      return 0;
    }
    memset(mCoffFile + mCoffOffset, 0, Padding);
    mCoffOffset += Padding;
  }

  StringTableFileOffset = mCoffOffset;

  //
  // Expand the COFF file to hold the string table
  //
  mCoffFile = realloc(mCoffFile, mCoffOffset + mStringTableSize);
  if (mCoffFile == NULL) {
    Error (NULL, 0, 4001, "Resource", "memory cannot be allocated for string table!");
    return 0;
  }

  //
  // Write the string table size as the first 4 bytes
  //
  *(UINT32 *)(mCoffFile + mCoffOffset) = mStringTableSize;
  mCoffOffset += 4;

  //
  // Copy the string table content (skip the first 4 bytes which are for the size)
  //
  if (mStringTableSize > 4) {
    memcpy(mCoffFile + mCoffOffset, mStringTable + 4, mStringTableSize - 4);
    mCoffOffset += mStringTableSize - 4;
  }

  //
  // Return the file offset where the string table was written.
  // The caller should update PointerToSymbolTable in the PE/COFF header.
  //
  return StringTableFileOffset;
}

//
//*****************************************************************************
// Functions called from GenFw main code.
//*****************************************************************************
//

INTN
IsElfHeader (
  UINT8  *FileBuffer
)
{
  return (FileBuffer[EI_MAG0] == ELFMAG0 &&
          FileBuffer[EI_MAG1] == ELFMAG1 &&
          FileBuffer[EI_MAG2] == ELFMAG2 &&
          FileBuffer[EI_MAG3] == ELFMAG3);
}

BOOLEAN
ConvertElf (
  UINT8  **FileBuffer,
  UINT32 *FileLength
  )
{
  ELF_FUNCTION_TABLE              ElfFunctions;
  UINT8                           EiClass;

  //
  // Initialize string table
  //
  mStringTable = NULL;
  mStringTableSize = 4;

  mFileBufferSize = *FileLength;
  //
  // Determine ELF type and set function table pointer correctly.
  //
  VerboseMsg ("Check Elf Image Header");
  EiClass = (*FileBuffer)[EI_CLASS];
  if (EiClass == ELFCLASS32) {
    if (!InitializeElf32 (*FileBuffer, &ElfFunctions)) {
      return FALSE;
    }
  } else if (EiClass == ELFCLASS64) {
    if (!InitializeElf64 (*FileBuffer, &ElfFunctions)) {
      return FALSE;
    }
  } else {
    Error (NULL, 0, 3000, "Unsupported", "ELF EI_CLASS not supported.");
    return FALSE;
  }

  //
  // Compute sections new address.
  //
  VerboseMsg ("Compute sections new address.");
  ElfFunctions.ScanSections ();

  //
  // Write and relocate sections.
  //
  VerboseMsg ("Write and relocate sections.");
  if (!ElfFunctions.WriteSections (SECTION_TEXT)) {
    return FALSE;
  }
  if (!ElfFunctions.WriteSections (SECTION_DATA)) {
    return FALSE;
  }
  if (!ElfFunctions.WriteSections (SECTION_HII)) {
    return FALSE;
  }
  if (mBuildIdFlag) {
    if (!ElfFunctions.WriteSections (SECTION_BUILD_ID)) {
      return FALSE;
    }
  }

  //
  // Translate and write relocations.
  //
  VerboseMsg ("Translate and write relocations.");
  ElfFunctions.WriteRelocations ();

  //
  // Write debug info.
  //
  VerboseMsg ("Write debug info.");
  ElfFunctions.WriteDebug ();

  //
  // For PRM Driver to Write export info.
  //
  if (mExportFlag) {
    VerboseMsg ("Write export info.");
    ElfFunctions.WriteExport ();
  }

  //
  // Make sure image size is correct before returning the new image.
  //
  VerboseMsg ("Set image size.");
  ElfFunctions.SetImageSize ();

  //
  // Write the string table if needed and update the PE header.
  //
  if (mStringTable != NULL && mStringTableSize > 4) {
    UINT32 StringTableOffset;
    VerboseMsg ("Write string table.");
    StringTableOffset = CoffWriteStringTable ();
    if (StringTableOffset != 0) {
      ElfFunctions.UpdatePeHeaderForStringTable (StringTableOffset);
    }
  }

  //
  // Replace.
  //
  free (*FileBuffer);
  *FileBuffer = mCoffFile;
  *FileLength = mCoffOffset;

  //
  // Free string table resources.
  //
  if (mStringTable != NULL) {
    free (mStringTable);
    mStringTable = NULL;
  }
  mStringTableSize = 4;

  //
  // Free resources used by ELF functions.
  //
  ElfFunctions.CleanUp ();

  return TRUE;
}
