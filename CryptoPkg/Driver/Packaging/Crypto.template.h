/** @file
  This Protocol provides Crypto services to DXE modules

  Copyright (C) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __EDKII_CRYPTO_PROTOCOL_H__
#define __EDKII_CRYPTO_PROTOCOL_H__

#include <Base.h>
#include <Library/BaseCryptLib.h>
#include <Library/PcdLib.h>

///
/// The version of the EDK II Crypto Protocol.
/// As APIs are added to BaseCryptLib, the EDK II Crypto Protocol is extended
/// with new APIs at the end of the EDK II Crypto Protocol structure.  Each time
/// the EDK II Crypto Protocol is extended, this version define must be
/// increased.
///
#define EDKII_CRYPTO_VERSION  10// MU_CHANGE

///
/// EDK II Crypto Protocol forward declaration
///
typedef struct _EDKII_CRYPTO_PROTOCOL EDKII_CRYPTO_PROTOCOL;

/**
  Returns the version of the EDK II Crypto Protocol.

  @return  The version of the EDK II Crypto Protocol.

**/
typedef
UINTN
(EFIAPI *EDKII_CRYPTO_GET_VERSION)(
  VOID
  );

// MU_CHANGE START
< !--REPLACEMENT-- >
// MU_CHANGE END

extern GUID gEdkiiCryptoProtocolGuid;

#endif
