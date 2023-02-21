/** @file
  This protocol provides services to register a platform specific handler for
  ResetSystem() during runtime.  The registered handlers are called after the
  UEFI 2.7 Reset Notifications are processed.

  Copyright (c) Microsoft Corporation
  Copyright (c) 2017 Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _PLATFORM_SPECIFIC_RUNTIME_RESET_HANDLER_PROTOCOL_H_
#define _PLATFORM_SPECIFIC_RUNTIME_RESET_HANDLER_PROTOCOL_H_

#include <Protocol/ResetNotification.h>

#define EDKII_PLATFORM_SPECIFIC_RUNTIME_RESET_HANDLER_PROTOCOL_GUID \
  { 0xe3f10880, 0x7f8f, 0x410a, { 0xa0, 0xc8, 0x86, 0xba, 0x03, 0xcb, 0x45, 0x7d } }

typedef EFI_RESET_NOTIFICATION_PROTOCOL EDKII_PLATFORM_SPECIFIC_RUNTIME_RESET_HANDLER_PROTOCOL;

extern EFI_GUID  gEdkiiPlatformSpecificRuntimeResetHandlerProtocolGuid;

#endif
