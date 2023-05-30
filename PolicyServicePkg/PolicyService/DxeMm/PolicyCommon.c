/** @file
  Common function implementations for storing and finding policies for the DXE/MM
  policy service modules.

  Copyright (c) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PolicyCommon.h"
#include "PolicyInterface.h"

LIST_ENTRY  mPolicyListHead = INITIALIZE_LIST_HEAD_VARIABLE (mPolicyListHead);
LIST_ENTRY  mNotifyListHead = INITIALIZE_LIST_HEAD_VARIABLE (mNotifyListHead);

//
// Global state for the potentially recursive notify routine.
//

BOOLEAN  mNotifyInProgress = FALSE;
BOOLEAN  mCallbacksDeleted = FALSE;

/**
  Retrieves the policy descriptor, buffer, and size for a given policy GUID.
  Assumes the caller is already in CS.

  @param[in]      PolicyGuid        The GUID of the policy being retrieved.
  @param[out]     PolicyDescriptor  Descriptor for the stored policy.
  @param[out]     Policy            The buffer where the policy data is copied.
  @param[in,out]  PolicySize        The size of the stored policy data buffer.
                                    On output, contains the size of the stored policy.

  @retval   EFI_SUCCESS           The policy was retrieved.
  @retval   EFI_BUFFER_TOO_SMALL  The provided buffer size was too small.
  @retval   EFI_NOT_FOUND         The policy does not exist.
**/
EFI_STATUS
EFIAPI
GetPolicyEntry (
  IN CONST EFI_GUID  *PolicyGuid,
  OUT POLICY_ENTRY   **PolicyEntry
  )
{
  LIST_ENTRY    *Link;
  POLICY_ENTRY  *CheckEntry;

  BASE_LIST_FOR_EACH (Link, &mPolicyListHead) {
    CheckEntry = POLICY_ENTRY_FROM_LINK (Link);
    if (CompareGuid (PolicyGuid, &CheckEntry->PolicyGuid)) {
      *PolicyEntry = CheckEntry;
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Checks if a given policy exists in the policy store. Assumes the caller
  is already in CS.

  @param[in]  PolicyGuid      The policy GUID to match.

  @retval   TRUE              The policy exists in the store.
  @retval   FALSE             The policy does not exists in the store.
**/
BOOLEAN
EFIAPI
CheckPolicyExists (
  IN CONST EFI_GUID  *PolicyGuid
  )
{
  POLICY_ENTRY  *Entry;

  return !EFI_ERROR (GetPolicyEntry (PolicyGuid, &Entry));
}

/**
  Retrieves the policy descriptor, buffer, and size for a given policy GUID.

  @param[in]      PolicyGuid        The GUID of the policy being retrieved.
  @param[out]     Attributes        The attributes of the stored policy.
  @param[out]     Policy            The buffer where the policy data is copied.
  @param[in,out]  PolicySize        The size of the stored policy data buffer.
                                    On output, contains the size of the stored policy.

  @retval   EFI_SUCCESS           The policy was retrieved.
  @retval   EFI_BUFFER_TOO_SMALL  The provided buffer size was too small.
  @retval   EFI_NOT_FOUND         The policy does not exist.
**/
EFI_STATUS
EFIAPI
CommonGetPolicy (
  IN CONST EFI_GUID  *PolicyGuid,
  OUT UINT64         *Attributes OPTIONAL,
  OUT VOID           *Policy,
  IN OUT UINT16      *PolicySize
  )
{
  EFI_STATUS    Status;
  POLICY_ENTRY  *Entry;

  if ((PolicyGuid == NULL) ||
      (PolicySize == NULL) ||
      ((Policy == NULL) && (*PolicySize != 0)))
  {
    return EFI_INVALID_PARAMETER;
  }

  PolicyLockAcquire ();
  Status = GetPolicyEntry (PolicyGuid, &Entry);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  if (Attributes != NULL) {
    *Attributes = Entry->Attributes;
  }

  if (*PolicySize < Entry->PolicySize) {
    *PolicySize = Entry->PolicySize;
    Status      = EFI_BUFFER_TOO_SMALL;
    goto Exit;
  }

  CopyMem (Policy, Entry->Policy, Entry->PolicySize);
  *PolicySize = Entry->PolicySize;

Exit:
  PolicyLockRelease ();
  return Status;
}

/**
  Parses the HOB list to find active policies to add to the policy store.

  @retval   EFI_SUCCESS           Policies added to the policy store.
  @retval   EFI_OUT_OF_RESOURCES  Failed to allocate memory for policy.
**/
EFI_STATUS
EFIAPI
IngestPoliciesFromHob (
  VOID
  )
{
  EFI_HOB_GUID_TYPE  *GuidHob;
  POLICY_HOB_HEADER  *PolicyHob;
  POLICY_ENTRY       *PolicyEntry;
  UINT32             PolicyCount;
  EFI_STATUS         Status;

  PolicyCount = 0;
  Status      = EFI_SUCCESS;
  PolicyLockAcquire ();
  for (GuidHob = GetFirstGuidHob (&gPolicyHobGuid);
       GuidHob != NULL;
       GuidHob = GetNextGuidHob (&gPolicyHobGuid, GET_NEXT_HOB (GuidHob)))
  {
    PolicyHob = (POLICY_HOB_HEADER *)GET_GUID_HOB_DATA (GuidHob);
    if (PolicyHob->Removed) {
      continue;
    }

    if (PolicyHob->Attributes & POLICY_ATTRIBUTE_PEI_ONLY) {
      continue;
    }

    ASSERT (!CheckPolicyExists (&PolicyHob->PolicyGuid));

    PolicyEntry = AllocatePool (sizeof (POLICY_ENTRY));
    if (PolicyEntry == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      break;
    }

    ZeroMem (PolicyEntry, sizeof (POLICY_ENTRY));
    PolicyEntry->Signature      = POLICY_ENTRY_SIGNATURE;
    PolicyEntry->PolicyGuid     = PolicyHob->PolicyGuid;
    PolicyEntry->FromHob        = TRUE;
    PolicyEntry->Attributes     = PolicyHob->Attributes;
    PolicyEntry->Policy         = GET_HOB_POLICY_DATA (PolicyHob);
    PolicyEntry->PolicySize     = PolicyHob->PolicySize;
    PolicyEntry->AllocationSize = 0;
    InsertTailList (&mPolicyListHead, &PolicyEntry->Link);
    PolicyCount++;

    Status = InstallPolicyIndicatorProtocol (&PolicyEntry->PolicyGuid);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a: Failed to install notification protocol. (%r)\n", __FUNCTION__, Status));
    }
  }

  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Found %d active policies in HOBs.\n", PolicyCount));
  }

  PolicyLockRelease ();
  return Status;
}

/**
  Removes a policy from the policy store. The policy will be removed from the store
  and freed if possible.

  @param[in]  PolicyGuid        The GUID of the policy being retrieved.

  @retval   EFI_SUCCESS         The policy was removed.
  @retval   EFI_NOT_FOUND       The policy does not exist.
**/
EFI_STATUS
EFIAPI
CommonRemovePolicy (
  IN CONST EFI_GUID  *PolicyGuid
  )
{
  EFI_STATUS    Status;
  POLICY_ENTRY  *Entry;

  if (PolicyGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  PolicyLockAcquire ();
  Status = GetPolicyEntry (PolicyGuid, &Entry);
  if (!EFI_ERROR (Status)) {
    RemoveEntryList (&Entry->Link);
    if (!Entry->FromHob) {
      FreePool (Entry->Policy);
    }

    Entry->FreeAfterNotify = TRUE;
    CommonPolicyNotify (POLICY_NOTIFY_REMOVED, Entry);
  }

  PolicyLockRelease ();
  return Status;
}

/**
  Creates or updates a policy in the policy store. Will notify any applicable
  callbacks.

  @param[in]  PolicyGuid          The uniquely identifying GUID for the policy.
  @param[in]  Attributes          Attributes of the policy to be set.
  @param[in]  Policy              The policy data buffer. This buffer will be
                                  copied into the data store.
  @param[in]  PolicySize          The size of the provided policy data.

  @retval   EFI_SUCCESS           Policy was created or updated.
  @retval   EFI_ACCESS_DENIED     Policy was already finalized prior to this call.
  @retval   EFI_OUT_OF_RESOURCES  Failed to allocate space for policy structures.
**/
EFI_STATUS
EFIAPI
CommonSetPolicy (
  IN CONST EFI_GUID  *PolicyGuid,
  IN UINT64          Attributes,
  IN VOID            *Policy,
  IN UINT16          PolicySize
  )
{
  EFI_STATUS    Status;
  POLICY_ENTRY  *Entry;
  VOID          *AllocatedPolicy;
  UINT32        Events;

  if ((PolicyGuid == NULL) || (Policy == NULL) || (PolicySize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  PolicyLockAcquire ();
  Status = GetPolicyEntry (PolicyGuid, &Entry);
  if (!EFI_ERROR (Status)) {
    if (Entry->Attributes & POLICY_ATTRIBUTE_FINALIZED) {
      Status = EFI_ACCESS_DENIED;
      goto Exit;
    }

    // Re-use the buffer if possible
    if (!Entry->FromHob && (PolicySize <= Entry->AllocationSize)) {
      CopyMem (Entry->Policy, Policy, PolicySize);
      Entry->PolicySize = PolicySize;
      Entry->Attributes = Attributes;
    } else {
      AllocatedPolicy = AllocatePool (PolicySize);
      if (AllocatedPolicy == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto Exit;
      }

      CopyMem (AllocatedPolicy, Policy, PolicySize);
      if (!Entry->FromHob) {
        FreePool (Entry->Policy);
      }

      Entry->Policy         = AllocatedPolicy;
      Entry->Attributes     = Attributes;
      Entry->PolicySize     = PolicySize;
      Entry->AllocationSize = PolicySize;
      Entry->FromHob        = FALSE;
    }
  } else {
    Entry = AllocatePool (sizeof (POLICY_ENTRY));
    if (Entry == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Exit;
    }

    AllocatedPolicy = AllocatePool (PolicySize);
    if (AllocatedPolicy == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Exit;
    }

    ZeroMem (Entry, sizeof (POLICY_ENTRY));
    Entry->Signature      = POLICY_ENTRY_SIGNATURE;
    Entry->PolicyGuid     = *PolicyGuid;
    Entry->Attributes     = Attributes;
    Entry->Policy         = AllocatedPolicy;
    Entry->PolicySize     = PolicySize;
    Entry->AllocationSize = PolicySize;
    CopyMem (Entry->Policy, Policy, PolicySize);
    InsertTailList (&mPolicyListHead, &Entry->Link);
  }

  Events = POLICY_NOTIFY_SET | (Entry->Attributes & POLICY_ATTRIBUTE_FINALIZED ? POLICY_NOTIFY_FINALIZED : 0);
  CommonPolicyNotify (Events, Entry);

  Status = InstallPolicyIndicatorProtocol (PolicyGuid);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to install notification protocol. (%r)\n", __FUNCTION__, Status));
    goto Exit;
  }

Exit:
  PolicyLockRelease ();
  return Status;
}

EFI_STATUS
EFIAPI
CommonRegisterNotify (
  IN CONST EFI_GUID           *PolicyGuid,
  IN CONST UINT32             EventTypes,
  IN CONST UINT32             Priority,
  IN POLICY_HANDLER_CALLBACK  CallbackRoutine,
  OUT VOID                    **Handle
  )
{
  LIST_ENTRY           *Link;
  POLICY_NOTIFY_ENTRY  *CheckEntry;
  POLICY_NOTIFY_ENTRY  *Entry;

  if ((CallbackRoutine == NULL) ||
      ((EventTypes & POLICY_NOTIFY_ALL) != EventTypes))
  {
    return EFI_INVALID_PARAMETER;
  }

  Entry = AllocatePool (sizeof (POLICY_NOTIFY_ENTRY));
  if (Entry == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem (Entry, sizeof (POLICY_NOTIFY_ENTRY));
  Entry->Signature       = POLICY_NOTIFY_ENTRY_SIGNATURE;
  Entry->PolicyGuid      = *PolicyGuid;
  Entry->EventTypes      = EventTypes;
  Entry->Priority        = Priority;
  Entry->CallbackRoutine = CallbackRoutine;

  //
  // Find the entry to insert this new entry before. If the list is empty then
  // this is the head.
  //

  BASE_LIST_FOR_EACH (Link, &mNotifyListHead) {
    CheckEntry = POLICY_NOTIFY_ENTRY_FROM_LINK (Link);
    if (CheckEntry->Priority > Priority) {
      break;
    }
  }

  InsertTailList (Link, &Entry->Link);
  *Handle = (VOID *)Entry;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CommonUnregisterNotify (
  IN VOID  *Handle
  )
{
  POLICY_NOTIFY_ENTRY  *Entry;

  Entry = (POLICY_NOTIFY_ENTRY *)Handle;
  if (Entry->Signature != POLICY_NOTIFY_ENTRY_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  if (!IsNodeInList (&mNotifyListHead, &Entry->Link)) {
    ASSERT (FALSE);
    return EFI_NOT_FOUND;
  }

  //
  // If this entry is the entry that currently being processed, step the entry
  // forward.
  //
  if (mNotifyInProgress) {
    Entry->Tombstone  = TRUE;
    mCallbacksDeleted = TRUE;
  } else {
    RemoveEntryList (&Entry->Link);
    FreePool (Entry);
  }

  return EFI_SUCCESS;
}

VOID
EFIAPI
CommonPolicyNotify (
  IN CONST UINT32  EventTypes,
  IN POLICY_ENTRY  *PolicyEntry
  )
{
  LIST_ENTRY           *Link;
  POLICY_NOTIFY_ENTRY  *NotifyEntry;
  BOOLEAN              FirstNotification;
  UINT32               Depth;

  //
  // Global recursion handling.
  //

  FirstNotification = !mNotifyInProgress;
  mNotifyInProgress = TRUE;

  //
  // Per-policy recursion handling.
  //

  ASSERT (PolicyEntry->NotifyDepth < MAX_UINT32);
  PolicyEntry->NotifyDepth++;
  Depth = PolicyEntry->NotifyDepth;

  BASE_LIST_FOR_EACH (Link, &mNotifyListHead) {
    NotifyEntry = POLICY_NOTIFY_ENTRY_FROM_LINK (Link);
    if (CompareGuid (&PolicyEntry->PolicyGuid, &NotifyEntry->PolicyGuid) &&
        ((EventTypes & NotifyEntry->EventTypes) != 0) &&
        !NotifyEntry->Tombstone)
    {
      NotifyEntry->CallbackRoutine (&PolicyEntry->PolicyGuid, EventTypes, NotifyEntry);

      //
      // If there was a newer notify then this notification is now moot.
      //

      if (PolicyEntry->NotifyDepth != Depth) {
        break;
      }
    }
  }

  //
  // If this is the top of the stack for the policy then clear that depth and
  // free in the case that the policy was removed during the callbacks.
  //

  if (Depth == 1) {
    PolicyEntry->NotifyDepth = 0;
    if (PolicyEntry->FreeAfterNotify) {
      FreePool (PolicyEntry);
      PolicyEntry = NULL;
    }
  }

  //
  // To simplify potential link list edge cases with the recursion, removed
  // callbacks that occur during the recursion are only tomb-stoned, if this
  // is the top of the stack then go through and remove those.
  //

  if (FirstNotification) {
    if (mCallbacksDeleted) {
      BASE_LIST_FOR_EACH (Link, &mNotifyListHead) {
        NotifyEntry = POLICY_NOTIFY_ENTRY_FROM_LINK (Link);
        if (NotifyEntry->Tombstone) {
          Link = Link->BackLink;
          RemoveEntryList (&NotifyEntry->Link);
          FreePool (NotifyEntry);
        }
      }

      mCallbacksDeleted = FALSE;
    }

    mNotifyInProgress = FALSE;
  }
}
