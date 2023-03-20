/*!
 *
 * BOOTDOOR
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Creates a hash summary of the input buffer.
 * If a length is not provided, it assumes it
 * is NULL terminated.
 *
!*/

D_SEC( B ) UINT32 HashString( PVOID Buffer, ULONG Length );
