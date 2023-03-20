/*!
 *
 * BOOTDOOR
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Parses the export address table looking
 * for the requested export if it is 
 * available.
 *
!*/
D_SEC( B ) PVOID PeGetFuncEat( PVOID Image, ULONG Hash )
{
	PUINT32			Aon = NULL;
	PUINT32			Aof = NULL;
	PUINT16			Aoo = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	/* Get pointer to images */
	Dos = C_PTR( Image );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	/* Get pointer to EAT */
	if ( Dir->VirtualAddress ) {
		Exp = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );
		Aon = C_PTR( U_PTR( Dos ) + Exp->AddressOfNames );
		Aof = C_PTR( U_PTR( Dos ) + Exp->AddressOfFunctions );
		Aoo = C_PTR( U_PTR( Dos ) + Exp->AddressOfNameOrdinals );

		/* Enumerate exports */
		for ( INT Idx = 0 ; Idx < Exp->NumberOfNames ; ++Idx ) {
			/* Matches our requested export? */
			if ( HashString( C_PTR( U_PTR( Dos ) + Aon[ Idx ] ), 0 ) == Hash ) {
				/* Return! :) */
				return C_PTR( U_PTR( Dos ) + Aof[ Aoo[ Idx ] ] );
			};
		};
	};
	return NULL;
};
