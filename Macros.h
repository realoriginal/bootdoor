/**
 *
 * BOOTDOOR
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#pragma once

/* Gets a pointer to the function or string via its relative offset to GetIp() */
#define G_PTR( x )	( ULONG_PTR )( GetIp( ) - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )

/* Sets a function in a specific region of memory */
#define D_SEC( x )	__attribute__(( section( ".text$" #x ) ))

/* Cast as a pointer with the specified typedef */
#define D_API( x )	__typeof__( x ) * x

/* Cast as a unsigned pointer-wide integer type */
#define U_PTR( x )	( ( ULONG_PTR ) x )

/* Cast as a unsigned pointer-wide type */
#define C_PTR( x )	( ( PVOID ) x )
