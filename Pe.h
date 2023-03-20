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
 * Parses the export address table looking
 * for the requested export if it is 
 * available.
 *
!*/
D_SEC( B ) PVOID PeGetFuncEat( PVOID Image, ULONG Hash );
