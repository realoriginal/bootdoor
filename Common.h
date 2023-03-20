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

#include <windows.h>
#include <intrin.h>
#include "gnu-efi/efi.h"
#include "Native.h"
#include "Config.h"
#include "Macros.h"
#include "Labels.h"
#include "Table.h"
#include "Hash.h"
#include "Pe.h"

#include "OslArchTransferToKernel.h"
#include "SetVirtualAddressMap.h"
#include "ExitBootServices.h"
#include "DrvMain.h"
#include "EfiMain.h"
