/**
 * \file
 * EFI Firmware Volume protocol.
 *
 */
#ifndef _efi_fv_h_
#define _efi_fv_h_

#include <Uefi.h>

int
read_ffs(
	EFI_BOOT_SERVICES * gBS,
	EFI_GUID * guid,
	void ** buffer,
	UINTN * size,
	EFI_SECTION_TYPE section_type
);

#endif
