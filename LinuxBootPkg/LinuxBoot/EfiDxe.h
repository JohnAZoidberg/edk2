#ifndef __efi_h__
#define __efi_h__

#include <PiDxe.h>

static inline void *
efi_find_table(
	EFI_SYSTEM_TABLE * st,
	UINT32 search_guid
)
{
	const EFI_CONFIGURATION_TABLE * ct = st->ConfigurationTable;

	serial_string("num tables=");
	serial_hex(st->NumberOfTableEntries, 4);

	for(UINTN i = 0 ; i < st->NumberOfTableEntries ; i++)
	{
		const EFI_GUID * guid = &ct[i].VendorGuid;
		serial_hex(*(UINT64*)guid, 16);
		if (guid->Data1 == search_guid)
			return ct[i].VendorTable;

	}

	return NULL;
}

#endif
