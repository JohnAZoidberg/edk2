/** \file
 * LinuxBoot BDS
 *
 * Locates the Linux kernel and initrd on a possible external volume,
 * finds the command line and uses the BootServices->StartImage()
 * to make it go.
 *
 * This allows LinuxBoot to locate the Linux kernel and initrd
 * outside of the normal DXE volume, which is quite small on some
 * systems.
 *
 */
// #define VOLUME_ADDRESS 0xFF840000 // Winterfell
// #define VOLUME_LENGTH  0x20000

#define VOLUME_ADDRESS ((UINTN *)0xFF000000)
#define VOLUME_LENGTH  0x01000000

#include "Serial.h"
#include "EfiDxe.h"
#include "EfiFv.h"

#include <Protocol/LoadedImage.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DxeServicesTableLib.h>

STATIC VOID
hexdump(UINT64 p, UINTN len)
{
  for(UINTN i = 0 ; i < len ; i += 8)
    serial_hex(*(CONST UINT64*)(p+i), 16);
}


STATIC EFI_STATUS
ProcessFv(
  CONST UINT64 *ptr,
  CONST UINTN  len
)
{
  serial_string("FvLoader: adding firmware volume 0x");
  serial_hex((UINT64) ptr, 8);

  EFI_HANDLE handle;
  EFI_STATUS Status = gDS->ProcessFirmwareVolume(
    (VOID *) ptr,
    len,
    &handle
  );

  if (!EFI_ERROR (Status))
  {
    serial_string("FVLoader: mapped 0x");
    serial_hex(len, 8);
  } else {
    serial_string("FvLoader: error rc="); serial_hex(Status, 8);
    hexdump((UINT64) ptr, 128);
  }

  return Status;
}


/*
 * The LinuxBoot kernel is invoked as a DXE driver that registers
 * the BDS (Boot Device Selector) protocol.  Once all of the DXE
 * executables have run, the DxeCore dispatcher will jump into the
 * BDS to choose what kernel to run.
 *
 * In our case, it is this kernel.  So we need to stash the config
 * for when we are re-invoked.
 */
static void EFIAPI
EmptyNotify(void* unused1, void* unused2)
{
  (void) unused1;
  (void) unused2;
}

// TODO: I think this is just like EfiEventGroupSignal from UefiLib
static void
efi_event_signal(
  EFI_GUID guid
)
{
  EFI_STATUS status;
  EFI_EVENT event;

  status = gBS->CreateEventEx(
    EVT_NOTIFY_SIGNAL,
    TPL_CALLBACK,
    EmptyNotify,
    NULL,
    &guid,
    &event
  );
  if (status)
    serial_hex(status, 8);

  status = gBS->SignalEvent(event);
  if (status)
    serial_hex(status, 8);

  status = gBS->CloseEvent(event);
  if (status)
    serial_hex(status, 8);
}


static void
efi_visit_handles(
  EFI_GUID * protocol,
  void (EFIAPI *callback)(EFI_HANDLE, void*),
  void* priv
)
{
  serial_string("efi_visit_handles ");
  serial_hex(protocol ? *(UINT32*) protocol : 0, 8);
  EFI_HANDLE * handle_buffer;
  UINTN handle_count;

  EFI_STATUS status = gBS->LocateHandleBuffer(
    protocol ? ByProtocol : AllHandles,
    protocol,
    NULL,
    &handle_count,
    &handle_buffer
  );
  if (status != 0)
  {
    serial_string("status=");
    serial_hex(status, 8);
    return;
  }

  serial_string("handle_count=");
  serial_hex(handle_count, 8);

  for(UINTN i = 0 ; i < handle_count ; i++)
  {
    //serial_hex((uint64_t) handle_buffer[i], 16);
    callback(handle_buffer[i], priv);
  }
}


static void EFIAPI
efi_connect_controllers(
  EFI_HANDLE handle,
  void * recursive_arg
)
{
  gBS->ConnectController(
    handle,
    NULL, // DriverImageHandle
    NULL, // RemainingDevicePath
    recursive_arg ? 1 : 0
  );
}



static void
efi_final_init(void)
{
  // equivilant to PlatformBootManagerBeforeConsole

  // connect all the pci root bridges
  serial_string("LinuxBoot: connect pci root brdiges\r\n");
  efi_visit_handles(&gEfiPciRootBridgeIoProtocolGuid, efi_connect_controllers, (void*) 0);

  // signal the acpi platform driver that it can download the ACPI tables
  serial_string("LinuxBoot: signal root bridges connected\r\n");
  efi_event_signal(gRootBridgesConnectedEventGroupGuid);

  // signal that dxe is about to end
  serial_string("LinuxBoot: signal dxe end\r\n");
  efi_event_signal(gEfiEndOfDxeEventGroupGuid);

  // Prevent further changes to LockBoxes or SMRAM.
  // This should be a configurable option
  //EFI_HANDLE handle = NULL;
  //EFI_GUID smm_ready_to_lock = gEfiDxeSmmReadyToLockProtocolGuid;
  //serial_string("LinuxBoot: signal smm ready to lock\r\n");

    //serial_string("DEBUG: Here 1\r\n");
  //gBS->InstallProtocolInterface(
  //  &handle,
  //  &smm_ready_to_lock,
  //  EFI_NATIVE_INTERFACE,
  //  NULL
  //);

  // connect all drivers their contorllers
  // this is copied from BmConnectAllDriversToAllControllers()
  // the DXE services table is buried in the configuration
  // table in the system table
/**
  Connect all the drivers to all the controllers.

  This function makes sure all the current system drivers manage the correspoinding
  controllers if have. And at the same time, makes sure all the system controllers
  have driver to manage it if have.
**/
  do {
    efi_visit_handles(NULL, efi_connect_controllers, (void*) 1);
    serial_string("LinuxBoot: bds_main dispatch\r\n");
  } while(gDS->Dispatch() == 0);

  // signal that we're ready to boot, which will
  // cause additional drivers to be loaded
  serial_string("LinuxBoot: signal ready to boot\r\n");
  efi_event_signal(gEfiEventReadyToBootGuid);

}



// code in MdeModulePkg/Library/UefiBootManagerLib/BmBoot.c
static int
linuxboot_start()
{
  EFI_STATUS status;
  EFI_GUID bzimage_guid = { 0xDECAFBAD, 0x6548, 0x6461, { 0x73, 0x2d, 0x2f, 0x2d, 0x4e, 0x45, 0x52, 0x46 }};
  EFI_GUID initrd_guid = { 0x74696e69, 0x6472, 0x632e, { 0x70, 0x69, 0x6f, 0x2f, 0x62, 0x69, 0x6f, 0x73 }};

  void * bzimage_buffer = NULL;
  UINTN bzimage_length = 0;
  serial_string("LinuxBoot: Looking for bzimage\r\n");
  if (read_ffs(gBS, &bzimage_guid, &bzimage_buffer, &bzimage_length, EFI_SECTION_PE32) < 0)
    return -1;

  // convert the RAM image of the kernel into a loaded image
  EFI_HANDLE bzimage_handle = NULL;
  status = gBS->LoadImage(
    TRUE, // Boot
    gImageHandle,
    NULL, // no device path
    bzimage_buffer,
    bzimage_length,
    &bzimage_handle
  );
  if (status != 0)
  {
    serial_string("LinuxBoot: unable to load bzImage image\r\n");
    return -1;
  }
  
  EFI_GUID loaded_image_guid = LOADED_IMAGE_PROTOCOL;
  EFI_LOADED_IMAGE_PROTOCOL * loaded_image = NULL;
  status = gBS->HandleProtocol(
    bzimage_handle,
    &loaded_image_guid,
    (void**) &loaded_image
  );
  if (status != 0)
  {
    serial_string("LinuxBoot: unable to get LoadedImageProtocol\r\n");
    return -1;
  }

  VOID *initrd_buffer = NULL;
  UINTN initrd_length = 0;
  serial_string("LinuxBoot: Looking for initrd\r\n");
  if (read_ffs(gBS, &initrd_guid, &initrd_buffer, &initrd_length, EFI_SECTION_RAW) < 0)
  {
    serial_string("LinuxBoot: no initrd found\r\n");
  } else {
    STATIC CHAR16 cmdline[] = L"found_initd";
    loaded_image->LoadOptions = cmdline;
    loaded_image->LoadOptionsSize = sizeof(cmdline);

    UINTN *hdr = (UINTN *) loaded_image->ImageBase;
    *(UINT32*)(hdr + 0x218) = (UINTN)(UINTN *) initrd_buffer;
    *(UINT32*)(hdr + 0x21c) = (UINTN)(UINTN *) initrd_length;
  }




  // attempt to load the kernel
  UINTN exit_data_len = 0;
  CHAR16 * exit_data = NULL;

  serial_string("LinuxBoot: Starting bzImage\r\n");
  status = gBS->StartImage(
    bzimage_handle,
    &exit_data_len,
    &exit_data
  );
  if (status != 0)
  {
    serial_string("LinuxBoot: Unable to start bzImage\r\n");
    return -1;
  }

  return 0;
}


STATIC EFI_STATUS EFIAPI
EfiBdsMain(void)
{
  serial_string("LinuxBoot: BDS time has arrived\r\n");
  efi_final_init();

  if (linuxboot_start() < 0)
    return 0;

  serial_string("LinuxBoot: SOMETHING IS WRONG\r\n");
  return EFI_NOT_FOUND;
}


STATIC struct
{
  EFI_STATUS (EFIAPI *bds_main)(void);
} efi_bds_arch_protocol;



EFI_STATUS
EFIAPI
LinuxBootEntryPoint(
  IN EFI_HANDLE          ImageHandle,
  IN EFI_SYSTEM_TABLE    *SystemTable
)
{
  serial_string("+--------------------+\r\n");
  serial_string("|                    |\r\n");
  serial_string("| Starting LinuxBoot |\r\n");
  serial_string("|                    |\r\n");
  serial_string("+--------------------+\r\n");

  // update the PCH to map the entire flashchip
  // BIOS_SEL1 and BIOS_SEL2

  // create any new volumes
  if (VOLUME_ADDRESS) {
    ProcessFv(VOLUME_ADDRESS, VOLUME_LENGTH);
  }

  // register the BDS callback
  efi_bds_arch_protocol.bds_main = EfiBdsMain;

  gBS->InstallProtocolInterface(
    &ImageHandle,
    &gEfiBdsArchProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &efi_bds_arch_protocol
  );

  serial_string("LinuxBoot: waiting for BDS callback\r\n");
  return 0;
}
