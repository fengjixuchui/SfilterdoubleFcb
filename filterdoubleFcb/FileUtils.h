#include "WDK.h"

NTSTATUS
IrpIoCompletion(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp,
	IN PVOID  Context
	);

NTSTATUS IrpReadFile(IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN ULONG Flags OPTIONAL,
	OUT ULONG *ReadLength OPTIONAL);

NTSTATUS
IrpWriteFile(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN ULONG Flags OPTIONAL,
	OUT ULONG *WriteLength OPTIONAL);

NTSTATUS
IrpQueryInformationFile(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
	);

NTSTATUS
IrpSetInformationFile(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
	);


NTSTATUS
IrpCloseFileObject(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject);

NTSTATUS
CreateFileByFsDevice(
	OUT PHANDLE FileHandle,
	OUT PFILE_OBJECT *FileObject,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG Disposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength,
	IN PVOID DeviceObject
	);

NTSTATUS GetBackupDriveFsDeviceObject(IN PDEVICE_OBJECT *DeviceObject);

NTSTATUS CreateFileFromBackupDrive(
	OUT PHANDLE FileHandle,
	OUT PFILE_OBJECT  *FileObject OPTIONAL,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	OUT PIO_STATUS_BLOCK  IoStatusBlock,
	IN ULONG  FileAttributes,
	IN ULONG  ShareAccess,
	IN ULONG  Disposition,
	IN ULONG  CreateOptions,
	IN PVOID  EaBuffer OPTIONAL,
	IN ULONG  EaLength
	);



