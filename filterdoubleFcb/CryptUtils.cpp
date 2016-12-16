#include "WDK.h"
#include "Struct.h"
#include "Include/CryptBox.h"
#include "RC4.h"
#include "Include/DriverConf.h"
#include "Utils.h"
//#include "Log.h"
#include "CryptUtils.h"

VOID BlockEncrypt(PUCHAR Buffer, ULONG Length, PUCHAR Key, ULONG KeyLength, struct rc4_state *State, INT BlockSize)
{
	ULONG BlockLength;
	while (Length)
	{
		if (Length >= BlockSize)
		{
			BlockLength = BlockSize;
		}
		else {
			BlockLength = Length;
		}

		rc4_setup(State, Key, KeyLength);

		//        DebugTrace(DEBUG_TRACE_SFSSup, ("SFSSup!BlockEncrypt KeyLength = %d, Box = %.2x %.2x %.2x %.2x %.2x %.2x\n", KeyLength, State->m[0], State->m[1], State->m[2], State->m[3], State->m[4], State->m[5]));

		rc4_crypt(State, Buffer, BlockLength);

		Buffer += BlockLength;
		Length -= BlockLength;
	}

}

NTSTATUS DecryptFileBuffer(PUCHAR Buffer, ULONG Length, PIO_CONTEXT IoContext)
{
	NTSTATUS				Status = STATUS_SUCCESS;
	int						Ret;
	unsigned int			DataLen;
	PLARGE_INTEGER			ByteOffset;
	LARGE_INTEGER			Offset;
	USHORT					Align;
	ULONG					Remain;
	PUCHAR					TempBuffer = NULL;
	rc4_state				*RC4State = NULL;
	PFCB					Fcb;
	PENCRYPT_IO				EncryptIo;
	PDEVICE_OBJECT			RealFsDevice;
	PFILE_OBJECT			RealFileObject;
	ULONGLONG				OldOffset;

	if (Length == 0)
	{
		return STATUS_SUCCESS;
	}

	DecodeFileObject(IoContext->FileObject, NULL, &Fcb, NULL);

	EncryptIo = &Fcb->EncryptIo;

	if (!EncryptIo->Encrypt)
	{
		return STATUS_SUCCESS;
	}

	ByteOffset = &IoContext->ByteOffset;
	RealFsDevice = IoContext->RealFsDevice;
	RealFileObject = IoContext->RealFileObject;

	RC4State = (rc4_state*) ExAllocatePoolWithTag(NonPagedPool, sizeof(rc4_state), L'rc4s');
	if (!RC4State)
	{
		//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!DecryptFileBuffer -> ExAllocatePoolWithTag is null.\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	OldOffset = RealFileObject->CurrentByteOffset.QuadPart;

	__try
	{

		Align = ByteOffset->LowPart & 0x1FF;

		Remain = BLOCK_SIZE - Align;
		if (Remain > Length)
		{
			Remain = Length;
		}

		if (ByteOffset->QuadPart < BLOCK_SIZE || Align != 0)
		{
			TempBuffer = (PUCHAR) ExAllocatePoolWithTag(NonPagedPool, BLOCK_SIZE, L'temp');
			if (!TempBuffer)
			{
				//DebugTrace(DEBUG_TRACE_SFSSup | DEBUG_TRACE_ERROR, ("SFSSup!DecryptFileBuffer -> ExAllocatePoolWithTag is null.\n"));
				Status = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			RtlZeroMemory(TempBuffer, BLOCK_SIZE);

			if (ByteOffset->QuadPart < BLOCK_SIZE)
			{
#if 0
				Offset.QuadPart = 0;
				Status = IrpReadFile(RealFsDevice, RealFileObject, TempBuffer, BLOCK_SIZE, &Offset, IRP_PAGING_IO, NULL);
				if (!NT_SUCCESS(Status))
				{
					__leave;
				}
				Ret = DecryptFileHeadSelf(EncryptIo, TempBuffer, BLOCK_SIZE, DataLen);
				if (Ret != ISAFE_STATUS_SUCCESS)
				{
					Status = STATUS_UNSUCCESSFUL;
					__leave;
				}
#endif
				RtlCopyMemory(TempBuffer, EncryptIo->FileHeader, BLOCK_SIZE);

			}
			else
			{
				RtlCopyMemory(TempBuffer + Align, Buffer, Remain);
				BlockEncrypt(TempBuffer, BLOCK_SIZE, EncryptIo->EncryptKey, EncryptIo->KeyLen, RC4State, BLOCK_SIZE);
			}

			RtlCopyMemory(Buffer, TempBuffer + Align, Remain);

			Length -= Remain;
			Buffer += Remain;
		}

		if (Length)
		{
			BlockEncrypt(Buffer, Length, EncryptIo->EncryptKey, EncryptIo->KeyLen, RC4State, BLOCK_SIZE);
		}

	}
	__finally
	{

		if (TempBuffer)
		{
			ExFreePool(TempBuffer);
		}

		if (RC4State)
		{
			ExFreePool(RC4State);
		}

		RealFileObject->CurrentByteOffset.QuadPart = OldOffset;

	}

	return Status;
}
