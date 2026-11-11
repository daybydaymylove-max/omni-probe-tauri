// SPDX-License-Identifier: Apache-2.0
// Omni-Probe Windows WDM Upper Filter Driver for Serial Ports (COM / USB-CDC)
// 目标平台: Windows 10 / 11 x64 / ARM64 (WDK 10.0.22621+ / 10.0.26100+)
// 功能: 在 Ports 类设备栈 (serial.sys / usbser.sys) 上层透传 IRP，无侵入镜像抓取
//       IRP_MJ_READ、IRP_MJ_WRITE 以及串口控制命令 (BAUD_RATE / DTR / RTS / LCR) 至安全环形缓冲区，
//       并通过控制设备 \Device\OmniSerialFilterControl (\\.\OmniSerialFilter) 供 Omni-Probe 读取。

#include <ntddk.h>
#include <ntddser.h>
#include <wdmsec.h>

#define OMNI_FLT_TAG 'tlFO'
#define OMNI_CONTROL_DEVICE_NAME   L"\\Device\\OmniSerialFilterControl"
#define OMNI_CONTROL_SYMLINK_NAME  L"\\DosDevices\\OmniSerialFilter"

// 自定义 IOCTL 定义 (与 Rust 端 serial_intercept.rs 保持位级一致)
#define FILE_DEVICE_OMNI_SERIAL    0x8310u
#define IOCTL_OMNI_SERIAL_GET_VERSION \
    CTL_CODE(FILE_DEVICE_OMNI_SERIAL, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_OMNI_SERIAL_POLL_EVENTS \
    CTL_CODE(FILE_DEVICE_OMNI_SERIAL, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_OMNI_SERIAL_RESET_RING \
    CTL_CODE(FILE_DEVICE_OMNI_SERIAL, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define OMNI_EVT_READ          1u
#define OMNI_EVT_WRITE         2u
#define OMNI_EVT_IOCTL_BAUD    3u
#define OMNI_EVT_IOCTL_LCR     4u
#define OMNI_EVT_IOCTL_MODEM   5u

#define OMNI_MAX_PAYLOAD_CAPTURE 256u
#define OMNI_RING_CAPACITY       1024u

#pragma pack(push, 1)
typedef struct _OMNI_SERIAL_EVENT {
    ULONGLONG Timestamp100ns;
    ULONG     DeviceIdHash;
    ULONG     EventType;
    ULONG     PayloadLength;
    ULONG     AuxValue;       // 如波特率值、IOCTL_SERIAL 控制掩码
    UCHAR     Payload[OMNI_MAX_PAYLOAD_CAPTURE];
} OMNI_SERIAL_EVENT, *POMNI_SERIAL_EVENT;

typedef struct _OMNI_SERIAL_DRIVER_INFO {
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
    ULONG ActiveFilterDevices;
    ULONGLONG DroppedEvents;
} OMNI_SERIAL_DRIVER_INFO, *POMNI_SERIAL_DRIVER_INFO;
#pragma pack(pop)

typedef struct _OMNI_GLOBAL_STATE {
    PDEVICE_OBJECT    ControlDevice;
    KSPIN_LOCK        RingLock;
    ULONG             WriteIdx;
    ULONG             ReadIdx;
    ULONG             Count;
    LONG              ActiveDeviceCount;
    ULONGLONG         DroppedEvents;
    OMNI_SERIAL_EVENT Ring[OMNI_RING_CAPACITY];
} OMNI_GLOBAL_STATE;

typedef struct _OMNI_DEVICE_EXTENSION {
    BOOLEAN        IsControlDevice;
    PDEVICE_OBJECT LowerDeviceObject;
    ULONG          DeviceIdHash;
    IO_REMOVE_LOCK RemoveLock;
} OMNI_DEVICE_EXTENSION, *POMNI_DEVICE_EXTENSION;

static OMNI_GLOBAL_STATE g_OmniState = { 0 };

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     OmniFltUnload;
DRIVER_ADD_DEVICE OmniFltAddDevice;
DRIVER_DISPATCH   OmniFltDispatchPassThrough;
DRIVER_DISPATCH   OmniFltDispatchRead;
DRIVER_DISPATCH   OmniFltDispatchWrite;
DRIVER_DISPATCH   OmniFltDispatchDeviceControl;
DRIVER_DISPATCH   OmniFltDispatchPnp;
DRIVER_DISPATCH   OmniFltDispatchPower;
IO_COMPLETION_ROUTINE OmniFltReadCompletion;

static VOID OmniPushRingEvent(
    _In_ ULONG DeviceIdHash,
    _In_ ULONG EventType,
    _In_opt_ CONST UCHAR* Buffer,
    _In_ ULONG Length,
    _In_ ULONG AuxValue
) {
    KIRQL oldIrql;
    LARGE_INTEGER sysTime;
    KeQuerySystemTimePrecise(&sysTime);

    KeAcquireSpinLock(&g_OmniState.RingLock, &oldIrql);

    if (g_OmniState.Count >= OMNI_RING_CAPACITY) {
        // 环满丢弃最旧一条保证实时流水不堵塞硬件驱动 IRP
        g_OmniState.ReadIdx = (g_OmniState.ReadIdx + 1) % OMNI_RING_CAPACITY;
        g_OmniState.Count--;
        g_OmniState.DroppedEvents++;
    }

    POMNI_SERIAL_EVENT evt = &g_OmniState.Ring[g_OmniState.WriteIdx];
    evt->Timestamp100ns = (ULONGLONG)sysTime.QuadPart;
    evt->DeviceIdHash = DeviceIdHash;
    evt->EventType = EventType;
    evt->AuxValue = AuxValue;

    ULONG copyLen = (Length > OMNI_MAX_PAYLOAD_CAPTURE) ? OMNI_MAX_PAYLOAD_CAPTURE : Length;
    evt->PayloadLength = Length;
    if (copyLen > 0 && Buffer != NULL) {
        RtlCopyMemory(evt->Payload, Buffer, copyLen);
    }

    g_OmniState.WriteIdx = (g_OmniState.WriteIdx + 1) % OMNI_RING_CAPACITY;
    g_OmniState.Count++;

    KeReleaseSpinLock(&g_OmniState.RingLock, oldIrql);
}

static NTSTATUS OmniHandleControlDeviceIoctl(_In_ PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    if (code == IOCTL_OMNI_SERIAL_GET_VERSION) {
        if (outLen >= sizeof(OMNI_SERIAL_DRIVER_INFO) && sysBuf != NULL) {
            POMNI_SERIAL_DRIVER_INFO drvInfo = (POMNI_SERIAL_DRIVER_INFO)sysBuf;
            drvInfo->MajorVersion = 1;
            drvInfo->MinorVersion = 0;
            drvInfo->BuildNumber = 26100;
            drvInfo->ActiveFilterDevices = (ULONG)InterlockedCompareExchange(&g_OmniState.ActiveDeviceCount, 0, 0);
            drvInfo->DroppedEvents = g_OmniState.DroppedEvents;
            info = sizeof(OMNI_SERIAL_DRIVER_INFO);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    } else if (code == IOCTL_OMNI_SERIAL_POLL_EVENTS) {
        ULONG maxItems = outLen / sizeof(OMNI_SERIAL_EVENT);
        if (maxItems == 0 || sysBuf == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            KIRQL oldIrql;
            ULONG drained = 0;
            POMNI_SERIAL_EVENT dst = (POMNI_SERIAL_EVENT)sysBuf;

            KeAcquireSpinLock(&g_OmniState.RingLock, &oldIrql);
            while (drained < maxItems && g_OmniState.Count > 0) {
                dst[drained] = g_OmniState.Ring[g_OmniState.ReadIdx];
                g_OmniState.ReadIdx = (g_OmniState.ReadIdx + 1) % OMNI_RING_CAPACITY;
                g_OmniState.Count--;
                drained++;
            }
            KeReleaseSpinLock(&g_OmniState.RingLock, oldIrql);

            info = drained * sizeof(OMNI_SERIAL_EVENT);
            status = STATUS_SUCCESS;
        }
    } else if (code == IOCTL_OMNI_SERIAL_RESET_RING) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_OmniState.RingLock, &oldIrql);
        g_OmniState.ReadIdx = 0;
        g_OmniState.WriteIdx = 0;
        g_OmniState.Count = 0;
        g_OmniState.DroppedEvents = 0;
        KeReleaseSpinLock(&g_OmniState.RingLock, oldIrql);
        status = STATUS_SUCCESS;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS OmniFltReadCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_reads_opt_(_Inexpressible_("varies")) PVOID Context
) {
    POMNI_DEVICE_EXTENSION ext = (POMNI_DEVICE_EXTENSION)Context;
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }

    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information > 0 && ext != NULL) {
        CONST UCHAR* dataPtr = NULL;
        ULONG bytesRead = (ULONG)Irp->IoStatus.Information;

        if (Irp->MdlAddress != NULL) {
            dataPtr = (CONST UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
        } else if (Irp->AssociatedIrp.SystemBuffer != NULL) {
            dataPtr = (CONST UCHAR*)Irp->AssociatedIrp.SystemBuffer;
        }

        if (dataPtr != NULL) {
            OmniPushRingEvent(ext->DeviceIdHash, OMNI_EVT_READ, dataPtr, bytesRead, 0);
        }
    }

    if (ext != NULL) {
        IoReleaseRemoveLock(&ext->RemoveLock, Irp);
    }
    UNREFERENCED_PARAMETER(DeviceObject);
    return STATUS_CONTINUE_COMPLETION;
}

NTSTATUS OmniFltDispatchRead(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    POMNI_DEVICE_EXTENSION ext = (POMNI_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext->IsControlDevice) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS lockStatus = IoAcquireRemoveLock(&ext->RemoveLock, Irp);
    if (!NT_SUCCESS(lockStatus)) {
        Irp->IoStatus.Status = lockStatus;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return lockStatus;
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, OmniFltReadCompletion, ext, TRUE, TRUE, TRUE);
    return IoCallDriver(ext->LowerDeviceObject, Irp);
}

NTSTATUS OmniFltDispatchWrite(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    POMNI_DEVICE_EXTENSION ext = (POMNI_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext->IsControlDevice) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG writeLen = irpSp->Parameters.Write.Length;
    if (writeLen > 0) {
        CONST UCHAR* dataPtr = NULL;
        if (Irp->MdlAddress != NULL) {
            dataPtr = (CONST UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
        } else if (Irp->AssociatedIrp.SystemBuffer != NULL) {
            dataPtr = (CONST UCHAR*)Irp->AssociatedIrp.SystemBuffer;
        }
        if (dataPtr != NULL) {
            OmniPushRingEvent(ext->DeviceIdHash, OMNI_EVT_WRITE, dataPtr, writeLen, 0);
        }
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDeviceObject, Irp);
}

NTSTATUS OmniFltDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    POMNI_DEVICE_EXTENSION ext = (POMNI_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext->IsControlDevice) {
        return OmniHandleControlDeviceIoctl(Irp);
    }

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;

    if (code == IOCTL_SERIAL_SET_BAUD_RATE && inLen >= sizeof(SERIAL_BAUD_RATE) && sysBuf != NULL) {
        PSERIAL_BAUD_RATE br = (PSERIAL_BAUD_RATE)sysBuf;
        OmniPushRingEvent(ext->DeviceIdHash, OMNI_EVT_IOCTL_BAUD, NULL, 0, br->BaudRate);
    } else if (code == IOCTL_SERIAL_SET_LINE_CONTROL && inLen >= sizeof(SERIAL_LINE_CONTROL) && sysBuf != NULL) {
        PSERIAL_LINE_CONTROL lc = (PSERIAL_LINE_CONTROL)sysBuf;
        ULONG packed = ((ULONG)lc->WordLength) | (((ULONG)lc->Parity) << 8) | (((ULONG)lc->StopBits) << 16);
        OmniPushRingEvent(ext->DeviceIdHash, OMNI_EVT_IOCTL_LCR, NULL, 0, packed);
    } else if (code == IOCTL_SERIAL_SET_DTR || code == IOCTL_SERIAL_CLR_DTR ||
               code == IOCTL_SERIAL_SET_RTS || code == IOCTL_SERIAL_CLR_RTS) {
        OmniPushRingEvent(ext->DeviceIdHash, OMNI_EVT_IOCTL_MODEM, NULL, 0, code);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDeviceObject, Irp);
}

NTSTATUS OmniFltDispatchPassThrough(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    POMNI_DEVICE_EXTENSION ext = (POMNI_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext->IsControlDevice) {
        PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
        NTSTATUS st = (irpSp->MajorFunction == IRP_MJ_CREATE || irpSp->MajorFunction == IRP_MJ_CLOSE ||
                       irpSp->MajorFunction == IRP_MJ_CLEANUP) ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Status = st;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return st;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDeviceObject, Irp);
}

NTSTATUS OmniFltDispatchPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    POMNI_DEVICE_EXTENSION ext = (POMNI_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext->IsControlDevice) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(ext->LowerDeviceObject, Irp);
}

NTSTATUS OmniFltDispatchPnp(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
    POMNI_DEVICE_EXTENSION ext = (POMNI_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext->IsControlDevice) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;
    if (irpSp->MinorFunction == IRP_MN_REMOVE_DEVICE) {
        IoReleaseRemoveLockAndWait(&ext->RemoveLock, Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(ext->LowerDeviceObject, Irp);
        IoDetachDevice(ext->LowerDeviceObject);
        IoDeleteDevice(DeviceObject);
        InterlockedDecrement(&g_OmniState.ActiveDeviceCount);
        return status;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDeviceObject, Irp);
}

NTSTATUS OmniFltAddDevice(_In_ PDRIVER_OBJECT DriverObject, _In_ PDEVICE_OBJECT PhysicalDeviceObject) {
    PDEVICE_OBJECT filterDevice = NULL;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        sizeof(OMNI_DEVICE_EXTENSION),
        NULL,
        FILE_DEVICE_SERIAL_PORT,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &filterDevice
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    POMNI_DEVICE_EXTENSION ext = (POMNI_DEVICE_EXTENSION)filterDevice->DeviceExtension;
    RtlZeroMemory(ext, sizeof(OMNI_DEVICE_EXTENSION));
    ext->IsControlDevice = FALSE;
    ext->DeviceIdHash = (ULONG)((ULONG_PTR)PhysicalDeviceObject ^ 0x9E3779B9u);
    IoInitializeRemoveLock(&ext->RemoveLock, OMNI_FLT_TAG, 0, 0);

    ext->LowerDeviceObject = IoAttachDeviceToDeviceStack(filterDevice, PhysicalDeviceObject);
    if (ext->LowerDeviceObject == NULL) {
        IoDeleteDevice(filterDevice);
        return STATUS_NO_SUCH_DEVICE;
    }

    filterDevice->Flags |= (ext->LowerDeviceObject->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE));
    filterDevice->DeviceType = ext->LowerDeviceObject->DeviceType;
    filterDevice->Characteristics = ext->LowerDeviceObject->Characteristics;
    filterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    InterlockedIncrement(&g_OmniState.ActiveDeviceCount);
    return STATUS_SUCCESS;
}

VOID OmniFltUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, OMNI_CONTROL_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (g_OmniState.ControlDevice != NULL) {
        IoDeleteDevice(g_OmniState.ControlDevice);
        g_OmniState.ControlDevice = NULL;
    }
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    KeInitializeSpinLock(&g_OmniState.RingLock);

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = OmniFltDispatchPassThrough;
    }
    DriverObject->MajorFunction[IRP_MJ_READ] = OmniFltDispatchRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = OmniFltDispatchWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OmniFltDispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_PNP] = OmniFltDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = OmniFltDispatchPower;
    DriverObject->DriverExtension->AddDevice = OmniFltAddDevice;
    DriverObject->DriverUnload = OmniFltUnload;

    UNICODE_STRING devName, symLink;
    RtlInitUnicodeString(&devName, OMNI_CONTROL_DEVICE_NAME);
    RtlInitUnicodeString(&symLink, OMNI_CONTROL_SYMLINK_NAME);

    // 限制仅 LocalSystem 与 Administrators 可连接 \\.\OmniSerialFilter，遵守内核最小特权原则
    UNICODE_STRING sddl;
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NTSTATUS status = IoCreateDeviceSecure(
        DriverObject,
        sizeof(OMNI_DEVICE_EXTENSION),
        &devName,
        FILE_DEVICE_OMNI_SERIAL,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        NULL,
        &g_OmniState.ControlDevice
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    POMNI_DEVICE_EXTENSION ctlExt = (POMNI_DEVICE_EXTENSION)g_OmniState.ControlDevice->DeviceExtension;
    RtlZeroMemory(ctlExt, sizeof(OMNI_DEVICE_EXTENSION));
    ctlExt->IsControlDevice = TRUE;
    g_OmniState.ControlDevice->Flags |= DO_BUFFERED_IO;
    g_OmniState.ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_OmniState.ControlDevice);
        g_OmniState.ControlDevice = NULL;
    }
    return status;
}
