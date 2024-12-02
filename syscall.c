#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread.h"
#include "filesystem.h"
#include "io.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

typedef struct _SYSCALL_ENABLER {
    BOOLEAN                 SyscallsDisabled;
    LOCK                    EnableLock;
} SYSCALL_ENABLER;

static SYSCALL_ENABLER SyscallEnabler; //pentru a verifica daca syscall urile sunt sau nu activate in kernel

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE* CompleteProcessorState
)
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;

        case SyscallIdFileWrite:
            status = SyscallFileWrite((UM_HANDLE)pSyscallParameters[0], (PVOID)pSyscallParameters[1], (QWORD)pSyscallParameters[2], (QWORD*)pSyscallParameters[3]);
            break;
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)pSyscallParameters);
            break;
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)pSyscallParameters);
            break;

            //proiect 2
        case SyscallIdFileClose:
            status = SyscallFileClose((UM_HANDLE)pSyscallParameters[0]);
            break;

        case SyscallIdProcessGetPid:
            status = SyscallProcessGetPid((UM_HANDLE)pSyscallParameters[0], (PID*)pSyscallParameters[1]);
            break;

        case SyscallIdProcessCreate:
            status = SyscallProcessCreate(
                (char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (char*)pSyscallParameters[2],
                (QWORD)pSyscallParameters[3],
                (UM_HANDLE*)pSyscallParameters[4]
            );
            break;

        case SyscallIdFileCreate:
            status = SyscallFileCreate((char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (BOOLEAN)pSyscallParameters[2],
                (BOOLEAN)pSyscallParameters[3],
                (UM_HANDLE*)pSyscallParameters[4]);
            break;

            // STUDENT TODO: implement the rest of the syscalls
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

//proiect 2

BOOLEAN
AreSyscallsDisabled(
) {
    INTR_STATE oldState;
    BOOLEAN d;

    LockAcquire(&SyscallEnabler.EnableLock, &oldState);
    d = SyscallEnabler.SyscallsDisabled;
    LockRelease(&SyscallEnabler.EnableLock, oldState);
    return d;
}

STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)
    char* ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength)
    char* Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE* ProcessHandle
) {

    if (AreSyscallsDisabled()) {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS status = STATUS_SUCCESS;

    if (ProcessHandle == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (ProcessPath == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MmuIsBufferValid((PVOID)ProcessPath, PathLength, PAGE_RIGHTS_READ, GetCurrentProcess());
    if (!SUCCEEDED(status))
    {
        return status;
    }

    if (Arguments != NULL) {
        status = MmuIsBufferValid((PVOID)Arguments, ArgLength, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            return status;
        }
    }

    char Path[MAX_PATH];
    const char* SystemDrive = IomuGetSystemPartitionPath();
    snprintf(Path, MAX_PATH, "%s%s\\%s", SystemDrive, "APPLICATIONS", ProcessPath);

    PPROCESS newProcess = NULL;
    if (ArgLength > 0) {
        status = ProcessCreate(Path, Arguments, &newProcess);
    }
    else {
        status = ProcessCreate(Path, NULL, &newProcess);
    }
    if (!SUCCEEDED(status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (newProcess == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    INTR_STATE oldState;
    PPROCESS currentProcess = GetCurrentProcess();
    if (currentProcess == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    LockAcquire(&currentProcess->ChildProcessesListLock, &oldState);
    InsertTailList(&currentProcess->ChildProcessesList, &newProcess->ChildProcess);
    LockRelease(&currentProcess->ChildProcessesListLock, oldState);
    newProcess->ParentProcess = currentProcess;
    *ProcessHandle = newProcess->Id;
    return status;
}

STATUS
SyscallFileCreate(
    char* Path,
    QWORD PathLength,
    BOOLEAN Directory,
    BOOLEAN Create,
    UM_HANDLE* FileHandle
)
{
    PFILE_OBJECT fileObject;
    PFILE_ENTRY fileEntry;
    STATUS status;
    PPROCESS currentProcess;

    if (Path == NULL || PathLength == 0 || FileHandle == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    status = MmuIsBufferValid(Path, PathLength, PAGE_RIGHTS_READ, GetCurrentProcess());
    if (!SUCCEEDED(status)) {
        return STATUS_INVALID_POINTER;
    }
    status = MmuIsBufferValid(FileHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_WRITE, GetCurrentProcess());
    if (!SUCCEEDED(status)) {
        return STATUS_INVALID_BUFFER;
    }

    if (Path[0] == '\0') {
        return STATUS_PATH_NOT_VALID;
    }

    status = IoCreateFile(&fileObject, Path, Directory, Create, FALSE);
    if (!SUCCEEDED(status)) {
        if (status == STATUS_FILE_NOT_FOUND) {
            return STATUS_FILE_NOT_FOUND;
        }
        else if (status == STATUS_FILE_ALREADY_EXISTS) {
            return STATUS_FILE_ALREADY_EXISTS;
        }
        else if (status == STATUS_PATH_NOT_VALID) {
            return STATUS_PATH_NOT_VALID;
        }
        else {
            return STATUS_UNSUCCESSFUL;
        }
    }

    *FileHandle = (UM_HANDLE)fileObject;
    fileEntry = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(FILE_ENTRY), HEAP_TEST_TAG, 0);
    if (fileEntry == NULL) {
        IoCloseFile(fileObject);
        return STATUS_HEAP_NO_MORE_MEMORY;
    }
    fileEntry->Handle = *FileHandle;
    fileEntry->FileObject = fileObject;
    currentProcess = GetCurrentProcess();

    INTR_STATE oldState;
    LockAcquire(&currentProcess->ThreadListLock, &oldState);
    InsertTailList(&currentProcess->FilesList, &fileEntry->ListEntry);
    LockRelease(&currentProcess->ThreadListLock, oldState);

    return STATUS_SUCCESS;
}

STATUS
SyscallFileClose(
    UM_HANDLE FileHandle
)
{
    STATUS status;
    PPROCESS currentProcess;
    PFILE_ENTRY fileEntry;
    LIST_ITERATOR iterator;
    PLIST_ENTRY listEntry;

    if (FileHandle == NULL || FileHandle < (UM_HANDLE)0x1000) {
        return STATUS_INVALID_PARAMETER1;
    }

    currentProcess = GetCurrentProcess();
    if (currentProcess == NULL) {
        return STATUS_INTERNAL_ERROR;
    }

    ListIteratorInit(&currentProcess->FilesList, &iterator);

    while ((listEntry = ListIteratorNext(&iterator)) != NULL) {
        fileEntry = CONTAINING_RECORD(listEntry, FILE_ENTRY, ListEntry);
        if (fileEntry->Handle == FileHandle) {
            RemoveEntryList(&fileEntry->ListEntry);
            status = IoCloseFile(fileEntry->FileObject);
            if (!SUCCEEDED(status)) {
                return status;
            }
            ExFreePoolWithTag(fileEntry, HEAP_TEST_TAG);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_FILE_NOT_FOUND;
}

STATUS
SyscallProcessExit(
    IN  STATUS                      ExitStatus
)
{
    PPROCESS Process = GetCurrentProcess();
    Process->TerminationStatus = ExitStatus;
    ProcessTerminate(Process);

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessGetPid(
    IN_OPT  UM_HANDLE               ProcessHandle,
    OUT     PID* ProcessId
)
{
    if (ProcessHandle == UM_INVALID_HANDLE_VALUE)
    {
        *ProcessId = GetCurrentProcess()->Id;
        return STATUS_SUCCESS;
    }
    *ProcessId = ((PPROCESS)ProcessHandle)->Id;
    return STATUS_SUCCESS;
}


void
SyscallPreinitSystem(
    void
)
{

}

STATUS
SyscallInitSystem(
    void
)
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
)
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
)
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD)SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD)SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                           Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    UNREFERENCED_PARAMETER(FileHandle);
    UNREFERENCED_PARAMETER(BytesToWrite);
    UNREFERENCED_PARAMETER(BytesWritten);
    LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);
    *BytesWritten = BytesToWrite;
    return STATUS_SUCCESS;
}

STATUS
SyscallThreadExit(
    IN  STATUS                      ExitStatus
)
{
    if (AreSyscallsDisabled()) {
        return STATUS_UNSUCCESSFUL;
    }

    ThreadExit(ExitStatus);
    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls