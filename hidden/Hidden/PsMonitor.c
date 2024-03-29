#include "PsMonitor.h"
#include "ExcludeList.h"
#include "Helper.h"
#include "PsTable.h"
#include "PsRules.h"
#include "Driver.h"
#include "Configs.h"


#define PSMON_ALLOC_TAG 'nMsP'

#define PROCESS_QUERY_LIMITED_INFORMATION      0x1000
#define SYSTEM_PROCESS_ID (HANDLE)4

BOOLEAN g_psMonitorInited = FALSE;
PVOID g_obRegCallback = NULL;

OB_OPERATION_REGISTRATION g_regOperation[2];
OB_CALLBACK_REGISTRATION g_regCallback;

PsRulesContext g_excludeProcessRules;
PsRulesContext g_protectProcessRules;

FAST_MUTEX     g_processTableLock;

typedef struct _ProcessListEntry {
	LPCWSTR path;
	ULONG inherit;
} ProcessListEntry, *PProcessListEntry;

CONST ProcessListEntry g_excludeProcesses[] = {
	{ NULL, PsRuleTypeWithoutInherit }
};


CONST ProcessListEntry g_protectProcesses[] = {
	{ NULL, PsRuleTypeWithoutInherit }
};

#define CSRSS_PAHT_BUFFER_SIZE 256

UNICODE_STRING g_csrssPath;
WCHAR          g_csrssPathBuffer[CSRSS_PAHT_BUFFER_SIZE];

BOOLEAN CheckProtectedOperation(HANDLE Source, HANDLE Destination)
{
	ProcessTableEntry srcInfo, destInfo;
	BOOLEAN result;

	if (Source == Destination)
		return FALSE;

	srcInfo.processId = Source;
	
	ExAcquireFastMutex(&g_processTableLock);
	result = GetProcessInProcessTable(&srcInfo);
	ExReleaseFastMutex(&g_processTableLock);
	
	if (!result)
		return FALSE;

	destInfo.processId = Destination;

	ExAcquireFastMutex(&g_processTableLock);

	if (!GetProcessInProcessTable(&destInfo))
	{
		ExReleaseFastMutex(&g_processTableLock);
		return FALSE;
	}

	
	if (!destInfo.inited)
	{
		result = TRUE;

		
		if (srcInfo.subsystem)
		{
			destInfo.inited = TRUE;
			if (!UpdateProcessInProcessTable(&destInfo))
				result = FALSE;
		}

		ExReleaseFastMutex(&g_processTableLock);

		if (!result)
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata: %p\n", destInfo.processId);

		return FALSE;
	}

	ExReleaseFastMutex(&g_processTableLock);

	if (!destInfo.protected)
		return FALSE;

	if (srcInfo.protected)
		return FALSE;

	if (srcInfo.subsystem)
		return FALSE;
	
	return TRUE;
}

OB_PREOP_CALLBACK_STATUS ProcessPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	
	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS ThreadPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (!IsDriverEnabled())
		return OB_PREOP_SUCCESS;

	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;

	DbgPrint("FsFilter1!" __FUNCTION__ ": hata: %p(%p:%p), Oper: %s, Space: %s\n",
		PsGetThreadId(OperationInformation->Object), PsGetCurrentProcessId(), PsGetCurrentThreadId(),
		(OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ? "create" : "dup"),
		(OperationInformation->KernelHandle ? "kernel" : "user")
	);

	if (!CheckProtectedOperation(PsGetCurrentProcessId(), PsGetProcessId(OperationInformation->Object)))
	{
		return OB_PREOP_SUCCESS;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": hata %p\n", PsGetCurrentProcessId());

	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
	else
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);

	return OB_PREOP_SUCCESS;
}

VOID CheckProcessFlags(PProcessTableEntry Entry, PCUNICODE_STRING ImgPath, HANDLE ParentId)
{
	ProcessTableEntry lookup;
	ULONG inheritType;
	BOOLEAN result;

	RtlZeroMemory(&lookup, sizeof(lookup));

	Entry->inited = (!g_psMonitorInited ? TRUE : FALSE);
	if (Entry->processId == (HANDLE)4)
		Entry->subsystem = TRUE;
	else
		Entry->subsystem = RtlEqualUnicodeString(&g_csrssPath, ImgPath, TRUE);

	
	Entry->excluded = FALSE;
	Entry->inheritExclusion = PsRuleTypeWithoutInherit;

	if (FindInheritanceInPsRuleList(g_excludeProcessRules, ImgPath, &inheritType))
	{
		Entry->excluded = TRUE;
		Entry->inheritExclusion = inheritType;
	}
	else if (ParentId != 0)
	{
		lookup.processId = ParentId;

		ExAcquireFastMutex(&g_processTableLock);
		result = GetProcessInProcessTable(&lookup);
		ExReleaseFastMutex(&g_processTableLock);

		if (result)
		{
			if (lookup.inheritExclusion == PsRuleTypeInherit)
			{
				Entry->excluded = TRUE;
				Entry->inheritExclusion = PsRuleTypeInherit;
			}
			else if (lookup.inheritExclusion == PsRuleTypeInheritOnce)
			{
				Entry->excluded = TRUE;
				Entry->inheritExclusion = PsRuleTypeWithoutInherit;
			}
		}
	}

	

	Entry->protected = FALSE;
	Entry->inheritProtection = PsRuleTypeWithoutInherit;

	if (FindInheritanceInPsRuleList(g_protectProcessRules, ImgPath, &inheritType))
	{
		Entry->protected = TRUE;
		Entry->inheritProtection = inheritType;
	}
	else if (ParentId != 0)
	{
		lookup.processId = ParentId;

		ExAcquireFastMutex(&g_processTableLock);
		result = GetProcessInProcessTable(&lookup);
		ExReleaseFastMutex(&g_processTableLock);

		if (result)
		{
			if (lookup.inheritProtection == PsRuleTypeInherit)
			{
				Entry->protected = TRUE;
				Entry->inheritProtection = PsRuleTypeInherit;
			}
			else if (lookup.inheritProtection == PsRuleTypeInheritOnce)
			{
				Entry->protected = TRUE;
				Entry->inheritProtection = PsRuleTypeWithoutInherit;
			}
		}
	}
}

VOID CreateProcessNotifyCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	ProcessTableEntry entry;
	BOOLEAN result;

	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo)
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata: %p (%p:%p), %wZ\n", ProcessId, PsGetCurrentProcessId(), PsGetCurrentThreadId(), CreateInfo->ImageFileName);
	else
		DbgPrint("FsFilter1!" __FUNCTION__ ":hata: %p (%p:%p)\n", ProcessId, PsGetCurrentProcessId(), PsGetCurrentThreadId());

	RtlZeroMemory(&entry, sizeof(entry));
	entry.processId = ProcessId;

	if (CreateInfo)
	{
		const USHORT maxBufSize = CreateInfo->ImageFileName->Length + NORMALIZE_INCREAMENT;
		UNICODE_STRING normalized;
		NTSTATUS status;

		normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, PSMON_ALLOC_TAG);
		normalized.Length = 0;
		normalized.MaximumLength = maxBufSize;

		if (!normalized.Buffer)
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata\n");
			return;
		}

		status = NormalizeDevicePath(CreateInfo->ImageFileName, &normalized);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x, path:%wZ\n", status, CreateInfo->ImageFileName);
			ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
			return;
		}

		CheckProcessFlags(&entry, &normalized, PsGetCurrentProcessId()/*CreateInfo->ParentProcessId*/);

		if (entry.excluded)
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%p\n", ProcessId);

		if (entry.protected)
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%p\n", ProcessId);

		ExAcquireFastMutex(&g_processTableLock);
		result = AddProcessToProcessTable(&entry);
		ExReleaseFastMutex(&g_processTableLock);

		if (!result)
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata\n", ProcessId);

		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
	}
	else
	{
		ExAcquireFastMutex(&g_processTableLock);
		result = RemoveProcessFromProcessTable(&entry);
		ExReleaseFastMutex(&g_processTableLock);

		if (!result)
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata\n", ProcessId);
	}

}

BOOLEAN IsProcessExcluded(HANDLE ProcessId)
{
	ProcessTableEntry entry;
	BOOLEAN result;

	
	if (ProcessId == (HANDLE)4)
		return TRUE;

	entry.processId = ProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	result = GetProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);

	if (!result)
		return FALSE;

	
	return ((entry.excluded || ProcessId == (HANDLE)4) ? TRUE : FALSE);
}

BOOLEAN IsProcessProtected(HANDLE ProcessId)
{
	ProcessTableEntry entry;
	BOOLEAN result;

	entry.processId = ProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	result = GetProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);

	if (!result)
		return FALSE;

	return entry.protected;
}

NTSTATUS ParsePsConfigEntry(PUNICODE_STRING Entry, PUNICODE_STRING Path, PULONG Inherit)
{
	USHORT inx, length = Entry->Length / sizeof(WCHAR);
	LPWSTR str = Entry->Buffer;
	UNICODE_STRING command, template;

	RtlZeroMemory(&command, sizeof(command));

	for (inx = 0; inx < length; inx++)
	{
		if (str[inx] == L';')
		{
			command.Buffer = str + inx + 1;
			command.Length = (length - inx - 1) * sizeof(WCHAR);
			command.MaximumLength = command.Length;
			break;
		}
	}

	if (inx == 0)
		return STATUS_NO_DATA_DETECTED;

	Path->Buffer = Entry->Buffer;
	Path->Length = inx * sizeof(WCHAR);
	Path->MaximumLength = Path->Length;

	RtlInitUnicodeString(&template, L"none");
	if (RtlCompareUnicodeString(&command, &template, TRUE) == 0)
	{
		*Inherit = PsRuleTypeWithoutInherit;
		return STATUS_SUCCESS;
	}

	RtlInitUnicodeString(&template, L"always");
	if (RtlCompareUnicodeString(&command, &template, TRUE) == 0)
	{
		*Inherit = PsRuleTypeInherit;
		return STATUS_SUCCESS;
	}

	RtlInitUnicodeString(&template, L"once");
	if (RtlCompareUnicodeString(&command, &template, TRUE) == 0)
	{
		*Inherit = PsRuleTypeInheritOnce;
		return STATUS_SUCCESS;
	}

	return STATUS_NOT_FOUND;
}

VOID LoadProtectedRulesCallback(PUNICODE_STRING Str, PVOID Params)
{
	UNICODE_STRING path;
	ULONG inherit;
	PsRuleEntryId ruleId;

	UNREFERENCED_PARAMETER(Params);

	if (NT_SUCCESS(ParsePsConfigEntry(Str, &path, &inherit)))
		AddProtectedImage(&path, inherit, FALSE, &ruleId);
}

VOID LoadIgnoredRulesCallback(PUNICODE_STRING Str, PVOID Params)
{
	UNICODE_STRING path;
	ULONG inherit;
	PsRuleEntryId ruleId;

	UNREFERENCED_PARAMETER(Params);

	if (NT_SUCCESS(ParsePsConfigEntry(Str, &path, &inherit)))
		AddExcludedImage(&path, inherit, FALSE, &ruleId);
}

NTSTATUS InitializePsMonitor(PDRIVER_OBJECT DriverObject)
{
	const USHORT maxBufSize = 512;
	NTSTATUS status;
	UNICODE_STRING str, normalized, csrss;
	UINT32 i;
	PsRuleEntryId ruleId;

	UNREFERENCED_PARAMETER(DriverObject);

	

	RtlZeroMemory(g_csrssPathBuffer, sizeof(g_csrssPathBuffer));
	g_csrssPath.Buffer = g_csrssPathBuffer;
	g_csrssPath.Length = 0;
	g_csrssPath.MaximumLength = sizeof(g_csrssPathBuffer);

	RtlInitUnicodeString(&csrss, L"\\SystemRoot\\System32\\csrss.exe");
	status = NormalizeDevicePath(&csrss, &g_csrssPath);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);
		return status;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": hata: %wZ\n", &g_csrssPath);

	

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, maxBufSize, PSMON_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;
	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hatad\n");
		return STATUS_ACCESS_DENIED;
	}

	

	status = InitializePsRuleListContext(&g_excludeProcessRules);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	for (i = 0; g_excludeProcesses[i].path; i++)
	{
		RtlInitUnicodeString(&str, g_excludeProcesses[i].path);

		status = NormalizeDevicePath(&str, &normalized);
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata %wZ\n", &normalized);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x, path:%wZ\n", status, &str);
			continue;
		}

		AddRuleToPsRuleList(g_excludeProcessRules, &normalized, g_excludeProcesses[i].inherit, &ruleId);
	}

	// Load entries from the config
	CfgEnumConfigsTable(IgnoreImagesTable, &LoadIgnoredRulesCallback, NULL);

	// protected

	status = InitializePsRuleListContext(&g_protectProcessRules);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ":hata:%08x\n", status);
		DestroyPsRuleListContext(g_excludeProcessRules);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	for (i = 0; g_protectProcesses[i].path; i++)
	{
		RtlInitUnicodeString(&str, g_protectProcesses[i].path);

		status = NormalizeDevicePath(&str, &normalized);
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata%wZ\n", &normalized);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata%wZ\n", status, &str);
			continue;
		}

		AddRuleToPsRuleList(g_protectProcessRules, &normalized, g_protectProcesses[i].inherit, &ruleId);
	}

	// Load entries from the config
	CfgEnumConfigsTable(ProtectImagesTable, &LoadProtectedRulesCallback, NULL);

	// Process table

	ExInitializeFastMutex(&g_processTableLock);

	status = InitializeProcessTable(CheckProcessFlags);
	if (!NT_SUCCESS(status))
	{
		DestroyPsRuleListContext(g_excludeProcessRules);
		DestroyPsRuleListContext(g_protectProcessRules);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);

	g_psMonitorInited = TRUE;

	

	g_regOperation[0].ObjectType = PsProcessType;
	g_regOperation[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	g_regOperation[0].PreOperation = ProcessPreCallback;
	g_regOperation[0].PostOperation = NULL;

	g_regOperation[1].ObjectType = PsThreadType;
	g_regOperation[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	g_regOperation[1].PreOperation = ThreadPreCallback;
	g_regOperation[1].PostOperation = NULL;

	g_regCallback.Version = OB_FLT_REGISTRATION_VERSION;
	g_regCallback.OperationRegistrationCount = 2;
	g_regCallback.RegistrationContext = NULL;
	g_regCallback.OperationRegistration = g_regOperation;
	RtlInitUnicodeString(&g_regCallback.Altitude, L"1000");

	status = ObRegisterCallbacks(&g_regCallback, &g_obRegCallback);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);
		DestroyPsMonitor();
		return status;
	}

	// Register rocess create\destroy callback

	status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);
		DestroyPsMonitor();
		return status;
	}

	return status;
}

NTSTATUS DestroyPsMonitor()
{
	if (!g_psMonitorInited)
		return STATUS_ALREADY_DISCONNECTED;

	if (g_obRegCallback)
	{
		ObUnRegisterCallbacks(g_obRegCallback);
		g_obRegCallback = NULL;
	}

	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, TRUE);

	DestroyPsRuleListContext(g_excludeProcessRules);
	DestroyPsRuleListContext(g_protectProcessRules);

	ExAcquireFastMutex(&g_processTableLock);
	DestroyProcessTable();
	ExReleaseFastMutex(&g_processTableLock);

	g_psMonitorInited = FALSE;

	return STATUS_SUCCESS;
}

NTSTATUS SetStateForProcessesByImage(PCUNICODE_STRING ImagePath, BOOLEAN Excluded, BOOLEAN Protected)
{
	PSYSTEM_PROCESS_INFORMATION processInfo = NULL, first;
	SIZE_T size = 0, offset;
	NTSTATUS status;

	status = QuerySystemInformation(SystemProcessInformation, &processInfo, &size);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);
		return status;
	}

	offset = 0;
	first = processInfo;
	do
	{
		HANDLE hProcess;
		CLIENT_ID clientId;
		OBJECT_ATTRIBUTES attribs;
		PUNICODE_STRING procName;
		ProcessTableEntry entry;

		processInfo = (PSYSTEM_PROCESS_INFORMATION)((SIZE_T)processInfo + offset);

		if (processInfo->ProcessId == 0)
		{
			offset = processInfo->NextEntryOffset;
			continue;
		}

		InitializeObjectAttributes(&attribs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		clientId.UniqueProcess = processInfo->ProcessId;
		clientId.UniqueThread = 0;

		status = ZwOpenProcess(&hProcess, 0x1000/*PROCESS_QUERY_LIMITED_INFORMATION*/, &attribs, &clientId);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		status = QueryProcessInformation(ProcessImageFileName, hProcess, &procName, &size);
		ZwClose(hProcess);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", processInfo->ProcessId, status);
			offset = processInfo->NextEntryOffset;
			continue;
		}

		entry.processId = processInfo->ProcessId;
		if (RtlCompareUnicodeString(procName, ImagePath, TRUE) == 0)
		{
			BOOLEAN result = TRUE;

			
			ExAcquireFastMutex(&g_processTableLock);
			
			if (GetProcessInProcessTable(&entry))
			{
				if (Excluded)
				{
					entry.excluded = TRUE;
					entry.inheritExclusion = PsRuleTypeWithoutInherit;
				}

				if (Protected)
				{
					entry.protected = TRUE;
					entry.inheritProtection = PsRuleTypeWithoutInherit;
				}

				if (!UpdateProcessInProcessTable(&entry))
					result = FALSE;
			}

			ExReleaseFastMutex(&g_processTableLock);

			if (!result)
				DbgPrint("FsFilter1!" __FUNCTION__ ": hata %p\n", processInfo->ProcessId);
		}

		FreeInformation(procName);
		offset = processInfo->NextEntryOffset;
	} while (offset);

	FreeInformation(first);
	return STATUS_SUCCESS;
}

NTSTATUS AddProtectedImage(PUNICODE_STRING ImagePath, ULONG InheritType, BOOLEAN ApplyForProcesses, PULONGLONG ObjId)
{
	const USHORT maxBufSize = ImagePath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, PSMON_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(ImagePath, &normalized);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x, path:%wZ\n", status, ImagePath);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": hata: %wZ\n", &normalized);
	status = AddRuleToPsRuleList(g_protectProcessRules, &normalized, InheritType, ObjId);

	if (ApplyForProcesses)
		SetStateForProcessesByImage(&normalized, FALSE, TRUE);

	ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);

	return status;
}

NTSTATUS GetProtectedProcessState(HANDLE ProcessId, PULONG InheritType, PBOOLEAN Enable)
{
	ProcessTableEntry entry;
	BOOLEAN result;

	entry.processId = ProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	result = GetProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);

	if (!result)
		return STATUS_NOT_FOUND;

	*Enable = entry.protected;
	*InheritType = entry.inheritProtection;

	return STATUS_SUCCESS;
}

NTSTATUS SetProtectedProcessState(HANDLE ProcessId, ULONG InheritType, BOOLEAN Enable)
{
	NTSTATUS status = STATUS_SUCCESS;
	ProcessTableEntry entry;
	BOOLEAN result;

	entry.processId = ProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	result = GetProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);

	if (!result)
		return STATUS_NOT_FOUND;

	if (Enable)
	{
		entry.protected = TRUE;
		entry.inheritProtection = InheritType;
	}
	else
	{
		entry.protected = FALSE;
	}

	ExAcquireFastMutex(&g_processTableLock);
	result = UpdateProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);

	if (!result)
		return STATUS_NOT_FOUND;

	return status;
}

NTSTATUS RemoveProtectedImage(ULONGLONG ObjId)
{
	return RemoveRuleFromPsRuleList(g_protectProcessRules, ObjId);
}

NTSTATUS RemoveAllProtectedImages()
{
	return RemoveAllRulesFromPsRuleList(g_protectProcessRules);
}

NTSTATUS AddExcludedImage(PUNICODE_STRING ImagePath, ULONG InheritType, BOOLEAN ApplyForProcesses, PULONGLONG ObjId)
{
	const USHORT maxBufSize = ImagePath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, PSMON_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ":hata\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(ImagePath, &normalized);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x, path:%wZ\n", status, ImagePath);
		ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);
		return status;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": hata: %wZ\n", &normalized);
	status = AddRuleToPsRuleList(g_excludeProcessRules, &normalized, InheritType, ObjId);

	if (ApplyForProcesses)
		SetStateForProcessesByImage(&normalized, TRUE, FALSE);

	ExFreePoolWithTag(normalized.Buffer, PSMON_ALLOC_TAG);

	return status;
}

NTSTATUS GetExcludedProcessState(HANDLE ProcessId, PULONG InheritType, PBOOLEAN Enable)
{
	ProcessTableEntry entry;
	BOOLEAN result;

	entry.processId = ProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	result = GetProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);

	if (!result)
		return STATUS_NOT_FOUND;

	*Enable = entry.excluded;
	*InheritType = entry.inheritExclusion;

	return STATUS_SUCCESS;
}

NTSTATUS SetExcludedProcessState(HANDLE ProcessId, ULONG InheritType, BOOLEAN Enable)
{
	NTSTATUS status = STATUS_SUCCESS;
	ProcessTableEntry entry;
	BOOLEAN result;

	entry.processId = ProcessId;

	ExAcquireFastMutex(&g_processTableLock);
	result = GetProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);

	if (!result)
		return STATUS_NOT_FOUND;

	if (Enable)
	{
		entry.excluded = TRUE;
		entry.inheritExclusion = InheritType;
	}
	else
	{
		entry.excluded = FALSE;
	}

	ExAcquireFastMutex(&g_processTableLock);
	result = UpdateProcessInProcessTable(&entry);
	ExReleaseFastMutex(&g_processTableLock);

	if (!result)
		return STATUS_NOT_FOUND;

	return status;
}

NTSTATUS RemoveExcludedImage(ULONGLONG ObjId)
{
	return RemoveRuleFromPsRuleList(g_excludeProcessRules, ObjId);
}

NTSTATUS RemoveAllExcludedImages()
{
	return RemoveAllRulesFromPsRuleList(g_excludeProcessRules);
}
