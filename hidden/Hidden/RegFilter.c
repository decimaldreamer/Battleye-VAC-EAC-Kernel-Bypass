

#include "RegFilter.h"
#include "ExcludeList.h"
#include "PsMonitor.h"
#include "Configs.h"
#include "Driver.h"
#include <Ntstrsafe.h>

#define FILTER_ALLOC_TAG 'FRlF'

BOOLEAN g_regFilterInited = FALSE;

ExcludeContext g_excludeRegKeyContext;
ExcludeContext g_excludeRegValueContext;


CONST PWCHAR g_excludeRegKeys[] = {
	NULL
};


CONST PWCHAR g_excludeRegValues[] = {
	NULL
};

LARGE_INTEGER g_regCookie = { 0 };

BOOLEAN CheckRegistryKeyInExcludeList(PVOID RootObject, PUNICODE_STRING keyPath)
{
	PCUNICODE_STRING regPath;
	NTSTATUS status;
	BOOLEAN found = FALSE;

	

	if (keyPath->Length > sizeof(WCHAR) && keyPath->Buffer[0] == L'\\')
	{
		
		found = CheckExcludeListRegKey(g_excludeRegKeyContext, keyPath);
	}
	else
	{
		
		enum { LOCAL_BUF_SIZE = 256 };
		WCHAR localBuffer[LOCAL_BUF_SIZE];
		LPWSTR dynBuffer = NULL;
		UNICODE_STRING fullRegPath;
		USHORT totalSize;

		

		status = CmCallbackGetKeyObjectID(&g_regCookie, RootObject, NULL, &regPath);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": Registry name query failed with code:%08x\n", status);
			return FALSE;
		}

		

		totalSize = regPath->Length + keyPath->Length + sizeof(WCHAR);
		if (totalSize / sizeof(WCHAR) > LOCAL_BUF_SIZE)
		{
			
			dynBuffer = (LPWSTR)ExAllocatePoolWithTag(NonPagedPool, totalSize, FILTER_ALLOC_TAG);
			if (!dynBuffer)
			{
				DbgPrint("FsFilter1!" __FUNCTION__ ": Memory allocation failed with code:%08x\n", status);
				return FALSE;
			}

			memcpy(dynBuffer, regPath->Buffer, regPath->Length);
			fullRegPath.Buffer = dynBuffer;
		}
		else
		{
			
			fullRegPath.Buffer = localBuffer;
		}

		
		memcpy(fullRegPath.Buffer, regPath->Buffer, regPath->Length);
		fullRegPath.Buffer[regPath->Length / sizeof(WCHAR)] = L'\\';
		memcpy(
			(PCHAR)fullRegPath.Buffer + regPath->Length + sizeof(WCHAR),
			keyPath->Buffer,
			keyPath->Length);

		fullRegPath.Length = totalSize;
		fullRegPath.MaximumLength = fullRegPath.Length;

		
		found = CheckExcludeListRegKey(g_excludeRegKeyContext, &fullRegPath);

		if (dynBuffer)
			ExFreePoolWithTag(dynBuffer, FILTER_ALLOC_TAG);
	}

	return found;
}

NTSTATUS RegPreCreateKey(PVOID context, PREG_PRE_CREATE_KEY_INFORMATION info)
{
	UNREFERENCED_PARAMETER(context);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		
		return STATUS_SUCCESS;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ":hata %wZ\n", info->CompleteName);

	if (CheckExcludeListRegKey(g_excludeRegKeyContext, info->CompleteName))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata!\n");
		return STATUS_ACCESS_DENIED;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPreCreateKeyEx(PVOID context, PREG_CREATE_KEY_INFORMATION info)
{
	UNREFERENCED_PARAMETER(context);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		
		return STATUS_SUCCESS;
	}

	if (CheckRegistryKeyInExcludeList(info->RootObject, info->CompleteName))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": found!\n");
		return STATUS_ACCESS_DENIED;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPreOpenKey(PVOID context, PREG_PRE_OPEN_KEY_INFORMATION info)
{
	UNREFERENCED_PARAMETER(context);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		
		return STATUS_SUCCESS;
	}

	DbgPrint("FsFilter1!" __FUNCTION__ ": RegPreCreateKey(absolute) %wZ\n", info->CompleteName);

	if (CheckExcludeListRegKey(g_excludeRegKeyContext, info->CompleteName))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": bulundu!\n");
		return STATUS_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPreOpenKeyEx(PVOID context, PREG_OPEN_KEY_INFORMATION info)
{
	UNREFERENCED_PARAMETER(context);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		
	}

	if (CheckRegistryKeyInExcludeList(info->RootObject, info->CompleteName))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ":bulundu!\n");
		return STATUS_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

BOOLEAN GetNameFromEnumKeyPreInfo(KEY_INFORMATION_CLASS infoClass, PVOID infoBuffer, PUNICODE_STRING keyName)
{
	switch (infoClass)
	{
	case KeyBasicInformation:
		{
			PKEY_BASIC_INFORMATION keyInfo = (PKEY_BASIC_INFORMATION)infoBuffer;
			keyName->Buffer = keyInfo->Name;
			keyName->Length = keyName->MaximumLength = (USHORT)keyInfo->NameLength;
		}
		break;
	case KeyNameInformation:
		{
			PKEY_NAME_INFORMATION keyInfo = (PKEY_NAME_INFORMATION)infoBuffer;
			keyName->Buffer = keyInfo->Name;
			keyName->Length = keyName->MaximumLength = (USHORT)keyInfo->NameLength;
		}
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

NTSTATUS RegPostEnumKey(PVOID context, PREG_POST_OPERATION_INFORMATION info)
{
	PREG_ENUMERATE_KEY_INFORMATION preInfo;
	PCUNICODE_STRING regPath;
	UNICODE_STRING keyName;
	UINT32 incIndex;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(context);

	if (!NT_SUCCESS(info->Status))
		return STATUS_SUCCESS;

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		
		return STATUS_SUCCESS;
	}

	status = CmCallbackGetKeyObjectID(&g_regCookie, info->Object, NULL, &regPath);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);
		return STATUS_SUCCESS;
	}

	preInfo = (PREG_ENUMERATE_KEY_INFORMATION)info->PreInformation;

	if (!GetNameFromEnumKeyPreInfo(preInfo->KeyInformationClass, preInfo->KeyInformation, &keyName))
		return STATUS_SUCCESS;

	incIndex = 0;
	if (CheckExcludeListRegKeyValueName(g_excludeRegKeyContext, (PUNICODE_STRING)regPath, &keyName, &incIndex))
		DbgPrint("FsFilter1!" __FUNCTION__ ": þurada %wZ (inc: %d)\n", regPath, incIndex);

	if (incIndex > 0)
	{
		HANDLE Key;
		ULONG resLen, i;
		BOOLEAN infinite = TRUE;
		PVOID tempBuffer;

		status = ObOpenObjectByPointer(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS, *CmKeyObjectType, KernelMode, &Key);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": ObOpenObjectByPointer() hatasý:%08x\n", status);
			return STATUS_SUCCESS;
		}

		tempBuffer = (LPWSTR)ExAllocatePoolWithTag(PagedPool, preInfo->Length, FILTER_ALLOC_TAG);
		if (tempBuffer)
		{
			for (i = 0; infinite; i++)
			{
				status = ZwEnumerateKey(Key, preInfo->Index + incIndex, preInfo->KeyInformationClass, tempBuffer, preInfo->Length, &resLen);
				if (!NT_SUCCESS(status))
					break;

				if (!GetNameFromEnumKeyPreInfo(preInfo->KeyInformationClass, tempBuffer, &keyName))
					break;

				if (!CheckExcludeListRegKeyValueName(g_excludeRegKeyContext, (PUNICODE_STRING)regPath, &keyName, &incIndex))
				{
					*preInfo->ResultLength = resLen;
					__try
					{
						RtlCopyMemory(preInfo->KeyInformation, tempBuffer, resLen);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						DbgPrint("FsFilter1!" __FUNCTION__ ": yeni anahtar deðeri kopyalanamadý\n");
					}

					break;
				}
			}

			ExFreePoolWithTag(tempBuffer, FILTER_ALLOC_TAG);
		}
		else
		{
			status = STATUS_SUCCESS;
		}

		info->ReturnStatus = status;

		ZwClose(Key);
	}

	return STATUS_SUCCESS;
}

BOOLEAN GetNameFromEnumValuePreInfo(KEY_VALUE_INFORMATION_CLASS infoClass, PVOID infoBuffer, PUNICODE_STRING keyName)
{
	switch (infoClass)
	{
	case KeyValueBasicInformation:
		{
			PKEY_VALUE_BASIC_INFORMATION keyInfo = (PKEY_VALUE_BASIC_INFORMATION)infoBuffer;
			keyName->Buffer = keyInfo->Name;
			keyName->Length = keyName->MaximumLength = (USHORT)keyInfo->NameLength;
		}
		break;
	case KeyValueFullInformation:
	case KeyValueFullInformationAlign64:
		{
			PKEY_VALUE_FULL_INFORMATION keyInfo = (PKEY_VALUE_FULL_INFORMATION)infoBuffer;
			keyName->Buffer = keyInfo->Name;
			keyName->Length = keyName->MaximumLength = (USHORT)keyInfo->NameLength;
		}
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

NTSTATUS RegPostEnumValue(PVOID context, PREG_POST_OPERATION_INFORMATION info)
{
	PREG_ENUMERATE_KEY_INFORMATION preInfo;
	PCUNICODE_STRING regPath;
	UNICODE_STRING keyName;
	UINT32 incIndex;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(context);

	if (!NT_SUCCESS(info->Status))
		return STATUS_SUCCESS;

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		
		return STATUS_SUCCESS;
	}

	status = CmCallbackGetKeyObjectID(&g_regCookie, info->Object, NULL, &regPath);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": kayýt defteri deðeri okunamadý:%08x\n", status);
		return STATUS_SUCCESS;
	}

	preInfo = (PREG_ENUMERATE_KEY_INFORMATION)info->PreInformation;

	if (!GetNameFromEnumValuePreInfo(preInfo->KeyInformationClass, preInfo->KeyInformation, &keyName))
		return STATUS_SUCCESS;

	incIndex = 0;
	if (CheckExcludeListRegKeyValueName(g_excludeRegValueContext, (PUNICODE_STRING)regPath, &keyName, &incIndex))
		DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! bulundu %wZ (inc: %d)\n", regPath, incIndex);

	if (incIndex > 0)
	{
		HANDLE Key;
		ULONG resLen, i;
		BOOLEAN infinite = TRUE;
		PVOID tempBuffer;

		status = ObOpenObjectByPointer(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS, *CmKeyObjectType, KernelMode, &Key);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": ObOpenObjectByPointer() hatasý:%08x\n", status);
			return STATUS_SUCCESS;
		}

		tempBuffer = (LPWSTR)ExAllocatePoolWithTag(PagedPool, preInfo->Length, FILTER_ALLOC_TAG);
		if (tempBuffer)
		{

			for (i = 0; infinite; i++)
			{
				status = ZwEnumerateValueKey(Key, preInfo->Index + incIndex, preInfo->KeyInformationClass, tempBuffer, preInfo->Length, &resLen);
				if (!NT_SUCCESS(status))
					break;

				if (!GetNameFromEnumValuePreInfo(preInfo->KeyInformationClass, tempBuffer, &keyName))
					break;

				if (!CheckExcludeListRegKeyValueName(g_excludeRegValueContext, (PUNICODE_STRING)regPath, &keyName, &incIndex))
				{
					*preInfo->ResultLength = resLen;
					__try
					{
						RtlCopyMemory(preInfo->KeyInformation, tempBuffer, resLen);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						DbgPrint("FsFilter1!" __FUNCTION__ ": hata\n");
					}

					break;
				}
			}

			ExFreePoolWithTag(tempBuffer, FILTER_ALLOC_TAG);
		}
		else
		{
			status = STATUS_SUCCESS;
		}

		info->ReturnStatus = status;

		ZwClose(Key);
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPreSetValue(PVOID context, PREG_SET_VALUE_KEY_INFORMATION info)
{
	NTSTATUS status;
	PCUNICODE_STRING regPath;
	UINT32 incIndex;

	UNREFERENCED_PARAMETER(context);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		
		return STATUS_SUCCESS;
	}

	status = CmCallbackGetKeyObjectID(&g_regCookie, info->Object, NULL, &regPath);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);
		return STATUS_SUCCESS;
	}

	incIndex = 0;
	if (CheckExcludeListRegKeyValueName(g_excludeRegValueContext, (PUNICODE_STRING)regPath, info->ValueName, &incIndex))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! bulundu %wZ\\%wZ (inc: %d)\n", regPath, info->ValueName, incIndex);
		return STATUS_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPreDeleteValue(PVOID context, PREG_DELETE_VALUE_KEY_INFORMATION info)
{
	NTSTATUS status;
	PCUNICODE_STRING regPath;
	UINT32 incIndex;

	UNREFERENCED_PARAMETER(context);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		return STATUS_SUCCESS;
	}

	status = CmCallbackGetKeyObjectID(&g_regCookie, info->Object, NULL, &regPath);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ":hata:%08x\n", status);
		return STATUS_SUCCESS;
	}

	incIndex = 0;
	if (CheckExcludeListRegKeyValueName(g_excludeRegValueContext, (PUNICODE_STRING)regPath, info->ValueName, &incIndex))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! bulundu %wZ\\%wZ (inc: %d)\n", regPath, info->ValueName, incIndex);
		return STATUS_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPreQueryValue(PVOID context, PREG_QUERY_VALUE_KEY_INFORMATION info)
{
	NTSTATUS status;
	PCUNICODE_STRING regPath;
	UINT32 incIndex;

	UNREFERENCED_PARAMETER(context);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		
		return STATUS_SUCCESS;
	}

	status = CmCallbackGetKeyObjectID(&g_regCookie, info->Object, NULL, &regPath);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);
		return STATUS_SUCCESS;
	}

	incIndex = 0;
	if (CheckExcludeListRegKeyValueName(g_excludeRegValueContext, (PUNICODE_STRING)regPath, info->ValueName, &incIndex))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! bulundu %wZ\\%wZ (inc: %d)\n", regPath, info->ValueName, incIndex);
		return STATUS_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RegPreQueryMultipleValue(PVOID context, PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION info)
{
	NTSTATUS status;
	PCUNICODE_STRING regPath;
	UINT32 incIndex, i;

	UNREFERENCED_PARAMETER(context);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		//DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! process excluded %d\n", PsGetCurrentProcessId());
		return STATUS_SUCCESS;
	}

	status = CmCallbackGetKeyObjectID(&g_regCookie, info->Object, NULL, &regPath);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);
		return STATUS_SUCCESS;
	}

	for (i = 0; i < info->EntryCount; i++)
	{
		incIndex = 0;
		if (CheckExcludeListRegKeyValueName(g_excludeRegValueContext, (PUNICODE_STRING)regPath, info->ValueEntries[i].ValueName, &incIndex))
		{
			DbgPrint("FsFilter1!" __FUNCTION__ ": !!!!! bulundu %wZ\\%wZ (inc: %d)\n", regPath, info->ValueEntries[i].ValueName, incIndex);
			return STATUS_NOT_FOUND;
		}
	}

	return STATUS_SUCCESS;
}

_Function_class_(EX_CALLBACK_FUNCTION)
NTSTATUS RegistryFilterCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	NTSTATUS status;

	if (!IsDriverEnabled())
		return STATUS_SUCCESS;

	switch (notifyClass)
	{
	case RegNtPreCreateKey:
		status = RegPreCreateKey(CallbackContext, (PREG_PRE_CREATE_KEY_INFORMATION)Argument2);
		break;
	case RegNtPreCreateKeyEx:
		status = RegPreCreateKeyEx(CallbackContext, (PREG_CREATE_KEY_INFORMATION)Argument2);
		break;
	case RegNtPreOpenKey:
		status = RegPreCreateKey(CallbackContext, (PREG_PRE_OPEN_KEY_INFORMATION)Argument2);
		break;
	case RegNtPreOpenKeyEx:
		status = RegPreOpenKeyEx(CallbackContext, (PREG_OPEN_KEY_INFORMATION)Argument2);
		break;
	case RegNtPostEnumerateKey:
		status = RegPostEnumKey(CallbackContext, (PREG_POST_OPERATION_INFORMATION)Argument2);
		break;
	case RegNtPostEnumerateValueKey:
		status = RegPostEnumValue(CallbackContext, (PREG_POST_OPERATION_INFORMATION)Argument2);
		break;
	case RegNtSetValueKey:
		status = RegPreSetValue(CallbackContext, (PREG_SET_VALUE_KEY_INFORMATION)Argument2);
		break;
	case RegNtPreDeleteValueKey:
		status = RegPreDeleteValue(CallbackContext, (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2);
		break;
	case RegNtPreQueryValueKey:
		status = RegPreQueryValue(CallbackContext, (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2);
		break;
	case RegNtPreQueryMultipleValueKey:
		status = RegPreQueryMultipleValue(CallbackContext, (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument2);
		break;
	default:
		status = STATUS_SUCCESS;
		break;
	}

	return status;
}

NTSTATUS AddCurrentControlSetVariants(PUNICODE_STRING KeyPath, ExcludeContext Context, ULONGLONG ObjId,
	NTSTATUS(*AddRoutine)(ExcludeContext, PUNICODE_STRING, PExcludeEntryId, ExcludeEntryId))
{
	UNICODE_STRING currVersion, currVersionXXX, tail;
	ULONGLONG objIds[2];
	NTSTATUS status;
	BOOLEAN tailed;

	RtlInitUnicodeString(&currVersion, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet");
	if (!RtlPrefixUnicodeString(&currVersion, KeyPath, TRUE))
		return STATUS_SUCCESS;

	tailed = (KeyPath->Length >= currVersion.Length + sizeof(WCHAR));

	
	if (tailed && KeyPath->Buffer[currVersion.Length / sizeof(WCHAR)] != L'\\')
		return STATUS_SUCCESS;

	currVersionXXX.Buffer = (LPWSTR)ExAllocatePoolWithTag(NonPagedPool, KeyPath->Length, FILTER_ALLOC_TAG);
	currVersionXXX.Length = 0;
	currVersionXXX.MaximumLength = KeyPath->Length;

	if (!currVersionXXX.Buffer)
		return STATUS_NO_MEMORY;

	__try
	{
		

		if (tailed)
		{
			tail.Buffer = KeyPath->Buffer + (currVersion.Length / sizeof(WCHAR)) + 1;
			tail.MaximumLength = tail.Length = KeyPath->Length - currVersion.Length - sizeof(WCHAR);
			RtlUnicodeStringPrintf(&currVersionXXX, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\%wZ", &tail);
		}
		else
		{
			RtlInitUnicodeString(&currVersionXXX, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001");
		}

		status = AddRoutine(Context, &currVersionXXX, &objIds[0], ObjId);
		if (!NT_SUCCESS(status))
			return status;

		

		if (tailed)
			RtlUnicodeStringPrintf(&currVersionXXX, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\%wZ", &tail);
		else
			RtlInitUnicodeString(&currVersionXXX, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002");

		status = AddRoutine(Context, &currVersionXXX, &objIds[1], ObjId);
		if (!NT_SUCCESS(status))
		{
			RemoveExcludeListEntry(Context, objIds[0]);
			return status;
		}
	}
	__finally
	{
		ExFreePoolWithTag(currVersionXXX.Buffer, FILTER_ALLOC_TAG);
	}

	return STATUS_SUCCESS;
}

VOID LoadConfigRegKeysCallback(PUNICODE_STRING Str, PVOID Params)
{
	ExcludeEntryId id;
	UNREFERENCED_PARAMETER(Params);
	AddHiddenRegKey(Str, &id);
}

VOID LoadConfigRegValuesCallback(PUNICODE_STRING Str, PVOID Params)
{
	ExcludeEntryId id;
	UNREFERENCED_PARAMETER(Params);
	AddHiddenRegValue(Str, &id);
}

NTSTATUS InitializeRegistryFilter(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;
	UNICODE_STRING altitude, str;
	ExcludeEntryId id;
	UINT32 i;

	

	status = InitializeExcludeListContext(&g_excludeRegKeyContext, ExcludeRegKey);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": exclude registry key list initialization failed with code:%08x\n", status);
		return status;
	}

	for (i = 0; g_excludeRegKeys[i]; i++)
	{
		RtlInitUnicodeString(&str, g_excludeRegKeys[i]);
		AddHiddenRegKey(&str, &id);
	}

	CfgEnumConfigsTable(HideRegKeysTable, &LoadConfigRegKeysCallback, NULL);

	status = InitializeExcludeListContext(&g_excludeRegValueContext, ExcludeRegValue);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": exclude registry value list initialization failed with code:%08x\n", status);
		DestroyExcludeListContext(g_excludeRegKeyContext);
		return status;
	}

	for (i = 0; g_excludeRegValues[i]; i++)
	{
		RtlInitUnicodeString(&str, g_excludeRegValues[i]);
		AddHiddenRegValue(&str, &id);
	}

	CfgEnumConfigsTable(HideRegValuesTable, &LoadConfigRegValuesCallback, NULL);

	

	RtlInitUnicodeString(&altitude, L"320000");

	status = CmRegisterCallbackEx(&RegistryFilterCallback, &altitude, DriverObject, NULL, &g_regCookie, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("FsFilter1!" __FUNCTION__ ": Registry filter registration failed with code:%08x\n", status);
		DestroyExcludeListContext(g_excludeRegKeyContext);
		DestroyExcludeListContext(g_excludeRegValueContext);
		return status;
	}

	g_regFilterInited = TRUE;
	return status;
}

NTSTATUS DestroyRegistryFilter()
{
	NTSTATUS status;

	if (!g_regFilterInited)
		return STATUS_NOT_FOUND;

	status = CmUnRegisterCallback(g_regCookie);
	if (!NT_SUCCESS(status))
		DbgPrint("FsFilter1!" __FUNCTION__ ": hata:%08x\n", status);

	DestroyExcludeListContext(g_excludeRegKeyContext);
	DestroyExcludeListContext(g_excludeRegValueContext);

	g_regFilterInited = FALSE;

	return status;
}

NTSTATUS AddHiddenRegKey(PUNICODE_STRING KeyPath, PULONGLONG ObjId)
{
	NTSTATUS status;
	
	status = AddExcludeListRegistryKey(g_excludeRegKeyContext, KeyPath, ObjId, 0);
	if (NT_SUCCESS(status))
	{
		status = AddCurrentControlSetVariants(KeyPath, g_excludeRegKeyContext, *ObjId, &AddExcludeListRegistryKey);
		if (!NT_SUCCESS(status))
			RemoveHiddenRegKey(*ObjId);
	}

	return status;
}

NTSTATUS RemoveHiddenRegKey(ULONGLONG ObjId)
{
	return RemoveExcludeListEntry(g_excludeRegKeyContext, ObjId);
}

NTSTATUS RemoveAllHiddenRegKeys()
{
	return RemoveAllExcludeListEntries(g_excludeRegKeyContext);
}

NTSTATUS AddHiddenRegValue(PUNICODE_STRING ValuePath, PULONGLONG ObjId)
{
	NTSTATUS status;

	status = AddExcludeListRegistryValue(g_excludeRegValueContext, ValuePath, ObjId, 0);
	if (NT_SUCCESS(status))
	{
		status = AddCurrentControlSetVariants(ValuePath, g_excludeRegValueContext, *ObjId, &AddExcludeListRegistryValue);
		if (!NT_SUCCESS(status))
			RemoveHiddenRegValue(*ObjId);
	}

	return status;
}

NTSTATUS RemoveHiddenRegValue(ULONGLONG ObjId)
{
	return RemoveExcludeListEntry(g_excludeRegValueContext, ObjId);
}

NTSTATUS RemoveAllHiddenRegValues()
{
	return RemoveAllExcludeListEntries(g_excludeRegValueContext);
}
