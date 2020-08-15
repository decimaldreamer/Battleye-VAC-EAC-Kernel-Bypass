#include <Windows.h>
#include "stdafx.h"

#define READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define SET_ID_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

namespace Offset {
	DWORD_PTR GameManager = 0x47F00D0;
	DWORD_PTR EntityList = 0xC0;

	DWORD_PTR Entity = 0x0008;
	DWORD_PTR EntityRef = 0x20;

	DWORD_PTR EntityInfo = 0x18;
	DWORD_PTR MainComponent = 0xB8;
	DWORD_PTR ChildComponent = 0x8;
	DWORD_PTR Health = 0x108;

	DWORD_PTR PlayerInfo = 0x2A0;
	DWORD_PTR PlayerInfoDeref = 0x0;
	DWORD_PTR PlayerTeamId = 0x140;
	DWORD_PTR PlayerName = 0x158;

	DWORD_PTR FeetPosition = 0x1C0;
	DWORD_PTR HeadPosition = 0x160;

	DWORD_PTR WeaponComp = 0x38;
	DWORD_PTR WeaponProcessor = 0xF0;
	DWORD_PTR Weapon = 0x0;
	DWORD_PTR WeaponInfo = 0x110;
	DWORD_PTR Spread = 0x2A0;
	DWORD_PTR Recoil = 0x2D8;
	DWORD_PTR Recoil2 = 0x354;
	DWORD_PTR Recoil3 = 0x304;
	DWORD_PTR AdsRecoil = 0x330;

	DWORD_PTR Renderer = 0x47A4930;
	DWORD_PTR GameRenderer = 0x0;
	DWORD_PTR EngineLink = 0xd8;
	DWORD_PTR Engine = 0x218;
	DWORD_PTR Camera = 0x38;

	DWORD_PTR ViewTranslastion = 0x1A0;
	DWORD_PTR ViewRight = 0x170;
	DWORD_PTR ViewUp = 0x180;
	DWORD_PTR ViewForward = 0x190;
	DWORD_PTR FOVX = 0x1B0;
	DWORD_PTR FOVY = 0x1C4;
}

typedef struct _READ_MEM
{
	DWORD64 address;
	DWORD64 response;
	ULONG size;

} READ_MEM, *PREAD_MEM;

typedef struct _WRITE_MEM
{
	DWORD64 address;
	float value;
	ULONG size;

} WRITE_MEM, *PWRITE_MEM;

class Wrappers
{
public:
	HANDLE hDriver;
	
	Wrappers(LPCSTR RegistryPath)
	{
		hDriver = CreateFileA(RegistryPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	}

	
	DWORD64 RPM(DWORD64 address, SIZE_T size)
	{
		READ_MEM read;

		read.address = address;
		read.size = size;

		if (DeviceIoControl(hDriver, READ_REQUEST, &read, sizeof(read), &read, sizeof(read), 0, 0))
			return (DWORD64)read.response;
		else
			return false;
	}

	
	bool WPM(DWORD64 address, float value, SIZE_T size)
	{
		DWORD bytes;
		WRITE_MEM  write;

		write.address = address;
		write.value = value;
		write.size = size;

		if (DeviceIoControl(hDriver, WRITE_REQUEST, &write, sizeof(write), 0, 0, &bytes, NULL))
			return true;
		else
			return false;
	}

	
	DWORD SetTargetPid(DWORD PID)
	{
		DWORD Bytes;

		if (DeviceIoControl(hDriver, SET_ID_REQUEST, &PID, sizeof(PID), 0, 0, &Bytes, NULL))
			return true;
		else
			return false;
	}

	DWORD64 GetMainModule()
	{
		DWORD64 MainModule;

		if (DeviceIoControl(hDriver, GET_MODULE_REQUEST, 0, 0, &MainModule, sizeof(MainModule), 0, 0))
			return MainModule;
		else
			return false;
	}
};