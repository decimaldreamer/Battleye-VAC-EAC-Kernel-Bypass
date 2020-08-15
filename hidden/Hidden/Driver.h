#pragma once

VOID EnableDisableDriver(BOOLEAN enabled);
BOOLEAN IsDriverEnabled();

extern ULONG ProtectedProgramPID;
extern ULONG LsassPID;
extern ULONG CsrssPID;
extern ULONG CsrssSecondPID;
