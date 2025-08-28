#include <windows.h>
#include <iostream>

typedef NTSTATUS (NTAPI *RtlSetProcessIsCriticalFunc)(
    BOOLEAN NewValue,
    PBOOLEAN OldValue,
    BOOLEAN NeedScb
);

static RtlSetProcessIsCriticalFunc g_pRtlSetProcessIsCritical = nullptr;
static BOOLEAN g_oldValue = FALSE;
static volatile bool g_isCritical = false;


bool EnablePrivilege(LPCSTR privName) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << "\n";
        return false;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, privName, &luid)) {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

 
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege: " << privName << "\n";
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}


BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (g_isCritical && g_pRtlSetProcessIsCritical) {
        NTSTATUS status = g_pRtlSetProcessIsCritical(FALSE, &g_oldValue, FALSE);
        if (status != 0) {
            std::cerr << "Warning: failed to unset critical in CtrlHandler, status: 0x" 
                      << std::hex << status << std::dec << "\n";
        } else {
            std::cout << "Unset process critical in CtrlHandler.\n";
            g_isCritical = false;
        }
    }
   
    return FALSE;
}

int main() {
    std::cout << "=== RtlSetProcessIsCritical demo ===\n";
    std::cout << "WARNING: setting a process as critical can cause BSOD if this process terminates unexpectedly.\n";
    std::cout << "Test only in a VM and run as Administrator.\n\n";

    
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        std::cerr << "Failed to enable SeDebugPrivilege. Try running as Administrator.\n";
       
    } else {
        std::cout << "SeDebugPrivilege enabled (or present).\n";
    }

    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "GetModuleHandleA(ntdll.dll) failed: " << GetLastError() << "\n";
        return 1;
    }

    g_pRtlSetProcessIsCritical = (RtlSetProcessIsCriticalFunc)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
    if (!g_pRtlSetProcessIsCritical) {
        std::cerr << "GetProcAddress(RtlSetProcessIsCritical) failed. Function may not be available on this OS.\n";
        return 1;
    }


    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        std::cerr << "SetConsoleCtrlHandler failed: " << GetLastError() << "\n";
      
    }

  
    NTSTATUS status = g_pRtlSetProcessIsCritical(TRUE, &g_oldValue, FALSE);
    if (status != 0) {
        std::cerr << "Failed to set process as critical, NTSTATUS: 0x" << std::hex << status << std::dec << "\n";
        std::cerr << "Common reasons: missing privilege, not running as Administrator, unsupported OS.\n";
        return 1;
    }

    g_isCritical = true;
    std::cout << "Process is now set as critical. If this process terminates unexpectedly, system may bugcheck (BSOD).\n";
    std::cout << "Press Ctrl+C to attempt to unset critical and exit cleanly.\n";

  
    while (g_isCritical) {
        Sleep(1000);
    }


    if (g_pRtlSetProcessIsCritical && g_isCritical == false) {
     
        NTSTATUS st = g_pRtlSetProcessIsCritical(FALSE, &g_oldValue, FALSE);
        if (st != 0) {
            std::cerr << "Final unset attempt failed, NTSTATUS: 0x" << std::hex << st << std::dec << "\n";
        } else {
            std::cout << "Final unset succeeded.\n";
        }
    }

    std::cout << "Exiting.\n";
    return 0;
}
