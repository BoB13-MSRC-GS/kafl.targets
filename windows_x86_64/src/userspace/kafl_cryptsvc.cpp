#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "nyx_api.h"
#include <stdio.h>
#include <rpcdce.h>
#include <rpc.h>
#include <rpcndr.h>
#include <dbghelp.h>
#include <psapi.h>
#include "cryptsvc_h.h"

#define TargetName1 L"cryptsvc.dll"
#define TargetName2 L"crypt32.dll"
#define HarnessName L"kafl_cryptsvc.dll"

#define PE_CODE_SECTION_NAME ".text"
#pragma comment(lib, "rpcrt4.lib")
#define RPC_SUCCESS(x) (x == RPC_S_OK)

#define ARRAY_SIZE 1024
PCSTR ntoskrnl = "C:\\Windows\\System32\\ntoskrnl.exe";
PCSTR kernel_func1 = "KeBugCheck";
PCSTR kernel_func2 = "KeBugCheckEx";

RPC_BINDING_HANDLE GetBindingHandle(void)
{
    RPC_STATUS          status = RPC_S_OK;
    RPC_WSTR            stringBinding = NULL;
    RPC_BINDING_HANDLE  hBinding = NULL;
    RPC_SECURITY_QOS    SecurityQOS = { 0 };

    status = RpcStringBindingComposeW(
        NULL,
        (RPC_WSTR)L"ncalrpc",
        NULL,
        (RPC_WSTR)L"keysvc",
        NULL,
        &stringBinding
    );
    if (!RPC_SUCCESS(status)) {
        hprintf("[-] RpcStringBindingCompose Error : 0x%08X\n", status);
        goto out;
    }
    status = RpcBindingFromStringBindingW(
        stringBinding,
        &hBinding
    );

    if (!RPC_SUCCESS(status)) {
        hprintf("[-] RpcBindingFromStringBinding Error : 0x%08X\n", status);
        goto out;
    }

out:
    if (stringBinding)
        RpcStringFree(&stringBinding);

    return hBinding;
}

void* __RPC_USER MIDL_user_allocate(size_t size) {
    return malloc(size);
}

void __RPC_USER MIDL_user_free(void* ptr) {
    free(ptr);
}

static inline void panic(void) {
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
    while (1) {}; /* halt */
}

FARPROC KernGetProcAddress(HMODULE kern_base, LPCSTR function) {
    // error checking? bah...
    HMODULE kernel_base_in_user_mode = LoadLibraryA(ntoskrnl);
    return (FARPROC)((PUCHAR)GetProcAddress(kernel_base_in_user_mode, function) - (PUCHAR)kernel_base_in_user_mode + (PUCHAR)kern_base);
}

UINT64 resolve_KeBugCheck(PCSTR kfunc) {
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    FARPROC KeBugCheck = NULL;
    int cDrivers, i;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        TCHAR szDriver[ARRAY_SIZE];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < cDrivers; i++) {
            if (GetDeviceDriverFileName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) {
                // assuming ntoskrnl.exe is first entry seems save (FIXME)
                if (i == 0) {
                    KeBugCheck = KernGetProcAddress((HMODULE)drivers[i], kfunc);
                    if (!KeBugCheck) {
                        hprintf("[-] w00t?");
                        ExitProcess(0);
                    }
                    break;
                }
            }
        }
    }
    else {
        printf("[-] EnumDeviceDrivers failed; array size needed is %d\n", (UINT32)(cbNeeded / sizeof(LPVOID)));
        ExitProcess(0);
    }

    return  (UINT64)KeBugCheck;
}

/* forward exceptions to panic handler */
void init_panic_handlers() {
    UINT64 panic_kebugcheck = 0x0;
    UINT64 panic_kebugcheck2 = 0x0;
    panic_kebugcheck = resolve_KeBugCheck(kernel_func1);
    panic_kebugcheck2 = resolve_KeBugCheck(kernel_func2);
    hprintf("Submitting bug check handlers\n");
    /* submit panic address */
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck);
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck2);
}

LONG CALLBACK exc_handle(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    DWORD exception_code = ExceptionInfo->ExceptionRecord->ExceptionCode;

    hprintf("Exception caught: %lx\n", exception_code);

    if ((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
        (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
        (exception_code == STATUS_HEAP_CORRUPTION) ||
        //(exception_code == 0xc0000374) ||
        (exception_code == EXCEPTION_STACK_OVERFLOW) ||
        (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
        (exception_code == STATUS_FATAL_APP_EXIT))
    {
        panic();
    }

    return TRUE;
}

///* force termination on AVs */
//void WINAPI nuke() {
//    TerminateProcess((HANDLE)-1, 0x41);
//}
//
//LONG CALLBACK catch_all(struct _EXCEPTION_POINTERS* ExceptionInfo) {
//    ExceptionInfo->ContextRecord->Rip = (DWORD64)nuke;
//    return EXCEPTION_CONTINUE_EXECUTION; // return -1;
//}

bool set_ip_range(HMODULE hModule, byte idx) {
    if (hModule == NULL) {
        hprintf("[Harness][set_ip_range] Cannot get module handle: %d\n", GetLastError());
        habort("Abort\n");
        return false;
    }

    // Get the PE header of the current module.
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        hprintf("[Harness][set_ip_range] Invalid PE signature\n");
        habort("Invalid PE signature\n");
        return false;
    }
    hprintf("\taddr: %p\n", (char*)hModule);
    // Get the section headers.
    PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders +
        sizeof(IMAGE_NT_HEADERS));
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER pSectionHeader = &pSectionHeaders[i];

        // Check for the .text section
        if (memcmp((LPVOID)pSectionHeader->Name, PE_CODE_SECTION_NAME, strlen(PE_CODE_SECTION_NAME)) == 0) {
            uint64_t codeStart = (uint64_t)hModule + pSectionHeader->VirtualAddress;
            uint64_t codeEnd = codeStart + pSectionHeader->Misc.VirtualSize;

            hprintf("\t\tDLL text section start addr:\t%p\n", codeStart);
            hprintf("\t\tDLL text section end addr:\t%p\n", codeEnd);
            hprintf("\t\tDLL text section size:\t%lx\n", pSectionHeader->Misc.VirtualSize);

            // submit them to kAFL
            uint64_t buffer[3] = { 0 };
            buffer[0] = codeStart; // low range
            buffer[1] = codeEnd; // high range
            buffer[2] = idx; // IP filter index [0-3]
            kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uint64_t)buffer);

            hprintf("\tLock Range: 0x%llx-0x%llx\n", buffer[0], buffer[1]);
            // ensure allways present in memory, avoid pagefaults for libxdc
            //if (!VirtualLock((LPVOID)codeStart, pSectionHeader->Misc.VirtualSize)) {
            //    hprintf("Error: %d\n", GetLastError());
            //}
            return true;
        }
    }

    hprintf("[Harness][set_ip_range] Couldn't locate .text section in PE image\n");
    habort("Couldn't locate .text section in PE image\n");
    return false;
}

void submit_ip_ranges() {
    HMODULE hModule1;
    byte idx = 0;
    hModule1 = GetModuleHandleW(TargetName1);
    hprintf("[Harness][submit_ip_ranges] Call set_ip_range - %ws\n", TargetName1);
    if (!set_ip_range(hModule1, idx)) {
        hprintf("[Harness][submit_ip_ranges] Failed set_ip_range - %ws\n", TargetName1);
        return;
    }
    hprintf("[Harness][submit_ip_ranges] Success set_ip_range - %ws\n", TargetName1);

    idx++;
    HMODULE hModule2;
    hModule2 = GetModuleHandleW(TargetName2);
    hprintf("[Harness][submit_ip_ranges] Call set_ip_range - %ws\n", TargetName2);
    if (!set_ip_range(hModule2, idx)) {
        hprintf("[Harness][submit_ip_ranges] Failed set_ip_range - %ws\n", TargetName2);
        return;
    }
    hprintf("[Harness][submit_ip_ranges] Success set_ip_range - %ws\n", TargetName2);
}

void drop_VA() {

    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO sys_info;
    LPVOID curr_addr;
    LPSTR filename[MAX_PATH] = { 0 };
    MODULEINFO module_info;

    GetSystemInfo(&sys_info);
    curr_addr = sys_info.lpMinimumApplicationAddress;

    while (curr_addr < sys_info.lpMaximumApplicationAddress)
    {
        memset(&mbi, 0, sizeof(mbi));
        if (VirtualQuery((LPCVOID)curr_addr, &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
            {
                GetModuleInformation((HANDLE)-1, (HMODULE)curr_addr, &module_info, sizeof(module_info));
                GetModuleFileNameA((HMODULE)curr_addr, (LPSTR)&filename, MAX_PATH);
                hprintf("[+] 0x%llx - 0x%llx \"%s\"\n", curr_addr, (void*)((DWORD64)curr_addr + (DWORD64)module_info.SizeOfImage), filename);
            }
            else
            {
                hprintf("0x%p-0x%p\n", curr_addr, (void*)((DWORD64)curr_addr + (DWORD64)mbi.RegionSize));
                switch (mbi.Protect)
                {
                case PAGE_EXECUTE:
                    hprintf("\033[42C--X\n");
                    break;
                case PAGE_EXECUTE_READ:
                    hprintf("\033[42CR-X\n");
                    break;
                case PAGE_EXECUTE_READWRITE:
                    hprintf("\033[42CRWX\n");
                    break;
                case PAGE_READONLY:
                    hprintf("\033[42CR--\n");
                    break;
                case PAGE_READWRITE:
                    hprintf("\033[42CRW-\n");
                    break;
                case PAGE_WRITECOPY:
                    hprintf("\033[42CRW- (cow)\n");
                    break;

                }
            }
        }
        curr_addr = (PCHAR)curr_addr + mbi.RegionSize;
    }
}


kAFL_payload* kafl_agent_init(void) {
    // initial fuzzer handshake
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // submit mode
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    // get host config
    host_config_t host_config = { 0 };
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    hprintf("[Harness][kafl_agent_init] bitmap sizes = <0x%x,0x%x>\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
    hprintf("[Harness][kafl_agent_init] payload size = %dKB\n", host_config.payload_buffer_size / 1024);
    hprintf("[Harness][kafl_agent_init] worker id = %02u\n", host_config.worker_id);

    // allocate buffer
    hprintf("[Harness][kafl_agent_init] Allocating buffer for kAFL_payload struct\n");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, host_config.payload_buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // ensure really present in resident pages
    if (!VirtualLock(payload_buffer, host_config.payload_buffer_size)) {
        habort("[Harness][kafl_agent_init] WARNING: Virtuallock failed to lock payload buffer\n");
    }

    if (AddVectoredExceptionHandler(1, exc_handle) == 0)
    {
        hprintf("[Harness][kafl_agent_init] WARNING: Cannot add veh handler %u\n", (UINT32)GetLastError());
        ExitProcess(0);
    }

     init_panic_handlers();

    // submit buffer
    hprintf("[Harness][kafl_agent_init] Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    // filters
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // submit agent config
    agent_config_t agent_config = {
        .agent_magic = NYX_AGENT_MAGIC,
        .agent_version = NYX_AGENT_VERSION,
    };
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    return payload_buffer;
}

int trigger() {
    hprintf("[Harness][trigger] DLL attached, Start\n");

    //SetPrivilege_Fuck();
    hprintf("[Check] GetLastError 1 : %d\n", GetLastError());

    kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);

    kAFL_payload* payload_buffer = kafl_agent_init();

    hprintf("[Check] GetLastError 2 : %d\n", GetLastError());

    kAFL_ranges* range_buffer = (kAFL_ranges*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (range_buffer == NULL) {
        hprintf("[Harness][trigger] Failed to allocate range buffer\n");
        return FALSE;
    }
    memset(range_buffer, 0xff, 0x1000);

    hprintf("[Check] GetLastError 3 : %d\n", GetLastError());

    hprintf("[Harness][trigger] range buffer %lx...\n", (UINT64)range_buffer);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (UINT64)range_buffer);

    hprintf("[Check] GetLastError 4 : %d\n", GetLastError());
    drop_VA();
    hprintf("[Check] GetLastError 5 : %d\n", GetLastError());
    SetLastError(0);
    // ERROR_MOD_NOT_FOUND
    // 126(0x7E)
    hprintf("[Check] Call SetLastError 0 about drop_VA() : %d\n", GetLastError());
    submit_ip_ranges();
    hprintf("[Check] GetLastError 6 : %d\n", GetLastError());







    RPC_STATUS status = RPC_S_OK;
    RPC_BINDING_HANDLE      hBinding = NULL;
    HRESULT hr;

    hBinding = GetBindingHandle();
    if (!hBinding) {
        hprintf("[Harness][trigger] Acquired RPC Binding Handle Error : %d\n", GetLastError());
        return 0;
    }
    hprintf("[Harness][trigger] Acquired RPC Binding Handle : 0x%llx\n", (ULONG64)hBinding);

    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    unsigned long size = payload_buffer->size;
    if (size >= 5) {
        unsigned long arg1 = *(unsigned long*)(payload_buffer->data);
        arg1 = (arg1 % 15) + 1;
        long arg2 = 0;
        wchar_t* arg3 = SysAllocString(L"");
        byte* arg4 = (byte*)(payload_buffer->data + sizeof(long));
        unsigned long arg5 = size - sizeof(long);
        byte* arg6 = NULL;
        long arg7 = 0;

        hr = Proc0_s_SSCertProtectFunction(hBinding, (long)arg1, arg2, arg3, arg4, (long)arg5, &arg6, &arg7);
		//if (hr != S_OK) {
		//	hprintf("[Harness][trigger] Proc0_s_SSCertProtectFunction Error : 0x%08X\n", hr);
		//}
  //      hprintf("[*] After send.... getlasterror : %d\n", GetLastError());
    }







    //hprintf("after\n");
    // revive
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        trigger();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}