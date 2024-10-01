#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "nyx_api.h"
#include <stdio.h>
#include "sysmain_h.h"
#include <rpcdce.h>
#include <rpc.h>
#include <rpcndr.h>
#include <dbghelp.h>
#include <psapi.h>

#define PAYLOAD_SIZE 128 * 1024
#define PE_CODE_SECTION_NAME ".text"
#pragma comment(lib, "rpcrt4.lib")
#define RPC_SUCCESS(x) (x == RPC_S_OK)
#define PROC_FORMAT_STRING_SIZE   49


void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
    return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
    free(p);
}

RPC_BINDING_HANDLE GetBindingHandle(void)
{
    RPC_STATUS          status = RPC_S_OK;
    RPC_WSTR            stringBinding = NULL;
    RPC_BINDING_HANDLE  hBinding = NULL;

    status = RpcStringBindingComposeW(
        NULL,
        (RPC_WSTR)L"ncalrpc",
        NULL,
        NULL,
        NULL,
        &stringBinding
    );
    if (!RPC_SUCCESS(status)) {
        printf("[-] RpcStringBindingCompose Error : 0x%08X\n", status);
        goto out;
    }
    status = RpcBindingFromStringBindingW(
        stringBinding,
        &hBinding
    );
    if (!RPC_SUCCESS(status)) {
        printf("[-] RpcBindingFromStringBinding Error : 0x%08X\n", status);
        goto out;
    }

out:
    if (stringBinding)
        RpcStringFree(&stringBinding);

    return hBinding;
}

static inline void panic(void) {
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
    while (1) {}; /* halt */
}

void submit_ip_ranges() {
    HMODULE hModule = GetModuleHandleW(L"sysmain.dll");
    if (hModule == NULL) {
        hprintf("Cannot get module handle: %d\n", GetLastError());
        habort("Abort\n");
    }
    hprintf("[*] sysmain DLL whole addr : %p \n", (char*)hModule);

    // Get the PE header of the current module.
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        habort("Invalid PE signature\n");
    }

    byte pt_idx = 0;
    // Get the section headers.
    PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders +
        sizeof(IMAGE_NT_HEADERS));
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER pSectionHeader = &pSectionHeaders[i];

        if (pt_idx == 2) return;

        // Check for the .text section
        if (memcmp((LPVOID)pSectionHeader->Name, PE_CODE_SECTION_NAME, strlen(PE_CODE_SECTION_NAME)) == 0) {
            uint64_t codeStart = (uint64_t)hModule + pSectionHeader->VirtualAddress;
            uint64_t codeEnd = codeStart + pSectionHeader->Misc.VirtualSize;

            hprintf("[*] DLL text section start addr : %p \n", codeStart);
            hprintf("[*] DLL text section end addr : %p \n", codeEnd);
            hprintf("[*] DLL text section size is... %lx \n", pSectionHeader->Misc.VirtualSize);

            // submit them to kAFL
            uint64_t buffer[3] = { 0 };
            buffer[0] = codeStart; // low range
            buffer[1] = codeEnd; // high range
            buffer[2] = pt_idx++; // IP filter index [0-3]
            kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uint64_t)buffer);

            hprintf("Lock Range: 0x%llx-0x%llx\n", buffer[0], buffer[1]);
            // ensure allways present in memory, avoid pagefaults for libxdc
            // if (!VirtualLock(codeStart1, pSectionHdr->Misc.VirtualSize))
            if (!VirtualLock((LPVOID)codeStart, pSectionHeader->Misc.VirtualSize)) {
                hprintf("Error: %d\n", GetLastError());
                //habort("Failed to lock .text section in resident memory\n");

            }
        }
    }
    // HMODULE hModule2 = GetModuleHandleW(L"kafl_sysmain.dll");
    // if (hModule2 == NULL) {
    //     habort("Cannot get module handle\n");
    // }
    // hprintf("[*] kafl_sysmain DLL whole addr : %p \n", (uint64_t)hModule2);

    // PIMAGE_DOS_HEADER pDOSHeader2 = (PIMAGE_DOS_HEADER)hModule2;
    // PIMAGE_NT_HEADERS pNTHeaders2 = (PIMAGE_NT_HEADERS)((BYTE*)hModule2 + pDOSHeader2->e_lfanew);
    // PIMAGE_SECTION_HEADER pSectionHeader2 = IMAGE_FIRST_SECTION(pNTHeaders2);

    // for (int i = 0; i < pNTHeaders2->FileHeader.NumberOfSections; i++) {
    //     if (memcmp(pSectionHeader2->Name, ".text", 5) == 0) {

    //         LPVOID codeStart2 = (LPVOID)((BYTE*)hModule2 + pSectionHeader2->VirtualAddress);
    //         LPVOID codeEnd2 = codeStart2 + pSectionHeader2->Misc.VirtualSize;

    //         hprintf("[*] DLL text section start addr : %p \n", codeStart2);
    //         hprintf("[*] DLL text section end addr : %p \n", codeEnd2);
    //         hprintf("[*] DLL text section size is... %lx \n", pSectionHeader2->Misc.VirtualSize);

    //         if (!VirtualLock(codeStart2, pSectionHeader2->Misc.VirtualSize)) {
    //             hprintf("Failed to lock .text section of target Module. Error: %d\n", GetLastError());
    //             return;
    //         }
    //         hprintf("Successfully locked .text section of kafl_sysmain.dll\n");

    //         return;
    //     }
    //     pSectionHeader2++;
    // }
    // habort("Couldn't locate .text section in PE image\n");
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

/* forward exceptions to panic handler */
LONG CALLBACK exc_handle(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    DWORD exception_code = ExceptionInfo->ExceptionRecord->ExceptionCode;

    hprintf("Exception caught: %lx\n", exception_code);

    if ((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
        (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
        //(exception_code == STATUS_HEAP_CORRUPTION) ||
        (exception_code == 0xc0000374) ||
        (exception_code == EXCEPTION_STACK_OVERFLOW) ||
        (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
        (exception_code == STATUS_FATAL_APP_EXIT))
    {
        panic();
    }

    return TRUE;
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
    hprintf("[host_config] bitmap sizes = <0x%x,0x%x>\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
    hprintf("[host_config] payload size = %dKB\n", host_config.payload_buffer_size / 1024);
    hprintf("[host_config] worker id = %02u\n", host_config.worker_id);

    // allocate buffer
    hprintf("[+] Allocating buffer for kAFL_payload struct\n");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, host_config.payload_buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // ensure really present in resident pages
    if (!VirtualLock(payload_buffer, host_config.payload_buffer_size)) {
        habort("[+] WARNING: Virtuallock failed to lock payload buffer\n");
    }

    if (AddVectoredExceptionHandler(1, exc_handle) == 0)
    {
        hprintf("[-] WARNING: Cannot add veh handler %u\n", (UINT32)GetLastError());
    }

    // submit buffer
    hprintf("[+] Submitting buffer address to hypervisor...\n");
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
    hprintf("[+] DLL attached, starting initialization...\n");

    hprintf("[+] Creating snapshot...\n");
    kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);

    if (!SetProcessWorkingSetSize(GetCurrentProcess(), 1 << 25 /* min: 64MB */, 1 << 31 /* max: 2GB */)) {
        hprintf("SetProcessWorkingSetSize failed. Error: %lu\n", GetLastError());
    }

    kAFL_payload* payload_buffer = kafl_agent_init();

    kAFL_ranges* range_buffer = (kAFL_ranges*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (range_buffer == NULL) {
        hprintf("[!] Failed to allocate range buffer\n");
        return FALSE;
    }
    memset(range_buffer, 0xff, 0x1000);

    hprintf("[+] range buffer %lx...\n", (UINT64)range_buffer);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (UINT64)range_buffer);

    RPC_BINDING_HANDLE      hBinding = NULL;
    hBinding = GetBindingHandle();
    if (!hBinding) {
        hprintf("[-] Acquired RPC Binding Handle Error : %d\n", GetLastError());
        return 0;
    }
    hprintf("[+] Acquired RPC Binding Handle : 0x%llx\n", (ULONG64)hBinding);

    RPC_STATUS status = RPC_S_OK;
    DWORD* arg1 = (DWORD*)malloc(0x200);
    long* arg2 = (long*)malloc(0x20);

    memset(arg1, 0, 0x200);

    drop_VA();
    submit_ip_ranges();

    // start
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    DWORD ssize = payload_buffer->size;
    hprintf("[*] Before send....\n");
    Proc0_PfRpcServerExecuteCommand(hBinding, (unsigned char*)payload_buffer->data, (long *) & ssize);
    hprintf("[*] res : .... getlasterror : %d\n", GetLastError());

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