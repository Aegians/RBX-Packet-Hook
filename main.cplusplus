#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
 
inline void initiate(const char *const console_name) {
    DWORD old_protection;
    VirtualProtect(&FreeConsole, 1, PAGE_EXECUTE_READWRITE, &old_protection);
    *reinterpret_cast<std::uint8_t *>(&FreeConsole) = 0xC3;
 
    AllocConsole();
 
    FILE *file_stream;
 
    freopen_s(&file_stream, "CONIN$", "r", stdin);
    freopen_s(&file_stream, "CONOUT$", "w", stdout);
    freopen_s(&file_stream, "CONOUT$", "w", stderr);
 
    SetConsoleTitleA(console_name);
}
 
std::uint8_t *base;
void *packet_write_original;
std::uint8_t __fastcall packet_write_hook(const void *const item, const void *const junk, std::uint8_t *const network_stream) {
    const auto status = static_cast<decltype(&packet_write_hook)>(packet_write_original)(item, junk, network_stream);
 
    const auto data = *reinterpret_cast<std::uint8_t **>(network_stream + 0x8);
 
    std::printf("[erm] sending item: %X (item: 0x%p, networkstream: 0x%p)\n", data[1], item, network_stream);
 
    return status;
}
 
long NTAPI exception_handler(PEXCEPTION_POINTERS exception) {
    if (exception->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
        auto &eax = exception->ContextRecord->Eax;
 
        // .text:01399BFA 8B 40 04 mov eax, [eax+4]
        packet_write_original = *reinterpret_cast<void **>(eax + 0x4);
 
        eax = reinterpret_cast<std::uintptr_t>(&packet_write_hook);
 
        exception->ContextRecord->Eip += 3;
 
        return EXCEPTION_CONTINUE_EXECUTION;
    }
 
    return EXCEPTION_CONTINUE_SEARCH;
}
 
void *us14116_original;
std::uint32_t __fastcall us14116_hook(const void *const job, const void *const junk, const void *const stats) {
    static const auto force_write = [&](void *const destination, const char *const value) {
        const auto size = std::strlen(value) - 1;
 
        DWORD old_protection;
        VirtualProtect(destination, 1, PAGE_EXECUTE_READWRITE, &old_protection);
        std::memcpy(destination, value, size);
        VirtualProtect(destination, 1, old_protection, &old_protection);
    };
 
    force_write(base + 0x01399BFA, "\x8B\x40\x04");
 
    const auto status = static_cast<decltype(&us14116_hook)>(us14116_original)(job, junk, stats);
 
    force_write(base + 0x01399BFA, "\xCC\x90\x90");
 
    return status;
}
 
bool __stdcall DllMain(void *, const std::uint32_t reason, void *) {
    if (reason == DLL_PROCESS_ATTACH) {
        initiate("[aegians] packet logger");
 
        AddVectoredExceptionHandler(1, &exception_handler);
 
        base = reinterpret_cast<std::uint8_t *>(GetModuleHandleA(nullptr));
        std::printf("[aegians] base: 0x%p\n", base);
 
        const auto task_scheduler = *reinterpret_cast<std::uintptr_t *>(base + 0x398EAE8);
        std::printf("[aegians] task_scheduler: 0x%p\n", task_scheduler);
 
        for (auto job_index = *reinterpret_cast<std::uintptr_t *>(task_scheduler + 0x134); job_index != *reinterpret_cast<std::uintptr_t *>(task_scheduler + 0x138); job_index += 8) {
            const auto job = *reinterpret_cast<std::uintptr_t *>(job_index);
 
            if (const auto &name = *reinterpret_cast<std::string *>(job + 0x10); name == "US14116") {
                auto &vftable = *reinterpret_cast<void ***>(job);
                us14116_original = vftable[5];
 
                std::printf("[aegians] %s: 0x%p\n", name.c_str(), us14116_original);
 
                auto vftable_copy = new void *[10];
                std::memcpy(vftable_copy, vftable, 40);
 
                vftable_copy[5] = &us14116_hook;
 
                vftable = vftable_copy;
 
                break;
            }
        }
    }
 
    return true;
}
