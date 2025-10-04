#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>

// --- Utility functions ---

// Find where this EXE is running
std::string get_exe_path() {
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return {};
    return std::string(buf, n);
}

// Default install dir
std::string get_default_install_dir() {
    return "C:\\Program Files\\mrya";
}

// Ask user for install dir
std::string ask_install_dir() {
    std::string def = get_default_install_dir();
    std::cout << "Enter install location [" << def << "]: ";
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) return def;
    return input;
}

// Append ;path\bin to PATH (user environment)
bool add_to_path(const std::string& dir) {
    std::string binPath = dir + "\\bin";

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Environment", 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    char buffer[8192] = {};
    DWORD size = sizeof(buffer);
    DWORD type = REG_EXPAND_SZ;
    if (RegQueryValueExA(hKey, "Path", nullptr, &type, (LPBYTE)buffer, &size) != ERROR_SUCCESS) {
        buffer[0] = '\0';
    }
    std::string path = buffer;

    if (path.find(binPath) == std::string::npos) {
        if (!path.empty() && path.back() != ';') path.push_back(';');
        path += binPath;
        RegSetValueExA(hKey, "Path", 0, REG_EXPAND_SZ,
            (const BYTE*)path.c_str(),
            (DWORD)(path.size() + 1));
    }
    RegCloseKey(hKey);

    SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
        (LPARAM)"Environment", SMTO_ABORTIFHUNG,
        5000, nullptr);

    return true;
}

// Remove ;path\bin from PATH
bool remove_from_path(const std::string& dir) {
    std::string binPath = dir + "\\bin";

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Environment", 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    char buffer[8192] = {};
    DWORD size = sizeof(buffer);
    DWORD type = REG_EXPAND_SZ;
    if (RegQueryValueExA(hKey, "Path", nullptr, &type, (LPBYTE)buffer, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    std::string path = buffer;

    size_t pos = path.find(binPath);
    if (pos != std::string::npos) {
        path.erase(pos, binPath.size());
        // Clean up stray semicolons
        while (path.find(";;") != std::string::npos)
            path.replace(path.find(";;"), 2, ";");
        if (!path.empty() && path.back() == ';')
            path.pop_back();

        RegSetValueExA(hKey, "Path", 0, REG_EXPAND_SZ,
            (const BYTE*)path.c_str(),
            (DWORD)(path.size() + 1));
    }

    RegCloseKey(hKey);

    SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
        (LPARAM)"Environment", SMTO_ABORTIFHUNG,
        5000, nullptr);

    return true;
}

// Remove installed files
void uninstall(const std::string& dir) {
    std::cout << "Uninstalling from: " << dir << std::endl;

    remove_from_path(dir);

    std::string cmd = "powershell -NoProfile -Command \"Remove-Item -Recurse -Force -Path '" + dir + "'\"";
    system(cmd.c_str());

    std::cout << "Uninstall complete." << std::endl;
}

void enable_vt_mode() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}


// --- Main installer logic ---
int main() {
    enable_vt_mode();

    std::cout << "\033[33m" << std::endl;
    std::wcout.imbue(std::locale(""));

    std::wcout << LR"(
       XWWWWWWX                 XWWWWWWWX        
       WWWWWWWWWW              WWWWWWWWWW        
       WWWWWWWWWWWX          XWWWWWWWWWWW        
       WWWWWWWWWWWWWX      XWWWWWWWWWWWWW        
       WWWWWWWWWWWWWWW    WWWWWWWWWWWWWWW        
       WWWWWWWWWWWWWWWWWXWWWWWWWWWWWWWWWW        
       WWWWWWW WWWWWWWWWWWWWWWWWWWWWWWWWW        
       WWWWWWW  XWWWWWWWWWWWWWW  WWWWWWWW        
       WWWWWWX    WWWWWWWWWWWX   WWWWWWWW        
       WWWWWWW      WWWWWWWW     XWWWWWWW        
       WWWWWWWX       WWWW       XWWWWWWW        
       WWWWWWWW        XX        XWWWWWWW        
       WWWWWWWWWW                XWWWWWWW        
        XWWWWWWWWWW              XWWWWWX         
          XWWWWWWWW              XWWWX           
            XWWWWWW              XWX             
              WWWWW                              
                WWW                              
                  W                              
    )" << std::endl;

    std::cout << "\033[0m" << std::endl;
    std::cout << "Welcome to the MRYA installer" << std::endl;
    std::cout << "(c) Gaupestudio 2025\n\n";

    std::string exePath = get_exe_path();
    if (exePath.empty()) {
        std::cout << "Failed to get exe path" << std::endl;
        return 1;
    }

    // Detect if installed already
    std::string dest = get_default_install_dir();
    DWORD attrib = GetFileAttributesA(dest.c_str());
    bool alreadyInstalled = (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));

    if (alreadyInstalled) {
        std::cout << "MRYA is already installed at " << dest << std::endl;
        std::cout << "[U]ninstall, [R]einstall/Upgrade, [Q]uit? ";
        std::string choice;
        std::getline(std::cin, choice);

        if (choice.empty()) choice = "Q";
        char c = toupper(choice[0]);
        if (c == 'Q') return 0;
        if (c == 'U') {
            uninstall(dest);
            return 0;
        }
        if (c == 'R') {
            uninstall(dest);
            std::cout << "Reinstalling..." << std::endl;
        }
    }

    // Read self to extract payload
    std::ifstream f(exePath, std::ios::binary);
    if (!f) {
        std::cout << "Failed to open exe" << std::endl;
        return 1;
    }
    std::vector<char> data((std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    f.close();

    const unsigned char zipSig[] = { 0x50,0x4B,0x03,0x04 };
    auto it = std::search(data.begin(), data.end(), zipSig, zipSig + 4);
    if (it == data.end()) {
        std::cout << "No ZIP payload found" << std::endl;
        return 2;
    }

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string outZip = std::string(tempPath) + "payload.zip";
    std::ofstream out(outZip, std::ios::binary);
    out.write(&(*it), data.end() - it);
    out.close();

    // Ask user for install dir (if not upgrade)
    if (!alreadyInstalled) {
        dest = ask_install_dir();
    }

    std::string mkdirCmd = "powershell -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '" + dest + "' | Out-Null\"";
    system(mkdirCmd.c_str());

    std::string cmd = "powershell -NoProfile -Command \"Expand-Archive -LiteralPath '" + outZip +
        "' -DestinationPath '" + dest + "' -Force\"";
    int rc = system(cmd.c_str());
    if (rc != 0) {
        std::cout << "Extraction failed" << std::endl;
        return 3;
    }

    if (!add_to_path(dest)) {
        std::cout << "Installed, but failed to update PATH" << std::endl;
    }
    else {
        std::cout << "Installation complete." << std::endl;
    }

    char buff[256];
    std::cin >> buff;

    return 0;
}
