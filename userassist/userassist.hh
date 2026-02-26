#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include <shlobj.h>
#include <objbase.h>
#include <Knownfolders.h>
#include <cwctype>
#include <future>
#include <unordered_map>

#include "../signature/_signature_parser.h"
#include "../yara/_yara_scan.hpp"
#include "../replaces/usn_reader.h"

struct UserAssistEntry
{
    std::wstring path;
    std::wstring guid;
    SignatureStatus status = SignatureStatus::NotFound;
    uint32_t runCount = 0;
    uint32_t focusCount = 0;
    uint64_t lastExecuted = 0;
    std::wstring lastExecutedStr;
    std::wstring focusTimeReadable;
    bool fileExists = false;
    bool hasValidData = false;
    std::vector<ReplaceInfo> replaces;
};

inline void rot13_inplace(std::wstring& input) noexcept 
{
    for (wchar_t& c : input)
    {
        if (std::iswalpha(c)) 
        {
            const wchar_t base = std::iswupper(c) ? L'A' : L'a';
            c = static_cast<wchar_t>((c - base + 13) % 26 + base);
        }
    }
}

inline std::wstring decode_known_folder(std::wstring path) 
{
    size_t pos = 0;
    while ((pos = path.find(L'{', pos)) != std::wstring::npos)
    {
        const size_t end = path.find(L'}', pos);
        if (end == std::wstring::npos) break;

        const std::wstring guidStr = path.substr(pos, end - pos + 1);
        GUID guid;

        if (SUCCEEDED(CLSIDFromString(guidStr.c_str(), &guid))) 
        {
            PWSTR folderPath = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(guid, 0, nullptr, &folderPath)))
            {
                std::wstring resolvedPath(folderPath);
                path.replace(pos, guidStr.length(), resolvedPath);
                CoTaskMemFree(folderPath);
                pos += resolvedPath.length();
                continue;
            }
        }
        pos = end + 1;
    }
    return path;
}

inline std::wstring filetime_to_string(uint64_t filetime) noexcept 
{
    if (filetime == 0) return L"-";

    const FILETIME ft{ static_cast<DWORD>(filetime & 0xFFFFFFFF), static_cast<DWORD>(filetime >> 32) };
    FILETIME localFt;
    if (!FileTimeToLocalFileTime(&ft, &localFt)) return L"-";

    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&localFt, &st)) return L"-";

    return std::format(L"{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

inline std::wstring focus_time_to_string(uint32_t milliseconds) noexcept 
{
    if (milliseconds == 0) return L"-";
    if (milliseconds < 1000) return std::format(L"{} ms", milliseconds);

    const uint32_t totalSeconds = milliseconds / 1000;
    const uint32_t hours = totalSeconds / 3600;
    const uint32_t minutes = (totalSeconds % 3600) / 60;
    const uint32_t seconds = totalSeconds % 60;

    if (hours >= 1) return std::format(L"{:02d}h {:02d}m {:02d}s", hours, minutes, seconds);
    if (minutes >= 1) return std::format(L"{:02d}m {:02d}s", minutes, seconds);
    return std::format(L"{:02d}s", seconds);
}

inline std::wstring get_system_drive() noexcept
{
    WCHAR systemPath[MAX_PATH] = { 0 };

    if (GetSystemDirectoryW(systemPath, MAX_PATH) == 0)
    {
        return L"C:";
    }

    std::wstring path(systemPath);
    if (path.length() >= 2 && path[1] == L':') 
    {
        return path.substr(0, 2);
    }

    return L"C:";
}

inline std::unordered_map<std::wstring, std::vector<ReplaceInfo>> CollectReplacesByPath(const std::wstring& volume)
{
    auto replaces = Run(volume);
    std::unordered_map<std::wstring, std::vector<ReplaceInfo>> map;

    for (const auto& r : replaces)
    {
        map[r.fullPath].push_back(r);
    }

    return map;
}

inline std::vector<UserAssistEntry> scan_user_assist(const std::wstring& volume = L"")
{
    std::vector<UserAssistEntry> entries;
    entries.reserve(512);

    const std::wstring effectiveVolume = volume.empty() ? get_system_drive() : volume;

    HRESULT hr = CoInitialize(nullptr);
    if (FAILED(hr)) {
        return entries;
    }

    InitGenericRules();
    InitYara();

    auto replacesByPath = CollectReplacesByPath(effectiveVolume);

    constexpr wchar_t baseKeyPath[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    HKEY hBaseKey = nullptr;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, baseKeyPath, 0, KEY_READ, &hBaseKey) != ERROR_SUCCESS) {
        FinalizeYara();
        CoUninitialize();
        return entries;
    }

    WCHAR subkeyName[256];
    DWORD subkeyNameSize = 256;
    DWORD index = 0;

    while (true) {
        subkeyNameSize = 256;
        const LONG result = RegEnumKeyExW(hBaseKey, index++, subkeyName, &subkeyNameSize, nullptr, nullptr, nullptr, nullptr);

        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) continue;

        const std::wstring guidName(subkeyName);
        HKEY hGuidKey = nullptr;

        if (RegOpenKeyExW(hBaseKey, subkeyName, 0, KEY_READ, &hGuidKey) != ERROR_SUCCESS) continue;

        HKEY hCountKey = nullptr;
        if (RegOpenKeyExW(hGuidKey, L"Count", 0, KEY_READ, &hCountKey) != ERROR_SUCCESS) {
            RegCloseKey(hGuidKey);
            continue;
        }

        WCHAR valueName[256];
        BYTE data[1024];
        DWORD valueIndex = 0;

        while (true)
        {
            DWORD valueNameSize = 256;
            DWORD dataSize = 1024;
            DWORD type = 0;

            const LONG result = RegEnumValueW(hCountKey, valueIndex++, valueName, &valueNameSize, nullptr, &type, data, &dataSize);

            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result != ERROR_SUCCESS) continue;

            std::wstring decodedName(valueName);
            rot13_inplace(decodedName);
            decodedName = decode_known_folder(std::move(decodedName));

            std::wstring filePath = decodedName;

            const size_t colonPos = filePath.find(L':');
            if (colonPos != std::wstring::npos && colonPos > 0 && colonPos + 2 < filePath.size() && filePath[colonPos + 1] == L'\\') {
                filePath = filePath.substr(0, 2) + filePath.substr(colonPos + 1);
            }

            for (wchar_t& c : filePath) 
            {
                if (c == L'/') c = L'\\';
            }

            UserAssistEntry entry;
            entry.path = std::move(decodedName);
            entry.guid = guidName;
            entry.fileExists = PathFileExistsW(filePath.c_str());
            entry.hasValidData = false;
            entry.lastExecuted = 0;

            if (entry.fileExists)
            {
                SignatureStatus sigStatus = GetSignatureStatus(filePath);

                if (sigStatus == SignatureStatus::Unsigned) {
                    const int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), static_cast<int>(filePath.size()), nullptr, 0, nullptr, nullptr);
                    std::string narrowPath(sizeNeeded, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, filePath.c_str(), static_cast<int>(filePath.size()), narrowPath.data(), sizeNeeded, nullptr, nullptr);

                    std::vector<std::string> yaraMatches;
                    if (FastScanFile(narrowPath, yaraMatches))
                    {
                        sigStatus = SignatureStatus::Cheat;
                    }
                }
                entry.status = sigStatus;
            }
            else {
                entry.status = SignatureStatus::NotFound;
            }

            if (dataSize >= 72)
            {
                entry.hasValidData = true;
                entry.runCount = *reinterpret_cast<uint32_t*>(&data[4]);
                entry.focusCount = *reinterpret_cast<uint32_t*>(&data[8]);
                entry.lastExecuted = *reinterpret_cast<uint64_t*>(&data[60]);
                entry.lastExecutedStr = filetime_to_string(entry.lastExecuted);
                entry.focusTimeReadable = focus_time_to_string(*reinterpret_cast<uint32_t*>(&data[12]));
            }

            auto it = replacesByPath.find(entry.path);
            if (it != replacesByPath.end())
            {
                entry.replaces = it->second;
            }

            entries.push_back(std::move(entry));
        }

        RegCloseKey(hCountKey);
        RegCloseKey(hGuidKey);
    }

    RegCloseKey(hBaseKey);

    FinalizeYara();
    CoUninitialize();

    std::ranges::sort(entries, [](const UserAssistEntry& a, const UserAssistEntry& b) noexcept 
        {
        return a.lastExecuted > b.lastExecuted;
        });

    return entries;
}