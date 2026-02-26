#pragma once

#include "userassist.hh"
#include "../replaces/usn_reader.h"
#include <string>
#include <vector>
#include <windows.h>

struct ReplaceInfoUI 
{
    std::string type;
    std::string startTime;
    std::string endTime;
    ULONGLONG lastUsn;
    std::vector<std::string> reasons;
};

struct UserAssistEntryUI 
{
    std::string path;
    std::string statusStr;
    SignatureStatus status;

    uint32_t runCount = 0;
    uint32_t focusCount = 0;
    std::string lastExecutedStr;
    std::string focusTimeReadable;

    bool fileExists = false;

    std::vector<ReplaceInfoUI> replaces;
};

inline std::string WideToUtf8(const std::wstring& wstr)
{
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return {};
    std::string out(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), out.data(), size_needed, nullptr, nullptr);
    return out;
}

inline std::string FileTimeToString(const FILETIME& ft)
{
    SYSTEMTIME utc{}, local{};
    FileTimeToSystemTime(&ft, &utc);
    SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local);

    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond);

    return buf;
}

inline std::vector<ReplaceInfoUI> ConvertReplacesToUI(const std::vector<ReplaceInfo>& in)
{
    std::vector<ReplaceInfoUI> out;
    out.reserve(in.size());

    for (const auto& r : in) {
        ReplaceInfoUI ui{};
        ui.type = r.type;
        ui.startTime = FileTimeToString(r.startTime);
        ui.endTime = FileTimeToString(r.endTime);
        ui.lastUsn = r.lastUsn;

        for (const auto& ev : r.events) {
            ui.reasons.push_back(ev.reason);
        }

        out.emplace_back(std::move(ui));
    }

    return out;
}

inline std::vector<UserAssistEntryUI> ConvertToUI(const std::vector<UserAssistEntry>& in) 
{
    std::vector<UserAssistEntryUI> out;
    out.reserve(in.size());

    for (const auto& entry : in) 
    {
        UserAssistEntryUI ui{};

        ui.path = WideToUtf8(entry.path);

        switch (entry.status) {
        case SignatureStatus::Cheat:     ui.statusStr = "Cheat"; break;
        case SignatureStatus::Signed:    ui.statusStr = "Signed"; break;
        case SignatureStatus::Fake:      ui.statusStr = "Fake Signature"; break;
        case SignatureStatus::Unsigned:  ui.statusStr = "UnSigned"; break;
        case SignatureStatus::NotFound:  ui.statusStr = "Not Found"; break;
        case SignatureStatus::NotMZ:     ui.statusStr = "Not MZ"; break;
        default:                         ui.statusStr = "Unknown"; break;
        }

        ui.status = entry.status;
        ui.runCount = entry.runCount;
        ui.focusCount = entry.focusCount;
        ui.lastExecutedStr = WideToUtf8(entry.lastExecutedStr);
        ui.focusTimeReadable = WideToUtf8(entry.focusTimeReadable);
        ui.fileExists = entry.fileExists;

        ui.replaces = ConvertReplacesToUI(entry.replaces);

        out.emplace_back(std::move(ui));
    }

    return out;
}