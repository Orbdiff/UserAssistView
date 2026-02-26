#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <ctime>
#include "../userassist/userassist_ui.hpp"
#include "icons/icon_loader.h"
#include "../time/_time_utils.h"

extern std::vector<UserAssistEntryUI> g_entries;
extern std::mutex                     g_mutex;
extern std::atomic<bool>              g_done;

extern char   searchBuffer[256];
extern bool   g_afterLogonOnly;
extern bool   g_showUnsignedCheat;
extern bool   g_showNotFound;
extern time_t g_logonTime;

void StartBackgroundScan();
void SetupImGuiStyle();
void LoadFonts();
void RunMainLoop(HWND hwnd);