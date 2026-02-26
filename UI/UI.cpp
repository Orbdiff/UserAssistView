#include "UI.h"
#include "dx/dx_renderer.h"

#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <algorithm>
#include <shlobj.h>
#include <thread>

#include "../userassist/userassist.hh"
#include "fonts/font.h"
#include "../time/_time_utils.h"

std::vector<UserAssistEntryUI> g_entries;
std::mutex                     g_mutex;
std::atomic<bool>              g_done(false);

char searchBuffer[256]   = "";
bool g_afterLogonOnly    = false;
bool g_showUnsignedCheat = false;
bool g_showNotFound      = false;
time_t g_logonTime       = 0;
std::string lastSearch;

int g_lastSortColumn     = 0;
bool g_lastSortAscending = true;
std::vector<UserAssistEntryUI> g_lastFilteredEntries;
std::vector<UserAssistEntryUI> g_sortedEntries;

static bool showReplacePopup = false;
static UserAssistEntryUI selectedEntryForReplace{};
static float fadeAlphaReplace = 0.0f;

void StartBackgroundScan()
{
    g_logonTime = GetCurrentUserLogonTime();

    std::thread scanThread([]()
        {
            auto results = scan_user_assist();
            auto uiResults = ConvertToUI(results);
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_entries = std::move(uiResults);
            }
            g_done = true;
        });
    scanThread.detach();
}

bool IsEntryAfterLogon(const UserAssistEntryUI& entry)
{
    if (g_logonTime == 0) return false;

    struct tm tmLocal = {};
    int year, month, day, hour, minute, second;
    if (sscanf(entry.lastExecutedStr.c_str(), "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second) == 6)
    {
        tmLocal.tm_year = year - 1900;
        tmLocal.tm_mon = month - 1;
        tmLocal.tm_mday = day;
        tmLocal.tm_hour = hour;
        tmLocal.tm_min = minute;
        tmLocal.tm_sec = second;
        time_t entryTime = mktime(&tmLocal);
        return entryTime >= g_logonTime;
    }
    return false;
}

inline void RenderStatusCell(SignatureStatus status, const std::string& statusStr)
{
    ImVec4 color;
    switch (status) {
    case SignatureStatus::Cheat:      color = ImVec4(1.0f, 0.2f, 0.2f, 1.0f); break;
    case SignatureStatus::Signed:     color = ImVec4(0.4f, 1.0f, 0.4f, 1.0f); break;
    case SignatureStatus::Unsigned:   color = ImVec4(1.0f, 0.4f, 0.4f, 1.0f); break;
    case SignatureStatus::NotFound:   color = ImVec4(1.0f, 0.8f, 0.4f, 1.0f); break;
    case SignatureStatus::NotMZ:      color = ImVec4(0.5f, 0.5f, 0.5f, 1);    break;
    case SignatureStatus::Fake:       color = ImVec4(1.0f, 0.5f, 0.5f, 1.0f); break;
    default:                          color = ImVec4(1, 1, 1, 1); break;
    }
    ImGui::TextColored(color, "%s", statusStr.c_str());
}

inline int GetStatusOrder(SignatureStatus status)
{
    switch (status) {
    case SignatureStatus::Signed:     return 0;
    case SignatureStatus::Unsigned:   return 1;
    case SignatureStatus::Cheat:      return 2;
    case SignatureStatus::Fake:       return 3;
    case SignatureStatus::NotFound:   return 4;
    case SignatureStatus::NotMZ:      return 5;
    default:                          return 6;
    }
}

bool SortEntries(const UserAssistEntryUI& a, const UserAssistEntryUI& b)
{
    int column = g_lastSortColumn;
    bool ascending = g_lastSortAscending;
    switch (column) {
    case 0:
        return ascending ? a.lastExecutedStr < b.lastExecutedStr : a.lastExecutedStr > b.lastExecutedStr;
    case 1:
        return ascending ? a.path < b.path : a.path > b.path;
    case 2: {
        int orderA = GetStatusOrder(a.status);
        int orderB = GetStatusOrder(b.status);
        return ascending ? orderA < orderB : orderA > orderB;
    }
    case 3:
        return ascending ? a.runCount < b.runCount : a.runCount > b.runCount;
    case 4:
        return ascending ? a.focusCount < b.focusCount : a.focusCount > b.focusCount;
    case 5:
        return ascending ? a.focusTimeReadable < b.focusTimeReadable : a.focusTimeReadable > b.focusTimeReadable;
    default:
        return false;
    }
}

bool EntriesMatch(const UserAssistEntryUI& a, const UserAssistEntryUI& b)
{
    return a.path == b.path &&
        a.status == b.status &&
        a.statusStr == b.statusStr &&
        a.runCount == b.runCount &&
        a.focusCount == b.focusCount &&
        a.lastExecutedStr == b.lastExecutedStr &&
        a.focusTimeReadable == b.focusTimeReadable &&
        a.fileExists == b.fileExists;
}

bool FilteredEntriesChanged(const std::vector<UserAssistEntryUI>& a, const std::vector<UserAssistEntryUI>& b)
{
    if (a.size() != b.size())
        return true;
    for (size_t i = 0; i < a.size(); i++)
    {
        if (!EntriesMatch(a[i], b[i]))
            return true;
    }
    return false;
}

void SetupImGuiStyle()
{
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    colors[ImGuiCol_Text]                 = ImVec4(0.95f, 0.95f, 0.95f, 1.00f);
    colors[ImGuiCol_TextDisabled]         = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
    colors[ImGuiCol_WindowBg]             = ImVec4(0.09f, 0.09f, 0.09f, 1.00f);
    colors[ImGuiCol_ChildBg]              = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
    colors[ImGuiCol_PopupBg]              = ImVec4(0.11f, 0.11f, 0.11f, 0.94f);
    colors[ImGuiCol_Border]               = ImVec4(0.19f, 0.19f, 0.19f, 1.00f);
    colors[ImGuiCol_BorderShadow]         = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]              = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]       = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    colors[ImGuiCol_FrameBgActive]        = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_TitleBg]              = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_TitleBgActive]        = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]     = ImVec4(0.08f, 0.08f, 0.08f, 0.75f);
    colors[ImGuiCol_MenuBarBg]            = ImVec4(0.11f, 0.11f, 0.11f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]          = ImVec4(0.08f, 0.08f, 0.08f, 1.00f);
    colors[ImGuiCol_ScrollbarGrab]        = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.30f, 0.30f, 0.30f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.35f, 0.35f, 0.35f, 1.00f);
    colors[ImGuiCol_Separator]            = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    colors[ImGuiCol_SeparatorHovered]     = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_SeparatorActive]      = ImVec4(0.30f, 0.30f, 0.30f, 1.00f);
    colors[ImGuiCol_Tab]                  = ImVec4(0.12f, 0.12f, 0.12f, 1.00f);
    colors[ImGuiCol_TabHovered]           = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
    colors[ImGuiCol_TabActive]            = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
    colors[ImGuiCol_TabUnfocused]         = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
    colors[ImGuiCol_TabUnfocusedActive]   = ImVec4(0.13f, 0.13f, 0.13f, 1.00f);
    colors[ImGuiCol_TableHeaderBg]        = ImVec4(0.12f, 0.12f, 0.12f, 1.00f);
    colors[ImGuiCol_TableBorderStrong]    = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
    colors[ImGuiCol_TableBorderLight]     = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
    colors[ImGuiCol_TableRowBg]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]        = ImVec4(0.11f, 0.11f, 0.11f, 1.00f);
    colors[ImGuiCol_ResizeGrip]           = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
    colors[ImGuiCol_ResizeGripHovered]    = ImVec4(0.30f, 0.30f, 0.30f, 1.00f);
    colors[ImGuiCol_ResizeGripActive]     = ImVec4(0.35f, 0.35f, 0.35f, 1.00f);
    colors[ImGuiCol_Button]               = ImVec4(0.18f, 0.18f, 0.18f, 1.00f);
    colors[ImGuiCol_ButtonHovered]        = ImVec4(0.22f, 0.36f, 0.55f, 1.00f);
    colors[ImGuiCol_ButtonActive]         = ImVec4(0.25f, 0.40f, 0.65f, 1.00f);
    colors[ImGuiCol_CheckMark]            = ImVec4(0.35f, 0.55f, 0.80f, 1.00f);
    colors[ImGuiCol_SliderGrab]           = ImVec4(0.25f, 0.40f, 0.65f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]     = ImVec4(0.30f, 0.50f, 0.75f, 1.00f);
    colors[ImGuiCol_Header]               = ImVec4(0.20f, 0.20f, 0.20f, 0.80f);
    colors[ImGuiCol_HeaderHovered]        = ImVec4(0.22f, 0.36f, 0.55f, 0.90f);
    colors[ImGuiCol_HeaderActive]         = ImVec4(0.25f, 0.40f, 0.65f, 0.90f);

    style.WindowRounding = 6.0f;
    style.FrameRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.TabRounding = 5.0f;
    style.WindowBorderSize = 1.0f;
    style.FrameBorderSize = 1.0f;
    style.ScrollbarSize = 14.0f;
    style.ItemSpacing = ImVec2(8, 6);
    style.ItemInnerSpacing = ImVec2(6, 4);
    style.CellPadding = ImVec2(6, 4);
    style.WindowPadding = ImVec2(14, 14);
    style.FramePadding = ImVec2(8, 5);
}

void LoadFonts()
{
    ImGuiIO& io = ImGui::GetIO();
    ImFont* poppins = io.Fonts->AddFontFromMemoryCompressedTTF(Poppins_Medium_compressed_data, Poppins_Medium_compressed_size, 17.0f);
    io.FontDefault = poppins;
}

void RunMainLoop(HWND hwnd)
{
    bool done = false;
    static float fadeOutAlpha = 1.0f;
    static bool showLoadingAnimation = true;
    const float fadeOutSpeed = 4.0f;

    while (!done)
    {
        MSG msg;
        while (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }

        if (done) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGuiWindowFlags windowFlags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBackground;

        RECT rect;
        GetClientRect(hwnd, &rect);
        ImGui::SetNextWindowSize(ImVec2(float(rect.right - rect.left), float(rect.bottom - rect.top)), ImGuiCond_Always);
        ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
        ImGui::Begin("UserAssist Viewer", nullptr, windowFlags);

        if (!g_done || showLoadingAnimation)
        {
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            float time = (float)ImGui::GetTime();

            ImVec2 pos = ImGui::GetWindowPos();
            ImVec2 size = ImGui::GetWindowSize();
            ImVec2 center = ImVec2(pos.x + size.x * 0.5f, pos.y + size.y * 0.5f);

            float radius = 16.0f;
            float thickness = 4.0f;
            ImVec2 spinnerCenter = ImVec2(center.x, center.y - 30.0f);

            int num_segments = 25;
            float start = abs(sinf(time * 1.8f) * (num_segments - 5));

            float a_min = 6.28318530718f * ((float)start) / (float)num_segments;
            float a_max = 6.28318530718f * ((float)num_segments - 3) / (float)num_segments;

            ImU32 accentCol = IM_COL32(255, 245, 150, (int)(255 * fadeOutAlpha));

            draw_list->PathClear();
            for (int i = 0; i < num_segments; i++)
            {
                const float a = a_min + ((float)i / (float)num_segments) * (a_max - a_min);
                draw_list->PathLineTo(ImVec2(spinnerCenter.x + cosf(a + time * -8) * radius, spinnerCenter.y + sinf(a + time * -8) * radius));
            }
            draw_list->PathStroke(accentCol, false, thickness);

            const char* loadingText = "Parsing UserAssist Entries";
            ImVec2 textSize = ImGui::CalcTextSize(loadingText);
            ImVec2 textPos = ImVec2(center.x - textSize.x * 0.5f, center.y + 25.0f);

            draw_list->AddText(textPos, IM_COL32(255, 245, 200, (int)(255 * fadeOutAlpha)), loadingText);

            if (g_done && showLoadingAnimation)
            {
                fadeOutAlpha -= ImGui::GetIO().DeltaTime * fadeOutSpeed;
                if (fadeOutAlpha <= 0.0f) {
                    fadeOutAlpha = 0.0f;
                    showLoadingAnimation = false;
                }
            }
        }
        else {
            if (showReplacePopup)
            {
                ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(0.0f, 0.0f, 0.0f, 0.6f));
                ImGui::OpenPopup("Replace Details Modal");
                ImVec2 center = ImGui::GetMainViewport()->GetCenter();
                ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

                static bool firstOpen = true;
                if (firstOpen)
                {
                    ImGui::SetNextWindowSize(ImVec2(1000, 600));
                    firstOpen = false;
                }

                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
                if (ImGui::BeginPopupModal("Replace Details Modal", &showReplacePopup))
                {
                    ImGui::PopStyleColor();
                    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 20));

                    ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "File: ");
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "%s", selectedEntryForReplace.path.c_str());

                    ImGui::Separator();

                    int replaceIndex = 0;
                    for (const auto& r : selectedEntryForReplace.replaces)
                    {
                        ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "USN: %llu", r.lastUsn);
                        ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "Time: %s", r.endTime.c_str());
                        ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "Replace: %s", r.type.c_str());

                        if (!r.reasons.empty())
                        {
                            std::string treeId = "Events_" + std::to_string(replaceIndex);
                            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
                            if (ImGui::TreeNode(treeId.c_str(), "Events"))
                            {
                                ImGui::PopStyleColor();
                                for (const auto& ev : r.reasons)
                                {
                                    ImGui::Bullet();
                                    ImGui::SameLine();
                                    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "%s", ev.c_str());
                                }
                                ImGui::TreePop();
                            }
                            else
                            {
                                ImGui::PopStyleColor();
                            }
                        }

                        ImGui::Dummy(ImVec2(0, 15));
                        replaceIndex++;
                    }

                    ImGui::PopStyleVar();
                    ImGui::EndPopup();
                }
                else
                {
                    ImGui::PopStyleColor();
                }
                ImGui::PopStyleColor();
            }

            std::lock_guard<std::mutex> lock(g_mutex);

            ImGui::PushItemWidth(400);
            ImGui::InputTextWithHint("##SearchUserAssist", "Search...", searchBuffer, sizeof(searchBuffer));
            ImGui::PopItemWidth();

            ImGui::SameLine(0, 20);
            ImGui::Checkbox("In Instance", &g_afterLogonOnly);
            if (ImGui::IsItemHovered()) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.4f, 1.0f));
                ImGui::SetTooltip("Show all paths entries after logon time");
                ImGui::PopStyleColor();
            }
            ImGui::SameLine();
            ImGui::Checkbox("Show Untrusted", &g_showUnsignedCheat);
            if (ImGui::IsItemHovered()) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.4f, 1.0f));
                ImGui::SetTooltip("Show paths without a valid signature, fake signature, cheat signature or matching YARA rules");
                ImGui::PopStyleColor();
            }
            ImGui::SameLine();
            ImGui::Checkbox("Show NotFound", &g_showNotFound);
            if (ImGui::IsItemHovered()) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.4f, 1.0f));
                ImGui::SetTooltip("Show paths where the signature status is NotFound");
                ImGui::PopStyleColor();
            }

            ImGui::Separator();
            ImGui::Spacing();

            std::string currentSearch(searchBuffer);
            std::transform(currentSearch.begin(), currentSearch.end(), currentSearch.begin(), ::tolower);

            bool filtersChanged = (lastSearch != currentSearch);

            if (filtersChanged)
            {
                lastSearch = currentSearch;
            }

            std::vector<UserAssistEntryUI> filteredEntries;
            for (const auto& entry : g_entries)
            {
                bool showEntry = true;

                if (g_afterLogonOnly)
                {
                    if (!IsEntryAfterLogon(entry))
                        showEntry = false;
                }

                if (g_showUnsignedCheat || g_showNotFound)
                {
                    if (!((g_showUnsignedCheat && (entry.status == SignatureStatus::Unsigned || entry.status == SignatureStatus::Cheat || entry.status == SignatureStatus::Fake)) ||
                        (g_showNotFound && entry.status == SignatureStatus::NotFound))) {
                        showEntry = false;
                    }
                }

                if (!currentSearch.empty() && showEntry)
                {
                    std::string pathLower = entry.path;
                    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);

                    std::string statusLower = entry.statusStr;
                    std::transform(statusLower.begin(), statusLower.end(), statusLower.begin(), ::tolower);

                    if (pathLower.find(currentSearch) == std::string::npos &&
                        statusLower.find(currentSearch) == std::string::npos)
                    {
                        showEntry = false;
                    }
                }

                if (showEntry)
                {
                    filteredEntries.push_back(entry);
                }
            }

            if (FilteredEntriesChanged(filteredEntries, g_lastFilteredEntries) || filtersChanged)
            {
                g_sortedEntries = filteredEntries;
                g_lastFilteredEntries = filteredEntries;

                if (!g_sortedEntries.empty())
                {
                    std::sort(g_sortedEntries.begin(), g_sortedEntries.end(), SortEntries);
                }
            }

            if (ImGui::BeginTable("UserAssist", 6,
                ImGuiTableFlags_Sortable |
                ImGuiTableFlags_Resizable |
                ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY |
                ImGuiTableFlags_ScrollX |
                ImGuiTableFlags_BordersOuterV |
                ImGuiTableFlags_BordersOuterH |
                ImGuiTableFlags_Hideable |
                ImGuiTableFlags_SizingStretchSame)) {

                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Executed Time", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 100);
                ImGui::TableSetupColumn("Run Count", ImGuiTableColumnFlags_WidthFixed, 80);
                ImGui::TableSetupColumn("Focus Count", ImGuiTableColumnFlags_WidthFixed, 100);
                ImGui::TableSetupColumn("Focus Time", ImGuiTableColumnFlags_WidthFixed, 100);
                ImGui::TableHeadersRow();

                ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs();
                if (sortSpecs && sortSpecs->SpecsCount > 0) {
                    int sortColumn = sortSpecs->Specs[0].ColumnIndex;
                    bool ascending = sortSpecs->Specs[0].SortDirection == ImGuiSortDirection_Ascending;

                    if (sortColumn != g_lastSortColumn || ascending != g_lastSortAscending)
                    {
                        g_lastSortColumn = sortColumn;
                        g_lastSortAscending = ascending;

                        if (!g_sortedEntries.empty())
                        {
                            std::sort(g_sortedEntries.begin(), g_sortedEntries.end(), SortEntries);
                        }
                    }
                }

                ImGuiListClipper clipper;
                clipper.Begin((int)g_sortedEntries.size());

                while (clipper.Step()) {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++)
                    {
                        const auto& entry = g_sortedEntries[row];
                        bool hasReplaces = !entry.replaces.empty();

                        ImGui::TableNextRow();

                        ImGui::TableNextColumn();
                        ImGui::Text("%s", entry.lastExecutedStr.c_str());

                        ImGui::TableNextColumn();
                        ImGui::BeginGroup();

                        std::wstring wpath = std::wstring(entry.path.begin(), entry.path.end());
                        IconDataDX11* iconPtr = GetOrQueueIcon(g_pd3dDevice, wpath);
                        if (iconPtr && iconPtr->IsLoaded) {
                            ImGui::Image(iconPtr->TextureView.Get(), ImVec2(16, 16));
                            ImGui::SameLine(0, 5);
                        }

                        ImVec4 pathColor = ImVec4(1, 1, 1, 1);
                        if (hasReplaces)
                            pathColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);

                        ImGui::PushStyleColor(ImGuiCol_Text, pathColor);
                        ImGui::Text("%s", entry.path.c_str());
                        ImGui::PopStyleColor();

                        if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip))
                        {
                            if (ImGui::CalcTextSize(entry.path.c_str()).x > ImGui::GetColumnWidth(-1)) 
                            {
                                ImGui::SetTooltip("%s", entry.path.c_str());
                            }
                        }

                        if (hasReplaces)
                        {
                            if (ImGui::IsItemClicked(ImGuiMouseButton_Left))
                            {
                                selectedEntryForReplace = entry;
                                showReplacePopup = true;
                            }
                        }

                        std::string popupId = "PathPopup_" + std::to_string(row);
                        if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                            ImGui::OpenPopup(popupId.c_str());

                        if (ImGui::BeginPopup(popupId.c_str()))
                        {
                            if (ImGui::MenuItem("Open Path")) 
                            {
                                std::wstring folderPath = wpath;
                                size_t pos = folderPath.find_last_of(L"\\/");

                                if (pos != std::wstring::npos)
                                    folderPath = folderPath.substr(0, pos);

                                if (!folderPath.empty())
                                    ShellExecuteW(nullptr, L"explore", folderPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                            }

                            if (ImGui::MenuItem("Copy Path"))
                                ImGui::SetClipboardText(entry.path.c_str());

                            ImGui::EndPopup();
                        }

                        ImGui::EndGroup();

                        ImGui::TableNextColumn();
                        RenderStatusCell(entry.status, entry.statusStr);

                        ImGui::TableNextColumn();
                        ImGui::Text("%u", entry.runCount);

                        ImGui::TableNextColumn();
                        ImGui::Text("%u", entry.focusCount);

                        ImGui::TableNextColumn();
                        ImGui::Text("%s", entry.focusTimeReadable.c_str());
                    }
                }
                ImGui::EndTable();
            }
        }

        ImGui::End();

        ImGui::Render();
        float clear_color[4] = { 0.09f, 0.09f, 0.09f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }
}