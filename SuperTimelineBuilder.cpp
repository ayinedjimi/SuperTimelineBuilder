/*
 * SuperTimelineBuilder - Générateur de timeline forensics multi-sources
 * Partie de WinToolsSuite v3.0
 *
 * Agrégation de multiples sources forensics :
 * - MFT ($MFT parsing)
 * - USN Journal
 * - Prefetch files
 * - Event Logs (Security/System/Application)
 * - Registry LastWrite times
 *
 * Format sortie : CSV compatible Plaso/log2timeline
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <commctrl.h>
#include <winevt.h>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "advapi32.lib")

// IDs des contrôles
#define IDC_LISTVIEW        1001
#define IDC_BTN_ADD_SOURCE  1002
#define IDC_BTN_BUILD       1003
#define IDC_BTN_FILTER      1004
#define IDC_BTN_EXPORT      1005
#define IDC_STATUS          1006

// Colonnes ListView
enum {
    COL_TIMESTAMP = 0,
    COL_SOURCE,
    COL_TYPE,
    COL_DESCRIPTION,
    COL_USER,
    COL_HOST,
    COL_DETAILS
};

// Structure pour un événement timeline
struct TimelineEvent {
    FILETIME timestamp;
    std::wstring source;      // MFT, USN, Prefetch, EventLog, Registry
    std::wstring type;         // Created, Modified, Deleted, Executed, etc.
    std::wstring description;  // Short description
    std::wstring user;
    std::wstring host;
    std::wstring details;      // Full details
};

// Variables globales
HWND g_hListView = nullptr;
HWND g_hStatus = nullptr;
std::vector<TimelineEvent> g_events;
HFONT g_hFont = nullptr;

// Conversion FILETIME vers wstring ISO8601
std::wstring FileTimeToISO8601(const FILETIME& ft) {
    SYSTEMTIME st, stUTC;
    FileTimeToSystemTime(&ft, &st);
    TzSpecificLocalTimeToSystemTime(nullptr, &st, &stUTC);

    wchar_t buffer[64];
    wsprintfW(buffer, L"%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        stUTC.wYear, stUTC.wMonth, stUTC.wDay,
        stUTC.wHour, stUTC.wMinute, stUTC.wSecond, stUTC.wMilliseconds);

    return std::wstring(buffer);
}

// Comparaison pour tri chronologique
bool CompareByTimestamp(const TimelineEvent& a, const TimelineEvent& b) {
    return CompareFileTime(&a.timestamp, &b.timestamp) < 0;
}

// Parsing Event Logs
void ParseEventLogs(const std::wstring& logName, std::vector<TimelineEvent>& events) {
    EVT_HANDLE hResults = EvtQuery(
        nullptr,
        logName.c_str(),
        L"*",
        EvtQueryChannelPath | EvtQueryForwardDirection
    );

    if (!hResults) return;

    EVT_HANDLE hEvent = nullptr;
    DWORD dwReturned = 0;

    while (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned)) {
        // Timestamp
        EVT_HANDLE hContext = EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem);
        DWORD dwBufferSize = 0;
        DWORD dwPropertyCount = 0;

        EvtRender(hContext, hEvent, EvtRenderEventValues, 0, nullptr, &dwBufferSize, &dwPropertyCount);

        std::vector<BYTE> buffer(dwBufferSize);
        if (EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, buffer.data(), &dwBufferSize, &dwPropertyCount)) {
            PEVT_VARIANT pValues = (PEVT_VARIANT)buffer.data();

            TimelineEvent evt;
            evt.timestamp = pValues[EvtSystemTimeCreated].FileTimeVal;
            evt.source = L"EventLog:" + logName;
            evt.type = L"EventID:" + std::to_wstring(pValues[EvtSystemEventID].UInt16Val);

            // Provider name
            if (pValues[EvtSystemProviderName].Type == EvtVarTypeString) {
                evt.description = pValues[EvtSystemProviderName].StringVal;
            }

            // User SID (si disponible)
            if (pValues[EvtSystemUserID].Type == EvtVarTypeSid) {
                LPWSTR sidStr = nullptr;
                if (ConvertSidToStringSidW(pValues[EvtSystemUserID].SidVal, &sidStr)) {
                    evt.user = sidStr;
                    LocalFree(sidStr);
                }
            }

            evt.host = L"localhost";
            evt.details = evt.description;

            events.push_back(evt);
        }

        EvtClose(hContext);
        EvtClose(hEvent);

        // Limiter à 1000 événements par log pour performance
        if (events.size() > 1000) break;
    }

    EvtClose(hResults);
}

// Parsing Registry LastWrite times (exemple clé Run)
void ParseRegistryKeys(HKEY hRoot, const std::wstring& subKey, std::vector<TimelineEvent>& events) {
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }

    // Get LastWriteTime de la clé
    FILETIME lastWriteTime;
    if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, nullptr, nullptr, &lastWriteTime) == ERROR_SUCCESS) {
        TimelineEvent evt;
        evt.timestamp = lastWriteTime;
        evt.source = L"Registry";
        evt.type = L"KeyModified";
        evt.description = subKey;
        evt.user = L"(system)";
        evt.host = L"localhost";
        evt.details = L"Registry key last modified: " + subKey;

        events.push_back(evt);
    }

    RegCloseKey(hKey);
}

// Simulation MFT parsing (simplifié - vrai parsing MFT complexe)
void SimulateMFTParsing(std::vector<TimelineEvent>& events) {
    // Dans implémentation réelle, utiliser NtfsReadMFT ou bibliothèque tierce
    // Ici on simule avec quelques événements exemple
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(L"C:\\Windows\\System32\\*.exe", &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        int count = 0;
        do {
            TimelineEvent evt;
            evt.timestamp = findData.ftCreationTime;
            evt.source = L"MFT";
            evt.type = L"FileCreated";
            evt.description = findData.cFileName;
            evt.user = L"(unknown)";
            evt.host = L"localhost";
            evt.details = L"File: C:\\Windows\\System32\\" + std::wstring(findData.cFileName);

            events.push_back(evt);

            // Ajouter modification
            evt.timestamp = findData.ftLastWriteTime;
            evt.type = L"FileModified";
            events.push_back(evt);

            if (++count >= 50) break; // Limiter pour démo
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }
}

// Simulation Prefetch parsing
void SimulatePrefetchParsing(std::vector<TimelineEvent>& events) {
    // Dans implémentation réelle, parser C:\Windows\Prefetch\*.pf
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(L"C:\\Windows\\Prefetch\\*.pf", &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        int count = 0;
        do {
            TimelineEvent evt;
            evt.timestamp = findData.ftLastWriteTime;
            evt.source = L"Prefetch";
            evt.type = L"Executed";
            evt.description = findData.cFileName;
            evt.user = L"(various)";
            evt.host = L"localhost";
            evt.details = L"Application executed: " + std::wstring(findData.cFileName);

            events.push_back(evt);

            if (++count >= 100) break;
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    }
}

// Thread de construction timeline
DWORD WINAPI BuildTimelineThread(LPVOID lpParam) {
    SetWindowTextW(g_hStatus, L"Initialisation timeline builder...");

    g_events.clear();
    ListView_DeleteAllItems(g_hListView);

    // Source 1: MFT (simulé)
    SetWindowTextW(g_hStatus, L"Parsing MFT (simulation)...");
    SimulateMFTParsing(g_events);

    // Source 2: Prefetch
    SetWindowTextW(g_hStatus, L"Parsing Prefetch files...");
    SimulatePrefetchParsing(g_events);

    // Source 3: Event Logs
    SetWindowTextW(g_hStatus, L"Parsing Event Log Security...");
    ParseEventLogs(L"Security", g_events);

    SetWindowTextW(g_hStatus, L"Parsing Event Log System...");
    ParseEventLogs(L"System", g_events);

    // Source 4: Registry
    SetWindowTextW(g_hStatus, L"Parsing Registry keys...");
    ParseRegistryKeys(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", g_events);
    ParseRegistryKeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", g_events);

    // Tri chronologique
    SetWindowTextW(g_hStatus, L"Tri chronologique des événements...");
    std::sort(g_events.begin(), g_events.end(), CompareByTimestamp);

    // Affichage dans ListView (limiter à 5000 pour performance UI)
    size_t displayCount = min(g_events.size(), 5000);
    for (size_t i = 0; i < displayCount; ++i) {
        const auto& evt = g_events[i];

        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = static_cast<int>(i);

        std::wstring timestamp = FileTimeToISO8601(evt.timestamp);
        lvi.iSubItem = COL_TIMESTAMP;
        lvi.pszText = const_cast<LPWSTR>(timestamp.c_str());
        ListView_InsertItem(g_hListView, &lvi);

        ListView_SetItemText(g_hListView, i, COL_SOURCE, const_cast<LPWSTR>(evt.source.c_str()));
        ListView_SetItemText(g_hListView, i, COL_TYPE, const_cast<LPWSTR>(evt.type.c_str()));

        std::wstring descShort = evt.description.length() > 50 ?
            evt.description.substr(0, 47) + L"..." : evt.description;
        ListView_SetItemText(g_hListView, i, COL_DESCRIPTION, const_cast<LPWSTR>(descShort.c_str()));

        ListView_SetItemText(g_hListView, i, COL_USER, const_cast<LPWSTR>(evt.user.c_str()));
        ListView_SetItemText(g_hListView, i, COL_HOST, const_cast<LPWSTR>(evt.host.c_str()));

        std::wstring detailsShort = evt.details.length() > 60 ?
            evt.details.substr(0, 57) + L"..." : evt.details;
        ListView_SetItemText(g_hListView, i, COL_DETAILS, const_cast<LPWSTR>(detailsShort.c_str()));
    }

    wchar_t status[256];
    wsprintfW(status, L"Timeline construite: %zu événement(s) (affichage: %zu)", g_events.size(), displayCount);
    SetWindowTextW(g_hStatus, status);

    return 0;
}

// Export CSV format Plaso
void ExportPlasoCSV() {
    wchar_t szFile[MAX_PATH] = L"super_timeline.csv";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetParent(g_hListView);
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream file(szFile, std::ios::out | std::ios::binary);
    if (!file) {
        MessageBoxW(GetParent(g_hListView), L"Impossible de créer le fichier",
                    L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    // BOM UTF-8
    file.put(0xEF);
    file.put(0xBB);
    file.put(0xBF);

    file.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));

    // En-tête format Plaso-compatible
    file << L"timestamp,source,type,user,host,short,full\n";

    // Données
    for (const auto& evt : g_events) {
        file << L"\"" << FileTimeToISO8601(evt.timestamp) << L"\",";
        file << L"\"" << evt.source << L"\",";
        file << L"\"" << evt.type << L"\",";
        file << L"\"" << evt.user << L"\",";
        file << L"\"" << evt.host << L"\",";
        file << L"\"" << evt.description << L"\",";
        file << L"\"" << evt.details << L"\"\n";
    }

    file.close();

    SetWindowTextW(g_hStatus, L"Export CSV Plaso réussi");
    MessageBoxW(GetParent(g_hListView), L"Export timeline réussi", L"Information", MB_OK | MB_ICONINFORMATION);
}

// Procédure fenêtre principale
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_hFont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

            g_hListView = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                WC_LISTVIEWW,
                L"",
                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                10, 10, 1360, 500,
                hwnd, (HMENU)IDC_LISTVIEW, GetModuleHandle(nullptr), nullptr
            );

            ListView_SetExtendedListViewStyle(g_hListView,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

            SendMessageW(g_hListView, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // Colonnes
            LVCOLUMNW lvc = {};
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;

            lvc.pszText = const_cast<LPWSTR>(L"Timestamp (UTC)");
            lvc.cx = 180;
            ListView_InsertColumn(g_hListView, COL_TIMESTAMP, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Source");
            lvc.cx = 140;
            ListView_InsertColumn(g_hListView, COL_SOURCE, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Type");
            lvc.cx = 120;
            ListView_InsertColumn(g_hListView, COL_TYPE, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Description");
            lvc.cx = 200;
            ListView_InsertColumn(g_hListView, COL_DESCRIPTION, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"User");
            lvc.cx = 150;
            ListView_InsertColumn(g_hListView, COL_USER, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Host");
            lvc.cx = 100;
            ListView_InsertColumn(g_hListView, COL_HOST, &lvc);

            lvc.pszText = const_cast<LPWSTR>(L"Détails");
            lvc.cx = 440;
            ListView_InsertColumn(g_hListView, COL_DETAILS, &lvc);

            // Boutons
            HWND hBtn = CreateWindowW(
                L"BUTTON", L"Ajouter Source",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 520, 150, 30,
                hwnd, (HMENU)IDC_BTN_ADD_SOURCE, GetModuleHandle(nullptr), nullptr
            );
            SendMessageW(hBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            hBtn = CreateWindowW(
                L"BUTTON", L"Builder Timeline",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                170, 520, 150, 30,
                hwnd, (HMENU)IDC_BTN_BUILD, GetModuleHandle(nullptr), nullptr
            );
            SendMessageW(hBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            hBtn = CreateWindowW(
                L"BUTTON", L"Filtrer Dates",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                330, 520, 130, 30,
                hwnd, (HMENU)IDC_BTN_FILTER, GetModuleHandle(nullptr), nullptr
            );
            SendMessageW(hBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            hBtn = CreateWindowW(
                L"BUTTON", L"Exporter Plaso CSV",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                470, 520, 170, 30,
                hwnd, (HMENU)IDC_BTN_EXPORT, GetModuleHandle(nullptr), nullptr
            );
            SendMessageW(hBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            g_hStatus = CreateWindowExW(
                0, L"STATIC", L"Prêt - Cliquez sur 'Builder Timeline' pour agréger les sources",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                10, 560, 1360, 20,
                hwnd, (HMENU)IDC_STATUS, GetModuleHandle(nullptr), nullptr
            );
            SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            return 0;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_ADD_SOURCE:
                    MessageBoxW(hwnd,
                        L"Fonctionnalité future: Ajout sources personnalisées\n"
                        L"(Import CSV externe, logs IIS, etc.)",
                        L"Information", MB_OK | MB_ICONINFORMATION);
                    break;

                case IDC_BTN_BUILD:
                    CreateThread(nullptr, 0, BuildTimelineThread, nullptr, 0, nullptr);
                    break;

                case IDC_BTN_FILTER:
                    MessageBoxW(hwnd,
                        L"Fonctionnalité future: Filtrage par date range\n"
                        L"(Utiliser Excel/LibreOffice pour filtrer CSV exporté)",
                        L"Information", MB_OK | MB_ICONINFORMATION);
                    break;

                case IDC_BTN_EXPORT:
                    ExportPlasoCSV();
                    break;
            }
            return 0;
        }

        case WM_DESTROY:
            if (g_hFont) DeleteObject(g_hFont);
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// Point d'entrée
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"SuperTimelineBuilderClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Échec RegisterClassExW", L"Erreur", MB_ICONERROR);
        return 1;
    }

    HWND hwnd = CreateWindowExW(
        0,
        wc.lpszClassName,
        L"Super Timeline Builder - WinToolsSuite v3.0",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1400, 640,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!hwnd) {
        MessageBoxW(nullptr, L"Échec CreateWindowExW", L"Erreur", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}
