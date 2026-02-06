#include "diagnostics.h"

#include "../calamari.public/byond.h"
#include "../calamari.public/events.h"
#include "../imgui/imgui.h"
#include <Psapi.h>
#include <ShlObj.h>
#include <chrono>
#include <ctime>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

namespace
{
    struct ModuleEntry
    {
        std::string name;
        std::string path;
        uintptr_t base = 0;
        size_t size = 0;
        uintptr_t entryPoint = 0;
        unsigned long timestamp = 0;
        std::vector<IMAGE_SECTION_HEADER> sections;
    };

    std::string PointerToHex(uintptr_t value)
    {
        std::ostringstream stream;
        stream << "0x" << std::hex << std::uppercase << value;
        return stream.str();
    }

    std::string FormatTimestamp(unsigned long timestamp)
    {
        if (timestamp == 0) {
            return "unknown";
        }
        std::time_t timeValue = static_cast<std::time_t>(timestamp);
        std::tm tmValue{};
        gmtime_s(&tmValue, &timeValue);
        std::ostringstream stream;
        stream << std::put_time(&tmValue, "%Y-%m-%d %H:%M:%S UTC");
        return stream.str();
    }

    std::string GetDocumentsByondPath()
    {
        char documents[MAX_PATH];
        if (FAILED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, documents))) {
            return "";
        }
        std::string path = std::string(documents) + "\\BYOND\\Calamari";
        DWORD attributes = GetFileAttributesA(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            CreateDirectoryA(path.c_str(), nullptr);
        }
        return path;
    }

    void WriteLine(std::ofstream& out, const std::string& line)
    {
        out << line << "\n";
    }

    ModuleEntry InspectModule(HMODULE module)
    {
        ModuleEntry entry;
        char name[MAX_PATH] = {};
        char path[MAX_PATH] = {};
        MODULEINFO info = {};

        if (GetModuleBaseNameA(GetCurrentProcess(), module, name, MAX_PATH)) {
            entry.name = name;
        }
        if (GetModuleFileNameExA(GetCurrentProcess(), module, path, MAX_PATH)) {
            entry.path = path;
        }
        if (GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info))) {
            entry.base = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
            entry.size = static_cast<size_t>(info.SizeOfImage);
            entry.entryPoint = reinterpret_cast<uintptr_t>(info.EntryPoint);
        }

        if (entry.base != 0) {
            auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(entry.base);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(entry.base + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    entry.timestamp = nt->FileHeader.TimeDateStamp;
                    auto section = IMAGE_FIRST_SECTION(nt);
                    for (unsigned int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
                        entry.sections.push_back(*section);
                    }
                }
            }
        }

        return entry;
    }

    std::vector<ModuleEntry> CollectModules()
    {
        std::vector<ModuleEntry> modules;
        HMODULE handles[1024];
        DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), handles, sizeof(handles), &needed)) {
            return modules;
        }
        size_t count = needed / sizeof(HMODULE);
        modules.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            modules.push_back(InspectModule(handles[i]));
        }
        return modules;
    }

    void WriteModule(std::ofstream& out, const ModuleEntry& module)
    {
        WriteLine(out, "Module: " + module.name);
        WriteLine(out, "  Path: " + module.path);
        WriteLine(out, "  Base: " + PointerToHex(module.base));
        WriteLine(out, "  Size: " + PointerToHex(static_cast<uintptr_t>(module.size)));
        WriteLine(out, "  Entry: " + PointerToHex(module.entryPoint));
        WriteLine(out, "  Timestamp: " + FormatTimestamp(module.timestamp));
        if (!module.sections.empty()) {
            WriteLine(out, "  Sections:");
            for (const auto& section : module.sections) {
                char name[9] = {};
                memcpy(name, section.Name, 8);
                std::ostringstream stream;
                stream << "    " << name
                       << " | RVA " << PointerToHex(section.VirtualAddress)
                       << " | VSZ " << PointerToHex(section.Misc.VirtualSize)
                       << " | RAW " << PointerToHex(section.SizeOfRawData);
                WriteLine(out, stream.str());
            }
        }
        WriteLine(out, "");
    }

    void WriteByondExports(std::ofstream& out)
    {
        struct ExportEntry {
            const char* name;
            void* pointer;
            const char* module;
        };

        ExportEntry exports[] = {
            {"DungClient::Ctor", reinterpret_cast<void*>(Calamari::Byond::DungClientCtor), "byondcore.dll"},
            {"GenMouseDownCommand", reinterpret_cast<void*>(Calamari::Byond::GenMouseDownCommandFunc), "byondcore.dll"},
            {"GenMouseUpCommand", reinterpret_cast<void*>(Calamari::Byond::GenMouseUpCommandFunc), "byondcore.dll"},
            {"GenClickCommand", reinterpret_cast<void*>(Calamari::Byond::GenClickCommandFunc), "byondcore.dll"},
            {"GenMouseMoveCommand", reinterpret_cast<void*>(Calamari::Byond::GenMouseMoveCommandFunc), "byondcore.dll"},
            {"GetCidLoc", reinterpret_cast<void*>(Calamari::Byond::GetCidLocFunc), "byondcore.dll"},
            {"GetCidName", reinterpret_cast<void*>(Calamari::Byond::GetCidNameFunc), "byondcore.dll"},
            {"GetServerPort", reinterpret_cast<void*>(Calamari::Byond::GetServerPortFunc), "byondcore.dll"},
            {"GetServerIP", reinterpret_cast<void*>(Calamari::Byond::GetServerIPFunc), "byondcore.dll"},
            {"GetPlayerCid", reinterpret_cast<void*>(Calamari::Byond::GetPlayerCidFunc), "byondcore.dll"},
            {"CIOutputCtrl::PutText", reinterpret_cast<void*>(Calamari::Byond::CIOutputCtrlPutTextFunc), "byondwin.dll"},
            {"DSStat::AddStat", reinterpret_cast<void*>(Calamari::Byond::DSAddStatFunc), "byondcore.dll"},
            {"CommandEvent", reinterpret_cast<void*>(Calamari::Byond::CommandEventFunc), "byondcore.dll"},
            {"ParseCommand", reinterpret_cast<void*>(Calamari::Byond::ParseCommandFunc), "byondcore.dll"},
            {"Byond32", reinterpret_cast<void*>(Calamari::Byond::Byond32Func), "byondcore.dll"},
            {"IsByondMember(DC)", reinterpret_cast<void*>(Calamari::Byond::DCIsByondMemberFunc), "byondcore.dll"},
            {"IsByondMember(DP)", reinterpret_cast<void*>(Calamari::Byond::DPIsByondMemberFunc), "byondcore.dll"},
        };

        WriteLine(out, "Resolved exports:");
        for (const auto& entry : exports) {
            std::ostringstream stream;
            stream << "  " << entry.name << " (" << entry.module << ") : ";
            if (entry.pointer) {
                HMODULE mod = GetModuleHandleA(entry.module);
                uintptr_t base = reinterpret_cast<uintptr_t>(mod);
                uintptr_t ptr = reinterpret_cast<uintptr_t>(entry.pointer);
                stream << PointerToHex(ptr);
                if (base) {
                    stream << " (offset " << PointerToHex(ptr - base) << ")";
                }
            } else {
                stream << "MISSING";
            }
            WriteLine(out, stream.str());
        }
        WriteLine(out, "");
    }
}

static void OnRender(Plugin* plugin, LPDIRECT3DDEVICE9, const RECT*)
{
    auto diagnostics = static_cast<Diagnostics*>(plugin);
    if (ImGui::TreeNode("Diagnostics")) {
        if (ImGui::Button("Dump runtime info")) {
            diagnostics->DumpRuntimeInfo();
        }
        ImGui::Text("Output: %s", diagnostics->GetConfig("OutputFile", "diagnostics.txt").c_str());
        ImGui::TreePop();
    }

    if (diagnostics->GetConfig("AutoDumpOnStart", "true") == "true"
        && diagnostics->GetConfig("AutoDumpCompleted", "false") != "true") {
        diagnostics->DumpRuntimeInfo();
    }
}

Diagnostics::Diagnostics()
    : Plugin()
{
    std::string autoDump = GetConfig("AutoDumpOnStart", "true");
    SetConfig("AutoDumpOnStart", autoDump);

    std::string output = GetConfig("OutputFile", "diagnostics.txt");
    SetConfig("OutputFile", output);

    outputPath = GetDocumentsByondPath();
    if (!outputPath.empty()) {
        outputPath += "\\" + output;
    } else {
        outputPath = output;
    }

    AddEvent(EVENT_RENDER, &OnRender, false);
}

std::string Diagnostics::GetName()
{
    return "Diagnostics";
}

void Diagnostics::DumpRuntimeInfo()
{
    std::ofstream out(outputPath, std::ios::app);
    if (!out.is_open()) {
        Log("Failed to open diagnostics output file: " + outputPath);
        return;
    }

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tmValue{};
    localtime_s(&tmValue, &now);
    std::ostringstream header;
    header << "==== Diagnostics Dump: " << std::put_time(&tmValue, "%Y-%m-%d %H:%M:%S") << " ====";
    WriteLine(out, header.str());

    WriteLine(out, "BYOND Version (from exports): " + Calamari::Byond::ByondVersion());
    WriteLine(out, "Dream Seeker window: " + PointerToHex(reinterpret_cast<uintptr_t>(Calamari::Byond::DirectXWnd)));
    WriteLine(out, "Input window: " + PointerToHex(reinterpret_cast<uintptr_t>(Calamari::Byond::InputWnd)));
    WriteLine(out, "");

    WriteByondExports(out);

    WriteLine(out, "Loaded modules:");
    auto modules = CollectModules();
    for (const auto& module : modules) {
        WriteModule(out, module);
    }

    WriteLine(out, "==== End Diagnostics ====");
    WriteLine(out, "");

    SetConfig("AutoDumpCompleted", "true");
    Log("Diagnostics dump written to: " + outputPath);
}

extern "C" __declspec(dllexport) Diagnostics* InitializePlugin()
{
    return new Diagnostics;
}
