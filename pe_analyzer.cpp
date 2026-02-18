#include "pe_analyzer.h"
#include <cmath>
#include <cstring>
#include <algorithm>

double PEAnalyzer::CalculateEntropy(const unsigned char* data, size_t size) {
    if (size == 0) return 0.0;

    size_t freq[256]{};
    for (size_t i = 0; i < size; i++)
        freq[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / size;
        entropy -= p * log2(p);
    }
    return entropy;
}

std::string PEAnalyzer::GetSectionName(const IMAGE_SECTION_HEADER& s) {
    char name[9]{};
    memcpy(name, s.Name, 8);
    return name;
}

DWORD PEAnalyzer::RvaToRaw(DWORD rva, const std::vector<IMAGE_SECTION_HEADER>& sections) {
    for (const auto& s : sections) {
        DWORD start = s.VirtualAddress;
        DWORD end = start + std::max(s.Misc.VirtualSize, s.SizeOfRawData);
        if (rva >= start && rva < end)
            return s.PointerToRawData + (rva - start);
    }
    return 0;
}

double PEAnalyzer::GetEntropyThreshold(const std::string& name) {
    if (name == ".text")  return 6.8;
    if (name == ".rdata") return 6.2;
    if (name == ".data")  return 5.5;
    if (name == ".rsrc")  return 6.8;
    if (name == ".reloc") return 2.0;
    return 7.2;
}

bool PEAnalyzer::analyze(const std::string& path) {
    m_result = PEAnalysisResult{};
    m_result.filePath = path;

    HANDLE hFile = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );

    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    DWORD bytesRead;
    IMAGE_DOS_HEADER dos{};
    IMAGE_FILE_HEADER file{};
    IMAGE_OPTIONAL_HEADER32 opt32{};
    IMAGE_OPTIONAL_HEADER64 opt64{};
    bool is64 = false;

    ReadFile(hFile, &dos, sizeof(dos), &bytesRead, nullptr);
    SetFilePointer(hFile, dos.e_lfanew + 4, nullptr, FILE_BEGIN);
    ReadFile(hFile, &file, sizeof(file), &bytesRead, nullptr);

    WORD magic;
    ReadFile(hFile, &magic, sizeof(magic), &bytesRead, nullptr);
    SetFilePointer(hFile, -2, nullptr, FILE_CURRENT);

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        is64 = true;
        ReadFile(hFile, &opt64, sizeof(opt64), &bytesRead, nullptr);
    } else {
        ReadFile(hFile, &opt32, sizeof(opt32), &bytesRead, nullptr);
    }

    m_result.arch = is64 ? "x64" : "x86";
    m_result.imageBase = is64 ? opt64.ImageBase : opt32.ImageBase;
    m_result.epRVA = is64 ? opt64.AddressOfEntryPoint : opt32.AddressOfEntryPoint;
    m_result.epVA = m_result.imageBase + m_result.epRVA;
    m_result.subsystem =
        ((is64 ? opt64.Subsystem : opt32.Subsystem) == IMAGE_SUBSYSTEM_WINDOWS_GUI)
            ? "GUI" : "Console";

    std::vector<IMAGE_SECTION_HEADER> sections;
    for (int i = 0; i < file.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER s{};
        ReadFile(hFile, &s, sizeof(s), &bytesRead, nullptr);
        sections.push_back(s);
    }

    m_result.sectionCount = (int)sections.size();

    for (auto& s : sections) {
        SectionInfo info{};
        info.name = GetSectionName(s);
        info.rva = s.VirtualAddress;
        info.rawSize = s.SizeOfRawData;
        info.virtualSize = s.Misc.VirtualSize;
        info.characteristics = s.Characteristics;

        info.canRead = s.Characteristics & IMAGE_SCN_MEM_READ;
        info.canWrite = s.Characteristics & IMAGE_SCN_MEM_WRITE;
        info.canExecute = s.Characteristics & IMAGE_SCN_MEM_EXECUTE;
        info.containsCode = s.Characteristics & IMAGE_SCN_CNT_CODE;

        DWORD start = s.VirtualAddress;
        DWORD end = start + std::max(s.Misc.VirtualSize, s.SizeOfRawData);
        info.entryPointHere =
            m_result.epRVA >= start && m_result.epRVA < end;

        info.isRWX = info.canRead && info.canWrite && info.canExecute;

        if (s.SizeOfRawData > 0) {
            SetFilePointer(hFile, s.PointerToRawData, nullptr, FILE_BEGIN);
            std::vector<unsigned char> buf(s.SizeOfRawData);
            ReadFile(hFile, buf.data(), s.SizeOfRawData, &bytesRead, nullptr);

            info.entropy = CalculateEntropy(buf.data(), buf.size());
            info.threshold = GetEntropyThreshold(info.name);
            info.highEntropy = info.entropy > info.threshold;

            if (info.highEntropy)
                m_result.suspicionScore += 2;
        }

        if (info.isRWX)
            m_result.suspicionScore += 3;

        m_result.sections.push_back(info);
    }

    if (m_result.suspicionScore >= 6)
        m_result.verdict = "LIKELY MALICIOUS";
    else if (m_result.suspicionScore >= 3)
        m_result.verdict = "SUSPICIOUS";
    else
        m_result.verdict = "CLEAN";

    CloseHandle(hFile);
    return true;
}

const PEAnalysisResult& PEAnalyzer::result() const {
    return m_result;
}
