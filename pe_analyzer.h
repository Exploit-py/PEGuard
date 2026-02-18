#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

struct SectionInfo {
    std::string name;
    DWORD rva;
    DWORD rawSize;
    DWORD virtualSize;
    DWORD characteristics;

    bool canRead;
    bool canWrite;
    bool canExecute;
    bool containsCode;
    bool entryPointHere;

    double entropy;
    double threshold;
    bool highEntropy;
    bool isRWX;
};

struct PEAnalysisResult {
    std::string filePath;
    std::string arch;
    std::string subsystem;

    uint64_t imageBase;
    uint64_t epRVA;
    uint64_t epVA;

    int sectionCount = 0;
    int suspicionScore = 0;
    std::string verdict;

    std::vector<SectionInfo> sections;
};

class PEAnalyzer {
public:
    bool analyze(const std::string& path);
    const PEAnalysisResult& result() const;

private:
    PEAnalysisResult m_result;

    double CalculateEntropy(const unsigned char* data, size_t size);
    std::string GetSectionName(const IMAGE_SECTION_HEADER& s);
    DWORD RvaToRaw(DWORD rva, const std::vector<IMAGE_SECTION_HEADER>& sections);
    double GetEntropyThreshold(const std::string& name);
};
