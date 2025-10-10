#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>

struct DllInfo
{
    WORD id;
    std::set<WORD> deps;

    void print() {
        std::cout << "DLL: " << std::dec << id << std::endl;
    }
};

bool parseDllInfo(const std::string& line, DllInfo& dllInfo)
{

    std::string leftPart, rightPart;

    // Split the line into two parts: DLL id and dependencies
    std::size_t arrowPos = line.find("->");
    if (arrowPos == std::string::npos) {
        return false;
    }

    // Extract the DLL id (before '->')
    leftPart = line.substr(0, arrowPos);
    dllInfo.id = static_cast<WORD>(std::atoi(leftPart.c_str()));

    // Extract the dependencies (after '->')
    rightPart = line.substr(arrowPos + 3); // Skip over "->"

    // Parse the dependencies
    std::stringstream ss(rightPart);
    std::string dep;
    while (std::getline(ss, dep, ',')) {
        dllInfo.deps.insert(static_cast<WORD>(std::atoi(dep.c_str())));
    }

    return true;
}

size_t read_dependencies(const std::string& inpFile, std::map<WORD, DllInfo>& dllInfos)
{
    std::ifstream infile(inpFile);  // open file for reading
    if (!infile.is_open()) {
        std::cerr << "Error: could not open file.\n";
        return 0;
    }
    size_t count = 0;
    std::string line;
    while (std::getline(infile, line)) {
        count++;

        if (line.find("->") == std::string::npos) {
            continue;
        }
        DllInfo info;
        parseDllInfo(line, info);

        dllInfos[info.id] = info;

    }
    infile.close();
    return count;
}