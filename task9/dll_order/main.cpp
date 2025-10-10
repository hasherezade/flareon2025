#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <set>

#include <iostream>
#include <sstream>
#include <set>
#include <map>


#include "util.h"
#include "verif.h"

#define DLLS_MAX 10000

size_t g_load_counts[DLLS_MAX] = { 0 };

std::map<DWORD, WORD> g_PosToDll;

struct DllInfo
{
    WORD id;
    std::set<WORD> deps;

    void countLoaded() const
    {
        for (auto itr = deps.begin(); itr != deps.end(); ++itr) {
            WORD dll = *itr;
            g_load_counts[dll]++;
        }
    }

    void print() {
        std::cout << "DLL: " << std::dec << id << std::endl;
        /*for (auto itr = deps.begin(); itr != deps.end(); ++itr) {
            std::cout << (*itr) << ", ";
        }
        std::cout << "\n";
        */
    }
};

bool parseDllInfo(const std::string& line, DllInfo &dllInfo) {

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

size_t read_resolved(const std::string& inpFile, std::map<WORD, DllInfo> &dllInfos)
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

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "Resolve DLL order\n" 
            << "Usage: <listing_file>\n"; //dlls_matrix.txt.3.txt
        return 0;
    }
    
    std::map<WORD, DllInfo> dllInfos;

    char* input_file = argv[1];
    size_t input_size = 0;
    read_resolved(input_file, dllInfos);
    
    DWORD* verif = (DWORD*)g_VerifBuf;
    for (auto itr = dllInfos.begin(); itr != dllInfos.end(); ++itr) {
        const DllInfo info = itr->second;
        info.countLoaded();
    }
    std::set<WORD> solved;

    while (solved.size() < DLLS_MAX) {
        size_t counter = 0;
        for (size_t i = 0; i < DLLS_MAX; i++) {
            if (solved.find(i) != solved.end()) {
                continue; // already resolved
            }
            if (g_load_counts[i] == 0) {
                counter++;
                DWORD pos = verif[i];
                //std::cout << "DLL: " << i << " : " << g_load_counts[i] << " pos: " << pos << "\n";
                g_PosToDll[pos] = i;
                solved.insert(i);
                for (auto it = dllInfos[i].deps.begin(); it != dllInfos[i].deps.end(); ++it) {
                    DWORD dep_id = *it;
                    g_load_counts[dep_id]--;
                    verif[dep_id] -= pos;
                }
            }
        }
        //std::cout << "Count: " << counter << std::endl;
    }
    bool isFirst = true;
    std::cout << "{";
    for (auto itr = g_PosToDll.begin(); itr != g_PosToDll.end(); ++itr) {
        if (!isFirst) {
            std::cout << ", ";
        }
        isFirst = false;
        std::cout << itr->second;
        //std::cout << itr->first << " : " << itr->second << std::endl;
    }
    std::cout << "};";
    return 0;
}
