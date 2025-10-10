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
#include "dll_deps.h"

#define DLLS_MAX 10000

size_t g_load_counts[DLLS_MAX] = { 0 };

std::map<DWORD, WORD> g_PosToDll;


void countLoaded(const std::set<WORD>& deps)
{
    for (auto itr = deps.begin(); itr != deps.end(); ++itr) {
        WORD dll = *itr;
        g_load_counts[dll]++;
    }
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "Resolve DLL order\n" 
            << "Usage: <listing_file>\n"; //dlls_matrix.txt.3.txt
        return 0;
    }
    
    char* input_file = argv[1];
    size_t input_size = 0;

    std::map<WORD, DllInfo> dllInfos;
    read_dependencies(input_file, dllInfos);
    
    DWORD* verif = (DWORD*)g_VerifBuf;
    for (auto itr = dllInfos.begin(); itr != dllInfos.end(); ++itr) {
        const DllInfo info = itr->second;
        countLoaded(info.deps);
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

    size_t i = 0;
    std::cout << "{";
    for (auto itr = g_PosToDll.begin(); itr != g_PosToDll.end(); ++itr, ++i) {
        if (i % 255 == 0) {
            std::cout << "\n";
        }
        std::cout << itr->second;
        if (i < (DLLS_MAX - 1)) {
            std::cout << ", ";
        }

        //std::cout << itr->first << " : " << itr->second << std::endl;
    }
    std::cout << "};";
    return 0;
}
