#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include <peconv.h> // include libPeConv header

#include "util.h"
#define MAX_DLLS 10000

bool getDllId(const std::string& dll_name, WORD &id)
{
    if (!isNumericDLL(dll_name)) return false;

    std::string name = get_base_filename(dll_name);
    id = std::atoi(name.c_str());
    return true;
}

struct dll_deps {
    WORD dll;
    std::set<WORD> deps;

    dll_deps(const std::string &dll_name)
    {
        if (!getDllId(dll_name, dll)) {
            dll = (-1);
        }
    }

    dll_deps(WORD _dll) : dll(_dll) {}

    void print(std::stringstream& ous)
    {
        ous << dll << " -> ";
        bool isFirst = true;
        for (auto itr = deps.begin(); itr != deps.end(); ++itr) {
            WORD d = *itr;
            if (!isFirst) {
                ous << ",";
            }
            ous << d;
            isFirst = false;
        }
        ous << std::endl;
    }

    void print(std::ofstream& ous)
    {
        std::stringstream ss;
        print(ss);
        ous << ss.str();
    }

    void print() {
        std::stringstream ss;
        print(ss);
        std::cout << ss.str();
    }
};


class my_func_resolver : peconv::t_function_resolver{
public:
    my_func_resolver(dll_deps& _my_deps)
    : my_deps(_my_deps)
    {
    }

    FARPROC resolve_func(LPCSTR lib_name, LPCSTR func_name)
    {
        WORD num = (-1);
        if (!getDllId(lib_name, num)) {
            return nullptr;
        }
        if (!isNumericDLL(lib_name)) return nullptr;
        my_deps.deps.insert(num);
    }

    dll_deps& my_deps;
};


int populateLayer(std::map<WORD, dll_deps*> &dllToDeps, WORD mainID)
{
    dll_deps* d = dllToDeps[mainID];
    size_t initialSize = d->deps.size();
    bool collected[MAX_DLLS] = { 0 };
    for (auto itr = d->deps.begin(); itr != d->deps.end(); ++itr) {
        WORD next = *itr;
        for (auto k = dllToDeps[next]->deps.begin(); k != dllToDeps[next]->deps.end(); ++k) {
            collected[*k] = true;
        }
    }
    for (WORD i = 0; i < MAX_DLLS; i++) {
        if (collected[i]) {
            d->deps.insert(i);
        }
    }

    return (d->deps.size() - initialSize);
}

bool dump_layer_to_file(std::string out_file, int layer, std::map<WORD, dll_deps*> &dllToDeps)
{
    std::stringstream ss; 
    ss << out_file << "." << std::dec << layer << ".txt";

    std::ofstream oFile(ss.str());  // open file for reading
    if (!oFile.is_open()) {
        std::cerr << "Error: could not open file.\n";
        return 0;
    }


    for (auto itr = dllToDeps.begin(); itr != dllToDeps.end(); ++itr) {
        dll_deps* dep = itr->second;
        dep->print(oFile);
    }
    oFile.close();
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        std::cout << "Usage: <listing_dir> <out_file>\n";
        return 0;
    }
    std::string input_dir = argv[1];
    std::string out_file = argv[2];

    std::map<WORD, dll_deps*> dllToDeps;

    for (WORD id = 0; id < MAX_DLLS; id++) {
        std::stringstream ss;
        ss << input_dir << "\\"
            << std::setw(4) << std::setfill('0') << id
            << ".dll";

        std::string input_file = ss.str();
        size_t mod_size = 0;
        
        dll_deps *deps = new dll_deps(input_file);
        my_func_resolver resolver(*deps);
        dllToDeps[deps->dll] = deps;
        BYTE* mainMod = peconv::load_pe_executable(input_file.c_str(), mod_size, (peconv::t_function_resolver*)&resolver);
        if (!mainMod) {
            std::cout << "Failed to load: " << input_file <<"\n";
            continue;
        }
        peconv::free_pe_buffer(mainMod);
    }
    std::cout << "First layer populated...\n";

   for (size_t i = 1; true; ++i) {
        size_t added = 0;
        for (auto itr = dllToDeps.begin(); itr != dllToDeps.end(); ++itr) {
            WORD id = itr->first;
            if (id % 1000 == 0) {
                std::cout << id << " Total added: " << added << "\n";
            }
            added += populateLayer(dllToDeps, itr->first);
        }
        std::cout << "Layer "  << i << " populated. " << " Added: " << added << "\n";
        dump_layer_to_file(out_file, i, dllToDeps);
        if (added == 0) break;
    }
    return 0;
}
