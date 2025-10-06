#include <windows.h>
#include <iostream>
#include <string>
#include <map>
#include <set>
#include "util.h"

#define EXE_NAME "ntfsm.exe"

int g_DebugLvl = 0;

uint64_t g_Position = (-1);
uint64_t g_Transitions = (-1);
uint64_t g_Base = 0x140000000;

BYTE* mod = nullptr;
std::map<uint64_t, std::string> linesMap;

uint64_t calc_next_addr(uint64_t state)
{
    uint64_t addr = state * 4 + 0xC687B8;
    return addr;
}

uint64_t next_state_va(uint64_t state)
{
    ULONG_PTR addr = calc_next_addr(state) + (ULONG_PTR)mod;
    //std::cout << "Next address: " << std::hex << addr << std::endl;
    uint32_t* addr_to_res = (uint32_t*)(addr);
    uint64_t va = (*addr_to_res) + g_Base;
    return va;
}

struct Node
{
    char val;
    uint64_t next_state;
    uint64_t jump_addr;

    Node(char _val, uint64_t _jump_addr = (-1), uint64_t _next_state = (-1))
        : val(_val), next_state(_next_state), jump_addr(_jump_addr)
    {
    }

    Node(const Node& n) : val(n.val), next_state(n.next_state), jump_addr(n.jump_addr)
    {
    }

    void print() const
    {
        std::cout << "VAL: " << val << "\t";
        if (next_state != (-1)) {
            std::cout << "NEXT: " << next_state << "\t";
            std::cout << "TARGET: " << std::hex << next_state_va(next_state) << "\n";
        }
        else {
            std::cout << "ADDR: " << jump_addr << "\t";
        }
        std::cout << std::endl;
    }

    bool operator=(const Node& n)
    {
        this->jump_addr = n.jump_addr;
        this->next_state = n.next_state;
        this->val = n.val;
    }

    bool operator<(const Node& n) const
    {
        return val < n.val;
    }
};

std::map<uint64_t, std::set<Node>> stateMap;

bool run_with_cmd(const std::string& cmd, PROCESS_INFORMATION &pi)
{
    std::string app_name = EXE_NAME;
    std::string inp = app_name + " " + cmd;

    return create_new_process(inp.c_str(), pi);
}

void hexdump(BYTE* buf, size_t buf_size)
{
    for (size_t i = 0; i < buf_size; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void show_stream(const std::string& stream, BYTE* buf, size_t buf_size)
{
    std::cout << "Stream: " << stream << "\n";
    hexdump(buf, buf_size);
    std::cout << std::endl;
}

BYTE* read_steam(const std::string& stream, size_t &read_size, bool show = false)
{
    std::string stream_file = std::string(EXE_NAME) + ":" + stream + ":$DATA";
    BYTE* buf = read_from_file(stream_file.c_str(), read_size);
    if (show) {
        show_stream(stream, buf, read_size);
    }
    return buf;
}

bool write_stream(const std::string& stream, BYTE *buf, size_t buf_size, bool show = false)
{
    std::string stream_file = std::string(EXE_NAME) + ":" + stream + ":$DATA";
    if (!write_to_file(stream_file.c_str(), buf, buf_size)) {
        return false;
    }
    if (show) {
        size_t read_size = 0;
        read_steam(stream, read_size, true);
    }
    return buf;
}

void show_all_streams(bool show = false)
{
    uint64_t position = 0;

    size_t read_size = 0;
    BYTE* buf = read_steam("position", read_size);
    if (read_size == sizeof(position)) {
        ::memcpy(&position, buf, sizeof(position));
        if (position != g_Position) {
            show = true;
            g_Position = position;
            std::cout << "Position: " << std::hex << position << "\n";
        }
    }
    if (show) {
        show_stream("position", buf, read_size);
    }
    ::free(buf);

    read_steam("input", read_size, show);
    read_steam("state", read_size, show);
    uint64_t transitions = 0;
    buf = read_steam("transitions", read_size, show);
    if (read_size == sizeof(transitions)) {
        ::memcpy(&transitions, buf, sizeof(transitions));
        if (transitions != g_Transitions) {
            show = true;
            g_Transitions = transitions;
            if (g_Transitions != 0) {
                std::cout << "Transitions: " << std::hex << transitions << "\n";
            }
        }
    }
}

void write_all_streams(const std::string &pass, uint64_t position, uint64_t transitions, uint64_t state)
{
    std::cout << "Writing...\n";
    bool show = true;
    write_stream("input", (BYTE*) pass.c_str(), pass.length(), show);
    write_stream("position", (BYTE*)&position, sizeof(position), show);
    write_stream("state", (BYTE*)&state, sizeof(state), show);
    write_stream("transitions", (BYTE*)&transitions, sizeof(transitions), show);
}


void overwrite(const std::string &pass)
{
    //std::string pass = "J123456789abcdef";
    std::cout << "Pass: " << pass << std::endl;
    uint64_t position = 0;
    uint64_t transitions = 0;
    uint64_t state = 0;
    write_all_streams(pass, position, transitions, state);
}

bool loadDisasmToMap(const std::string& path, std::map<uint64_t, std::string>& outMap)
{
    std::ifstream infile(path);
    if (!infile.is_open()) {
        std::cerr << "[-] Could not open file: " << path << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty()) continue;

        // Split on ';'
        size_t sep = line.find(';');
        if (sep == std::string::npos) continue;

        std::string addrStr = line.substr(0, sep);
        std::string disasmStr = line.substr(sep+1);
        try {
            uint64_t va = std::stoull(addrStr, nullptr, 16);
            outMap[va] = disasmStr;
        }
        catch (const std::exception& e) {
            std::cerr << "[-] Failed to parse line: " << line << " (" << e.what() << ")" << std::endl;
            continue;
        }
    }

    return true;
}

bool resolve_state_values(uint64_t state, uint64_t va)
{
    auto itr = linesMap.find(va);
    if (itr == linesMap.end()) {
        return false;
    }
    size_t nodesCount = 0;
    size_t rcount = 0;
    auto& myNodes = stateMap[state];
    char currVal = 0;
    bool line_found = false;
    size_t i = 0;
    for (size_t i = 0; itr != linesMap.end() && i < 50; i++, itr++) {
        uint64_t addr = itr->first;
        std::string disasm = itr->second;
        if (disasm == "rdtsc") {
            rcount++;
        }
        if (rcount > 2) break;

        if (line_found) {
            line_found = false;
            const std::string prefix = "je 0x";
            if (disasm.compare(0, prefix.size(), prefix) != 0) continue;
            if (g_DebugLvl > 1) {
                std::cout << std::hex << addr << " : " << disasm << std::endl;
            }
            uint64_t va = std::stoull(disasm.c_str() + 3, nullptr, 16);
            Node n(currVal, va);
            myNodes.insert(n);
            nodesCount++;
            currVal = 0;
            continue;
        }

        const std::string prefix = "cmp byte ptr [rsp + ";
        if (disasm.compare(0, prefix.size(), prefix) != 0) continue;
        const std::string prefix2 = "], 0x";
        int find2 = disasm.find_last_of(',');
        std::string val = disasm.substr(find2 + 1);
        currVal = std::stoi(val, nullptr, 16);

        line_found = true;
        if (g_DebugLvl > 1) {
            std::cout << std::hex << addr << " : " << disasm << std::endl;
        }
    }
    if (g_DebugLvl) {
        std::cout << ">>> NODES: " << nodesCount << "\n";
    }
    return (nodesCount > 0) ? true : false;
}


bool find_next_state(uint64_t state, uint64_t va, Node& n)
{
    auto itr = linesMap.find(va);
    if (itr == linesMap.end()) {
        return false;
    }
    bool line_found = false;
    size_t i = 0;
    for (size_t i = 0; itr != linesMap.end() && i < 50; i++, itr++) {
        uint64_t addr = itr->first;
        std::string disasm = itr->second;

        const std::string prefix = "mov qword ptr [rsp + ";
        if (disasm.compare(0, prefix.size(), prefix) != 0) break; // wrong, not resolving it...

        int find2 = disasm.find_last_of(',');
        std::string val = disasm.substr(find2 + 1);
        uint64_t nextState = std::stol(val, nullptr, 16);

        if (g_DebugLvl > 1) {
            std::cout << std::hex << addr << " : " << disasm << std::endl;
        }
        n.next_state = nextState; //resolved - ok
        break;
    }
    return true;
}

bool resolve_next_states(uint64_t state)
{
    auto& myNodes = stateMap[state];
    for (auto itr = myNodes.begin(); itr != myNodes.end(); ++itr) {
        const Node& n = (*itr);
        auto lItr = linesMap.find(n.jump_addr);
        if (lItr == linesMap.end()) {
            std::cerr << "Address Not found!\n";
            return false;
        }
        find_next_state(state, n.jump_addr, const_cast<Node&>(n));
        if (g_DebugLvl) {
            n.print();
        }
    }
    return true;
}


void resolve_state(uint64_t state)
{
    if (g_DebugLvl) {
        std::cout << "\n---\nState: " << std::hex << state << "\n---\n";
    }
    ULONG_PTR addr = calc_next_addr(state) + (ULONG_PTR)mod;
    //std::cout << "Next address: " << std::hex << addr << std::endl;
    uint32_t* addr_to_res = (uint32_t*)(addr);
    uint64_t va = (*addr_to_res) + g_Base;
    if (g_DebugLvl) {
        std::cout << "Ptr: " << std::hex << va << std::endl;
    }
    if (resolve_state_values(state, va)) {
        resolve_next_states(state);
    }
    if (g_DebugLvl) {
        std::cout << "---" << std::endl;
    }
}

bool follow_states(uint64_t state)
{
    auto& myNodes = stateMap[state];
    for (auto itr = myNodes.begin(); itr != myNodes.end(); ++itr) {
        const Node& n = (*itr);
        auto lItr = linesMap.find(n.jump_addr);
        if (lItr == linesMap.end()) {
            std::cerr << "Address Not found!\n";
            return false;
        }
        if (!find_next_state(state, n.jump_addr, const_cast<Node&>(n))) {
            std::cout << "Failed to find next!\n";
            n.print();
            return false;
        }
        resolve_state(n.next_state);
        follow_states(n.next_state);
    }
    return true;
}


bool map_disasm()
{
    if (linesMap.size() == 0) {
        if (!loadDisasmToMap("disasm1.txt", linesMap)) {
            return false;
        }
        std::cout << "Mapped!\n";
    }
    return true;
}

bool show_strings(uint64_t state, std::string str)
{
    auto& myNodes = stateMap[state];
    if (myNodes.size() == 0) return false;

    for (auto itr = myNodes.begin(); itr != myNodes.end(); ++itr) {
        const Node& n = (*itr);
        std::cout << "[" << state << "] : " << n.val << "->" << " [" << n.next_state << "]" << " : (len=" << str.length() << ") " << str << std::endl;
        if (!show_strings(n.next_state, str + n.val)) {
            std::cout << "---\n";
        }
    }
    return true;
}

int main(int argc, char *argv[])
{

    if (argc >= 2) {
        std::string pass = argv[1];
        if (pass.length() != 16) {
            std::cout << "Wrong pass len: " << std::dec << pass.length() << "\n";
            return (-1);
        }
        std::cout << "# Overwrite mode, pass: " << pass << "\n";
        overwrite(pass);
        return 0;
    }
    std::cout << "# Read mode\n";
    show_all_streams(true);

    std::vector<char> mapped;
    mod = load_image(EXE_NAME, mapped);
    if (!mod) {
        std::cout << "Loading file failed!\n";
    }
    else {
        std::cout << "File Loaded!\n";
    }
    if (!map_disasm()) {
        std::cerr << "Failed to map disasm\n";
        return 0;
    }
    bool show_stored = false;
    if (show_stored) {
        size_t read_size;
        uint64_t state = 0;
        BYTE* buf = read_steam("state", read_size, false);
        if (buf && read_size == sizeof(state)) {
            ::memcpy(&state, buf, sizeof(state));
            if (state == (-1)) {
                return 0;
            }
            resolve_state(state);
        }
        return 0;
    }
    bool follow_all = true;
    std::map<std::string, uint64_t> stateStr;
    resolve_state(0);
    if (follow_all) {
        follow_states(0);
        show_strings(0, "");
    }
    std::cout << "[ok]\n";
	return 0;
}