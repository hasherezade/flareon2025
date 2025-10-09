#include "parse_records.h"

// Parse: FFuncWrapper(dll=0000.dll, type=1, args=['0x...', '0x...', ...])
FFuncWrapperC* parseFFuncWrapper(const std::string& line)
{
    // 1) Grab dll and type with a regex; capture everything until ", args=["
    static const std::regex head_re(
        R"(^\s*FFuncWrapper\(dll=([^,]+),\s*type=(\d+),\s*args=\[)",
        std::regex::ECMAScript);

    std::smatch m;
    if (!std::regex_search(line, m, head_re)) {
        return nullptr; // doesn't match expected shape
    }

    FFuncWrapperC* out = new FFuncWrapperC();
    out->dll = m[1].str();
    out->type = std::stoi(m[2].str());

    // 2) Find the args segment: everything between the first '[' after "args=" and the matching ']'
    // We already matched the prefix up to "args=[", so continue from there.
    const std::size_t args_list_begin = m.position() + m.length(); // index just after '['
    const std::size_t close_bracket = line.find(']', args_list_begin);
    if (close_bracket == std::string::npos) return nullptr;

    const std::string args_segment = line.substr(args_list_begin, close_bracket - args_list_begin);

    // 3) Extract all quoted hex numbers with another regex
    static const std::regex hex_re(R"('((?:0x|0X)[0-9a-fA-F]+)')");
    for (std::sregex_iterator it(args_segment.begin(), args_segment.end(), hex_re), end; it != end; ++it) {
        const std::string hexstr = (*it)[1].str();     // e.g. "0x5ff9fb802d463415"
        // std::stoull handles "0x" prefix if base=0 (automatic base detection)
        std::uint64_t val = std::stoull(hexstr, nullptr, 0);
        out->args.push_back(val);
    }
    return out;
}

Precalculated* parsePrecalculatedLine(const std::string& line)
{
    static const std::regex head_re(R"(^\s*Precalculated:\s*\[)", std::regex::ECMAScript);
    if (!std::regex_search(line, head_re)) {
        return nullptr;
    }

    Precalculated* out = new Precalculated();
    size_t vI = 0;
    // Find all quoted hex numbers
    static const std::regex hex_re(R"(['"]((?:0x|0X)[0-9a-fA-F]+)['"])", std::regex::ECMAScript);
    for (std::sregex_iterator it(line.begin(), line.end(), hex_re), end; it != end; ++it) {
        const std::string token = (*it)[1].str(); // e.g. "0x5a4e7d2f..."
        try {
            std::uint64_t val = std::stoull(token, nullptr, 0); // base=0 lets 0x auto-detect
            out->values[vI++] = val;
        }
        catch (...) {
            delete out;
            return nullptr;
        }
    }
    return out;
}


size_t read_resolved(const std::string &inpFile, Precalculated** prec, std::vector<FFuncWrapperC*> &wrappers)
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
        if (line.find("FFuncWrapper(") != std::string::npos) {
            FFuncWrapperC* wr = parseFFuncWrapper(line);
            if (!wr) continue;
            wrappers.push_back(wr);
        }
        if (line.find("Precalculated") != std::string::npos) {
            Precalculated* _prec = parsePrecalculatedLine(line);
            if (!_prec) continue;
            (*prec) = _prec;
        }
    }
    infile.close();
    return wrappers.size();
}