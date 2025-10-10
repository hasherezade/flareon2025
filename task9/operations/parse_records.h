#pragma once
#include <iostream>
#include <fstream>
#include <string>

#include <string>
#include <vector>
#include <regex>
#include <cstdint>
#include <iostream>
#include <set>

#define MATRIX_SIZE 4

struct FFuncWrapperC {
    std::string dll;
    int type = 0;
    std::vector<std::uint64_t> args;
};

FFuncWrapperC* parseFFuncWrapper(const std::string& line);

struct Precalculated {
    std::uint64_t values[MATRIX_SIZE];
};

Precalculated* parsePrecalculatedLine(const std::string& line);

size_t read_resolved(const std::string& inpFile, Precalculated** prec, std::vector<FFuncWrapperC*>& wrappers);

