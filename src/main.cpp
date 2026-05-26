#include "roe/cli.hpp"

#include <iostream>

int main(int argc, char** argv)
{
    return roe::cli::main_entry(argc, argv, std::cout, std::cerr);
}
