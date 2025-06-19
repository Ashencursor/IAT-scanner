#pragma once
#include "utils.h"      // Has other useful headers inside
#include <filesystem>   // For std::filesystem
#include <fstream>      // For std::ifstream
#include <string>
#include <locale>
#include <vector>
#include <string_view>



std::vector<std::uint8_t> GetRawDllBytesFromFile(std::string_view filePath)
{
    if (!std::filesystem::exists(filePath.data()))
    {
        printf("[-] The path doesn't exist\n");
        return {};
    }
    /*
    if (!std::filesystem::path(filePath.data()).extension().string().ends_with(".dll"))
    {
        printf("[-] The file you're trying to read is not a DLL\n");
        return {};
    }
    */
    std::ifstream file(filePath.data(), std::ios::binary);
    if (!file)
    {
        printf("[-] Can't read the file\n");
        return {};
    }

    // Get the size of the file and resize the vector as needed.
    file.seekg(0, std::ios::end);
    std::vector<std::uint8_t> contents(file.tellg());
    file.seekg(0, std::ios::beg);

    // Copy the file contents into the vector.
    file.read(reinterpret_cast<char*>(contents.data()), contents.size());


    return contents;
}

std::string toLower(std::string str) {
    std::string result = str; // Create a copy of the input string
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return std::tolower(c);
        });
    return result; // Return the lowercase string
}