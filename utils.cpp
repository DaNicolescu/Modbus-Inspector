#include "utils.h"

std::string byte_to_binary_string(uint8_t number)
{
    std::string binary_string;

    for (uint8_t i = 0; i < 8; i++) {
        if ((number >> i) & 1)
            binary_string.push_back('1');
        else
            binary_string.push_back('0');
    }

    return binary_string;
}
