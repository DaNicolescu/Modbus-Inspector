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

int bytes_to_int(uint8_t hi, uint8_t lo)
{
    int result;

    result = lo | (hi << 8);

    return result;
}

float bytes_to_float(uint8_t hi, uint8_t lo)
{
    float result;

    result = lo | (hi << 8);

    return result;
}
