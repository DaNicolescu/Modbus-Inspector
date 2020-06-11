#ifndef UTILS_H
#define UTILS_H

#include <string>

std::string byte_to_binary_string(uint8_t number);
int bytes_to_int(uint8_t hi, uint8_t lo);
float bytes_to_float(uint8_t hi, uint8_t lo);

#endif
