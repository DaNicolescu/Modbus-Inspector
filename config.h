#ifndef CONFIG_H
#define CONFIG_H

#include <string>

#define XLS_CONFIG_FILE_NAME                        "../config.xls"
#define XLS_DEVICES_SHEET_NAME                      "devices"
#define XLS_DEVICE_ADDRESSES_SHEET_NAME             "device "

#define XLS_DEVICES_NUM_OF_COLUMNS                  10
#define XLS_DEVICES_SLAVE_ID_COLUMN                 1
#define XLS_DEVICES_DEVICE_NAME_COLUMN              2
#define XLS_DEVICES_READ_COILS_COLUMN               3
#define XLS_DEVICES_WRITE_COILS_COLUMN              4
#define XLS_DEVICES_INPUTS_COLUMN                   5
#define XLS_DEVICES_READ_HLD_REGS_COLUMN            6
#define XLS_DEVICES_WRITE_HLD_REGS_COLUMN           7
#define XLS_DEVICES_INPUT_REGS_COLUMN               8
#define XLS_DEVICES_GENERIC_FUNCS_COLUMN            9
#define XLS_DEVICES_SPECIFIC_FUNCS_COLUMN           10

#define XLS_DEVICE_ADDRESSES_NUM_OF_COLUMNS         6
#define XLS_DEVICE_ADDRESSES_ADDRESS_COLUMN         1
#define XLS_DEVICE_ADDRESSES_RW_COLUMN              2
#define XLS_DEVICE_ADDRESSES_DESCRIPTION_COLUMN     3
#define XLS_DEVICE_ADDRESSES_SIZE_COLUMN            4
#define XLS_DEVICE_ADDRESSES_TYPE_COLUMN            5
#define XLS_DEVICE_ADDRESSES_RANGE_COLUMN           6

#define XLS_ADDRESS_READ                            "R"
#define XLS_ADDRESS_READ_WRITE                      "RW"

#define XLS_BOOL_TYPE_STR                           "bool"
#define XLS_INT_TYPE_STR                            "int"
#define XLS_UINT_TYPE_STR                           "uint"
#define XLS_FLOAT_TYPE_STR                          "float"
#define XLS_BOOL_TYPE                               1
#define XLS_INT_TYPE                                2
#define XLS_UINT_TYPE                               3
#define XLS_FLOAT_TYPE                              4

#define XLS_1BIT_ADDRESS_SIZE_STR                   "1"
#define XLS_8BIT_ADDRESS_SIZE_STR                   "8"
#define XLS_16BIT_ADDRESS_SIZE_STR                  "16"
#define XLS_1BIT_ADDRESS_SIZE                       1
#define XLS_8BIT_ADDRESS_SIZE                       2
#define XLS_16BIT_ADDRESS_SIZE                      3

void display_xls_config_file(std::string file_name);
void extract_data_from_xls_config_file(std::string file_name,
std::unordered_map<uint8_t, struct device_struct*> &devices_map);

#endif
