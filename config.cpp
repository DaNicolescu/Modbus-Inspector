#include <string.h>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <unordered_map>

#include "config.h"
#include "XlsReader.h"
#include "device_struct.h"

void read_range(struct address_struct *addr, std::string str)
{
    std::pair<union value_type, union value_type> pair;
    union value_type first_num;
    union value_type second_num;
    char *cstr = new char[str.length() + 1];
    char *token;

    strcpy(cstr, str.c_str());

    token = strtok(cstr, ":");

    std::cout << "read range: " << str << std::endl;

    if (!token) {
        std::cout << "Invalid Range" << std::endl;

        return;
    }

    switch (addr->type) {
    case XLS_INT_TYPE:
        sscanf(token, "%d", &first_num.i);

        break;
    case XLS_UINT_TYPE:
        sscanf(token, "%d", &first_num.i);

        break;
    case XLS_FLOAT_TYPE:
        sscanf(token, "%f", &first_num.f);

        break;
    default:
        std::cout << "Invalid Type" << std::endl;

        return;
    }

    std::cout << "token1:" << token << std::endl;

    token = strtok(NULL, ":");

    if (!token) {
        addr->possible_values.push_back(first_num);
    } else {
        std::cout << "token2:" << token << std::endl;
        switch (addr->type) {
        case XLS_INT_TYPE:
            sscanf(token, "%d", &second_num.i);

            break;
        case XLS_UINT_TYPE:
            sscanf(token, "%d", &second_num.i);

            break;
        case XLS_FLOAT_TYPE:
            sscanf(token, "%f", &second_num.f);

            break;
        default:
            std::cout << "Invalid Type" << std::endl;

            return;
        }

        pair.first = first_num;
        pair.second = second_num;

        addr->possible_ranges.push_back(pair);
    }

}

std::vector<std::string> split_into_strings(std::string str,
                                            std::string delimiter)
{
    std::cout << str << std::endl;
    std::string::iterator end_pos = std::remove(str.begin(), str.end(), ' ');
    str.erase(end_pos, str.end());
    std::cout << str << std::endl;
    char *cstr = new char[str.length() + 1];
    char *cdelimiter = new char[delimiter.length() + 1];
    char *current;
    std::vector<std::string> arr;

    std::cout << "Split into strings" << std::endl;

    strcpy(cstr, str.c_str());

    strcpy(cdelimiter, delimiter.c_str());

    std::cout << cstr << std::endl;
    std::cout << cdelimiter << std::endl;

    current = strtok(cstr, cdelimiter);

    while (current) {
        std::cout << current << std::endl;
        arr.push_back(current);
        current = strtok(NULL, cdelimiter);
    }

    return arr;
}

std::vector<uint8_t> split_into_uint8s(std::string str,
                                       std::string delimiter)
{
    char *cstr = const_cast<char*>(str.c_str());
    char *cdelimiter = const_cast<char*>(delimiter.c_str());
    char *current;
    int crt_num;
    std::vector<uint8_t> arr;

    current = strtok(cstr, cdelimiter);

    while (current) {
        std::stringstream sstream(current);
        sstream >> crt_num;
        arr.push_back(crt_num);
        current = strtok(NULL, cdelimiter);
    }

    return arr;
}

void display_xls_config_file(std::string file_name)
{
    xls::WorkBook work_book(file_name);
    int num_of_sheets = work_book.GetSheetCount();

    for (int sheet_num = 0; sheet_num < num_of_sheets; sheet_num++) {
        std::cout << "Sheet Name: " << work_book.GetSheetName(sheet_num)
            << std::endl;

        work_book.InitIterator(sheet_num);

        while (true) {
            xls::cellContent cell = work_book.GetNextCell();

            if (cell.type == xls::cellBlank)
                break;

            work_book.ShowCell(cell);
        }

        std::cout << std::endl << std::endl;
    }
}

void extract_data_from_xls_config_file(std::string file_name,
                                       std::unordered_map<uint8_t,
                                       struct device_struct*> &devices_map)
{
    xls::WorkBook work_book(file_name);
    int num_of_sheets = work_book.GetSheetCount();
    int devices_sheet_num;
    struct device_struct *dev = NULL;
    uint16_t crt_row = 0;
    int int_id;
    std::vector<std::string> coils_ranges;
    std::vector<std::string> strings_vec;

    for (devices_sheet_num = 0; devices_sheet_num < num_of_sheets;
         devices_sheet_num++) {

        if (work_book.GetSheetName(devices_sheet_num) == XLS_DEVICES_SHEET_NAME)
            break;
    }

    if (devices_sheet_num == num_of_sheets) {
        std::cout << "No sheet with the name " << XLS_DEVICES_SHEET_NAME
            << " found" << std::endl;

        return;
    }

    work_book.InitIterator(devices_sheet_num);

    std::cout << "pula1" << std::endl;

    while (true) {
        xls::cellContent cell = work_book.GetNextCell();

        if (cell.type == xls::cellBlank)
            break;

        work_book.ShowCell(cell);

        if (cell.row == 1)
            continue;

        switch (cell.col) {
        case XLS_DEVICES_SLAVE_ID_COLUMN:
            std::cout << "slave id" << std::endl;

            dev = new device_struct;

            std::cout << "malloced" << std::endl;

            if (!dev) {
                std::cout << "Not enough memory for a new device structure"
                    << std::endl;
            }

            sscanf(cell.str.c_str(), "%d", &int_id);

            dev->id = (uint8_t) int_id;
            std::cout << "dev id: " << (unsigned) dev->id << std::endl;
            dev->name = "No devices name";

            std::cout << "set device strings" << std::endl;

            devices_map[dev->id] = dev;

            crt_row = cell.row;

            break;
        case XLS_DEVICES_DEVICE_NAME_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            dev->name = cell.str;

            break;
        case XLS_DEVICES_READ_COILS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            coils_ranges = split_into_strings(cell.str, ",");

            for (std::string str : coils_ranges) {
                std::cout << "coil: " << str << std::endl;
                dev->add_read_coils_range(str);
            }

            break;
        case XLS_DEVICES_WRITE_COILS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            coils_ranges = split_into_strings(cell.str, ",");

            for (std::string str : coils_ranges) {
                std::cout << "coil: " << str << std::endl;
                dev->add_write_coils_range(str);
            }

            break;
        case XLS_DEVICES_INPUTS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            strings_vec = split_into_strings(cell.str, ",");

            for (std::string str : strings_vec) {
                std::cout << "input: " << str << std::endl;
                dev->add_inputs_range(str);
            }

            break;
        case XLS_DEVICES_READ_HLD_REGS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            strings_vec = split_into_strings(cell.str, ",");

            for (std::string str : strings_vec) {
                std::cout << "read holding register: " << str << std::endl;
                dev->add_read_hld_regs_range(str);
            }

            break;
        case XLS_DEVICES_WRITE_HLD_REGS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            strings_vec = split_into_strings(cell.str, ",");

            for (std::string str : strings_vec) {
                std::cout << "write holding register: " << str << std::endl;
                dev->add_write_hld_regs_range(str);
            }

            break;
        case XLS_DEVICES_INPUT_REGS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            strings_vec = split_into_strings(cell.str, ",");

            for (std::string str : strings_vec) {
                std::cout << "input register: " << str << std::endl;
                dev->add_input_regs_range(str);
            }

            break;
        case XLS_DEVICES_GENERIC_FUNCS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

           dev->generic_supported_functions = split_into_uint8s(cell.str, ",");

           break;
        case XLS_DEVICES_SPECIFIC_FUNCS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

           dev->specific_supported_functions = split_into_uint8s(cell.str, ",");

            break;
         default:
            std::cout << "Invalid column" << std::endl;

            return;
        }
    }

    std::unordered_map<uint8_t, struct device_struct*>::iterator it;
    std::vector<std::string> range_strings;
    struct address_struct *addr;
    int device_sheet_num;
    int crt_dev_slave_id;

    for (it = devices_map.begin(); it != devices_map.end(); it++) {
        crt_dev_slave_id = it->first;
        dev = it->second;

        std::cout << "Device " << crt_dev_slave_id << std::endl;

        for (device_sheet_num = 0; device_sheet_num < num_of_sheets;
             device_sheet_num++) {

            if (work_book.GetSheetName(device_sheet_num)
                == XLS_DEVICE_ADDRESSES_SHEET_NAME
                + std::to_string(crt_dev_slave_id))
                break;
        }

        if (device_sheet_num == num_of_sheets) {
            std::cout << "No sheet found for device " << crt_dev_slave_id
                << std::endl;

            return;
        }

        work_book.InitIterator(device_sheet_num);

        while (true) {
            xls::cellContent cell = work_book.GetNextCell();

            if (cell.type == xls::cellBlank)
                break;

            work_book.ShowCell(cell);

            if (cell.row == 1)
                continue;

            switch (cell.col) {
            case XLS_DEVICE_ADDRESSES_ADDRESS_COLUMN:
                addr = new address_struct;

                if (!addr) {
                    std::cout << "Not enough memory to allocate an" <<
                        "address_struct" << std::endl;

                    return;
                }

                sscanf(cell.str.c_str(), "%hu", &addr->address);

                std::cout << "address: " << addr->address << std::endl;

                dev->addresses_map[addr->address] = addr;

                crt_row = cell.row;

                break;
            case XLS_DEVICE_ADDRESSES_RW_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                if (cell.str == XLS_ADDRESS_READ) {
                    addr->write = false;
                } else if (cell.str == XLS_ADDRESS_READ_WRITE) {
                    addr->write = true;
                } else {
                    std::cout << "Invalid R/W cell" << std::endl;

                    return;
                }

                break;
            case XLS_DEVICE_ADDRESSES_DESCRIPTION_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                addr->description = cell.str;

                break;
            case XLS_DEVICE_ADDRESSES_SIZE_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                if (cell.str == XLS_1BIT_ADDRESS_SIZE_STR) {
                    addr->size = XLS_1BIT_ADDRESS_SIZE;
                } else if (cell.str == XLS_8BIT_ADDRESS_SIZE_STR) {
                    addr->size = XLS_8BIT_ADDRESS_SIZE;
                } else if (cell.str == XLS_16BIT_ADDRESS_SIZE_STR) {
                    addr->size = XLS_16BIT_ADDRESS_SIZE;
                } else {
                    std::cout << "Invalid size" << std::endl;

                    return;
                }

                break;
            case XLS_DEVICE_ADDRESSES_TYPE_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                if (cell.str == XLS_BOOL_TYPE_STR) {
                    addr->type = XLS_BOOL_TYPE;
                } else if (cell.str == XLS_INT_TYPE_STR) {
                    addr->type = XLS_INT_TYPE;
                } else if (cell.str == XLS_UINT_TYPE_STR) {
                    addr->type = XLS_UINT_TYPE;
                } else if (cell.str == XLS_FLOAT_TYPE_STR) {
                    addr->type = XLS_FLOAT_TYPE;
                } else {
                    std::cout << "Invalid Type" << std::endl;

                    return;
                }

                break;
            case XLS_DEVICE_ADDRESSES_RANGE_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                std::cout << std::endl;
                std::cout << std::endl;
                std::cout << std::endl;
                std::cout << std::endl;
                std::cout << std::endl;

                std::cout << cell.str << std::endl;

                range_strings = split_into_strings(cell.str, ",");

                for (std::string str : range_strings) {
                    std::cout << "read range for " << str << std::endl;
                    read_range(addr, str);
                }

                break;
            case XLS_DEVICE_ADDRESSES_NOTES_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                addr->notes = cell.str;

                break;
            default:
                std::cout << "Invalid column" << std::endl;

                return;
            }
        }
    }

}
