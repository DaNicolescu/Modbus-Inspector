#ifndef DEVICE_STRUCT_H
#define DEVICE_STRUCT_H

#include <string>
#include <vector>
#include <utility>
#include <unordered_map>

union value_type {
    int i;
    float f;
};

struct address_struct {
    uint16_t address;
    bool write;
    std::string description;
    std::string notes;
    uint8_t size;
    uint8_t type;
    int db_id;
    std::vector<union value_type> possible_values;
    std::vector<std::pair<union value_type, union value_type>> possible_ranges;

    bool check_int_range(uint16_t address, int value);
    bool check_float_range(uint16_t address, float value);

    void display();
};

struct device_struct {
    uint8_t id;
    std::string name;
    std::vector<std::pair<uint16_t, uint16_t>> read_coils;
    std::vector<std::pair<uint16_t, uint16_t>> write_coils;
    std::vector<std::pair<uint16_t, uint16_t>> inputs;
    std::vector<std::pair<uint16_t, uint16_t>> read_holding_registers;
    std::vector<std::pair<uint16_t, uint16_t>> write_holding_registers;
    std::vector<std::pair<uint16_t, uint16_t>> input_registers;
    std::vector<uint8_t> generic_supported_functions;
    std::vector<uint8_t> specific_supported_functions;
    std::unordered_map<uint16_t, struct address_struct*> addresses_map;

    static std::pair<uint16_t, uint16_t> make_uint16_pair(std::string str);

    bool supported_function(uint8_t function);
    struct address_struct *get_address(uint16_t address);

    void add_read_coils_range(std::string str);
    void add_write_coils_range(std::string str);
    void add_inputs_range(std::string str);
    void add_read_hld_regs_range(std::string str);
    void add_write_hld_regs_range(std::string str);
    void add_input_regs_range(std::string str);

    bool valid_read_coils_addresses(uint16_t address, uint16_t num_of_points);
    bool valid_write_coils_addresses(uint16_t address, uint16_t num_of_points);
    bool valid_inputs_addresses(uint16_t address, uint16_t num_of_points);
    bool valid_read_hld_regs_addresses(uint16_t address,
                                       uint16_t num_of_points);
    bool valid_write_hld_regs_addresses(uint16_t address,
                                        uint16_t num_of_points);
    bool valid_input_regs_addresses(uint16_t address, uint16_t num_of_points);

    void display_addresses(uint16_t address, uint16_t num_of_points);
    void display_addresses(const struct modbus_aggregate *aggregated_frame);

    void display();
};

#endif
