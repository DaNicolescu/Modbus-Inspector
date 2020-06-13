#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <modbus.h>

int main(void)
{
    modbus_t *ctx;
    int rc;
    uint8_t raw_req[] = { 0xFF, 0x03, 0x00, 0x01,
        0x0, 0x05 };
    int req_length;
    uint8_t rsp[MODBUS_TCP_MAX_ADU_LENGTH];

    /* TCP */
    ctx = modbus_new_tcp("127.0.0.1", 502);
    modbus_set_debug(ctx, TRUE);

    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "Connection failed: %s\n",
                modbus_strerror(errno));
        modbus_free(ctx);
        return -1;
    }

    req_length = modbus_send_raw_request(ctx, raw_req, 6 * sizeof(uint8_t));
    modbus_receive_confirmation(ctx, rsp);

    /* Close the connection */
    modbus_close(ctx);
    modbus_free(ctx);

    return 0;
}
