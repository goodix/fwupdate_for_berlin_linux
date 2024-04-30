#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdbool.h>

#include "log_wrapper.h"

#define MAX_CONFIG_SIZE             (4 * 1024)
#define MAX_FIRMWARE_SIZE           (512 * 1024)
#define MAX_FILE_NAME_LEN           256

int goodix_fw_update(uint8_t *fw_data, int size,
	uint8_t *cfg_data, int cfg_size, char *type, char *register_node);

/* return config len on success else return < 0 */
static int ascii_to_array(const uint8_t *src_buf, int src_len, uint8_t *dst_buf)
{
    int i, ret = -1;
    int cfg_len = 0;
    long val;
    uint8_t temp_buf[5];

    for (i = 0; i < src_len;) {
        if (!isalnum(src_buf[i])) {
            i++;
            continue;
        }

        temp_buf[0] = src_buf[i];
        temp_buf[1] = src_buf[i + 1];
        temp_buf[2] = src_buf[i + 2];
        temp_buf[3] = src_buf[i + 3];
        temp_buf[4] = '\0';
        val = strtol((const char *)temp_buf, NULL, 16);
        if (val <= 255) {
            if (cfg_len < MAX_CONFIG_SIZE) {
                dst_buf[cfg_len++] = val & 0xFF;
                i += 4;
            } else {
                ret = -2;
                goto convert_failed;
            }
        } else {
            ret = -3;
            goto convert_failed;
        }
    }
    return cfg_len;
convert_failed:
    return ret;
}

/* try get ic config from local file system.
 * @cfg_file: config file path.
 * @data: buffer for store config data.
 * return: on success return file size.
 * */
int load_config_file(const char *cfg_file, uint8_t* data)
{
    int ret;
    int file_size = 0;
    FILE* file_fp;
    uint8_t *tmp_buf = NULL;

    file_fp = fopen(cfg_file, "rb");
    if (!file_fp) {
        NLOGE("failed open file: %s, %s", cfg_file, strerror(errno));
        return -1;
    }
    if (fseek(file_fp, 0, SEEK_END)) {
        NLOGE("failed find file end");
        return -2;
    }

    file_size = ftell(file_fp);
    fseek(file_fp, 0, SEEK_SET);

    tmp_buf = malloc(file_size);
    if (!tmp_buf) {
        NLOGE("failed alloc memory");
        file_size = -3;
        goto exit;
    }
    ret = fread(tmp_buf, 1, file_size, file_fp);
    if (ret != file_size) {
        NLOGE("failed read file data");
        file_size = -4;
    }

    file_size = ascii_to_array(tmp_buf, file_size, data);

exit:
    fclose(file_fp);
    free(tmp_buf);
    return file_size;
}


/* try get firmware file from local file system
 * @fw_file: firmware file path.
 * @data: buffer for store firmware data, set data with NULL.
 *      to get the file size.
 * return: on success return file size.
 * */
int load_firmware_file(const char *fw_file, uint8_t *data)
{
    int ret;
    int file_size = 0;
    FILE *file_fp;

    file_fp = fopen(fw_file, "rb");
    if (!file_fp) {
        NLOGE("failed open file: %s, %s", fw_file, strerror(errno));
        return -1;
    }
    if (fseek(file_fp, 0, SEEK_END)) {
        NLOGE("failed find file end");
        return -2;
    }

    file_size = ftell(file_fp);
    NLOGI("get firmware file size %d", file_size);
    fseek(file_fp, 0, SEEK_SET);

    if (data) {
        ret = fread(data, 1, file_size, file_fp);
        if (ret != file_size) {
            NLOGE("failed read file data");
            file_size = -3;
        }
    }

    fclose(file_fp);
    return file_size;
}


#define VERSION "1.0.0"

void display_help(char *program_name) {
    printf("This program are used to upgrade firmware for goodix BerlinB or BerlinD series touch IC.\n"
           "This program use sysfs node \"registers\" created by goodix_berlin driver to communicate with touch IC.\n"
           "Usage: %s -f firmware_file -c config_file -d registers_node -t device_type\n", program_name);
    printf("Options:\n");
    printf("  -f <firmware_file>: Specify the firmware file\n");
    printf("  -c <config_file>: Specify the ASCII format config file\n");
    printf("  -d <registers_node>: Specify registers node such as /sys/bus/spi/devices/spi-GDIX9916:00/registers\n");
    printf("  -t <device_type>: Specify the device type can be \"BerlinB\" or \"BerlinD\"\n");
    printf("  -h: Display help information\n");
    printf("  -v: Display version information\n");
}

int main(int argc, char *argv[]) {
    int opt;
    char *firmware_file = NULL;
    char *config_file = NULL;
    char *registers_node = NULL;
    char *device_type = NULL;
    int ret = -1;
    uint8_t *fw_data = NULL, *config_data = NULL;
    int config_len = 0, fw_len = 0;

    while ((opt = getopt(argc, argv, "f:c:d:t:hv")) != -1) {
        switch (opt) {
            case 'f':
                firmware_file = optarg;
                break;
            case 'c':
                config_file = optarg;
                break;
            case 'd':
                registers_node = optarg;
                break;
            case 't':
                device_type = optarg;
                break;
            case 'h':
                display_help(argv[0]);
                return 0;
            case 'v':
                printf("Version: %s\n", VERSION);
                return 0;
            default:
                fprintf(stderr, "Invalid option. Use -h for help.\n");
                return 1;
        }
    }

    if (firmware_file == NULL || config_file == NULL || registers_node == NULL || device_type == NULL) {
        fprintf(stderr, "Missing required arguments. Use -h for help.\n");
        return 1;
    }

    printf("Firmware file: %s\n", firmware_file);
    printf("Config file: %s\n", config_file);
    printf("Device type: %s\n", device_type);
    printf("Registers node: %s\n", registers_node);


    config_data = malloc(MAX_CONFIG_SIZE);
    if (!config_data) {
        NLOGE("failed alloc buffer for config data");
        return -1;
    }
    fw_data = malloc(MAX_FIRMWARE_SIZE);
    if (!fw_data) {
        NLOGE("failed alloc buffer for firmware data");
        free(config_data);
        return -2;
    }

    config_len = load_config_file(config_file, config_data);
    if (config_len <= 0) {
        NLOGE("failed load config data");
        goto err_load_config;
    }

    fw_len = load_firmware_file(firmware_file, fw_data);
    if (fw_len <= 0) {
        NLOGE("failed load firmware data");
        goto err_load_firmware;
    }

    ret = goodix_fw_update(fw_data, fw_len, config_data,
            config_len, device_type, registers_node);

    NLOGE("%s do fw update", ret < 0 ? "Failed" : "Success");

err_load_config:
err_load_firmware:
    free(config_data);
    free(fw_data);

    return 0;
}