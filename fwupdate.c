#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "log_wrapper.h"
#include "fwupdate_utils.h"

#define BUS_TYPE_SPI 0x01
#define BUS_TYPE_I2C 0

#define EPERM       1
#define ENOMEM      12
#define EFAULT      14
#define EAGAIN      11
#define EBUS        16
#define EINVAL      22
#define EMEMCMP     50
#define ETIMEOUT    51 

#define GOODIX_BUS_RETRY_TIMES      	3

#define FW_HEADER_SIZE_BRA				256
#define FW_HEADER_SIZE					512
#define FW_SUBSYS_INFO_SIZE				10
#define FW_SUBSYS_INFO_OFFSET_BRA		36
#define FW_SUBSYS_INFO_OFFSET			42
#define FW_SUBSYS_MAX_NUM				47

#define ISP_MAX_BUFFERSIZE		    	4096

#define NO_NEED_UPDATE                  99

#define FW_PID_LEN		                8
#define FW_VID_LEN       	            4
#define FLASH_CMD_LEN 		            11

#define FW_FILE_CHECKSUM_OFFSET         8
#define CONFIG_DATA_TYPE 		        4
#define CONFIG_ID_OFFSET 		        30

#define ISP_RAM_ADDR_BRA				0x18400
#define ISP_RAM_ADDR_BRB				0x57000
#define ISP_RAM_ADDR_BRD				0x23800
#define ISP_RAM_ADDR_MAR				0x3B800
#define HW_REG_CPU_RUN_FROM				0x10000
#define FLASH_CMD_REG_BRA				0x10400
#define FLASH_CMD_REG_BRB				0x13400
#define FLASH_CMD_REG_BRD				0x12400
#define FLASH_CMD_REG_MAR				0x10174
#define HW_REG_ISP_BUFFER_BRA			0x10410
#define HW_REG_ISP_BUFFER_BRB			0x13410
#define HW_REG_ISP_BUFFER_BRD			0x12410
#define HW_REG_ISP_BUFFER_MAR			0x12400
#define CONFIG_DATA_ADDR_BRA			0x3E000
#define CONFIG_DATA_ADDR_BRB			0x40000
#define CONFIG_DATA_ADDR_BRD			0x3E000
#define CONFIG_DATA_ADDR_MAR			0x3F000

#define HOLD_CPU_REG_W					0x0002
#define HOLD_CPU_REG_R					0x2000
#define MISCTL_REG_BRA					0xD807
#define MISCTL_REG_BRB					0xD807
#define MISCTL_REG_BRD					0xD804
#define ENABLE_MISCTL_BRA				0x08
#define ENABLE_MISCTL_BRB				0x40
#define ENABLE_MISCTL_BRD				0x20700000
#define ESD_KEY_REG						0xCC58
#define WATCH_DOG_REG_BRA				0xCC54
#define WATCH_DOG_REG_BRB				0xD054
#define WATCH_DOG_REG_BRD				0xD040

#define FLASH_CMD_TYPE_READ  			0xAA
#define FLASH_CMD_TYPE_WRITE 			0xBB
#define FLASH_CMD_ACK_CHK_PASS	    	0xEE
#define FLASH_CMD_ACK_CHK_ERROR     	0x33
#define FLASH_CMD_ACK_IDLE      		0x11
#define FLASH_CMD_W_STATUS_CHK_PASS 	0x22
#define FLASH_CMD_W_STATUS_CHK_FAIL 	0x33
#define FLASH_CMD_W_STATUS_ADDR_ERR 	0x44
#define FLASH_CMD_W_STATUS_WRITE_ERR 	0x55
#define FLASH_CMD_W_STATUS_WRITE_OK 	0xEE

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

enum compare_status {
    COMPARE_EQUAL = 0,
    COMPARE_NOCODE,
    COMPARE_PIDMISMATCH,
    COMPARE_FW_NOTEQUAL,
    COMPARE_CFG_NOTEQUAL,
};

enum IC_TYPE_ID {
    IC_TYPE_BERLIN_B = 5,
    IC_TYPE_BERLIN_D = 6,
};

struct update_info_t {
    int header_size;
    int subsys_info_offset;
    u32 isp_ram_reg;
    u32 flash_cmd_reg;
    u32 isp_buffer_reg;
    u32 config_data_reg;
    u32 misctl_reg;
    u32 watch_dog_reg;
    u32 enable_misctl_val;
};

/* berlinB update info */
struct update_info_t update_brb = {
    FW_HEADER_SIZE,
    FW_SUBSYS_INFO_OFFSET,
    ISP_RAM_ADDR_BRB,
    FLASH_CMD_REG_BRB,
    HW_REG_ISP_BUFFER_BRB,
    CONFIG_DATA_ADDR_BRB,
    MISCTL_REG_BRB,
    WATCH_DOG_REG_BRB,
    ENABLE_MISCTL_BRB,
};

/* berlinD update info */
struct update_info_t update_brd = {
    FW_HEADER_SIZE,
    FW_SUBSYS_INFO_OFFSET,
    ISP_RAM_ADDR_BRD,
    FLASH_CMD_REG_BRD,
    HW_REG_ISP_BUFFER_BRD,
    CONFIG_DATA_ADDR_BRD,
    MISCTL_REG_BRD,
    WATCH_DOG_REG_BRD,
    ENABLE_MISCTL_BRD,
};

/**
 * fw_subsys_info - subsytem firmware infomation
 * @type: sybsystem type
 * @size: firmware size
 * @flash_addr: flash address
 * @data: firmware data
 */
struct fw_subsys_info {
    u8 type;
    u32 size;
    u32 flash_addr;
    const u8 *data;
};

#pragma pack(1)
typedef struct {
    uint8_t rom_pid[6];
    uint8_t rom_vid[3];
    uint8_t rom_vid_reserved;
    uint8_t patch_pid[8];
    uint8_t patch_vid[4];
    uint8_t patch_vid_reserved;
    uint8_t sensor_id;
    uint8_t reserved[2];
    uint16_t checksum;
} fw_version_t;
#pragma pack()

/*
 * struct goodix_fw_version - firmware version
 * @valid: whether these infomation is valid
 * @pid: product id string
 * @vid: firmware version code
 * @cid: customer id code
 * @sensor_id: sendor id
 */
struct goodix_fw_version {
    bool valid;
    u8 pid[FW_PID_LEN];
    u8 vid[FW_VID_LEN];
    u8 sensor_id;
} active_fw_info;

/**
 *  firmware_summary
 * @size: fw total length
 * @checksum: checksum of fw
 * @hw_pid: mask pid string
 * @hw_pid: mask vid code
 * @fw_pid: fw pid string
 * @fw_vid: fw vid code
 * @subsys_num: number of fw subsystem
 * @chip_type: chip type
 * @protocol_ver: firmware packing
 *   protocol version
 * @bus_type: 0 represent I2C, 1 for SPI
 * @subsys: sybsystem info
 */
#pragma pack(1)
struct  firmware_summary {
    u32 size;
    u32 checksum;
    u8 hw_pid[6];
    u8 hw_vid[3];
    u8 fw_pid[FW_PID_LEN];
    u8 fw_vid[FW_VID_LEN];
    u8 subsys_num;
    u8 chip_type;
    u8 protocol_ver;
    u8 bus_type;
    u8 flash_protect;
    u8 reserved[2];
    struct fw_subsys_info subsys[FW_SUBSYS_MAX_NUM];
};
#pragma pack()

struct firmware {
    u8 *data;
    int size;
};

/**
 * firmware_data - firmware data structure
 * @fw_summary: firmware infomation
 * @firmware: firmware data structure
 */
struct firmware_data {
    struct  firmware_summary fw_summary;
    struct firmware firmware;
};

struct config_data {
    uint8_t *data;
    int size;
};

#pragma pack(1)
struct goodix_flash_cmd {
    union {
        struct {
            uint8_t status;
            uint8_t ack;
            uint8_t len;
            uint8_t cmd;
            uint8_t fw_type;
        uint16_t fw_len;
        uint32_t fw_addr;
            //uint16_t checksum;
        };
        uint8_t buf[16];
    };
};
#pragma pack()

struct fw_update_ctrl {
    bool force_update;
    int ic_type;
    struct firmware_data fw_data;
    struct config_data cfg;
    struct update_info_t *update_info;
} g_fw_update_ctrl;

int g_reg_rw_fd;
int fwupdate_bus_init(const char *register_node)
{
    g_reg_rw_fd = open(register_node, O_RDWR);
    if (g_reg_rw_fd == -1) {
        perror("Failed to open register node");
        return -1;
    }
    return 0;
}

int _goodix_reg_read(uint32_t addr, uint8_t *buf, int len)
{
    ssize_t bytes_read;
    off_t offset = addr;
    off_t new_offset = lseek(g_reg_rw_fd, offset, SEEK_SET);

    if (new_offset == -1) {
        perror("Failed to set offset");
        return -1;
    }
    bytes_read = read(g_reg_rw_fd, buf, (size_t)len);
    if (bytes_read == -1) {
        perror("Failed to read from file");
        return -2;
    }
    return 0;
}

int _goodix_reg_write(uint32_t addr, uint8_t *buf, int len)
{
    ssize_t bytes_written;
    off_t offset = addr;
    off_t new_offset = lseek(g_reg_rw_fd, offset, SEEK_SET);

    if (new_offset == -1) {
        perror("Failed to set offset");
        return -1;
    }
    bytes_written = write(g_reg_rw_fd, buf, (size_t)len);
    if (bytes_written == -1) {
        perror("Failed to write to file");
        return -2;
    }
    return 0;
}


#define MAX_TRANSFER_SIZE		2048
int goodix_reg_read(uint32_t reg, uint8_t *data, int len)
{
    int transfer_length = 0, pos = 0;
    int retry, r = 0;

    while (pos != len) {
        if (len - pos > MAX_TRANSFER_SIZE)
            transfer_length = MAX_TRANSFER_SIZE;
        else
            transfer_length = len - pos;

        for (retry = 0; retry < GOODIX_BUS_RETRY_TIMES; retry++) {
            if (!_goodix_reg_read(reg + pos, data + pos, transfer_length)) {
                pos += transfer_length;
                break;
            }
            NLOGI("read retry[%d]:0x%x", retry + 1, reg);
            usleep(20000);
        }
        if (retry == GOODIX_BUS_RETRY_TIMES) {
            NLOGE("read failed,reg:%04x,size:%u", reg, len);
            r = -1;
            goto read_exit;
        }
    }

read_exit:
    return r;
}

int goodix_reg_write(uint32_t reg, uint8_t *data, int len)
{

    uint32_t transfer_length = 0;
    int pos = 0, retry, r = 0;

    while (pos != len) {
        if (len - pos > MAX_TRANSFER_SIZE)
            transfer_length = MAX_TRANSFER_SIZE;
        else
            transfer_length = len - pos;

        for (retry = 0; retry < GOODIX_BUS_RETRY_TIMES; retry++) {
            if (!_goodix_reg_write(reg + pos, data + pos, transfer_length)) {
                pos += transfer_length;
                break;
            }
            NLOGI("write retry[%d]", retry + 1);
            usleep(20000);
        }
        if (retry == GOODIX_BUS_RETRY_TIMES) {
            NLOGE("write failed,reg:%04x,size:%u", reg, len);
            r = -1;
            goto write_exit;
        }
    }

write_exit:
    return r;
}

#define SOFTWARE_RESET_ADDR          0xD808
void chip_reset(int delay_ms)
{
    uint8_t reg_val=0xFE;

    goodix_reg_write(SOFTWARE_RESET_ADDR, &reg_val, 1);
    if (delay_ms)
        usleep(delay_ms * 1000);
}

/*****************************************************************************
* gdix_append_checksum
* @summary
*    Calcualte data checksum with the specified mode.
*
* @param data
*   data need to be calculate
* @param len
*   data length
* @param mode
*   calculate for u8 or u16 checksum
* @return
*   return the data checksum value.
*
*****************************************************************************/
#define CHECKSUM_MODE_U8             0
#define CHECKSUM_MODE_U16            1
uint32_t gdix_append_checksum(uint8_t *data, int len, int mode)
{
    uint32_t checksum = 0;
    int i;

    checksum = 0;
    if (mode == CHECKSUM_MODE_U8) {
        for (i = 0; i < len; i++)
            checksum += data[i];
    } else {
        for (i = 0; i < len; i+=2)
            checksum += (data[i] + (data[i+1] << 8));
    }

    if (mode == CHECKSUM_MODE_U8) {
        data[len] = checksum & 0xff;
        data[len + 1] = (checksum >> 8) & 0xff;
        return 0xFFFF & checksum;
    }
    data[len] = checksum & 0xff;
    data[len + 1] = (checksum >> 8) & 0xff;
    data[len + 2] = (checksum >> 16) & 0xff;
    data[len + 3] = (checksum >> 24) & 0xff;
    return checksum;
}

/**
 * goodix_reg_write_confirm - write register and confirm the value
 *  in the register.
 * @dev: pointer to touch device
 * @addr: register address
 * @data: pointer to data buffer
 * @len: data length
 * return: 0 write success and confirm ok
 *		   < 0 failed
 */
int goodix_reg_write_confirm(unsigned int addr, unsigned char *data, unsigned int len)
{
    u8 *cfm = NULL;
    u8 cfm_buf[32];
    int r, i;

    if (len > sizeof(cfm_buf)) {
        cfm = malloc(len);
        if (!cfm) {
            NLOGE("Mem alloc failed");
            return -ENOMEM;
        }
    } else {
        cfm = &cfm_buf[0];
    }

    for (i = 0; i < GOODIX_BUS_RETRY_TIMES; i++) {
        r = goodix_reg_write(addr, data, len);
        if (r < 0) {
            NLOGE("[IOCTL] spi sync write data failed");
            //goto exit;
        }

        r = goodix_reg_read(addr, cfm, len);
        if (r < 0) {
            NLOGE("[IOCTL] spi sync read data failed");
            //goto exit;
        }

        if (memcmp(data, cfm, len)) {
            r = -EMEMCMP;
            NLOGI("need write data:");
            NLOG_ARRAY_U8(data, len, 16, NLOG_LEVEL_INFO);
            NLOGI("read out data:");
            NLOG_ARRAY_U8(cfm, len, 16, NLOG_LEVEL_INFO);
            continue;
        } else {
            r = 0;
            break;
        }
    }

    if (cfm != &cfm_buf[0])
        free(cfm);
    return r;
}

int checksum_cmp(const uint8_t *data, int size, int mode)
{
    uint32_t cal_checksum = 0;
    uint32_t r_checksum = 0;
    uint32_t i;

    if (mode == CHECKSUM_MODE_U8) {
        if (size < 2) {
            return 1;
        }
        for (i = 0; i < size - 2; i++)
            cal_checksum += data[i];
        r_checksum = data[size - 2] + (data[size - 1] << 8);
        return (cal_checksum & 0xFFFF) == r_checksum ? 0 : 1;
    }

    if (size < 4)
        return 1;
    for (i = 0; i < size - 4; i += 2)
        cal_checksum += data[i] + (data[i + 1] << 8);
    r_checksum = data[size - 4] + (data[size - 3] << 8) +
            (data[size - 2] << 16) + (data[size - 1] << 24);
    return cal_checksum == r_checksum ? 0 : 1;
}

#define FW_VERSION_INFO_ADDR         0x10014
int get_fw_version_info(fw_version_t *fw_version)
{
    int err = -1, i;
    uint8_t buf[sizeof(*fw_version)] = {0};
    uint8_t temp_buf[9] = {0};

    for (i = 0; i < 3; i++) {
        err = goodix_reg_read(FW_VERSION_INFO_ADDR, buf, sizeof(buf));
        if (err) {
            NLOGE("read fw version: %d, retry %d", err, i);
            err = -1;
            usleep(5000);
            continue;
        }

        if (checksum_cmp(buf, sizeof(buf), CHECKSUM_MODE_U8)) {
            NLOGE("invalid fw version: checksum error!");
            NLOG_ARRAY_U8(buf, sizeof(buf), 32, NLOG_LEVEL_ERROR);
            err = -1;
            usleep(20000);
            continue;
        }
        break;
    }
    if (err != 0) {
        NLOGE("failed get valied fw version");
        return err;
    }

    memcpy(fw_version, buf, sizeof(*fw_version));
    memcpy(temp_buf, fw_version->rom_pid, sizeof(fw_version->rom_pid));
    NLOGI("rom_pid: %s", temp_buf);
    NLOGI("rom_vid: %02x %02x %02x", fw_version->rom_vid[0], fw_version->rom_vid[1], fw_version->rom_vid[2]);
    memcpy(temp_buf, fw_version->patch_pid, sizeof(fw_version->patch_pid));
    NLOGI("patch_pid: %s", temp_buf);
    NLOGI("patch_vid: %02x %02x %02x %02x", fw_version->patch_vid[0], fw_version->patch_vid[1],
        fw_version->patch_vid[2], fw_version->patch_vid[3]);
    NLOGI("sensor id: %d", fw_version->sensor_id);
    return 0;
}

/**
 * goodix_parse_firmware - parse firmware header infomation
 *	and subsystem infomation from firmware data buffer
 *
 * @fw_data: firmware struct, contains firmware header info
 *	and firmware data.
 * return: 0 - OK, < 0 - error
 */
/* sizeof(length) + sizeof(checksum) */
static int goodix_parse_firmware(struct firmware_data *fw_data)
{
    const struct firmware *firmware;
    struct  firmware_summary *fw_summary;
    int subsys_info_offset = g_fw_update_ctrl.update_info->subsys_info_offset;
    int header_size = g_fw_update_ctrl.update_info->header_size;
    unsigned int i, fw_offset, info_offset;
    u32 checksum;
    int r = 0;

    fw_summary = &fw_data->fw_summary;

    /* copy firmware head info */
    firmware = &fw_data->firmware;
    if (firmware->size < subsys_info_offset) {
        NLOGE("Invalid firmware size:%d", firmware->size);
        r = -EINVAL;
        goto err_size;
    }
    memcpy(fw_summary, firmware->data, sizeof(*fw_summary));

    /* check firmware size */
    fw_summary->size = le32_to_cpu(fw_summary->size);
    if (firmware->size != fw_summary->size + FW_FILE_CHECKSUM_OFFSET) {
        NLOGE("Bad firmware, size not match, %d != %d", firmware->size, fw_summary->size + 6);
        r = -EINVAL;
        goto err_size;
    }

    for (i = FW_FILE_CHECKSUM_OFFSET, checksum = 0; i < firmware->size; i+=2)
        checksum += firmware->data[i] + (firmware->data[i+1] << 8);

    /* byte order change, and check */
    fw_summary->checksum = le32_to_cpu(fw_summary->checksum);
    if (checksum != fw_summary->checksum) {
        NLOGE("Bad firmware, cheksum error");
        r = -EINVAL;
        goto err_size;
    }

    if (fw_summary->subsys_num > FW_SUBSYS_MAX_NUM) {
        NLOGE("Bad firmware, invalid subsys num: %d",
               fw_summary->subsys_num);
        r = -EINVAL;
        goto err_size;
    }

    /* parse subsystem info */
    fw_offset = header_size;
    for (i = 0; i < fw_summary->subsys_num; i++) {
        info_offset = subsys_info_offset + i * FW_SUBSYS_INFO_SIZE;
        fw_summary->subsys[i].type = firmware->data[info_offset];
        fw_summary->subsys[i].size = le32_to_cpup(&firmware->data[info_offset + 1]);
        fw_summary->subsys[i].flash_addr = le32_to_cpup(&firmware->data[info_offset + 5]);
        if (fw_offset > firmware->size) {
            NLOGE("Sybsys offset exceed Firmware size");
            goto err_size;
        }

        fw_summary->subsys[i].data = firmware->data + fw_offset;
        fw_offset += fw_summary->subsys[i].size;
    }

    NLOGI("Firmware package protocol: V%u", fw_summary->protocol_ver);
    NLOGI("Fimware PID:GT%s", fw_summary->fw_pid);
    NLOGI("Fimware VID:%02X%02X%02X%02X", fw_summary->fw_vid[0],
                fw_summary->fw_vid[1], fw_summary->fw_vid[2], fw_summary->fw_vid[3]);
    NLOGI("Firmware chip type:%02X", fw_summary->chip_type);
    NLOGI("Firmware bus type:%s",
        (fw_summary->bus_type & BUS_TYPE_SPI) ? "SPI" : "I2C");
    NLOGI("Firmware size:%u", fw_summary->size);
    NLOGI("Firmware subsystem num:%u", fw_summary->subsys_num);

err_size:
    return r;
}

/**
 * goodix_fw_version_compare - compare the active version with
 * firmware file version.
 * @fwu_ctrl: firmware infomation to be compared
 * return: 0 equal, -EINVAL for PID mismatch, -EMEMCMP for VID mismatch
 */
#define GOODIX_NOCODE "NOCODE"
#define GOODIX_CFG_ID_ADDR 0x10076
static int goodix_fw_version_compare(struct fw_update_ctrl *fwu_ctrl)
{
    int ret = 0;
    u32 file_cfg_id;
    u32 ic_cfg_id;
    fw_version_t fw_version;
    struct firmware_summary *fw_summary = &fwu_ctrl->fw_data.fw_summary;

    /* compare fw_version */
    ret = get_fw_version_info(&fw_version);
    if (ret)
        return -1;

    if (!memcmp(fw_version.rom_pid, GOODIX_NOCODE, 6) ||
        !memcmp(fw_version.patch_pid, GOODIX_NOCODE, 6)) {
        NLOGI("there is no code in the chip");
        return COMPARE_NOCODE;
    }

    if (memcmp(fw_version.patch_pid, fw_summary->fw_pid, FW_PID_LEN)) {
        NLOGI("Product ID mismatch:%s != %s",
            fw_version.patch_pid, fw_summary->fw_pid);
        return COMPARE_PIDMISMATCH;
    }

    ret = memcmp(fw_version.patch_vid, fw_summary->fw_vid, FW_VID_LEN);
    if (ret) {
        NLOGI("active firmware version:%02x %02x %02x %02x", fw_version.patch_vid[0],
                fw_version.patch_vid[1], fw_version.patch_vid[2], fw_version.patch_vid[3]);
        NLOGI("firmware file version:%02x %02x %02x %02x", fw_summary->fw_vid[0], fw_summary->fw_vid[1],
                fw_summary->fw_vid[2], fw_summary->fw_vid[3]);
        return COMPARE_FW_NOTEQUAL;
    }
    NLOGI("fw_version equal");

    /* compare config id */
    if (fwu_ctrl->cfg.size > 0) {
        file_cfg_id = le32_to_cpup(&(fwu_ctrl->cfg.data[CONFIG_ID_OFFSET]));
        goodix_reg_read(GOODIX_CFG_ID_ADDR, (u8 *)&ic_cfg_id, sizeof(ic_cfg_id));
        if (ic_cfg_id != file_cfg_id) {
            NLOGI("ic_cfg_id:0x%x != file_cfg_id:0x%x",
                ic_cfg_id, file_cfg_id);
            return COMPARE_CFG_NOTEQUAL;
        }
        NLOGI("config_id equal");
    }

    return COMPARE_EQUAL;
}

/**
 * goodix_load_isp - load ISP program to deivce ram
 * @dev: pointer to touch device
 * @fw_data: firmware data
 * return 0 ok, <0 error
 */
static int goodix_load_isp(struct firmware_data *fw_data)
{
    fw_version_t isp_fw_version;
    struct fw_subsys_info *fw_isp;
    u32 isp_ram_reg = g_fw_update_ctrl.update_info->isp_ram_reg;
    u8 reg_val[8] = {0x00};
    int r;

    memset(&isp_fw_version, 0, sizeof(isp_fw_version));
    fw_isp = &fw_data->fw_summary.subsys[0];

    NLOGI("Loading ISP start,fw_isp->size = %d",fw_isp->size);
    r = goodix_reg_write_confirm(isp_ram_reg,
                    (u8 *)fw_isp->data, fw_isp->size);
    if (r < 0) {
        NLOGE("Loading ISP error");
        return r;
    }

    NLOGI("Success send ISP data");

    /* SET BOOT OPTION TO 0X55 */
    memset(reg_val, 0x55, 8);
    r = goodix_reg_write_confirm(HW_REG_CPU_RUN_FROM, reg_val, 8);
    if (r < 0) {
        NLOGE("Failed set REG_CPU_RUN_FROM flag");
        return r;
    }
    NLOGI("Success write [8]0x55 to 0x%x", HW_REG_CPU_RUN_FROM);

    chip_reset(100);
    /*check isp state */
    if (get_fw_version_info(&isp_fw_version)) {
        NLOGE("failed read isp version");
        return -2;
    }
    if (memcmp(&isp_fw_version.patch_pid[3], "ISP", 3)) {
        NLOGE("patch id error %c%c%c != %s", 
        isp_fw_version.patch_pid[3], isp_fw_version.patch_pid[4],
        isp_fw_version.patch_pid[5], "ISP");
        return -3;
    }
    NLOGI("ISP running successfully");
    return 0;
}

/**
 * goodix_update_prepare - update prepare, loading ISP program
 *  and make sure the ISP is running.
 * @fwu_ctrl: pointer to fimrware control structure
 * return: 0 ok, <0 error
 */
static int goodix_update_prepare(struct fw_update_ctrl *fwu_ctrl)
{
    u32 misctl_reg = fwu_ctrl->update_info->misctl_reg;
    u32 watch_dog_reg = fwu_ctrl->update_info->watch_dog_reg;
    u32 enable_misctl_val = fwu_ctrl->update_info->enable_misctl_val;
    u8 reg_val[4] = {0};
    u8 temp_buf[64] = {0};
    int retry;
    int r;

    /*reset IC*/
    NLOGI("firmware update, reset");
    chip_reset(5);

    retry = 100;
    /* Hold cpu*/
    do {
        reg_val[0] = 0x01;
        reg_val[1] = 0x00;
        r = goodix_reg_write(HOLD_CPU_REG_W, reg_val, 2);
        r |= goodix_reg_read(HOLD_CPU_REG_R, &temp_buf[0], 4);
        r |= goodix_reg_read(HOLD_CPU_REG_R, &temp_buf[4], 4);
        r |= goodix_reg_read(HOLD_CPU_REG_R, &temp_buf[8], 4);
        if (!r && !memcmp(&temp_buf[0], &temp_buf[4], 4) &&
            !memcmp(&temp_buf[4], &temp_buf[8], 4) &&
            !memcmp(&temp_buf[0], &temp_buf[8], 4)) {
            break;
        }
        usleep(100);
        NLOGI("retry hold cpu %d", retry);
        NLOG_ARRAY_U8(temp_buf, 12, 16, NLOG_LEVEL_INFO);
    } while (--retry);
    if (!retry) {
        NLOGE("Failed to hold CPU, return =%d", r);
        return -1;
    }
    NLOGI("Success hold CPU");

    /* enable misctl clock */
    if (fwu_ctrl->ic_type == IC_TYPE_BERLIN_D)
        goodix_reg_write(misctl_reg, (u8 *)&enable_misctl_val, 4);
    else
        goodix_reg_write(misctl_reg, (u8 *)&enable_misctl_val, 1);
    NLOGI("enbale misctl clock");

    /* disable watch dog */
    reg_val[0] = 0x00;
    goodix_reg_write(watch_dog_reg, reg_val, 1);
    NLOGI("disable watch dog");

    /* load ISP code and run form isp */
    r = goodix_load_isp(&fwu_ctrl->fw_data);
    if (r < 0)
        NLOGE("Failed lode and run isp");

    return r;
}

/* goodix_send_flash_cmd: send command to read or write flash data
 * @flash_cmd: command need to send.
 * */
static int goodix_send_flash_cmd(struct goodix_flash_cmd *flash_cmd)
{
    int i, ret, retry;
    struct goodix_flash_cmd tmp_cmd = {0};
    u32 flash_cmd_reg = g_fw_update_ctrl.update_info->flash_cmd_reg;

    NLOGI("try send flash cmd");
    NLOG_ARRAY_U8(flash_cmd->buf, sizeof(flash_cmd->buf), 16, NLOG_LEVEL_INFO);
    ret = goodix_reg_write(flash_cmd_reg, flash_cmd->buf, sizeof(flash_cmd->buf));
    if (ret) {
        NLOGE("failed send flash cmd %d", ret);
        return ret;
    }

    retry = 5;
    for (i = 0; i < retry; i++) {
        ret = goodix_reg_read(flash_cmd_reg, tmp_cmd.buf, sizeof(tmp_cmd.buf));
        if (!ret && tmp_cmd.ack == FLASH_CMD_ACK_CHK_PASS)
            break;
        usleep(5000);
        NLOGI("flash cmd ack error retry %d, ack 0x%x, ret %d", i, tmp_cmd.ack, ret);
    }
    if (tmp_cmd.ack != FLASH_CMD_ACK_CHK_PASS) {
        NLOGE("flash cmd ack error, ack 0x%x, ret %d", tmp_cmd.ack, ret);
        NLOG_ARRAY_U8(tmp_cmd.buf, sizeof(tmp_cmd.buf), 16, NLOG_LEVEL_ERROR);
        return -EINVAL;
    }
    NLOGI("flash cmd ack check pass");

    retry = 20;
    for (i = 0; i < retry; i++) {
        ret = goodix_reg_read(flash_cmd_reg, tmp_cmd.buf, sizeof(tmp_cmd.buf));
        if (!ret && tmp_cmd.ack == FLASH_CMD_ACK_CHK_PASS &&
            tmp_cmd.status == FLASH_CMD_W_STATUS_WRITE_OK) {
            NLOGI("flash status check pass");
            return 0;
        }

        NLOGI("flash cmd status not ready, retry %d, ack 0x%x, status 0x%x, ret %d",
            i, tmp_cmd.ack, tmp_cmd.status, ret);
        usleep(15000);
    }
    NLOG_ARRAY_U8(tmp_cmd.buf, sizeof(tmp_cmd.buf), 16, NLOG_LEVEL_INFO);
    NLOGE("flash cmd status error %d, ack 0x%x, status 0x%x, ret %d",
        i, tmp_cmd.ack, tmp_cmd.status, ret);
    if (ret) {
        NLOGI("reason: bus or paltform error");
        return -EBUS;
    }

    switch (tmp_cmd.status) {
        case FLASH_CMD_W_STATUS_CHK_PASS:
            NLOGE("data check pass, but failed get follow-up results");
            return -EFAULT;
        case FLASH_CMD_W_STATUS_CHK_FAIL:
            NLOGE("data check failed, please retry");
            return -EAGAIN;
        case FLASH_CMD_W_STATUS_ADDR_ERR:
            NLOGE("flash target addr error, please check");
            return -EFAULT;
        case FLASH_CMD_W_STATUS_WRITE_ERR:
            NLOGE("flash data write err, please retry");
            return -EAGAIN;
        default:
            NLOGE("unknown status");
            return -EFAULT;
    }
}

static int goodix_flash_package(uint8_t subsys_type, uint8_t *pkg,
    uint32_t flash_addr, u16 pkg_len)
{
    int ret, retry;
    struct goodix_flash_cmd flash_cmd = {0};
    u32 isp_buffer_reg = g_fw_update_ctrl.update_info->isp_buffer_reg;

    retry = 2;
    do {
        ret = goodix_reg_write_confirm(isp_buffer_reg, pkg, pkg_len);
        if (ret < 0) {
            NLOGE("Failed to write firmware packet");
            return ret;
        }

        flash_cmd.len = FLASH_CMD_LEN;
        flash_cmd.cmd = FLASH_CMD_TYPE_WRITE;
        flash_cmd.fw_type = subsys_type;
        flash_cmd.fw_len = cpu_to_le16(pkg_len);
        flash_cmd.fw_addr = cpu_to_le32(flash_addr);

        gdix_append_checksum(&(flash_cmd.buf[2]), 9, CHECKSUM_MODE_U8);

        ret = goodix_send_flash_cmd(&flash_cmd);
        if (!ret) {
            NLOGI("success write package to 0x%x, len %d", flash_addr, pkg_len - 4);
            return 0;
        }
    } while (ret == -EAGAIN && --retry);

    return ret;
}

/**
 * goodix_flash_subsystem - flash subsystem firmware,
 *  Main flow of flashing firmware.
 *	Each firmware subsystem is divided into several
 *	packets, the max size of packet is limited to
 *	@{ISP_MAX_BUFFERSIZE}
 * @dev: pointer to touch device
 * @subsys: subsystem infomation
 * return: 0 ok, < 0 error
 */
static int goodix_flash_subsystem(struct fw_subsys_info *subsys)
{
    u32 data_size, offset;
    u32 total_size;
    u32 subsys_base_addr = subsys->flash_addr;
    u8 *fw_packet = NULL;
    int r = 0;

    /*
     * if bus(i2c/spi) error occued, then exit, we will do
     * hardware reset and re-prepare ISP and then retry
     * flashing
     */
    total_size = subsys->size;
    fw_packet = malloc(ISP_MAX_BUFFERSIZE + 4);
    if (!fw_packet) {
        NLOGE("Failed alloc memory");
        return -EINVAL;
    }

    offset = 0;
    while (total_size > 0) {
        data_size = total_size > ISP_MAX_BUFFERSIZE ?
                ISP_MAX_BUFFERSIZE : total_size;
        NLOGI("Flash firmware to %08x,size:%u bytes",
            subsys_base_addr + offset, data_size);

        memcpy(fw_packet, &subsys->data[offset], data_size);
        /* set checksum for package data */
        gdix_append_checksum(fw_packet, data_size, CHECKSUM_MODE_U16);

        r = goodix_flash_package(subsys->type, fw_packet, subsys_base_addr + offset, data_size + 4);
        if (r) {
            NLOGE("failed flash to %08x,size:%u bytes",
            subsys_base_addr + offset, data_size);
            break;
        }
        offset += data_size;
        total_size -= data_size;
    } /* end while */

    free(fw_packet);
    return r;
}

/**
 * goodix_flash_firmware - flash firmware
 * @dev: pointer to touch device
 * @fw_data: firmware data
 * return: 0 ok, < 0 error
 */
static int goodix_flash_firmware(struct fw_update_ctrl *fw_ctrl)
{
    struct firmware_data *fw_data = &fw_ctrl->fw_data;
    struct  firmware_summary  *fw_summary;
    struct fw_subsys_info *fw_x;
    struct fw_subsys_info subsys_cfg = {0};
    int retry = GOODIX_BUS_RETRY_TIMES;
    int i, r = 0, fw_num;
    u32 config_data_reg = fw_ctrl->update_info->config_data_reg;

    /* start from subsystem 1,
     * subsystem 0 is the ISP program */

    fw_summary = &fw_data->fw_summary;
    fw_num = fw_summary->subsys_num;

    /* flash config data first if we have */
    if (fw_ctrl->cfg.size > 0) {
        subsys_cfg.data = fw_ctrl->cfg.data;
        subsys_cfg.size = 4096;
        subsys_cfg.flash_addr = config_data_reg;
        subsys_cfg.type = CONFIG_DATA_TYPE;
        r = goodix_flash_subsystem(&subsys_cfg);
        if (r) {
            NLOGE("failed flash config with ISP, %d", r);
            return r;
        }
        NLOGI("success flash config with ISP");
    }

    for (i = 1; i < fw_num && retry;) {
        NLOGI("--- Start to flash subsystem[%d] ---", i);
        fw_x = &fw_summary->subsys[i];
        r = goodix_flash_subsystem(fw_x);
        if (r == 0) {
            NLOGI("--- End flash subsystem[%d]: OK ---", i);
            i++;
        } else if (r == -EAGAIN) {
            retry--;
            NLOGE("--- End flash subsystem%d: Fail, errno:%d, retry:%d ---",
                i, r, GOODIX_BUS_RETRY_TIMES - retry);
        } else if (r < 0) { /* bus error */
            NLOGE("--- End flash subsystem%d: Fatal error:%d exit ---",
                i, r);
            goto exit_flash;
        }
    }

exit_flash:
    return r;
}

/**
 * goodix_update_finish - update finished, free resource
 *  and reset flags---
 * @fwu_ctrl: pointer to fw_update_ctrl structrue
 * return: 0 ok, < 0 error
 */
static int goodix_update_finish(struct fw_update_ctrl *fwu_ctrl)
{
    int ret;

    /*reset*/	
    chip_reset(200);

    ret = goodix_fw_version_compare(fwu_ctrl);
    if (ret == COMPARE_EQUAL || ret == COMPARE_CFG_NOTEQUAL)
        return 0;

    return -1;
}

/**
 * goodix_fw_update_proc - firmware update process, the entry of
 *  firmware update flow
 * @fwu_ctrl: firmware control
 * return: = 0 update ok, < 0 error or NO_NEED_UPDATE
 */
int goodix_fw_update_proc(struct fw_update_ctrl *fwu_ctrl)
{
#define FW_UPDATE_RETRY		2
    int retry0 = FW_UPDATE_RETRY;
    int retry1 = FW_UPDATE_RETRY;
    int ret = 0;

    ret = goodix_parse_firmware(&fwu_ctrl->fw_data);
    if (ret < 0)
        return ret;

    if (fwu_ctrl->force_update == false) {
        ret = goodix_fw_version_compare(fwu_ctrl);
        if (!ret) {
            NLOGI("firmware upgraded");
            return NO_NEED_UPDATE;
        }
#ifdef _WIN32
        /* on Windows platfrom we must guarantee PID is equal to do fw update */
        if (ret == COMPARE_PIDMISMATCH)
            return ret;
#endif
    }

start_update:
    do {
        ret = goodix_update_prepare(fwu_ctrl);
        if (ret) {
            NLOGE("failed prepare ISP, retry %d",
                FW_UPDATE_RETRY - retry0);
        }
    } while (ret && --retry0 > 0);
    if (ret) {
        NLOGE("Failed to prepare ISP, exit update:%d", ret);
        goto err_fw_prepare;
    }

    /* progress: 20%~100% */
    ret = goodix_flash_firmware(fwu_ctrl);
    if (ret < 0 && --retry1 > 0) {
        NLOGE("Bus error, retry firmware update:%d",
                FW_UPDATE_RETRY - retry1);
        goto start_update;
    }
    if (ret){
        NLOGE("flash fw data enter error");
   } else {
        NLOGI("flash fw data success, need check version");
   }

err_fw_prepare:
    ret = goodix_update_finish(fwu_ctrl);
    if (!ret)
        NLOGI("Firmware update successfully");
    else
        NLOGE("Firmware update failed");

    return ret;
}

int goodix_fw_update(uint8_t *fw_data, int size,
    uint8_t *cfg_data, int cfg_size, char *type, char *register_node)
{
    if (fwupdate_bus_init(register_node)) {
        return -1;
    }

    g_fw_update_ctrl.force_update = 1;
    memset(&g_fw_update_ctrl.fw_data, 0,
            sizeof(g_fw_update_ctrl.fw_data));

    g_fw_update_ctrl.fw_data.firmware.size = size;
    g_fw_update_ctrl.fw_data.firmware.data = fw_data;
    g_fw_update_ctrl.cfg.data = cfg_data;
    g_fw_update_ctrl.cfg.size = cfg_size;

    if (!memcmp(type, "BerlinB", strlen("BerlinB"))) {
        g_fw_update_ctrl.update_info = &update_brb;
        g_fw_update_ctrl.ic_type = IC_TYPE_BERLIN_B;
    } else if (!memcmp(type, "BerlinD", strlen("BerlinD"))) {
        g_fw_update_ctrl.update_info = &update_brd;
        g_fw_update_ctrl.ic_type = IC_TYPE_BERLIN_D;
    } else {
        NLOGE("Unsupported device type: %s", type);
        return -2;
    }

    return goodix_fw_update_proc(&g_fw_update_ctrl);
}

#ifdef __cplusplus
}
#endif
