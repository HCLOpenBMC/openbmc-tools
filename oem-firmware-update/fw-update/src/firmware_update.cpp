/*
/ Copyright (c) 2019-2020 Facebook Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <sys/sysinfo.h>
#include <systemd/sd-journal.h>
#include <phosphor-logging/log.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/steady_timer.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <gpiod.hpp>

#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <vector>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace firmwareUpdate
{

// Max retry limit
static constexpr uint8_t max_retry = 3;
static constexpr uint8_t bic_max_retry = 12;

// IANA ID
static constexpr uint8_t iana_id_0 = 0x15;
static constexpr uint8_t iana_id_1 = 0xA0;
static constexpr uint8_t iana_id_2 = 0x00;

// ME recovery cmd
static constexpr uint8_t bic_intf_me = 0x1;
static constexpr uint8_t me_recv_cmd_0 = 0xB8;
static constexpr uint8_t me_recv_cmd_1 = 0xD7;
static constexpr uint8_t me_recv_cmd_2 = 0x57;
static constexpr uint8_t me_recv_cmd_3 = 0x01;
static constexpr uint8_t me_recv_cmd_4 = 0x00;

static constexpr uint8_t verify_me_recv_cmd_0 = 0x18;
static constexpr uint8_t verify_me_recv_cmd_1 = 0x04;
static constexpr uint8_t me_recv_cmd = 0x1;

// BIOS SIZE
static constexpr uint32_t bios_64k_size = (64*1024);
static constexpr uint32_t bios_32k_size = (32*1024);

// Command Id
static constexpr uint8_t me_recv_id = 0x2;
static constexpr uint8_t get_fw_chksum_id = 0xA;
static constexpr uint8_t firmware_update_id = 0x9;
static constexpr uint8_t get_cpld_update_progress = 0x1A;
static constexpr uint8_t en_bridgeic_update_flag = 0xC;
static constexpr uint8_t bic_cmd_download = 0x21;
static constexpr uint8_t bic_cmd_run = 0x22;
static constexpr uint8_t bic_cmd_status = 0x23;
static constexpr uint8_t bic_cmd_data = 0x24;

// BIC commands
static constexpr uint8_t gpio_low = 0x0;
static constexpr uint16_t i2c_slave = 0x0703;
static constexpr uint16_t i2c_func = 0x0705;
static constexpr uint8_t bridge_slave_address = 0x20;
static constexpr uint8_t cmd_download_size = 0xB;
static constexpr uint8_t cmd_run_size = 0x7;
static constexpr uint8_t cmd_status_size = 0x3;
static constexpr uint32_t bic_flash_start = 0x8000;
static constexpr uint8_t bic_pkt_max = 252;

// Error Codes
static constexpr uint8_t write_flash_err   = 0x80;
static constexpr uint8_t power_sts_chk_err = 0x81;
static constexpr uint8_t data_len_err      = 0x82;
static constexpr uint8_t flash_erase_err   = 0x83;
static constexpr uint8_t cpld_err_code     = 0xFD;
static constexpr uint8_t me_recv_err_0     = 0x81;
static constexpr uint8_t me_recv_err_1     = 0x2;

// General declarations
static constexpr uint8_t resp_size = 6;
static constexpr uint8_t net_fn = 0x38;
static constexpr uint8_t ipmb_write_128b = 128;

// Host Numbers
static constexpr uint8_t host1 = 0;
static constexpr uint8_t host2 = 4;
static constexpr uint8_t host3 = 8;
static constexpr uint8_t host4 = 12;

static constexpr uint8_t update_bios= 0;
static constexpr uint8_t update_cpld= 1;
static constexpr uint8_t update_bic_bootloader= 2;
static constexpr uint8_t update_bic= 3;
static constexpr uint8_t update_vr= 4;

std::shared_ptr<sdbusplus::asio::connection> conn;
static boost::asio::io_service io;
static constexpr uint8_t lun = 0;

using respType =
    std::tuple<int, uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>;


void print_help()
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
    "Usage: <file_name> <bin_file_path> <host1/2/3/4> <--update> <bios/cpld/bic/bicbtl/vr>");
}


/*
Function Name    : sendIPMBRequest
Description      : Send data to target through IPMB
*/
int sendIPMBRequest(uint8_t host, uint8_t netFn, uint8_t cmd,
                    std::vector<uint8_t> &cmdData,
                    std::vector<uint8_t> &respData)
{
    auto method = conn->new_method_call("xyz.openbmc_project.Ipmi.Channel.Ipmb",
                                        "/xyz/openbmc_project/Ipmi/Channel/Ipmb",
                                        "org.openbmc.Ipmb", "sendRequest");
    method.append(host, netFn, lun, cmd, cmdData);

    auto reply = conn->call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Error reading from IPMB");
        return -1;
    }

    respType resp;
    reply.read(resp);

    respData =
        std::move(std::get<std::remove_reference_t<decltype(respData)>>(resp));
    respData.insert(respData.begin(), std::get<4>(resp));

    if (respData.size() <= 0)
    {
        return -1;
    }
    return 0;
}


/*
Function Name    : sendFirmwareUpdateData
Description      : Form vectors with required data to send
*/
int sendFirmwareUpdateData(uint8_t slotId, std::vector<uint8_t> &sendData,
                           uint32_t offset, uint8_t target)
{
    // Vector declaration
    std::vector<uint8_t> cmdData{iana_id_0, iana_id_1, iana_id_2};
    std::vector<uint8_t> respData;

    // Variable declaration
    int retries = max_retry;
    uint8_t len_byte[2];
    uint8_t offset_byte[4];
    *(uint32_t *)&offset_byte = offset;
    *(uint16_t *)&len_byte = sendData.size();

    // Frame the Firmware send IPMB data
    cmdData.push_back(target);
    cmdData.insert(cmdData.end(), offset_byte, offset_byte + sizeof(offset_byte));
    cmdData.insert(cmdData.end(), len_byte, len_byte + sizeof(len_byte));
    cmdData.insert(cmdData.end(), sendData.begin(), sendData.end());

    while (retries != 0)
    {
        int ret = sendIPMBRequest(slotId, net_fn, firmware_update_id,
                                  cmdData, respData);
        if (ret)
        {
            return -1;
        }
        // Check the completion code and the IANA_ID (0x15) for success
        if ((respData[0] == 0) && (respData[1] == iana_id_0)){
            break;
        } else if (respData[0] == write_flash_err) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Write Flash Error!!");
        } else if (respData[0] == power_sts_chk_err) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Power status check Fail!!");
        } else if (respData[0] == data_len_err) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Data length Error!!");
        } else if (respData[0] == flash_erase_err) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Flash Erase Error!!");
        } else {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data...");
        }
        std::string logMsg = "slot:" + std::to_string(slotId) + " Offset:" +
            std::to_string(offset) + " len:" + std::to_string(sendData.size()) +
            " Retrying..";
        phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
        retries--;
    }

    if (retries == 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Error!!! Not able to send bios data!!!");
        return -1;
    }
    return 0;
}


/*
Function Name    : getChksumFW
Description      : Get the checksum value of bios image
*/
int getChksumFW(uint8_t slotId, uint32_t offset, uint32_t len,
                std::vector<uint8_t> &respData, uint8_t target)
{
    // Variable declaration
    std::vector<uint8_t> cmdData{iana_id_0, iana_id_1, iana_id_2};
    int retries = max_retry;
    uint8_t len_byte[4];
    uint8_t offset_byte[4];
    *(uint32_t *)&offset_byte = offset;
    *(uint32_t *)&len_byte = len;

    // Frame the IPMB request data
    cmdData.push_back(target);
    cmdData.insert(cmdData.end(), offset_byte, offset_byte + sizeof(offset_byte));
    cmdData.insert(cmdData.end(), len_byte, len_byte + sizeof(len_byte));

    while (retries > 0)
    {
        sendIPMBRequest(slotId, net_fn, get_fw_chksum_id, cmdData, respData);
        if (respData.size() != resp_size)
        {
            std::string logMsg = "Checksum values not obtained properly for slot: " +
               std::to_string(slotId) + " Offset:" + std::to_string(offset)
               + " len:" + std::to_string(len) + " Retrying..." ;
            phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
            retries--;
        }
    }

    if (retries == 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Failed to get the Checksum value from firmware..");
        return -1;
    }
    return 0;
}


/*
Function Name    : meRecovery
Description      : Set Me to recovery mode
*/
int meRecovery(uint8_t slotId, uint8_t mode)
{
    // Variable declarations
    std::vector<uint8_t> cmdData{iana_id_0, iana_id_1,
                                 iana_id_2, bic_intf_me};
    std::vector<uint8_t> respData;
    int retries = max_retry;
    uint8_t me_recovery_cmd[] = {me_recv_cmd_0,
                                 me_recv_cmd_1,
                                 me_recv_cmd_2,
                                 me_recv_cmd_3,
                                 me_recv_cmd_4};

    // Frame the IPMB send request data for ME recovery
    cmdData.insert(cmdData.end(), me_recovery_cmd,
                   me_recovery_cmd + sizeof(me_recovery_cmd));
    cmdData.push_back(mode);

    phosphor::logging::log<phosphor::logging::level::INFO>(
    "Setting ME to recovery mode");
    while (retries > 0)
    {
        sendIPMBRequest(slotId, net_fn, me_recv_id, cmdData, respData);
        if (respData.size() != resp_size) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "ME is not set into recovery mode.. Retrying...");
        } else if (respData[3] != cmdData[3]) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Interface not valid.. Retrying...");
        } else if (respData[0] == 0) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "ME recovery mode -> Completion Status set..");
            break;
        } else if (respData[0] != 0) {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "ME recovery mode -> Completion Status not set.. Retrying..");
        } else {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid data or command...");
        }
        retries--;
    }

    if (retries == 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Failed to set ME to recovery mode..");
        return -1;
    }

    // Verify whether ME went to recovery mode
    std::vector<uint8_t> meData{iana_id_0,
                                iana_id_1,
                                iana_id_2,
                                bic_intf_me,
                                verify_me_recv_cmd_0,
                                verify_me_recv_cmd_1};
    std::vector<uint8_t> meResp;
    retries = max_retry;

    while (retries != 0)
    {
        sendIPMBRequest(slotId, net_fn, me_recv_id, meData, meResp);
        if (meResp[3] != meData[3])
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Interface not valid.. Retrying...");
        } else if ((mode == me_recv_id) && (meResp[1] == me_recv_err_0) &&
                                           (meResp[2] == me_recv_err_1))
        {
            return 0;
        }
        retries--;
    }

    if (retries == 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Failed to set ME to recovery mode in self tests..");
        return -1;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
                  "ME is set to recovery mode");
    return 0;
}


int biosVerifyImage(const char *imagePath, uint8_t slotId, uint8_t target)
{
    // Check for bios image
    uint32_t offset = 0;
    uint32_t biosVerifyPktSize = bios_32k_size;

    phosphor::logging::log<phosphor::logging::level::INFO>("Verify Bios image..");

    // Open the file
    std::streampos fileSize;
    std::ifstream file(imagePath,
                       std::ios::in | std::ios::binary);

    if (!file.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Unable to open file");
        return -1;
    }
    file.seekg(0, std::ios::beg);

    phosphor::logging::log<phosphor::logging::level::INFO>(
    "Starting Bios image verification");
    while (offset < fileSize)
    {
        // Read the data
        std::vector<int> chksum(biosVerifyPktSize);
        file.read((char *)&chksum[0], biosVerifyPktSize);

        // Calculate checksum
        uint32_t tcksum = 0;
        for (int byte_index = 0; byte_index < chksum.size(); byte_index++)
        {
            tcksum += chksum[byte_index];
        }

        std::vector<std::uint8_t> calChksum((std::uint8_t *)&tcksum,
                                            (std::uint8_t *)&(tcksum) +
                                             sizeof(std::uint32_t));

       // Get the checksum value from firmware
       uint8_t retValue;
       std::vector<uint8_t> fwChksumData;

       retValue = getChksumFW(slotId, offset, biosVerifyPktSize,
                              fwChksumData, target);
       if (retValue != 0)
       {
           phosphor::logging::log<phosphor::logging::level::ERR>(
           "Failed to get the Checksum value!!");
           return -1;
       }

       for (uint8_t ind = 0; ind <= calChksum.size(); ind++)
       {
           // Compare both and see if they match or not
           if (fwChksumData[ind] != calChksum[ind])
           {
               std::string logMsg = "Checksum Failed! Offset: " +
                         std::to_string(offset) +
                         " Expected: " + std::to_string(calChksum[ind]) +
                         " Actual: " + std::to_string(fwChksumData[ind]);
               phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
               return -1;
           }
       }
       offset += biosVerifyPktSize;
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
    "Bios image verification Successful..");
    file.close();
    return 0;
}


/*
Function Name   : updateFirmwareTarget
Description     : Send data to respective target for FW udpate
Param: slotId   : Slot Id
Param: imagePath: Binary image path
Param: target: cmd Id to find the target (BIOS, CPLD, VR, ME)
*/
int updateFirmwareTarget(uint8_t slotId, const char *imagePath, uint8_t target)
{
    // Variable Declartion
    int count = 0x0;
    uint32_t offset = 0x0;
    uint32_t ipmbWriteMax  = ipmb_write_128b;

    // Set ME to recovery mode
    int ret_val = meRecovery(slotId, me_recv_cmd);
    if (ret_val != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Me set to recovery mode failed");
        return -1;
    }

    // Open the file
    std::streampos fileSize;
    std::ifstream file(imagePath,
                       std::ios::in | std::ios::binary | std::ios::ate);

    if (!file.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Unable to open file");
    }

    // Get its size
    fileSize = file.tellg();
    std::string logMsg = "Bin File Size: " + std::to_string(fileSize);
    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());

    // Check whether the image is valid
    if (fileSize <= 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Invalid bin File");
        return -1;
    } else {
        phosphor::logging::log<phosphor::logging::level::INFO>(
        "Valid bin File");
    }
    file.seekg(0, std::ios::beg);
    int index = 1;

    phosphor::logging::log<phosphor::logging::level::INFO>(
    "Firmware write started");
    while (offset < fileSize)
    {

        // count details
        uint32_t count = ipmbWriteMax;
        uint8_t target_value = target;

        if ((target == update_bios) && ((offset + ipmbWriteMax) >= (index * bios_64k_size)))
        {
            count = (index * bios_64k_size) - offset;
            index++;
        }

        if ((target != update_bios) && ((offset+count) >= fileSize))
        {
            target_value = target_value | 0x80;
        }

        // Read the data
        std::vector<uint8_t> fileData(ipmbWriteMax);
        file.read((char *)&fileData[0], ipmbWriteMax);

        // Send data
        int ret = sendFirmwareUpdateData(slotId, fileData, offset, target_value);
        if (ret != 0)
        {
            std::string logMsg = "Firmware update Failed at offset: " +
                       std::to_string(offset);
            phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
            return -1;
        }

        // Update counter
        offset += count;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
    "Firmware write Done");
    file.close();

    if (target == update_bios)
    {
        int ret = biosVerifyImage(imagePath, slotId, target);
        if (ret) {
            return -1;
        }
    }

    return 0;
}


int getGpioValue(uint8_t slotId)
{
    // GPIO status
    std::string name;
    gpiod::line gpioLine;

    // Get the gpio name
    if (slotId == host1) {
        name = "I2C_SLOT1";
    } else if (slotId == host2) {
        name = "I2C_SLOT2";
    } else if (slotId == host3) {
        name = "I2C_SLOT3";
    } else if (slotId == host4) {
        name = "I2C_SLOT4";
    } else {
        phosphor::logging::log<phosphor::logging::level::ERR>("SlotId not valid");
        return -1;
    }

    // Find the GPIO line
    gpioLine = gpiod::find_line(name);
    if (!gpioLine)
    {
        std::string logMsg = "Failed to find the " + name + " line";
        phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
        return -1;
    }

    try
    {
        gpioLine.request(
            {"fwUpdate", gpiod::line_request::EVENT_BOTH_EDGES});
    }
    catch (std::exception&)
    {
        std::string logMsg = "Failed to request events for " + name;
        phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
        return -1;
    }

    int gpio_data = gpioLine.get_value();
    std::string logMsg = "GPIO value: " + std::to_string(gpio_data);
    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
    if (gpio_data == gpio_low)
    {
        return 1;
    } else {
	    return 0;
	}
}


static int i2cOpenBus(uint8_t slotId)
{
    uint8_t busId;
    char busCharDev[16];
    // Get the I2C bus number
    if (slotId == host1) {
        busId = 1;
    } else if (slotId == host2) {
        busId = 3;
    } else if (slotId == host3) {
        busId = 5;
    } else if (slotId == host4) {
        busId = 7;
    } else {
        busId = -1;
    }

    std::snprintf(busCharDev, sizeof(busCharDev) - 1, "/dev/i2c-%d", busId);
    int busFd = open(busCharDev, O_RDWR);
    if (busFd < 0)
    {
        std::string logMsg = "Failed to open i2c device: /dev/i2c-" + std::to_string(busId);
        phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
        return -1;
    }

    int rc = ioctl(busFd, i2c_slave, bridge_slave_address);
    if (rc < 0) {
        std::string logMsg = "Failed to open slave @ address: " + std::to_string(bridge_slave_address);
        phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
        close(busFd);
    }

    return busFd;
}


static int i2cIOFun(int fd, uint8_t *tbuf, uint8_t tcount, uint8_t *rbuf, uint8_t rcount) {
    struct i2c_rdwr_ioctl_data data;
    struct i2c_msg msg[2];
    int n_msg = 0;
    int rc;

    if (tcount) {
        msg[n_msg].addr = bridge_slave_address;
        msg[n_msg].flags = 0;
        msg[n_msg].len = tcount;
        msg[n_msg].buf = tbuf;
        n_msg++;
    }

    if (rcount) {
        msg[n_msg].addr = bridge_slave_address;
        msg[n_msg].flags = I2C_M_RD;
        msg[n_msg].len = rcount;
        msg[n_msg].buf = rbuf;
        n_msg++;
    }

    data.msgs = msg;
    data.nmsgs = n_msg;

    rc = ioctl(fd, I2C_RDWR, &data);
    if (rc < 0) {
        std::string logMsg = "Failed to do Raw IO operation";
        phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
        return -1;
    }
  return 0;
}


int bicUpdateFw(uint8_t slotId, const char *imagePath)
{
    // Variable Declartion
    uint32_t offset = 0x0;
    int i = 0; 

    // Open the file
    std::streampos fileSize;
    std::ifstream file(imagePath,
                       std::ios::in | std::ios::binary | std::ios::ate);

    if (!file.is_open())
    {
        std::string logMsg = "Unable to open file";
        phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
    }

    // Get its size
    fileSize = file.tellg();
    std::string logMsg = "Bin File Size: " + std::to_string(fileSize);
    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());

    // Check whether the image is valid
    if (fileSize <= 0)
    {
    	std::string logMsg = "Invalid Bin File";
    	phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
        return -1;
    } else {
    	std::string logMsg = "Valid Bin File";
    	phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
    }
    file.seekg(0, std::ios::beg);
    std::string logMsg1 = "Firmware write started";
    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg1.c_str());

    // Enable Bridge-IC I2C update flag
    std::vector<uint8_t> cmdData{iana_id_0,
                                 iana_id_1,
                                 iana_id_2,
                                 0x1};
    std::vector<uint8_t> respData;
    int retries = max_retry;

    std::string logMsg2 = "Enable Bridge-IC I2C update flag";
    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg2.c_str());
    while (retries != 0)
    {
        int ret = sendIPMBRequest(slotId, net_fn, en_bridgeic_update_flag, cmdData, respData);
        if (ret)
        {
            return -1;
        }
        // Check the completion code and the IANA_ID (0x15) for success
        if ((respData[0] == 0) && (respData[1] == iana_id_0)){
            break;
        } else {
            phosphor::logging::log<phosphor::logging::level::ERR>(
            "Bridge-IC update flag is not enabled!! Retrying..");
        }
    }

    // Stop the IPMB services
    char cmd_data[50];
    strcpy(cmd_data, "systemctl stop ipmb.service");
    // call the above fun
    system(cmd_data);

	// Delay
	sleep(2);

    // Open I2C driver
    int ifd = i2cOpenBus(slotId);
	if (ifd < 0) {
        return -1;
    }

    // Check whether BIC is ready
    for (i = 0; i < bic_max_retry; i++)
    {
        if (getGpioValue(slotId) == 0)
        {
            std::string logMsg = "BIC ready for update after " +
                std::to_string(i) + " tries";
            phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
            break;
        }
		// Delay
		sleep(1);
    }

    if (i == bic_max_retry)
    {
        std::string logMsg = "BIC is NOT ready for update";
    	phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());

        close(ifd);
        return -1;
    }

	// General Declarations
	uint8_t tbuf[256] = {0};
	uint8_t rbuf[16] = {0};
    uint8_t xbuf[256] = {0};
	int rc;
    int tcount;
    int rcount;
    int xcount;
    uint32_t last_offset = 0;
    uint32_t size = fileSize;

    // Start Bridge IC update(0x21)
	tbuf[0] = cmd_download_size;
    tbuf[1] = 0x00; //Checksum, will fill later
    tbuf[2] = bic_cmd_download;
    // update flash address: 0x8000
    tbuf[3] = (bic_flash_start >> 24) & 0xff;
    tbuf[4] = (bic_flash_start >> 16) & 0xff;
    tbuf[5] = (bic_flash_start >> 8) & 0xff;
    tbuf[6] = (bic_flash_start) & 0xff;

    // image size
    tbuf[7] = (size >> 24) & 0xff;
    tbuf[8] = (size >> 16) & 0xff;
    tbuf[9] = (size >> 8) & 0xff;
    tbuf[10] = (size) & 0xff;

    // calcualte checksum for data portion
    for (i = 2; i < cmd_download_size; i++) {
        tbuf[1] += tbuf[i];
    }
    tcount = cmd_download_size;
    rcount = 0;

	rc = i2cIOFun(ifd, tbuf, tcount, rbuf, rcount);
	if (rc) {
        std::string logMsg = "i2cIOFun failed download ack";
    	phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
	  return -1; //goto error_exit;
	}

	//delay for download command process ---
	sleep(1);

	tcount = 0;
	rcount = 2;
	rbuf[0]=0;
	rbuf[1]=0;
	rc = i2cIOFun(ifd, tbuf, tcount, rbuf, rcount);
	if (rc) {
        std::string logMsg = "i2cIOFun failed download ack";
    	phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
	    return -1;
	}

    if (rbuf[0] != 0x00 || rbuf[1] != 0xcc) {
        std::string logMsg = "Response values: " + std::to_string(rbuf[0])
            + " " + std::to_string(rbuf[1]);
    	phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
		return -1;
	}

	// Loop to send all the image data
	uint32_t count = 252;
    while (offset < fileSize)
	{
	    tbuf[0] = cmd_status_size;
	    tbuf[1] = bic_cmd_status;
	    tbuf[2] = bic_cmd_status;

        tcount = cmd_status_size;
        rcount = 0;

        rc = i2cIOFun(ifd, tbuf, tcount, rbuf, rcount);
        if (rc) {
            std::string logMsg = "i2cIOFun failed to get status";
    	    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
            return -1;
        }
	    // Delay
	    usleep(500);

        tcount = 0;
        rcount = 5;

	    memset(rbuf, 0, sizeof(rbuf));
        rc = i2cIOFun(ifd, tbuf, tcount, rbuf, rcount);
        if (rc) {
            std::string logMsg = "i2cIOFun failed to get status Ack";
    	    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
            return -1;
        }

        if (rbuf[0] != 0x00 ||
            rbuf[1] != 0xcc ||
            rbuf[2] != 0x03 ||
            rbuf[3] != 0x40 ||
            rbuf[4] != 0x40) {
            std::string logMsg = "Response values: " + std::to_string(rbuf[0])
                + " " + std::to_string(rbuf[1]) +  " " + std::to_string(rbuf[2])
                + " " + std::to_string(rbuf[3]) +  " " + std::to_string(rbuf[4]);
    	    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
            return -1;
        }

        // Send ACK ---
	    tbuf[0] = 0xcc;
        tcount = 1;
        rcount = 0;
        rc = i2cIOFun(ifd, tbuf, tcount, rbuf, rcount);
        if (rc) {
            std::string logMsg = "i2cIOFun failed to send ACK";
    	    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
            return -1;
        }

		if ((offset+count) >= fileSize)
		{
			count = size - offset;
		}

		// Read the data
		uint8_t fileData[count];
		file.read((char *)&fileData[0], count);

		tbuf[0] = count+3;
		tbuf[1] = bic_cmd_data;
		tbuf[2] = bic_cmd_data;

		for (i=0 ; i < count; i++)
		{
			tbuf[3+i] = fileData[i];
		    tbuf[1] += fileData[i];
		}

		tcount = tbuf[0];
		rcount = 0;

		rc = i2cIOFun(ifd, tbuf, tcount, rbuf, rcount);
		if (rc) {
            std::string logMsg = "i2cIOFun failed to send Bin data";
    	    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
		    return -1;
		}

		usleep(500);
		tcount = 0;
		rcount = 2;

		memset(rbuf, 0, sizeof(rbuf));
		rc = i2cIOFun(ifd, tbuf, tcount, rbuf, rcount);
		if (rc) {
            std::string logMsg = "i2cIOFun failed to get Bin data ack";
    	    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
		    return -1;
		}

		if (rbuf[0] != 0x00 || rbuf[1] != 0xcc) {
            std::string logMsg = "Response values: " + std::to_string(rbuf[0])
                + " " + std::to_string(rbuf[1]);
    	    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
		    return -1;
		}
		offset += count;
    }

	// Run the new image
	tbuf[0] = cmd_run_size;
	tbuf[1] = 0x0;
	tbuf[2] = bic_cmd_run;
	tbuf[3] = (bic_flash_start >> 24) & 0xff;
	tbuf[4] = (bic_flash_start >> 16) & 0xff;
	tbuf[5] = (bic_flash_start >> 8) & 0xff;
	tbuf[6] = (bic_flash_start) & 0xff;

	for (i = 2; i < cmd_run_size; i++) {
	  tbuf[1] += tbuf[i];
	}

	tcount = cmd_run_size;
	rcount = 0;

	rc = i2cIOFun(ifd, tbuf, tcount, rbuf, rcount);
	if (rc) {
        std::string logMsg = "i2cIOFun failed to run new image";
    	phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
		return -1;
	}

	// Delay
	usleep(500);

	tcount = 0;
	rcount = 2;

	memset(rbuf, 0, sizeof(rbuf));
	rc = i2cIOFun(ifd, tbuf, tcount, rbuf, rcount);
	if (rc) {
        std::string logMsg = "i2cIOFun failed to get run new image Ack";
    	phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
		return -1;
	}

	if (rbuf[0] != 0x00 || rbuf[1] != 0xcc) {
        std::string logMsg = "Response values: " + std::to_string(rbuf[0])
            + " " + std::to_string(rbuf[1]);
        phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
	    return -1;
	}

	sleep(2);
    // Check whether BIC is ready
    for (i = 0; i < bic_max_retry; i++)
    {
        if (getGpioValue(slotId) == 0)
        {
            std::string logMsg = "BIC ready for update after " +
                std::to_string(i) + " tries";
            phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
            break;
        }
    }

    if (i == bic_max_retry)
    {
        std::string logMsg = "BIC is NOT ready for update";
        phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());

        close(ifd);
        return -1;
    }

	// Restart ipmbd daemon
    char cmd_data_1[50];
    strcpy(cmd_data_1, "systemctl start ipmb.service");
    // call the above fun
    system(cmd_data_1);

	if (ifd > 0) {
	   close(ifd);
	}

    std::string logMsg3 = "BIC FW update completed!!";
    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg3.c_str());
    return 0;
}


int cpldUpdateFw(uint8_t slotId, const char *imagePath)
{
    int ret = updateFirmwareTarget(slotId, imagePath, update_cpld);
    if (ret != 0)
    {
        std::string logMsg = "CPLD update failed for slot#" +
                             std::to_string(slotId);
        phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
        return -1;
    }
    std::string logMsg = "CPLD update completed successfully for slot#" +
                         std::to_string(slotId);
    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
    return 0;
}


int hostBiosUpdateFw(uint8_t slotId, const char *imagePath)
{
    int ret = updateFirmwareTarget(slotId, imagePath, update_bios);
    if (ret != 0)
    {
        std::string logMsg = "BIOS update failed for slot#" +
                             std::to_string(slotId);
        phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
        return -1;
    }
    std::string logMsg = "BIOS update completed successfully for slot#" +
                         std::to_string(slotId);
    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
    return 0;
}


int updateFw(char *argv[], uint8_t slotId)
{
    const char *binFile = argv[1];
    // Check for the FW udpate
    if (strcmp(argv[3], "--update") != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Invalid Update command");
        print_help();
        return -1;
    }

    if (strcmp(argv[4], "bios") == 0)
    {
        int ret = hostBiosUpdateFw(slotId, binFile);
        if (ret != 0)
        {
            return -1;
        }

    } else if (strcmp(argv[4], "cpld") == 0) {
        int ret = cpldUpdateFw(slotId, binFile);
        if (ret != 0)
        {
            return -1;
        }

    } else {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Invalid Update command");
        print_help();
        return -1;
    }

    return 0;
}

}// namespace end

int main(int argc, char *argv[])
{
    firmwareUpdate::conn =
        std::make_shared<sdbusplus::asio::connection>(firmwareUpdate::io);
    // Get the arguments
    uint8_t slotId;

    // Check for the host name
    if(strcmp(argv[2], "host1") == 0) {
        slotId = firmwareUpdate::host1;
    } else if (strcmp(argv[2], "host2") == 0) {
        slotId = firmwareUpdate::host2;
    } else if (strcmp(argv[2], "host3") == 0) {
        slotId = firmwareUpdate::host3;
    } else if (strcmp(argv[2], "host4") == 0) {
        slotId = firmwareUpdate::host4;
    } else {
        phosphor::logging::log<phosphor::logging::level::ERR>(
        "Invalid host number");
        firmwareUpdate::print_help();
        return -1;
    }

    // Update the FW
    int ret = firmwareUpdate::updateFw(argv, slotId);
    if (ret != 0)
    {
        std::string logMsg = "FW update failed for slot#" + std::to_string(slotId);
        phosphor::logging::log<phosphor::logging::level::ERR>(logMsg.c_str());
        return -1;
    }
    std::string logMsg = "FW update completed successfully for slot#" +
                         std::to_string(slotId);
    phosphor::logging::log<phosphor::logging::level::INFO>(logMsg.c_str());
    return 0;
}

