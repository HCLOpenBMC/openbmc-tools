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

#include "fb_yv2_misc.hpp"

#include <sys/sysinfo.h>
#include <nlohmann/json.hpp>
#include <systemd/sd-journal.h>
#include <phosphor-logging/log.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>

#include <vector>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdlib.h>

std::shared_ptr<sdbusplus::asio::connection> conn;
static boost::asio::io_service io;
static constexpr uint8_t lun = 0;

using respType =
    std::tuple<int, uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>;


void print_help()
{
    std::cerr << "The input format should be like below\n";
    std::cerr << "<file_name> <bin_file_path> <host1/2/3/4> <--update> <bios/cpld/bridgeIC/VR>\n";
}


/*
Function Name    : sendIPMBRequest
Description      : Send data to target through Ipmb
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
    std::vector<uint8_t> cmdData{IANA_ID_0, IANA_ID_1, IANA_ID_2};
    std::vector<uint8_t> respData;

    // Variable declaration
    int ret = 0;
    uint8_t len_byte[2];
    uint8_t offset_byte[4];
    *(uint32_t *)&offset_byte = offset;
    *(uint16_t *)&len_byte = sendData.size();
    int retries = MAX_RETRY;

    // Frame the send vector data
    cmdData.push_back(target);
    cmdData.insert(cmdData.end(), offset_byte, offset_byte + sizeof(offset_byte));
    cmdData.insert(cmdData.end(), len_byte, len_byte + sizeof(len_byte));
    cmdData.insert(cmdData.end(), sendData.begin(), sendData.end());

    std::cerr << "sendFirmwareUpdateData started\n";
    while (retries != 0)
    {
        sendIPMBRequest(slotId, NET_FN, FIRMWARE_UPDATE_ID, cmdData, respData);
        uint8_t retStatus = respData[0];

        if ((retStatus == 0) && (respData[1] == IANA_ID_0)){
            break;
        } else if (retStatus == WRITE_FLASH_ERR) {
            std::cerr << "Write Flash Error!!";
        } else if (retStatus == POWER_STS_CHK_ERR) {
            std::cerr << "Power status check Fail!!";
        } else if (retStatus == DATA_LEN_ERR) {
            std::cerr << "Data length Error!!";
        } else if (retStatus == FLASH_ERASE_ERR) {
            std::cerr << "Flash Erase Error!!";
        } else {
            std::cerr << "Invalid Data...";
        }
        sleep(0.001);
        std::cerr << " slot:" << slotId << " Offset:" << offset
                  << " len:" << sendData.size() << "Retrying.....\n";
        retries--;
    }

    if (retries == 0)
    {
        std::cerr << "Error!!! Not able to send bios data!!! \n";
        return -1;
    }
    std::cerr << "sendFirmwareUpdateData Done\n";
  return 0;
}


/*
Function Name    : getChksumFW
Description      : Get the checksum value of bios image
*/
int getChksumFW(uint8_t slotId, uint32_t offset, uint32_t len,
                std::vector<uint8_t> &respData, uint8_t target)
{
    // Declaration
    std::vector<uint8_t> cmdData{IANA_ID_0, IANA_ID_1, IANA_ID_2};
    int retries = MAX_RETRY;
    uint8_t len_byte[4];
    uint8_t offset_byte[4];
    *(uint32_t *)&offset_byte = offset;
    *(uint32_t *)&len_byte = len;

    // Frame the send vector data
    cmdData.push_back(target);
    cmdData.insert(cmdData.end(), offset_byte, offset_byte + sizeof(offset_byte));
    cmdData.insert(cmdData.end(), len_byte, len_byte + sizeof(len_byte));

    while (retries != 0)
    {
        sendIPMBRequest(slotId, NET_FN, GET_FW_CHK_SUM, cmdData, respData);
        if (respData.size() != RESP_SIZE)
        {
            sleep(0.001);
            std::cerr << "Checksum not obtained properly for slot:" << slotId
                << " Offset:" << offset << " len:" << len << "Retrying.....\n";
            retries--;
        }
    }

    if (retries == 0)
    {
        std::cerr << "Failed to get the Checksum value from firmware.. \n";
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
    // Declarations
    std::vector<uint8_t> cmdData{IANA_ID_0, IANA_ID_1,
	                             IANA_ID_2, BIC_INTF_ME};
    std::vector<uint8_t> respData;
    int retries = MAX_RETRY;
    uint8_t me_recovery_cmd[] = {ME_RECOVERY_CMD_0,
	                             ME_RECOVERY_CMD_1,
                                 ME_RECOVERY_CMD_2,
								 ME_RECOVERY_CMD_3,
                                 ME_RECOVERY_CMD_4};

    // Frame the send vector data
    cmdData.insert(cmdData.end(), me_recovery_cmd,
                   me_recovery_cmd + sizeof(me_recovery_cmd));
    cmdData.push_back(mode);

    std::cerr << "Starting ME recovery mode\n";
    while (retries != 0)
    {
        sendIPMBRequest(slotId, NET_FN, ME_RECOVERY_ID, cmdData, respData);
        if (respData.size() != RESP_SIZE) {
            std::cerr << "ME is not set into recovery mode.. Retrying... \n";
        } else if (respData[3] != cmdData[3]) {
            std::cerr << "Interface not valid.. Retrying...  \n";
        } else if (respData[0] == 0) {
            std::cerr << "ME recovery mode -> Completion Status set.. \n";
            break;
        } else if (respData[0] != 0) {
            std::cerr << "ME recovery mode -> Completion Status not set.. Retrying..\n";
        } else {
            sleep(0.001);
            std::cerr << "Invalid data or command... \n";
        }
        sleep(0.001);
        retries--;
    }

    if (retries == 0)
    {
        std::cerr << "Failed to set ME to recovery mode.. \n";
        return -1;
    }

    // Verify whether ME went to recovery mode
    std::vector<uint8_t> meData{IANA_ID_0,
                                IANA_ID_1,
                                IANA_ID_2,
                                BIC_INTF_ME,
                                VERIFY_ME_RECV_CMD_0,
                                VERIFY_ME_RECV_CMD_1};
    std::vector<uint8_t> meResp;
    retries = MAX_RETRY;

    while (retries != 0)
    {
        sendIPMBRequest(slotId, NET_FN, ME_RECOVERY_ID, meData, meResp);
        if (meResp[3] != meData[3])
        {
            sleep(0.001);
            std::cerr << "Interface not valid.. Retrying...  \n";
        } else if ((mode == 0x1) && (meResp[1] == 0x81) && (meResp[2] == 0x02))
        {
            return 0;
        }
        retries--;
    }

    if (retries == 0)
    {
        std::cerr << "Failed to set ME to recovery mode in self tests.. \n";
        return -1;
    }
    std::cerr << "ME is set to recovery mode\n";
    return 0;
}


int getCpldUpdateProgress(uint8_t slotId, std::vector<uint8_t> &respData)
{
    // Declarations
    std::vector<uint8_t> cmdData{IANA_ID_0, IANA_ID_1, IANA_ID_2};
    int ret;
    int retries = 0;

    while (retries != MAX_RETRY)
    {
        ret = sendIPMBRequest(slotId, NET_FN, GET_CPLD_UPDATE_PROGRESS, cmdData, respData);
        if (ret)
        {
            sleep(0.001);
            std::cerr << "getCpldUpdateProgress: slot: " << +slotId
                      << ", retrying..\n";
            retries++;
        } else
        {
            break;
        }
    }

    if (retries == MAX_RETRY)
    {
        std::cerr << "Failed to set response.. \n";
        return -1;
    }
    return 0;
}


int biosVerifyImage(const char *imagePath, uint8_t slotId, uint8_t target)
{
    // Check for bios image
    uint32_t offset_d = 0;
    uint32_t biosVerifyPktSize = BIOS_32k_SIZE;

    std::cerr << "Verify Bios image...\n";

    // Open the file
    std::streampos fileSize;
    std::ifstream file(imagePath,
                       std::ios::in | std::ios::binary | std::ios::ate);

    if (file.is_open())
    {
        file.seekg(0, std::ios::beg);

        std::cerr << "Starting Bios image verification\n";
        while (offset_d < fileSize)
        {
            // Read the data
            std::vector<int> chksum(biosVerifyPktSize);
            file.read((char *)&chksum[0], biosVerifyPktSize);

            // Calculate checksum
            uint32_t tcksum = 0;
            for (int i = 0; i < chksum.size(); i++)
            {
                tcksum += chksum[i];
            }

            std::vector<std::uint8_t> calChksum((std::uint8_t *)&tcksum,
                                                (std::uint8_t *)&(tcksum) +
                                                 sizeof(std::uint32_t));

           // Get the checksum value from firmware
           uint8_t retValue;
           std::vector<uint8_t> fwChksumData;

           retValue = getChksumFW(slotId, offset_d, biosVerifyPktSize, fwChksumData, target);
           if (retValue != 0)
           {
               std::cerr << "Failed to get the Checksum value!! \n";
               return -1;
           }

           for (uint8_t i = 0; i <= calChksum.size(); i++)
           {
               // Compare both and see if they match or not
               if (fwChksumData[i] != calChksum[i])
               {
                   std::cerr << "checksum does not match, offset:" << offset_d
                             << " Calculated chksum:" << +calChksum[i]
                             << " FW Chksum:" << +fwChksumData[i] << "\n";
                   return -1;
               } else {
                   std::cerr << "checksum match, offset:" << offset_d
                             << " Calculated chksum:" << +calChksum[i]
                             << " FW Chksum:" << +fwChksumData[i] << "\n";
               }
           }
           offset_d += biosVerifyPktSize;
        }
        std::cerr << "Bios image verification done..\n";
        file.close();
    } else {
    std::cerr << "Unable to open file";
    }
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
    // Read the binary data from bin file
    int count = 0x0;
    uint32_t offset = 0x0;
    uint32_t ipmbWriteMax  = IPMB_WRITE_128B;

    // Set ME to recovery mode
    int ret_val = meRecovery(slotId, ME_RECOVERY_MODE);
    if (ret_val != 0)
    {
        std::cerr << "Me set to recovery mode failed\n";
        return -1;
    }

    // Open the file
    std::streampos fileSize;
    std::ifstream file(imagePath,
                       std::ios::in | std::ios::binary | std::ios::ate);

    if (file.is_open())
    {
        // Get its size
        fileSize = file.tellg();
        std::cerr << "Total Filesize " << fileSize << "\n";

        // Check whether the image is valid
        if (fileSize <= 0)
        {
            std::cerr << "Invalid bin File\n";
            return -1;
        } else {
            std::cerr << "Valid bin File\n";
        }
        file.seekg(0, std::ios::beg);
        int i = 1;

        while (offset < fileSize)
        {

            // count details
            uint32_t count = ipmbWriteMax;

            if ((offset + ipmbWriteMax) >= (i * BIOS_64k_SIZE))
            {
                count = (i * BIOS_64k_SIZE) - offset;
                i++;
            }

            // Read the data
            std::vector<uint8_t> fileData(ipmbWriteMax);
            file.read((char *)&fileData[0], ipmbWriteMax);

            // Send data
            int ret = sendFirmwareUpdateData(slotId, fileData, offset, target);
            if (ret != 0)
            {
                std::cerr << "Firmware update Failed at offset " << offset << "\n";
                return -1;
            }

            // Update counter
            offset += count;
        }
        file.close();
    } else {
    std::cerr << "Unable to open file";
    }

    if (target == UPDATE_BIOS)
    {
        int ret = biosVerifyImage(imagePath, slotId, target);
        if (ret) {
            return -1;
        }
    }

    if (target == UPDATE_CPLD)
    {
        std::vector<uint8_t> respData;

        for (int i = 0; i < 60; i++)
        {
            // wait 60s at most
            int ret = getCpldUpdateProgress(slotId, respData);
            if (ret) {
                return -1;
            }

            if (respData[4] == CPLD_ERR_CODE) {
                return -1;
            }

            respData[4] %= 101;
            if (respData[4] == 100)
               break;

            sleep(0.1);
        }
    }
    return 0;
}


int cpldUpdateFw(uint8_t slotId, const char *imagePath)
{
    int ret = updateFirmwareTarget(slotId, imagePath, UPDATE_CPLD);
    if (ret != 0)
    {
        std::cerr << "CPLD update failed for slot #" << +slotId << "\n";
        return -1;
    }
    std::cerr << "CPLD update completed successfully for slot#"
              << +slotId << "\n";
    return 0;
}


int hostBiosUpdateFw(uint8_t slotId, const char *imagePath)
{
    int ret = updateFirmwareTarget(slotId, imagePath, UPDATE_BIOS);
    if (ret != 0)
    {
        std::cerr << "BIOS update failed for slot #" << +slotId << "\n";
        return -1;
    }
    std::cerr << "BIOS update completed successfully for slot#"
              << +slotId << "\n";
    return 0;
}


int updateFw(char *argv[], uint8_t slotId)
{
    const char *binFile = argv[1];
    // Check for the FW udpate
    if (strcmp(argv[3], "--update") == 0)
    {
        if (strcmp(argv[4], "bios") == 0)
        {
            int ret = hostBiosUpdateFw(slotId, binFile);
            if (ret != 0)
            {
                std::cerr << "BIOS update failed for slot #" << +slotId << "\n";
                return -1;
            }

        } else if (strcmp(argv[4], "cpld") == 0) {
            int ret = cpldUpdateFw(slotId, binFile);
            if (ret != 0)
            {
                std::cerr << "CPLD update failed for slot #" << +slotId << "\n";
                return -1;
            }

        } else {
            std::cerr << "Invalid Update command\n";
            print_help();
            return -1;
        }
    }
    return 0;
}


int main(int argc, char *argv[])
{
    // command -> fb_yv2_misc binfile host1 --update bios/cpld

    conn = std::make_shared<sdbusplus::asio::connection>(io);
    // Get the arguments
    uint8_t slotId;

    // Check for the host name
    if(strcmp(argv[2], "host1") == 0) {
        slotId = HOST_1;
    } else if (strcmp(argv[2], "host2") == 0) {
        slotId = HOST_2;
    } else if (strcmp(argv[2], "host3") == 0) {
        slotId = HOST_3;
    } else if (strcmp(argv[2], "host4") == 0) {
        slotId = HOST_4;
    } else {
        std::cerr << "Invalid host number\n";
        print_help();
        return -1;
    }

    // Update the FW
    int ret = updateFw(argv, slotId);
    if (ret != 0)
    {
        std::cerr << "FW update failed for slot #" << +slotId << "\n";
        return -1;
    }
    std::cerr << "FW update completed successfully for slot#"
              << +slotId << "\n";

    return 0;
}

