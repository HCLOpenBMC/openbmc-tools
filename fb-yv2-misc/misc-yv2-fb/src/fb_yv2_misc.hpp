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


namespace firmwareUpdate
{

	// Max try limit
	#define MAX_RETRY 3

	// IANA ID
	#define IANA_ID_0 0x15
	#define IANA_ID_1 0xA0
	#define IANA_ID_2 0x00

	// ME recovery cmd
	#define BIC_INTF_ME 0x1
	#define ME_RECOVERY_CMD_0 0xB8
	#define ME_RECOVERY_CMD_1 0xD7
	#define ME_RECOVERY_CMD_2 0x57
	#define ME_RECOVERY_CMD_3 0x01
	#define ME_RECOVERY_CMD_4 0x00

	#define VERIFY_ME_RECV_CMD_0 0x18
	#define VERIFY_ME_RECV_CMD_1 0x04
	#define ME_RECOVERY_MODE 0x1

	// BIOS SIZE
	#define BIOS_64k_SIZE (64*1024)
	#define BIOS_32k_SIZE (32*1024)

	#define UPDATE_BIOS 0
	#define UPDATE_CPLD 1
	#define UPDATE_BIC_BOOTLOADER 3
	#define UPDATE_BIC 4
	#define UPDATE_VR 5

	// Host Numbers
	#define HOST_1 0
	#define HOST_2 1
	#define HOST_3 2
	#define HOST_4 3

	// Command Id
	#define ME_RECOVERY_ID 0x2
	#define GET_FW_CHK_SUM 0xA
	#define FIRMWARE_UPDATE_ID 0x9
	#define GET_CPLD_UPDATE_PROGRESS 0x1A

	// Error Codes
	#define WRITE_FLASH_ERR   0x80
	#define POWER_STS_CHK_ERR 0x81
	#define DATA_LEN_ERR      0x82
	#define FLASH_ERASE_ERR   0x83
	#define CPLD_ERR_CODE     0xFD

	// General declarations
	#define RESP_SIZE 6
	#define NET_FN 0x38
	#define IPMB_WRITE_128B 128
}
