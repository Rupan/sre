#!/usr/bin/python3

"""
    SPDX-License-Identifier: GPL-3.0-or-later
    Interpret a supplied file as if it were a UBoot legacy image.
    This is useful if e.g. the file magic has been changed by a vendor.

    Copyright (C) 2020 Michael Mohr

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
    Print out information from a suspected UBoot image header in legacy
    format.  The enums were produced using the specification here:
        https://github.com/u-boot/u-boot/blob/master/include/image.h
"""

import enum
import os
import struct
import sys
import zlib
from datetime import datetime


class UBootOSType(enum.Enum):
    IH_OS_INVALID = 0  # Invalid OS
    IH_OS_OPENBSD = 1  # OpenBSD
    IH_OS_NETBSD = 2  # NetBSD
    IH_OS_FREEBSD = 3  # FreeBSD
    IH_OS_4_4BSD = 4  # 4.4BSD
    IH_OS_LINUX = 5  # Linux
    IH_OS_SVR4 = 6  # SVR4
    IH_OS_ESIX = 7  # Esix
    IH_OS_SOLARIS = 8  # Solaris
    IH_OS_IRIX = 9  # Irix
    IH_OS_SCO = 10  # SCO
    IH_OS_DELL = 11  # Dell
    IH_OS_NCR = 12  # NCR
    IH_OS_LYNXOS = 13  # LynxOS
    IH_OS_VXWORKS = 14  # VxWorks
    IH_OS_PSOS = 15  # pSOS
    IH_OS_QNX = 16  # QNX
    IH_OS_U_BOOT = 17  # Firmware
    IH_OS_RTEMS = 18  # RTEMS
    IH_OS_ARTOS = 19  # ARTOS
    IH_OS_UNITY = 20  # Unity OS
    IH_OS_INTEGRITY = 21  # INTEGRITY
    IH_OS_OSE = 22  # OSE
    IH_OS_PLAN9 = 23  # Plan 9
    IH_OS_OPENRTOS = 24  # OpenRTOS
    IH_OS_ARM_TRUSTED_FIRMWARE = 25  # ARM Trusted Firmware
    IH_OS_TEE = 26  # Trusted Execution Environment
    IH_OS_OPENSBI = 27  # RISC-V OpenSBI
    IH_OS_EFI = 28  # EFI Firmware (e.g. GRUB2)


class UBootCPUArch(enum.Enum):
    IH_ARCH_INVALID = 0  # Invalid CPU
    IH_ARCH_ALPHA = 1  # Alpha
    IH_ARCH_ARM = 2  # ARM
    IH_ARCH_I386 = 3  # Intel x86
    IH_ARCH_IA64 = 4  # IA64
    IH_ARCH_MIPS = 5  # MIPS
    IH_ARCH_MIPS64 = 6  # MIPS     64 Bit
    IH_ARCH_PPC = 7  # PowerPC
    IH_ARCH_S390 = 8  # IBM S390
    IH_ARCH_SH = 9  # SuperH
    IH_ARCH_SPARC = 10  # Sparc
    IH_ARCH_SPARC64 = 11  # Sparc 64 Bit
    IH_ARCH_M68K = 12  # M68K
    IH_ARCH_NIOS = 13  # Nios-32
    IH_ARCH_MICROBLAZE = 14  # MicroBlaze
    IH_ARCH_NIOS2 = 15  # Nios-II
    IH_ARCH_BLACKFIN = 16  # Blackfin
    IH_ARCH_AVR32 = 17  # AVR32
    IH_ARCH_ST200 = 18  # STMicroelectronics ST200
    IH_ARCH_SANDBOX = 19  # Sandbox architecture (test only)
    IH_ARCH_NDS32 = 20  # ANDES Technology - NDS32
    IH_ARCH_OPENRISC = 21  # OpenRISC 1000
    IH_ARCH_ARM64 = 22  # ARM64
    IH_ARCH_ARC = 23  # Synopsys DesignWare ARC
    IH_ARCH_X86_64 = 24  # AMD x86_64, Intel and Via
    IH_ARCH_XTENSA = 25  # Xtensa
    IH_ARCH_RISCV = 26  # RISC-V


class UBootImageType(enum.Enum):
    IH_TYPE_INVALID = 0  # Invalid Image
    IH_TYPE_STANDALONE = 1  # Standalone Program
    IH_TYPE_KERNEL = 2  # OS Kernel Image
    IH_TYPE_RAMDISK = 3  # RAMDisk Image
    IH_TYPE_MULTI = 4  # Multi-File Image
    IH_TYPE_FIRMWARE = 5  # Firmware Image
    IH_TYPE_SCRIPT = 6  # Script file
    IH_TYPE_FILESYSTEM = 7  # Filesystem Image (any type)
    IH_TYPE_FLATDT = 8  # Binary Flat Device Tree Blob
    IH_TYPE_KWBIMAGE = 9  # Kirkwood Boot Image
    IH_TYPE_IMXIMAGE = 10  # Freescale IMXBoot Image
    IH_TYPE_UBLIMAGE = 11  # Davinci UBL Image
    IH_TYPE_OMAPIMAGE = 12  # TI OMAP Config Header Image
    IH_TYPE_AISIMAGE = 13  # TI Davinci AIS Image
    # OS Kernel Image, can run from any load address
    IH_TYPE_KERNEL_NOLOAD = 14
    IH_TYPE_PBLIMAGE = 15  # Freescale PBL Boot Image
    IH_TYPE_MXSIMAGE = 16  # Freescale MXSBoot Image
    IH_TYPE_GPIMAGE = 17  # TI Keystone GPHeader Image
    IH_TYPE_ATMELIMAGE = 18  # ATMEL ROM bootable Image
    IH_TYPE_SOCFPGAIMAGE = 19  # Altera SOCFPGA CV/AV Preloader
    IH_TYPE_X86_SETUP = 20  # x86 setup.bin Image
    IH_TYPE_LPC32XXIMAGE = 21  # x86 setup.bin Image
    IH_TYPE_LOADABLE = 22  # A list of typeless images
    IH_TYPE_RKIMAGE = 23  # Rockchip Boot Image
    IH_TYPE_RKSD = 24  # Rockchip SD card
    IH_TYPE_RKSPI = 25  # Rockchip SPI image
    IH_TYPE_ZYNQIMAGE = 26  # Xilinx Zynq Boot Image
    IH_TYPE_ZYNQMPIMAGE = 27  # Xilinx ZynqMP Boot Image
    IH_TYPE_ZYNQMPBIF = 28  # Xilinx ZynqMP Boot Image (bif)
    IH_TYPE_FPGA = 29  # FPGA Image
    IH_TYPE_VYBRIDIMAGE = 30  # VYBRID .vyb Image
    IH_TYPE_TEE = 31  # Trusted Execution Environment OS Image
    IH_TYPE_FIRMWARE_IVT = 32  # Firmware Image with HABv4 IVT
    IH_TYPE_PMMC = 33  # TI Power Management Micro-Controller Firmware
    IH_TYPE_STM32IMAGE = 34  # STMicroelectronics STM32 Image
    IH_TYPE_SOCFPGAIMAGE_V1 = 35  # Altera SOCFPGA A10 Preloader
    IH_TYPE_MTKIMAGE = 36  # MediaTek BootROM loadable Image
    IH_TYPE_IMX8MIMAGE = 37  # Freescale IMX8MBoot Image
    IH_TYPE_IMX8IMAGE = 38  # Freescale IMX8Boot Image
    IH_TYPE_COPRO = 39  # Coprocessor Image for remoteproc


class UBootCompressionType(enum.Enum):
    IH_COMP_NONE = 0  # No compression Used
    IH_COMP_GZIP = 1  # gzip compression Used
    IH_COMP_BZIP2 = 2  # bzip2 compression Used
    IH_COMP_LZMA = 3  # lzma compression Used
    IH_COMP_LZO = 4  # lzo compression Used
    IH_COMP_LZ4 = 5  # lz4 compression Used
    IH_COMP_ZSTD = 6  # zstd compression Used


def _main(firmware_path):
    file_size = os.path.getsize(firmware_path)
    with open(firmware_path, "rb") as fd:
        header = fd.read(64)
        # Arbitrary size limit to prevent OOM
        if file_size < 256 * (1024 ** 2):
            calculated_data_crc = zlib.crc32(fd.read())
        else:
            calculated_data_crc = None

    ih_magic = header[:4]
    (
        ih_hcrc,  # Image Header CRC Checksum
        ih_time,  # Image Creation Timestamp
        ih_size,  # Image Data Size
        ih_load,  # Data  Load  Address
        ih_ep,  # Entry Point Address
        ih_dcrc,  # Image Data CRC Checksum
        ih_os,  # Operating System
        ih_arch,  # CPU architecture
        ih_type,  # Image Type
        ih_comp,  # Compression Type
    ) = struct.unpack(">IIIIIIBBBB", header[4:32])
    ih_name = header[32:].rstrip(b"\x00")  # Image Name

    print(f"Decomposed header for {firmware_path}")
    print("=" * 64)
    print(f"Magic:              {ih_magic}")
    print(f"Header CRC:         0x{ih_hcrc:08x}")
    print(f'Created (UTC):      {datetime.utcfromtimestamp(ih_time).strftime("%Y-%m-%d %H:%M:%S")}')
    print(f"Data size:          {ih_size} (matches: {file_size - 64 == ih_size})")
    print(f"Load address:       0x{ih_load:08x}")
    print(f"Entry point:        0x{ih_ep:08x}")
    if calculated_data_crc is None:
        print(f"Data CRC:           0x{ih_dcrc:08x}")
    else:
        print(f"Data CRC:           0x{ih_dcrc:08x} (matches: {calculated_data_crc == ih_dcrc})")
    print("=" * 64)
    print(f"OS type:            {UBootOSType(ih_os)}")
    print(f"CPU arch:           {UBootCPUArch(ih_arch)}")
    print(f"Image Type:         {UBootImageType(ih_type)}")
    print(f"Compression:        {UBootCompressionType(ih_comp)}")
    print(f"Image name:         {ih_name}")


if __name__ == "__main__":
    _main(sys.argv[1])
