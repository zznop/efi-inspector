"""Interface for parsing UEFI Firmware File Systems (FFS)
"""

import struct
import logging
from dataclasses import dataclass
from uuid import UUID
from ctypes import (
    LittleEndianStructure,
    c_uint32,
    c_uint8,
    c_uint16,
    c_uint64,
    sizeof,
    memmove,
    pointer,
)

from .guids import FIRMWARE_FILE_GUIDS, FIRMWARE_VOLUME_GUIDS


EFI_FILE_TYPES = {
    0x00: "Unknown",
    0x01: "Raw",
    0x02: "Freeform",
    0x03: "Security Core",
    0x04: "PEI Core",
    0x05: "DXE Core",
    0x06: "PEI Module",
    0x07: "DXE Driver",
    0x08: "PEI/DXE (Combined)",
    0x09: "Application",
    0x0A: "System Management",
    0x0B: "Firmware Volume Image",
    0x0C: "SMM/DXE Driver (Combined)",
    0x0D: "SMM Core",
    # OEM Reserved
    0xF0: "FFS Padding",
}


EFI_SECTION_TYPES = {
    0x01: ("Compressed", "compressed"),
    0x02: ("Guid Defined", "guid"),
    0x03: ("Disposable", "disposable"),
    0x10: ("PE32 image", "pe"),
    0x11: ("PE32+ PIC image", "pic.pe"),
    0x12: ("Terse executable (TE)", "te"),
    0x13: ("DXE dependency expression", "dxe.depex"),
    0x14: ("Version section", "version"),
    0x15: ("User interface name", "ui"),
    0x16: ("IA-32 16-bit image", "ia32.16bit"),
    0x17: ("Firmware volume image", "fv"),
    0x18: ("Free-form GUID", "freeform.guid"),
    0x19: ("Raw", "raw"),
    0x1B: ("PEI dependency expression", "pie.depex"),
    0x1C: ("SMM dependency expression", "smm.depex"),
}


@dataclass
class FlashRegionInfo:
    """Stores info on SPI flash regions"""

    name: str
    base: int
    limit: int


@dataclass
class EFIFirmwareVolumeInfo:
    """Stores info on EFI firmware FFS volumes"""

    name: str
    start: int
    size: int
    header_size: int
    guid: UUID
    attributes: int
    checksum: int


@dataclass
class EFIFirmwareFileInfo:
    """Stores info on EFI firmware FFS files"""

    name: str
    start: int
    size: int
    data_start: int
    guid: UUID
    type: int
    state: int


@dataclass
class EFIFirmwareSectionInfo:
    """Stores info on EFI firmware sections"""

    start: int
    size: int
    data_start: int
    data_size: int
    type: int


class EFIFirmwareVolumeBlockMapEntry(LittleEndianStructure):
    """Represents a EFI_FV_BLOCK_MAP_ENTRY structure"""

    _fields_ = [
        ("NumBlocks", c_uint32),
        ("Length", c_uint32),
    ]


class EFIFirmwareVolumeHeader(LittleEndianStructure):
    """Represents a EFI_FIRMWARE_VOLUME_HEADER structure"""

    _fields_ = [
        ("ZeroVector", c_uint8 * 16),
        ("FileSystemGuid", c_uint8 * 16),
        ("FvLength", c_uint64),
        ("Signature", c_uint32),
        ("Attributes", c_uint32),
        ("HeaderLength", c_uint16),
        ("Checksum", c_uint16),
        ("ExtHeaderOffset", c_uint16),
        ("Reserved", c_uint8),
        ("Revision", c_uint8),
    ]


class EFIFirmwareFileHeader(LittleEndianStructure):
    """Represents a EFI_FIRMWARE_FILE_HEADER structure"""

    _fields_ = [
        ("FileNameGuid", c_uint8 * 16),
        ("Checksum", c_uint16),
        ("FileType", c_uint8),
        ("Attributes", c_uint8),
        ("Size", c_uint8 * 3),
        ("State", c_uint8),
    ]


class EFIFirmwareSectionHeader(LittleEndianStructure):
    """Represents an EFI_FIRMWARE_SECTION_HEADER structure"""

    _fields_ = [
        ("Size", c_uint8 * 3),
        ("Type", c_uint8),
    ]


class FirmwareFileSystem:
    """Class for parsing UEFI firmware file systems (FFS)"""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def get_sections(self, _file: EFIFirmwareFileInfo) -> list:
        """Parse FFS file and return a list of information on contained sections"""

        sections = []
        filehdr = EFIFirmwareFileHeader()
        n = sizeof(filehdr)
        while n < _file.size:
            sechdr = EFIFirmwareSectionHeader()
            filedata = self.data[_file.start + n : _file.start + n + _file.size]
            memmove(pointer(sechdr), filedata, sizeof(sechdr))
            hdr_sz = sizeof(sechdr)
            secsize = int.from_bytes(bytes(sechdr.Size), "little")  # 24-bit to int
            if secsize == 0xFFFFFFFF:  # FFSv3 extended hdr
                secsize = struct.unpack(
                    "<I", self.data[_file.start + hdr_sz : _file.start + hdr_sz + 4]
                )[0]
                hdr_sz += 4

            data_ofs = _file.start + n + hdr_sz
            sections.append(
                EFIFirmwareSectionInfo(
                    _file.start + n, secsize, data_ofs, secsize - hdr_sz, sechdr.Type
                )
            )

            n += secsize

        return sections

    def _parse_firmware_files(self, offset: int, voldata: bytes) -> EFIFirmwareFileInfo:
        filehdr = EFIFirmwareFileHeader()
        memmove(pointer(filehdr), voldata, sizeof(filehdr))
        guid = UUID(bytes_le=bytes(filehdr.FileNameGuid))
        name = FIRMWARE_FILE_GUIDS.get(str(guid).upper(), str(guid))
        filesize = int.from_bytes(bytes(filehdr.Size), "little")
        file_data_ofs = offset + sizeof(filehdr)
        logging.info(
            "file found at 0x%08x (%s) type=%02x size=0x%08x",
            file_data_ofs,
            guid,
            filehdr.FileType,
            filesize,
        )

        return EFIFirmwareFileInfo(
            name,
            offset,
            filesize,
            file_data_ofs,
            guid,
            filehdr.FileType,
            filehdr.State ^ 0xFF,
        )

    def get_files(self, volume: EFIFirmwareVolumeInfo) -> list:
        """Parse FFS volume and return a list of information on contained files
        """

        fvo = volume.start
        fvhdr = EFIFirmwareVolumeHeader()
        memmove(pointer(fvhdr), self.data[fvo : fvo + sizeof(fvhdr)], sizeof(fvhdr))

        guid = UUID(bytes_le=bytes(fvhdr.FileSystemGuid))
        logging.info(
            "volume found at 0x%08x-0x%08x (%s)", fvo, fvo + fvhdr.FvLength, guid
        )

        # Deserialize each entry in the block map
        block_map = self.data[fvo + sizeof(fvhdr) : fvo + fvhdr.HeaderLength]
        block_map_entry = EFIFirmwareVolumeBlockMapEntry()
        block_entries = []
        for i in range(0, len(block_map), sizeof(block_map_entry)):
            memmove(
                pointer(block_map_entry),
                self.data[
                    fvo
                    + sizeof(fvhdr)
                    + i : fvo
                    + sizeof(fvhdr)
                    + i
                    + sizeof(block_map_entry)
                ],
                sizeof(block_map_entry),
            )

            if not block_map_entry.NumBlocks:
                continue

            block_entries.append((block_map_entry.NumBlocks, block_map_entry.Length))

        # Iterate through the block map entries to collect the data for each volume
        voldata = b""
        volume_data_base = fvo + fvhdr.HeaderLength
        files = []
        for entry in block_entries:
            voldata += self.data[
                volume_data_base : volume_data_base + entry[0] * entry[1]
            ]

        # Skip files that are F'd out
        volidx = 0
        while len(voldata) >= 24 and voldata[:24] != (b"\xff" * 24):
            file_info = self._parse_firmware_files(volume_data_base + volidx, voldata)
            if not file_info.size:
                break  # Free space at the end of the volume

            if (
                file_info.type != 0xF0
            ):  # Don't add if it's padding at the end of a volume
                files.append(file_info)
            next_file_idx = (file_info.size + 7) & (~7)
            voldata = voldata[next_file_idx:]
            volidx += next_file_idx

        return files

    def get_volumes(self, region: FlashRegionInfo) -> list:
        """Search the flash region for FFS volumes and return a list of information on each volume"""

        volume_offsets = []
        region_data = self.data[region.base:region.limit]
        for aligned in range(0, len(region_data), 32):
            if region_data[aligned : aligned + 4] == b"_FVH":
                volume_offsets.append(region.base + aligned - 40)

            magic = region_data[(aligned + 16 // 2) : (aligned + 16 // 2 + 4)]
            if magic == b"_FVH":
                volume_offsets.append(
                    region.base + aligned + 16 // 2 - 40
                )  # 40 == offset of Signature

        volumes = []
        for offset in volume_offsets:
            fvhdr = EFIFirmwareVolumeHeader()
            memmove(
                pointer(fvhdr),
                self.data[offset : offset + sizeof(fvhdr)],
                sizeof(fvhdr),
            )
            guid = UUID(bytes_le=bytes(fvhdr.FileSystemGuid))

            name = FIRMWARE_VOLUME_GUIDS.get(str(guid).lower(), str(guid))
            volumes.append(
                EFIFirmwareVolumeInfo(
                    name,
                    offset,
                    fvhdr.HeaderLength,
                    sizeof(fvhdr),
                    guid,
                    fvhdr.Attributes,
                    fvhdr.Checksum,
                )
            )

        return volumes

    def get_flash_regions(self) -> list:
        """Parse the SPI flash descriptor table and return a list of information on each region
        """

        mapoff = 16
        flmap0 = struct.unpack("<I", self.data[mapoff + 4 : mapoff + 8])[0]
        num_regions = (flmap0 >> 24) & 0x7
        region_names = [
            "Flash Descriptor",
            "BIOS Region",
            "ME Region",
            "GbE Region",
            "PDR Region",
        ]

        # I've seen this set to 0 despite that there are multiple regions. Set to 3 and assume
        # there's atleast a flash descriptor, BIOS region, and an Intel ME region
        if not num_regions:
            num_regions = 3

        regions = []
        for i in range(0, num_regions):
            frba = (flmap0 >> 12) & 0xFF0
            flreg = struct.unpack(
                "<I",
                self.data[frba + i * 4 : frba + i * 4 + 4],
            )[0]

            limit = (flreg >> 4) & 0xFFF000
            base = (flreg << 12) & 0xFFF000
            if limit == 0 and base == 0xFFF000:
                return None

            limit |= 0xFFF
            region_name = f"Region {i}"
            try:
                region_name = region_names[i]
            except IndexError:
                pass

            regions.append(FlashRegionInfo(region_name, base, limit))

        return regions
