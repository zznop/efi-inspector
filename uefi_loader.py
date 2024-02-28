"""Binary Ninja loader for UEFI firmware flash images
"""

from struct import unpack
from .uefi.ffs import FirmwareFileSystem, EFIFirmwareFileInfo
from binaryninja import Type, BinaryView, SegmentFlag, SectionSemantics, platform


class UEFIImageView(BinaryView):
    """BinaryView for UEFI firmware images"""

    name = "UEFI Flash Image"
    long_name = "Unified Extensible Firmware Interface (UEFI) Flash Image"

    def __init__(self, data: bytes) -> None:
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

        # Map it so the last 16 bytes of the image aligns with the x86 reset vector at 0xfffffff0
        # For AArch64 UEFI firmware the reset vector could be anywhere
        self.baseaddr = 0xFFFFFFFF - data.length + 1
        self.platform = None

    def _identify_platform_from_te(
        self, ffs: FirmwareFileSystem, _file: EFIFirmwareFileInfo) -> None:
        magic = -1
        sections = ffs.get_sections(_file)
        for section in sections:
            if section.type != 0x12:  # TE Image Section
                continue

            magic, machine = unpack(
                "<hh", self.data[section.data_start : section.data_start + 4]
            )
            if magic == 0x5A56:
                break

        # Majority of Intel processors start in 16-bit mode on reset
        if machine == 332:
            self.platform = platform.Platform["x86_16"]
        elif machine == -31132:
            self.platform = platform.Platform["x86_16"]
        elif machine == -31916:
            self.platform = platform.Platform["aarch64"]
        else:
            # Assume x86
            self.platform = platform.Platform["x86_16"]

    @classmethod
    def is_valid_for_data(cls, raw: bytes) -> bool:
        """Determine if the loaded binary is a valid UEFI image"""

        # SPI flash size is always 1 MiB aligned
        if not raw.length or raw.length % 1048576:
            return False

        return raw[16:20] == b"\x5a\xa5\xf0\x0f"

    def perform_is_executable(self) -> bool:
        """UEFI image is executable"""

        return True

    def perform_get_address_size(self) -> int:
        """32-bit address width should be appropriate in all cases"""

        return 4

    def init(self):
        """Setup the BinaryView"""

        # Assume Intel (temporarily) - shouldn't matter if we're wrong
        self.platform = platform.Platform["x86_16"]
        fvhdr, name = self.parse_type_string(
            """
        struct {
            uint8_t ZeroVector[16];
            uint8_t FileSystemGuid[16];
            uint64_t FvLength;
            uint32_t Signature;
            uint32_t Attributes;
            uint16_t HeaderLength;
            uint16_t Checksum;
            uint16_t ExtHeaderOffset;
            uint8_t Reserved;
            uint8_t Revision;
        } EFI_FIRMWARE_VOLUME_HEADER;
        """
        )
        self.define_type(Type.generate_auto_type_id("source", name), name, fvhdr)

        filehdr, name = self.parse_type_string(
            """
        struct {
            uint8_t FileNameGuid[16];
            uint16_t Checksum;
            uint8_t FileType;
            uint8_t Attributes;
            uint8_t Size[3];
            uint8_t State;
        } EFI_FIRMWARE_FILE_HEADER;
        """
        )
        self.define_type(Type.generate_auto_type_id("source", name), name, filehdr)

        # Parse flash descriptor
        ffs = FirmwareFileSystem(self.data)

        # Iterate through flash regions and create segments
        for region in ffs.get_flash_regions():
            segment_flags = SegmentFlag.SegmentReadable
            if region.name == "BIOS Region":
                segment_flags |= SegmentFlag.SegmentExecutable

            self.add_auto_segment(
                self.baseaddr + region.base,
                region.limit + 1,
                region.base,
                region.limit + 1,
                segment_flags,
            )

            # Setting it to ReadOnlyDataSectionSemantics prevents linear sweep from going nuts.
            # This is a flash dump and only a small amount of code runs out of flash. We don't
            # want it to identify code except at the reset vector (where we tell it to)
            self.add_auto_section(
                region.name,
                self.baseaddr + region.base,
                region.limit + 1,
                SectionSemantics.ReadOnlyDataSectionSemantics,
            )

            # Iterate through volumes in each region to assign EFI_FIMRWARE_VOLUME_HEADER structs
            platform_set = False
            for volume in ffs.get_volumes(region):
                self.define_data_var(self.baseaddr + volume.start, fvhdr)

                # Iterate through files in volume and assign the EFI_FIRMWARE_FILE_HEADER structs
                for file in ffs.get_files(volume):
                    self.define_data_var(self.baseaddr + file.start, filehdr)

                    # If we hit the PEICore, determine the machine type from the TE
                    if file.type == 0x4 and not platform_set:  # PEI Core
                        self._identify_platform_from_te(ffs, file)
                        platform_set = True

        # If it's x86 firmware, set entry at the x86 reset vector. If it's
        # AArch64, we don't have a good way to know where that is (currently)
        if self.platform == platform.Platform["x86_16"]:
            self.add_entry_point(0xFFFFFFF0)

        return True
