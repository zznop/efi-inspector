"""EFI Inspector plugin for inspecting / operating on UEFI flash images
"""

from uuid import UUID
from enum import Enum
from os import path
from binaryninja import (
    BinaryView,
    BackgroundTaskThread,
    ChoiceField,
    get_form_input,
    show_message_box,
    get_directory_name_input,
    get_text_line_input,
)
from .uefi.ffs import FirmwareFileSystem, EFI_FILE_TYPES, EFI_SECTION_TYPES


def _generate_choice_field_for_files(files: list) -> ChoiceField:
    file_choices = []
    for _file in files:
        type_name = EFI_FILE_TYPES.get(_file.type, "OEM Type")
        file_choices.append(f"({type_name}) {_file.name}")

    return ChoiceField("Select a file", file_choices)


class EFIInspectorOperation(Enum):
    """Enum for specifying the EFIInspector operation to be performed"""

    GENERATE_REPORT = 1
    EXTRACT_SECTION = 2
    SEARCH_GUID = 3


class EFIInspector(BackgroundTaskThread):
    """Class that facilitates analysis of EFI images in Binary Ninja"""

    def __init__(self, bv: BinaryView, operation: EFIInspectorOperation) -> None:
        BackgroundTaskThread.__init__(self, "", False)
        self.bv = bv
        self.operation = operation
        self.raw = bv.parent_view
        self.progress = ""
        self.baseaddr = 0
        if self.bv.segments:
            self.baseaddr = self.bv.segments[0].start

    def _generate_ffs_report(self):
        ffs = FirmwareFileSystem(self.raw)
        regions = ffs.get_flash_regions()
        if not regions:
            show_message_box("EFI Inspector", "No flash regions found in loaded image")
            return

        markdown = "```\n"
        for region in regions:
            start = self.baseaddr + region.base
            end = start + region.limit
            markdown += f"├──[{start:08X}-{end:08X}] {region.name}\n"

            for volume in ffs.get_volumes(region):
                start = self.baseaddr + region.base
                end = start + volume.size
                markdown += f"│   ├──[{start:08X}-{end:08X}] {volume.name} (Volume)\n"

                # No files in NVRAM volume
                if volume.name == 'NVRAM EVSA':
                    continue

                for _file in ffs.get_files(volume):
                    start = self.baseaddr + _file.start
                    end = start + _file.size
                    type_name = EFI_FILE_TYPES.get(_file.type, "OEM Type")
                    markdown += f"│   │   ├──[{start:08X}-{end:08X}] {_file.name} ({type_name})\n"

        markdown += "```\n"
        self.bv.show_markdown_report("EFI Firmware File System", markdown, "")

    def _extract_file(self):
        ffs = FirmwareFileSystem(self.raw)
        regions = ffs.get_flash_regions()
        if not regions:
            show_message_box("EFI Inspector", "No flash regions found in loaded image")
            return

        files = []
        for region in regions:
            for volume in ffs.get_volumes(region):
                files.extend(ffs.get_files(volume))

        if not files:
            show_message_box("EFI Inspector", "No files found in FFS volumes")
            return

        filecf = _generate_choice_field_for_files(files)
        get_form_input([filecf], "Extract EFI file")
        if not filecf.result:
            return  # User aborted

        file_info = files[filecf.result]
        sections = ffs.get_sections(file_info)
        if not sections:
            show_message_box("EFI Inspector", "No sections found in FFS file")
            return

        outdir = get_directory_name_input("Output directory")
        if not outdir:
            return  # User aborted

        for section in sections:
            section_addr = section.data_start + self.baseaddr
            _, extension = EFI_SECTION_TYPES.get(section.type, ("OEM Type", "bin"))
            filename = (
                f"{file_info.name.replace('.', '_')}_{section_addr:08x}.{extension}"
            )
            fullpath = path.join(outdir, filename)
            with open(fullpath, "wb") as f:
                f.write(
                    self.raw[
                        section.data_start : section.data_start + section.data_size
                    ]
                )

        show_message_box(
            "EFI Inspector",
            f"({len(sections)}) EFI file section(s) extracted",
        )

    def _find_guid_blob_address(self, input_guid: str) -> int:
        ffs = FirmwareFileSystem(self.raw)
        for region in ffs.get_flash_regions():
            for volume in ffs.get_volumes(region):
                if input_guid == volume.guid:
                    return self.baseaddr + volume.start

                for _file in ffs.get_files(volume):
                    if input_guid == _file.guid:
                        return self.baseaddr + _file.start

        return None

    def _search_guid(self) -> None:
        input_guid = get_text_line_input("GUID", "EFI FFS GUID Search")
        if not input_guid:
            return  # User aborted

        try:
            input_guid = UUID(input_guid.decode("utf-8"))
        except ValueError:
            show_message_box("UEFI Inspector", "Supplied GUID is invalid")
            return

        address = self._find_guid_blob_address(input_guid)
        if address is None:
            show_message_box("EFI Inspector", "Failed to find blob belonging to GUID")
            return

        self.bv.navigate(self.bv.view, address)

    def run(self) -> None:
        """Analyze EFI image and perform the user-specified operation"""

        if self.operation == EFIInspectorOperation.GENERATE_REPORT:
            self.progress = "EFI Inspector: generating file system report..."
            self._generate_ffs_report()
        elif self.operation == EFIInspectorOperation.EXTRACT_SECTION:
            self._extract_file()
        elif self.operation == EFIInspectorOperation.SEARCH_GUID:
            self._search_guid()

        self.progress = ""


def run_efi_inspector_generate_report(bv: BinaryView) -> None:
    """Generate markdown report on EFI firmware file system layout"""

    task = EFIInspector(bv, EFIInspectorOperation.GENERATE_REPORT)
    task.start()


def run_efi_inspector_extract_file(bv: BinaryView) -> None:
    """Extract a file from EFI firmware file system"""

    task = EFIInspector(bv, EFIInspectorOperation.EXTRACT_SECTION)
    task.start()


def run_efi_inspector_search_guid(bv: BinaryView) -> None:
    """Search for blob in FFS by GUID"""

    task = EFIInspector(bv, EFIInspectorOperation.SEARCH_GUID)
    task.start()
