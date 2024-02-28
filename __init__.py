"""Binary Ninja UEFI inspector tool
"""

from binaryninja import PluginCommand
from .uefi_loader import UEFIImageView
from .efi_inspector import (
    run_efi_inspector_generate_report,
    run_efi_inspector_extract_file,
    run_efi_inspector_search_guid,
)

PluginCommand.register(
    "EFI Inspector: Generate FFS report",
    "Generate report on UEFI firmware file system",
    run_efi_inspector_generate_report,
)

PluginCommand.register(
    "EFI Inspector: Extract FFS file",
    "Extract a file from UEFI firmware file system",
    run_efi_inspector_extract_file,
)

PluginCommand.register(
    "EFI Inspector: Search GUID",
    "Search UEFI FFS for a blob by GUID",
    run_efi_inspector_search_guid,
)

UEFIImageView.register()
