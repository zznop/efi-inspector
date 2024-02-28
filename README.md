# efi-inspector

Binary Ninja plugin for inspecting UEFI firmware images

# Features

* Load UEFI firmware flash images containing valid flash descriptors
   * Apply structures to flash regions, EFI FFS volumes, and EFI FFS files
   * Enumerate the platform architecture by locating and parsing PEI Core TE
   * Set entry point and disassemble at reset vector (Intel architectures only)
* Generate a markdown report of the EFI firmware file system tree
* Search EFI firmware file system for blobs by GUID
* Extract EFI files to disk

# Screenshots

**Load UEFI Flash Image**

![demo load](img/loader.png)

**Generate Markdown Report on Firmware File System Layout**

![demo report](img/ffs-layout.png)

**Extract a EFI File from Firmware File System**

![demo extract](img/extract-file.png)

**Search EFI Firmware File System for Blob by GUID**

![demo search](img/guid-search.png)

## License

This plugin is released under a MIT license.

## Related Projects

* [UEFITool](https://github.com/LongSoft/UEFITool)
* [uefi-firmware-parser](https://github.com/theopolis/uefi-firmware-parser)