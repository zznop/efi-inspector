"""Contains dictionaries of GUIDs and associated names for FFS volumes and files
"""

FIRMWARE_VOLUME_GUIDS = {
    "7a9354d9-0468-444a-81ce-0bf617d890df": "FFS1",
    "8c8ce578-8a3d-4f1c-9935-896185c32dd3": "FFS2",
    "5473c07a-3dcb-4dca-bd6f-1e9689e7349a": "FFS3",
    "fff12b8d-7696-4c8b-a985-2747075b4f50": "NVRAM EVSA",
    "cef5b9a3-476d-497f-9fdc-e98143e0422c": "NVRAM NVAR",
    "00504624-8a59-4eeb-bd0f-6b36e96128e0": "NVRAM EVSA2",
    "04adeead-61ff-4d31-b6ba-64f8bf901f5a": "APPLE BOOT",
    "16b45da2-7d70-4aea-a58d-760e9ecb841d": "PFH1",
    "e360bdba-c3ce-46be-8f37-b231e5cb9f35": "PFH2",
}

FIRMWARE_FILE_GUIDS = {
    "16D0A23E-C09C-407D-A14A-AD058FDD0CA1": "ACPI",
    "11D8AC35-FB8A-44D1-8D09-0B5606D321B9": "DSDT",
    "95DFCAE5-BB28-4D6B-B1E2-3AF3A6BF434F": "PTID",
    "FB045DB2-598E-485A-BA30-5D7B1B1BD54D": "AOAC",
    "60AC3A8F-4D66-4CD4-895A-C3F06E6665EE": "iFfsAcpiTables",
    "5B232086-350A-42C7-A70E-3497B5765D85": "OEMSSDT",
    "299141BB-211A-48A5-92C0-6F9A0A3A006E": "PPMACPI",
    "27E569D5-0AFC-4D8F-8C90-783AC4A318AB": "SaAcpiTables",
    "22046D50-F390-498C-92E5-5BA4F8E7F8B6": "SBSATAIDE",
    "CACB3817-81E6-497E-87FF-C8FA8F24EC28": "SgACPI",
    "6A061113-FE54-4A07-A28E-0A69359EB069": "SgTpvACPI",
    "D1E59F50-E8C3-4545-BF61-11F002233C97": "TxtPeiAp",
    "2D27C618-7DCD-41F5-BB10-21166BE7E143": "BiosAc",
    "1BA0062E-C779-4582-8566-336AE8F78F09": "SecCore",
    "17088572-377F-44EF-8F4E-B09FFF46A070": "Microcode",
    "FC510EE7-FFDC-11D4-BD41-0080C73C8881": "DxeApriori",
    "1B45CC0A-156A-428A-AF62-49864DA0E6E6": "PeiApriori",
    "7D113AA9-6280-48C6-BACE-DFE7668E8307": "MPTPM",
    "0515BC05-2959-4E91-89C6-6B3A3F1FCB65": "TCG_MPDriver",
    "92BA9255-2819-4479-867A-1C58F072C5B2": "TCG_MADriver",
    "3EB9F0D3-40D0-435B-B692-809151807FF4": "TCM_MPDriver",
    "CA0D6FF6-62A7-4B1F-BB90-52EECA01A99F": "TCM_MADriver",
    "0AA31BC6-3379-41E8-825A-53F82CC0F254": "TPM32BIN",
    "142204E2-C7B1-4AF9-A729-923758D96D03": "LEGX16",
    "0639408B-19A6-4B5D-BAFB-12A2F5114032": "Acoustic",
    "750890A6-7ACF-4F4F-81BD-B400C2BEA95A": "AcpiModeEnable",
    "197DB236-F856-4924-90F8-CDF12FB875F3": "Microcode",
    "333BB2A3-4F20-4C8B-AC38-0672D74315F8": "AcpiPlatformPei",
    "8B5FBABD-F51F-4942-BF16-16AAA38AE52B": "AcpiPlatform",
    "DFD8D5CC-5AED-4820-A2B6-5C55E4E640EF": "AcpiPlatformSmi",
    "BFD59D42-FE0F-4251-B772-4B098A1AEC85": "ActiveBios",
    "96F1AC24-2B21-45FA-A0B5-67010C95E9D8": "AhciMmioSmm",
    "BC3245BD-B982-4F55-9F79-056AD7E987C5": "AhciSmm",
    "8F5A2E02-538C-4D59-B920-C4786ACBC552": "Ahci",
    "67820532-7613-4DD3-9ED7-3D9BE3A7DA63": "Aint13",
    "33C6406D-2F6B-41B5-8705-52BAFB633C09": "AlertStandardFormatDxe",
    "3E4817FD-2742-4351-B59F-91493280329C": "AlertStandardFormatPei",
    "9F3A0016-AE55-4288-829D-D22FD344C347": "AmiBoardInfo",
    "1CE12314-AFBC-11F0-8A3E-AB44B8EE3120": "PpmPolicyInitDxe",
    "50F6096D-7C98-4C78-9A1D-C5A1833B6A88": "AmiTcgNvflagSample",
    "A29A63E3-E4E7-495F-8A6A-07738300CBB3": "AmiTcgPlatformDXE",
    "9B3F28D5-10A6-46C8-BA72-BD40B847A71A": "AmiTcgPlatformPeiAfterMem",
    "E9312938-E56B-4614-A252-CF7D2F377E26": "AmiTcgPlatformPeiBeforeMem",
    "B1DA0ADF-4F77-4070-A88E-BFFE1C60529A": "AMITSE",
    "294B1CEF-9BEB-42D5-9971-0C8963CDAF02": "SmLogo",
    "A59A0056-3341-44B5-9C9C-6D76F7673817": "SignON",
    "D739F969-FB2D-4BC2-AFE7-081327D3FEDE": "AMTDxe",
    "5507247A-846B-4F22-B55F-72B4049435EF": "AmtLockKBD",
    "A05ECE52-15A8-424E-BFD3-FCF3D566A09C": "AmtPeiPolicyInit",
    "290EA249-6E88-423C-B0DA-75CDDE7920CC": "AmtPetAlert",
    "1BE65202-9318-492D-A551-08DF2BD60AEE": "AmtPlatformPolicy",
    "773CB08B-511A-4BD5-85AD-41D4F4B64A52": "AmtSetup",
    "A8C67255-E029-4B1A-968E-ECA6E9C11C73": "AmtSmbios",
    "D77C900D-A1C7-41C5-B989-0C3D37FCA432": "AmtWrapperDxe",
    "8DD91798-EE87-4F0E-8A84-3F998311F930": "ArpDxe",
    "E72527CF-505B-4B50-99CD-A32467FA4AA4": "AsfTable",
    "4F4FF580-B8A0-4332-A6B0-E2E568E36C9C": "ASFVerbosity",
    "6DB9486F-6AF6-4090-984D-238482CE3EA4": "BdatAccessHandler",
    "25ACF158-DD61-4E64-9A49-55851E9A26C7": "BIOSBLKIO",
    "97CC7188-79C9-449F-B969-065B64BF9C69": "BiosExtensionLoader",
    "0DCA793A-EA96-42D8-BD7B-DC7F684E38C1": "RomLayout",
    "6E59DF06-62D3-40B0-82B5-175CF84A94E4": "OEMPEI",
    "BFE205C9-5B17-4F8F-9375-89614AF8E199": "OEMDXE",
    "FAC2EFAD-8511-4E34-9CAE-16A257BA9488": "Capsule",
    "6869C5B3-AC8D-4973-8B37-E354DBF34ADD": "CmosManagerSmm",
    "DAC2B117-B5FB-4964-A312-0DCC77061B9B": "Font",
    "CEF5B9A3-476D-497F-9FDC-E98143E0422C": "NVRAM",
    "9221315B-30BB-46B5-813E-1B1BF4712BD3": "Defaults",
    "5AE3F37E-4EAE-41AE-8240-35465B5E81EB": "CORE_DXE",
    "92685943-D810-47FF-A112-CC8490776A1F": "CORE_PEI",
    "1555ACF3-BD07-4685-B668-A86945A4124D": "CpuPeiBeforeMem",
    "2BB5AFA9-FF33-417B-8497-CB773C2B93BF": "CpuPei",
    "E03ABADF-E536-4E88-B3A0-B77F78EB34FE": "CpuDxe",
    "62D171CB-78CD-4480-8678-C6A2A797A8DE": "CpuInitDxe",
    "01359D99-9446-456D-ADA4-50A711C03ADA": "CpuInitPei",
    "15B9B6DA-00A9-4DE7-B8E8-ED7AFB88F16E": "CpuPolicyInitDxe",
    "0AC2D35D-1C77-1033-A6F8-7CA55DF7D0AA": "CpuPolicyPei",
    "C866BD71-7C79-4BF1-A93B-066B830D8F9A": "CpuS3Peim",
    "326E7ACE-2133-1BA2-800A-B9C00ACCB17D": "CpuSmmSaveRes",
    "116E1ACF-2533-4CC2-820A-BBC10A2AB07C": "CpuSpSmi",
    "0D1ED2F7-E92B-4562-92DD-5C82EC917EAE": "CRBPEI",
    "16271FCA-55D9-4A33-93FC-5A3EB128DEB6": "CRBDXE",
    "221F1D4F-034C-4BEA-B2BB-B7A9672B06D7": "CRBSMI",
    "D6D2FBA6-EF60-4C38-A83E-6769814D23B0": "CryptoPei",
    "20D8FFFE-15C3-4EA9-9D28-CFE2745D78F3": "CryptoDxe",
    "A062CF1F-8473-4AA3-8793-600BC4FFE9A8": "CSMCORE",
    "29CF55F8-B675-4F5D-8F2F-B87A3ECFD063": "CsmVideo",
    "3FD1D3A2-99F7-420B-BC69-8BB1D492A332": "Fid",
    "CD84562C-6864-40A3-A081-C8D35E82B920": "CspLibDxe",
    "8DD9176E-EE87-4F0E-8A84-3F998311F930": "Dhcp4Dxe",
    "8DD9176D-EE87-4F0E-8A84-3F998311F930": "Dhcp6Dxe",
    "399CF3A7-82C7-4D9B-9123-DB11842986D3": "DpcDxe",
    "13AC6DD0-73D0-11D4-B06B-00AA00BD6DE7": "EBC",
    "333BB2A3-4F20-4CCC-AC38-0672D7412345": "FastBootPei",
    "D122882C-DA73-438B-A6B3-E07B7D18DB6F": "FastBootSMI",
    "93022F8C-1F09-47EF-BBB2-5814FF609DF5": "FileSystem",
    "AEC4159D-F2FC-4090-95CE-38317A8ED64C": "FirmwarePerformanceTable",
    "8B9D3EE0-4BA4-433B-9C48-4E830B3B40FD": "FloppyCtrl",
    "55E76644-78A5-4A82-A900-7126A5798892": "HeciDxe",
    "9CF30325-DC5C-4556-A8B0-74215C5F7FC4": "HeciPei",
    "921CD783-3E22-4579-A71F-00D74197FCC8": "HeciSmm",
    "5BBA83E5-F027-4CA7-BFD0-16358CC9E123": "IccOverClocking",
    "14257B56-BDA2-4FAF-8E4F-C885DF75583C": "IccPlatform",
    "59B90A53-461B-4C50-A79F-A32773C319AE": "IdeBusSrc",
    "C4F2D007-37FD-422D-B63D-7ED73886E6CA": "IdeRController",
    "A9B700CF-019E-4D8B-A3A7-88E1EA01699E": "IdeSecurity",
    "D57C852E-809F-45CF-A377-D77BC0CB78EE": "IdeSmart",
    "316B1230-0500-4592-8C09-EABA0FB6B07F": "IdeSMM",
    "B6B9295F-CABF-4CEC-BB14-FE4246F2173A": "iFfsDxe",
    "DDB412A6-E3F3-4E9E-90A3-2A991270219C": "iFfsDxePolicyInit",
    "53F019E9-BB0C-424B-870A-1FAF10B1CB4C": "iFfsPei",
    "43172851-CF7E-4345-9FE0-D7012BB17B88": "iFfsSmm",
    "4953F720-006D-41F5-990D-0AC7742ABB60": "IntelGigabitLan",
    "C1C418F9-591D-461C-82A2-B9CD96DFEA86": "IntelLegacyInterrupt",
    "5C266089-E103-4D43-9AB5-12D7095BE2AF": "IntelSaGopDriver",
    "878AC2CC-5343-46F2-B563-51F89DAF56BA": "IntelIvbGopVbt",
    "5BBA83E6-F027-4CA7-BFD0-16358CC9E123": "IntelIvbGopDriver",
    "0F729F33-25C1-41A7-86B2-23A737A91823": "IntelSnbGopVbt",
    "8D59EBC8-B85E-400E-970A-1F995D1DB91E": "IntelSnbGopDriver",
    "2374EDDF-F203-4FC0-A20E-61BAD73089D6": "IoTrap",
    "8F92960F-2880-4659-B857-915A8901BDC8": "Ip4Dxe",
    "8F9296EF-2880-4659-B857-915A8901BDC8": "Ip4Config",
    "8F92960E-2880-4659-B857-915A8901BDC8": "Ip6Dxe",
    "FCF94301-9763-4A64-AA84-7892C4712367": "IpSecDxe",
    "3B24F79D-91A0-46FF-BE29-458AE211FAC5": "KbcEmul",
    "71ED12D1-250B-42FB-8C17-10DCFA771701": "LegacyInterrupt",
    "59242DD8-E7CF-4979-B60E-A6067E2A185F": "LegacyRegion",
    "FE6F8ACD-55A6-4C6B-B448-64E659DE94B3": "LegacyRegion2",
    "4A3602BC-1A05-4C82-99B4-588CD2A32CD5": "LEGACYSREDIR",
    "DF5CD25A-8E55-46BA-8CDA-BC7DB7BF9C64": "MdesStatusCodeDrv",
    "9CFD802C-09A1-43D6-8217-AA49C1F90D2C": "Mebx",
    "B62EFBBB-3923-4CB9-A6E8-DB818E828A80": "MebxSetupBrowser",
    "5820EEB4-C135-4854-9D2A-AA9EFC4475E9": "MeFwDowngrade",
    "3B42EF57-16D3-44CB-8632-9FDB06B41451": "MemoryInit",
    "459C70C3-9344-4484-9F93-7822530D0D11": "MePciPlatform",
    "12C67BE1-AD2E-4F13-A95F-6EDC2C4392DE": "MEPeiPolicyInit",
    "BA67550C-3628-4137-A53E-42660E081604": "MePlatformPolicy",
    "F3331DE6-4A55-44E4-B767-7453F7A1A021": "MicrocodeUpdate",
    "EDA39402-F375-4496-92D3-83B43CB8A76A": "SmBiosMemory",
    "16271FCA-55D9-4A33-93FC-5A3EB128DE21": "MiscSubclassDxe",
    "C30B94E3-C8F2-4AB0-91AB-FA8DF621B1C9": "MnpDxe",
    "61AFA223-8AC8-4440-9AB5-762B1BF05156": "Mtftp4Dxe",
    "61AFA251-8AC8-4440-9AB5-762B1BF05156": "Mtftp6Dxe",
    "31A0B6EF-A400-4419-8327-0FB134AA59E7": "Mxm30Dxe",
    "6707536E-46AF-42D3-8F6C-15F2F202C234": "MXMdat",
    "79AA6086-035A-4AD9-A89A-A6D5AA27F0E2": "NBPEI",
    "E4ECD0B2-E277-4F2B-BECB-E4D75C9A812E": "NBDXE",
    "D933DEDE-0260-4E76-A7D9-2F9F2440E5A5": "NBSMI",
    "0029DE6A-E024-4EB8-A91D-9F23AA1F4E92": "NetworkStackSetupScreen",
    "8A4E8240-74F8-4024-AE2B-B39221C9FA59": "NvOptimusSMM",
    "C8CA0BB8-67DA-4883-8CFC-9180CB9EEC68": "OemActivation",
    "57E56594-CE95-46AD-9531-3C49310CA7CE": "OFBD",
    "59AF16B0-661D-4865-A381-38DE68385D8D": "OpalSecurity",
    "DE23ACEE-CF55-4FB6-AA77-984AB53DE823": "PchInitDxe",
    "FD236AE7-0791-48C4-B29E-29BDEEE1A838": "PchInitPeim",
    "8C376010-2400-4D7D-B47B-9D851DF3C9D1": "PchMeUma",
    "ACAEAA7A-C039-4424-88DA-F42212EA0E55": "PchPcieSmm",
    "BB1FBD4F-2E30-4793-9BED-74F672BC8FFE": "PchReset",
    "FF259F16-18D1-4298-8DD2-BD87FF2894A9": "PchResetPeim",
    "271DD6F2-54CB-45E6-8585-8C923C1AC706": "PchS3Peim",
    "08F2C63B-08DE-4CCD-8670-ACFE644A1C48": "PchS3Support",
    "FC1B7640-3466-4C06-B1CC-1C935394B5C2": "PchSerialGpio",
    "643DF777-F312-42ED-81CC-1B1F57E18AD6": "PchSmbusArpDisabled",
    "22B194B4-CC0E-46C7-9FCE-DA10D6ED1731": "PchSmbusArpEnabled",
    "E052D8A6-224A-4C32-8D37-2E0AE162364D": "PchSmbusDxe",
    "59287178-59B2-49CA-BC63-532B12EA2C53": "PchSmbusSmm",
    "B0D6ED53-B844-43F5-BD2F-61095264E77E": "PchSmiDispatcher",
    "AA652CB9-2D52-4624-9FAE-D4E58B67CA46": "PchSpiPeim",
    "C194C6EA-B68C-4981-B64B-9BD271474B20": "PchSpiRuntime",
    "27F4917B-A707-4AAD-9676-26DF168CBF0D": "PchSpiSmm",
    "B716A6F8-F3A1-4B8E-8582-5A303F1CDD64": "PchSpiWrap",
    "6B4FDBD2-47E1-4A09-BA8E-8E041F208B95": "PchUsb",
    "3C1DE39F-D207-408A-AACC-731CFB7F1DD7": "PciBus",
    "80E66E0A-CCD1-43FA-A7B1-2D5EE0F13910": "PciRootBridge",
    "A89EC8E0-0BA1-40AA-A03E-ABDDA5295CDE": "PciExpressDxe",
    "8D6756B9-E55E-4D6A-A3A5-5E4D72DDF772": "PciHostBridge",
    "3022E512-B94A-4F12-806D-7EF1177899D8": "PciHotPlug",
    "FB142B99-DF57-46CB-BC69-0BF858A734F9": "PciSerial",
    "08EFD15D-EC55-4023-B648-7BA40DF7D05D": "PeiRamBoot",
    "DF8556F0-3A61-11DE-8A39-0800200C9A66": "PerfTunePei",
    "F16BDBF0-3A61-11DE-8A39-0800200C9A66": "PerfTuneDxe",
    "CB49CE50-3A75-11DE-8A39-0800200C9A66": "PerfTuneSmm",
    "1314216C-CB8D-421C-B854-06231386E642": "PlatformInfo",
    "9A9A912B-5F53-4586-8820-704485A29D21": "PlatformReset",
    "8C783970-F02A-4A4D-AF09-8797A51EEC8D": "PowerManagement",
    "2DF10014-CF21-4280-8C3F-E539B8EE5150": "PpmPolicyInitDxe",
    "E008B434-0E73-440C-8612-A143F6A07BCB": "Recovery",
    "70E1A818-0BE1-4449-BFD4-9EF68C7F02A8": "ReFlash",
    "67C53648-DA56-4726-AE21-FBA4D04686B3": "RsdpPlus",
    "CBC59C4A-383A-41EB-A8EE-4498AEA567E4": "Runtime",
    "EFD652CC-0E99-40F0-96C0-E08C089070FC": "S3Restore",
    "26A2481E-4424-46A2-9943-CC4039EAD8F8": "S3Save",
    "DE23ACEE-CF55-4FB6-AA77-984AB53DE811": "SaInitDxe",
    "FD236AE7-0791-48C4-B29E-29BDEEE1A811": "SaInitPeim",
    "2D1E361C-7B3F-4D15-8B1F-66E551FABDC7": "SaLateInitSmm",
    "BB65942B-521F-4EC3-BAF9-A92540CF60D2": "SataController",
    "91B4D9C1-141C-4824-8D02-3C298E36EB3F": "SataDriver",
    "C1FBD624-27EA-40D1-AA48-94C3DC5C7E0D": "SBPEI",
    "B7D19491-E55A-470D-8508-85A5DFA41974": "SBDXE",
    "E23F86E1-056E-4888-B685-CFCD67C179D4": "SBRun",
    "7B8DB049-C7C7-4D3B-809F-926DEE47CCA2": "SBSMI",
    "A0EF80E3-F9AB-4CBA-98FD-704620F4048D": "SecFlashUpdDxe",
    "83FA5AED-5171-4949-BDC9-0CBC9E123663": "FwCapsuleRecoveryPPI",
    "3BF4AF16-AB7C-4B43-898D-AB26AC5DDC6C": "SecSMIFlash",
    "A95C1D60-CB9F-4BD8-A030-3F1C4A185156": "SecureBootMod",
    "CC0F8A3F-3DEA-4376-9679-5426BA0A907E": "PkVar",
    "9FE7DE69-0AEA-470A-B50A-139813649189": "KekVar",
    "FBF95065-427F-47B3-8077-D13C60710998": "dbVar",
    "9D7A05E9-F740-44C3-858B-75586A8F9C8E": "dbxVar",
    "3FEEC852-F14C-4E7F-97FD-4C3A8C5BBECC": "FWkey",
    "9E625A27-4840-47CC-A6B5-1E9311CFC60E": "Pkpub",
    "899407D7-99FE-43D8-9A21-79EC328CAC21": "Setup",
    "7BB28B99-61BB-11D5-9A5D-0090273FC14D": "LogoBmp",
    "1FFF93C2-8C76-49E4-8AB3-43D92F5445EF": "LogoJpg",
    "6F0CF054-AE6A-418C-A7CE-3C7A7CD74EC0": "LogoPcx",
    "63B2BC2D-DF5D-419B-873C-2C78A6604A7A": "SgDxePolicyInit",
    "1E75E77F-8A15-4653-964D-542C157EF40A": "SgPeiPolicyInit",
    "0E2DAF63-8A4F-4026-A899-DE2D7F46E5EC": "SgTpvPei",
    "3FE57AC2-C675-46B1-8458-AC6206588424": "SgTpvDxe",
    "C18B8105-AB89-44DE-8D37-50B31FAE5D1E": "SgTpvAcpiS3Save",
    "6298FE18-D5EF-42B7-BB0C-2953283F5704": "SleepSmi",
    "90CB75DB-71FC-489D-AACF-943477EC7212": "SmartTimer",
    "B13EDD38-684C-41ED-A305-D7B7E32497DF": "SMBios",
    "2B341C7B-0B32-4A65-9D46-E1B3ABD4C25C": "Smbios131",
    "CEF68C66-06AB-4FB3-A3ED-5FFA885B5725": "SMBiosBoard",
    "E2A74738-8934-48F5-8412-99E948C8DC1B": "SmbiosDMIEdit",
    "AF382531-52E6-4CC4-B247-DB8E320CBBA3": "SmbiosDMIEditBoard",
    "FD44820B-F1AB-41C0-AE4E-0C55556EB9BD": "SMBiosFlashData",
    "DED7956D-7E20-4F20-91A1-190439B04D5B": "SmbiosGetFlashData",
    "DAF4BF89-CE71-4917-B522-C89D32FBC59F": "SMBiosStaticData",
    "B98999A4-E96F-475A-99FC-762126F50F5A": "SMBIOSUpdateData",
    "4B680E2D-0D63-4F62-B930-7AE995B9B3A3": "SmBusDxe",
    "9EA28D33-0175-4788-BEA8-6950516030A5": "SmBusPei",
    "BC327DBD-B982-4F55-9F79-056AD7E987C5": "SMIFlash",
    "1323C7F8-DAD5-4126-A54B-7A05FBF41515": "SmmAccess",
    "6ECFCE51-5724-450C-A38A-58553E954422": "SmmAccessPeim",
    "8B8214F9-4ADB-47DD-AC62-8313C537E9FA": "SmmBasePeim",
    "5552575A-7E00-4D61-A3A4-F7547351B49E": "SmmBaseRuntime",
    "753630C9-FAE5-47A9-BBBF-88D621CD7282": "SmmChildDispatcher",
    "E53734A3-E594-4C25-B1A2-081445650F7F": "SmmChildDispatcher2",
    "A0BAD9F7-AB78-491B-B583-C52B7F84B9E0": "SmmControl",
    "9CC55D7D-FBFF-431C-BC14-334EAEA6052B": "SmmDisp",
    "7FED72EE-0170-4814-9878-A8FB1864DFAF": "SmmRelocDxe",
    "ABB74F50-FD2D-4072-A321-CAFC72977EFA": "SmmRelocPeim",
    "8D3BE215-D6F6-4264-BEA6-28073FB13AEA": "SmmThunk",
    "3DD7A87B-D5BD-44AF-986F-2E13DB5D274C": "SnpDxe",
    "5479E09C-2E74-481B-89F8-B0172E388D1F": "StartWatchDog",
    "0D82A9EC-1289-4FD4-AC0B-4C6B1A25ABC6": "SwitchableGraphicsDxe",
    "7EDE6A1F-548E-453E-A95C-66939FE0295C": "SwitchableGraphicsPei",
    "5E9CABA3-F2B1-497A-ADAC-24F575E9CDE9": "TcgDxe",
    "2688B232-9C02-4C12-BE1F-857C0FF2AAE3": "TcgDxeplatform",
    "858EBE6F-360F-415B-B7DC-463AAEB03412": "TcgLegacy",
    "34989D8E-930A-4A95-AB04-2E6CFDFF6631": "TcgPei",
    "12345678-930A-4A95-AB04-2E6CFDFF6631": "TcgPeiAftermem",
    "6B844C5B-6B75-42CA-8E8E-1CB94412B59B": "TcgPeiplatform",
    "0FE9DA53-043D-4265-A94D-FD77FEDE2EB4": "TcgPlatformSetupPeiPolicy",
    "196CA3D8-9A5A-4735-B328-8FFC1D93D188": "TcgPlatformSetupPolicy",
    "FD93F9E1-3C73-46E0-B7B8-2BBA3F718F6C": "TCGSmm",
    "B1625D3C-9D2D-4E0D-B864-8A763EE4EC50": "TcpDxe",
    "C810485E-D0EC-4E98-AAB5-120C7E554428": "TdtAm",
    "DCAA4B60-408F-4BAD-99B9-B880D4EF0950": "TdtDxe",
    "CA5E3DF0-940A-48F1-8C14-DB2FB5998B36": "TdtWrapper",
    "7A08CB98-E9BC-41C3-BE19-B302F3F1F595": "Terminal",
    "FF917E22-A228-448D-BDAA-68EFCCDDA5D3": "TxtDxe",
    "67791E00-0C05-4AE7-A921-FC4057221653": "TxtOneTouchDxe",
    "CA9D8617-D652-403B-B6C5-BA47570116AD": "TxtPei",
    "6B789215-B063-45FD-868A-668A49F00EC6": "TXTWrapperPei",
    "87D402CD-8B07-4B93-B38B-F8799F28B033": "TXTWrapperDxe",
    "10EE5462-B207-4A4F-ABD8-CB522ECAA3A4": "Udp4Dxe",
    "10EE54AE-B207-4A4F-ABD8-CB522ECAA3A4": "Udp6Dxe",
    "0EF8A3B1-388A-4B62-8BE6-C7877D50AEDF": "UefiPxeBcDxe",
    "580DD900-385D-11D7-883A-00500473D4EB": "UHCD",
    "24CCD374-3DF6-4181-86F6-E3C66920A145": "UpdateMemoryRecord",
    "4C006CD9-19BA-4617-8483-609194A1ACFC": "USBINT13",
    "6895F6F0-8879-45B8-A9D9-9639E532319E": "UhciPeiUsb",
    "C463CEAC-FC57-4F36-88B7-356C750C3BCA": "UhcPeim",
    "52DAA304-DEB3-449B-AFB8-A88A54F28F95": "OhciPei",
    "45D68DB9-8B4E-48C0-99E9-F21F262DB653": "XhciPei",
    "D56A4094-570F-4D3D-8F5F-8D8AA0B396CB": "EhciPei",
    "8401A046-6F70-4505-8471-7015B40355E3": "UsbBotPeim",
    "04EAAAA1-29A1-11D7-8838-00500473D4EB": "USBRT",
    "CE366D33-B057-4C03-8561-CAF17738B66F": "WdtAppDxe",
    "0F69F6D7-0E4B-43A6-BFC2-6871694369B0": "WdtAppPei",
    "5AAB83E5-F027-4CA7-BFD0-16358CC9E453": "WdtDxe",
    "1D88C542-9DF7-424A-AA90-02B61F286938": "WdtPei",
    "A08276EC-A0FE-4E06-8670-385336C7D093": "x86Thunk",
    "DDCF3616-3275-4164-98B6-FE85707FFE7D": "FlashNvStorage",
    "F541796D-A62E-4954-A775-9584F61B9CDD": "TcgDxe.efi",
    "F7731B4C-58A2-4DF4-8980-5645D39ECE58": "PowerManagement.efi",
    "B09CB87C-67D8-412B-BB9D-9F4B214D720A": "VTd.efi",
    "11527125-78B2-4D3E-A0DF-41E75C221F5A": "CpuS3.efi",
    "21094ECB-9F20-4781-AE4B-50728B389A6E": "IchInit.efi",
    "EFFC8F05-B526-4EB5-B36B-8CD889923C0C": "LegacyRegion.efi",
    "88888888-8888-8888-8888-888888888888": "WholeFv.raw",
    "7A9354D9-0468-444A-81CE-0BF617D890DF": "FVMAIN",
    "8C8CE578-8A3D-4F1C-9935-896185C32DD3": "FVMAIN",
    "FFF12B8D-7696-4C8B-A985-2747075B4F50": "NVSTORAGE",
    "00504624-8A59-4EEB-BD0F-6B36E96128E0": "FPNVSTORAGE",
    "EDBEDF47-6EA3-4512-83C1-70F4769D4BDE": "Capsule_A.fvi",
    "4A538818-5AE0-4EB2-B2EB-488B23657022": "FvMainCompact",
    "FE5CEA76-4F72-49E8-986F-2CD899DFFE5D": "FaultTolerantWrite.dxe",
    "233C2592-1CEC-494A-A097-15DC96379777": "FwVol.dxe",
    "0E84FC69-29CC-4C6D-92AC-6D476921850F": "UpdateDriver.dxe",
    "283FA2EE-532C-484D-9383-9F93B36F0B7E": "UpdateData.raw",
    "98B8D59B-E8BA-48EE-98DD-C295392F1EDB": "ConfigData.RAW",
    "35B898CA-B6A9-49CE-8C72-904735CC49B7": "DxeMain.dxe",
    "4D37DA42-3A0C-4EDA-B9EB-BC0E1DB4713B": "PpisNeededByDxeCore.pei",
    "51C9F40C-5243-4473-B265-B3C8FFAFF9FA": "Crc32SectionExtract.dxe",
    "316C608A-4429-49FC-9E2C-0B814D5EE4F3": "PlatformPolicyManager.dxe",
    "1C6B2FAF-D8BD-44D1-A91E-7321B4C2F3D1": "ScriptSave.dxe",
    "2BDED685-F733-455F-A840-43A22B791FB3": "AcpiS3Save.dxe",
    "45424D0C-E6AF-4AF2-AD99-FA77168742D1": "SmartTimer.dxe",
    "A6F691AC-31C8-4444-854C-E2C1A6950F92": "Bds.dxe",
    "A46BA67D-B169-4E04-9AAC-1845CBDEE0AA": "AcpiMetronome.dxe",
    "4C862FC6-0E54-4E36-8C8F-FF6F3167951F": "FtwLite.dxe",
    "B601F8C4-43B7-4784-95B1-F4226CB40CEE": "Runtime.dxe",
    "AD608272-D07F-4964-801E-7BD3B7888652": "MonotonicCounter.dxe",
    "F099D67F-71AE-4C36-B2A3-DCEB0EB2B7D8": "WatchDogTimer.dxe",
    "F1EFB523-3D59-4888-BB71-EAA5A96628FA": "SecurityStub.dxe",
    "BAE7599F-3C6B-43B7-BDF0-9CE07AA91AA6": "CpuIo.dxe",
    "6F0198AA-1F1D-426D-AE3E-39AB633FCC28": "Cf9Reset.dxe",
    "378D7B65-8DA9-4773-B6E4-A47826A833E1": "PcRtc.dxe",
    "9F455D3B-2B8A-4C06-960B-A71B9714B9CD": "StatusCode.dxe",
    "CBD2E4D5-7068-4FF5-B462-9822B4AD8D60": "Variable.dxe",
    "AED6AA78-D5BF-4BC5-8CC5-F9EE47CF9299": "CapsuleRuntime.dxe",
    "A1F436EA-A127-4EF8-957C-8048606FF670": "Undi.dxe",
    "A2F436EA-A127-4EF8-957C-8048606FF670": "SNP.dxe",
    "A3F436EA-A127-4EF8-957C-8048606FF670": "BC.dxe",
    "A46C3330-BE36-4977-9D24-A7CF92EEF0FE": "PxeDhcp4.dxe",
    "C57AD6B7-0515-40A8-9D21-551652854E37": "Shell.app",
    "240612B5-A063-11D4-9A3A-0090273FC14D": "IsaBus.dxe",
    "0ABD8284-6DA3-4616-971A-83A5148067BA": "LegacyFloppy.dxe",
    "93B80003-9FB3-11D4-9A3A-0090273FC14D": "IsaSerial.dxe",
    "202A2B0E-9A31-4812-B291-8747DF152439": "Ps2Mouse.dxe",
    "69FD8E47-A161-4550-B01A-5594CEB2B2B2": "IdeBus.dxe",
    "C0734D12-7927-432B-986B-A7E3A35BA005": "LightPciBusPciBus.dxe",
    "B40612B9-A063-11D4-9A3A-0090273FC14D": "UsbBot.dxe",
    "A3527D16-E6CC-42F5-BADB-BF3DE177742B": "UsbCbi0.dxe",
    "B40612B2-A063-11D4-9A3A-0090273FC14D": "UsbCbi1.dxe",
    "2D2E62CF-9ECF-43B7-8219-94E7FC713DFE": "UsbKb.dxe",
    "A5C6D68B-E78A-4426-9278-A8F0D9EB4D8F": "UsbMassStorage.dxe",
    "2D2E62AA-9ECF-43B7-8219-94E7FC713DFE": "UsbMouse.dxe",
    "BDFE430E-8F2A-4DB0-9991-6F856594777E": "Ehci.dxe",
    "2FB92EFA-2EE0-4BAE-9EB6-7464125E1EF7": "Uhci.dxe",
    "240612B7-A063-11D4-9A3A-0090273FC14D": "UsbBus.dxe",
    "D4BECF5B-190D-46DB-92CC-3F5D74904DDA": "SmmAccess.dxe",
    "D00752EA-A49C-40AD-A6DA-921C030C4B2F": "DxeIchInit.dxe",
    "0325B5A1-0937-4A4F-B8AF-EC3F80EE6B35": "SataController.dxe",
    "966DFABF-A140-4BBA-83CA-12021090BB44": "DxeIchSmbusLight.dxe",
    "77148690-7E43-4673-AFAE-34532CDD4248": "SmmControl.dxe",
    "2383608E-C6D0-4E3E-858D-45DFAC3543D5": "PciHostBridge.dxe",
    "6388CB0C-CD3A-4D1E-B26C-4D823D8B4BDF": "PciExpress.dxe",
    "F3749E2C-5139-4E7A-B53A-4F5080B68B8F": "PciSerial.dxe",
    "F10CF621-1502-4130-A860-D300459E2C08": "MEbxInvoke.dxe",
    "08B97689-86AF-4A36-9E35-117B4D2EF26A": "Afsc.dxe",
    "BCCDE9D2-BABD-44F5-BB3F-D7B16174F64B": "Asf.dxe",
    "F78153D0-870D-4EEE-A684-741499C9A8CE": "Eist.dxe",
    "51CCF399-4FDF-4E55-A45B-E123F84D456A": "ConPlatform.dxe",
    "18435CD7-8003-4CED-AFA4-ECBC440C0F30": "FwBlockService.dxe",
    "316C618A-4429-493C-9E2C-0BA14D5EE4F3": "SstSpiChip.dxe",
    "945A0C97-4882-410A-9F30-E31C99398F7B": "DxeIchSpi.dxe",
    "D1150ED7-E582-4192-84A2-71B4EBA9A7C6": "AcpiPlatform.dxe",
    "E0ECBEC9-B193-4351-A488-36A655F22F9F": "SaveMemoryConfig.dxe",
    "7E374E25-8E01-4FEE-87F2-390C23C606CD": "PlatformAcpiTable.FFS",
    "E3932A34-5729-4F24-9FB1-D7409B456A15": "OemBadgingSupport.dxe",
    "EF0C99B6-B1D3-4025-9405-BF6A560FE0E0": "SmbiosMisc.dxe",
    "89F09528-C33A-47FB-BA19-FADE80A39F76": "DxePlatform.dxe",
    "EE0BFF80-2B33-4005-8EF1-3F9B23C25136": "GetCpuInfo.dxe",
    "056E7324-A718-465B-9A84-228F06642B4F": "PlatformFix.dxe",
    "506533A6-E626-4500-B14F-17939C0E5B60": "AcpiSupport.dxe",
    "408EDCEC-CF6D-477C-A5A8-B4844E3DE281": "ConSplitter.dxe",
    "CCCB0C28-4B24-11D5-9A5A-0090273FC14D": "GraphicsConsole.dxe",
    "9E863906-A40F-4875-977F-5B93FF237FC6": "Terminal.dxe",
    "53BCC14F-C24F-434C-B294-8ED2D4CC1860": "DataHub.dxe",
    "CA515306-00CE-4032-874E-11B755FF6866": "DataHubStdErr.dxe",
    "CA261A26-7718-4B9B-8A07-5178B1AE3A02": "DiskIo.dxe",
    "9B680FCE-AD6B-4F3A-B60B-F59899003443": "DevicePathDriver.dxe",
    "961578FE-B6B7-44C3-AF35-6BC705CD2B1F": "Fat.dxe",
    "43B93232-AFBE-11D4-BD0F-0080C73C8881": "Partition.dxe",
    "8F26EF0A-4F7F-4E4B-9802-8C22B700FFAC": "English.dxe",
    "7E0C6E3E-C80F-47D1-8ADA-554926B2B6B3": "GenericMemoryTest.dxe",
    "EF17CEE7-267D-4BFD-A257-4A6AB3EE8591": "MemorySubClass.dxe",
    "EAF59C0E-BD46-413A-9AE9-DD9F6D1A927D": "Smbios.dxe",
    "FCD337AB-B1D3-4EF8-957C-8048606FF670": "HiiDatabase.dxe",
    "EBF342FE-B1D3-4EF8-957C-8048606FF670": "SetupBrowser.dxe",
    "CE3DA938-6AD6-458A-8831-6B0A03DF6C86": "Pentium4Base.FFS",
    "C65A623F-2768-4700-BE2C-1D8BA2C43998": "Inside.FFS",
    "FCD6562A-253A-40D7-87DE-28CFF25898C6": "InsideHT.FFS",
    "0182244E-F95D-43FC-91EC-60594EF47599": "Lpc47m18x.dxe",
    "18EF8946-68F5-49E6-B202-CE90C3EEF1C9": "IchSmmDispatcher.dxe",
    "C2A743FE-9951-4299-9817-71DB147570D9": "SmmPlatform.dxe",
    "1EDC318F-4005-488D-AF3A-9BB5179BC6F1": "GmchMbi.dxe",
    "79CA4208-BBA1-4A9A-8456-E1E66A81484E": "Legacy8259.dxe",
    "0B2CFBF2-3E08-4C4E-A74D-59748A9F930F": "LegacyRegion.dxe",
    "D3709BB4-B194-4B71-B9C0-DBD8D2DA97AD": "IntelIchLegacyInterrupt.dxe",
    "1547B4F3-3E8A-4FEF-81C8-328ED647AB1A": "AwdLegacy16.FFS",
    "5479662B-6AE4-49E8-A6BD-6DE4B625811F": "BiosKeyboard.dxe",
    "F122A15C-C10B-4D54-8F48-60F4F06DD1AD": "LegacyBios.dxe",
    "F84CFFF4-511E-41C8-B829-519F5152F444": "LegacyBiosPlatform.dxe",
    "E2441B64-7EF4-41FE-B3A3-8CAA7F8D3017": "PciPlatform.dxe",
    "8DFAE5D4-B50E-4C10-96E6-F2C266CACBB6": "VideoRom.FFS",
    "52C05B14-0B98-496C-BC3B-04B50211D680": "PeiCore",
    "57F55732-CF55-43C7-B66B-216CE2282888": "MonoStatusCode.pei",
    "2B3685C5-CF90-4A67-8A48-9134BA32D677": "PlatformStage1.pei",
    "34C8C28F-B61C-45A2-8F2E-89E46BECC63B": "PeiVariable.pei",
    "921B35BF-0255-4722-BF5A-5B8B69093593": "IchInit.pei",
    "C779F6D8-7113-4AA1-9648-EB1633C7D53B": "Capsule.pei",
    "CB537AA2-F727-440B-9702-ADE9D0A293F1": "PlatformStage2.pei",
    "5242AADB-BDAB-4B92-B7D5-A58B6E0EEE6B": "IchSmbusArpDisabled.pei",
    "39C8FAEE-FBEE-41A3-9282-123F18C48CD9": "BroadwaterMemoryInit.pei",
    "86D70125-BAA3-4296-A62F-602BEBBB9081": "DxeIpl.pei",
    "B7A5041B-78BA-48E3-B63B-44C7578113B6": "FloppyPeim.pei",
    "B7A5041A-78BA-49E3-B73B-54C757811FB6": "AtapiPeim.pei",
    "1188F1FC-06E9-49B8-A615-F5A0886FCF89": "UhciInit.pei",
    "1E4EAAB1-E637-443E-A5D6-56E60D97C619": "UsbComboPeim.pei",
    "5B60CCFD-1011-4BCF-B7D1-BB99CA96A603": "PeiFatLite.pei",
    "8BCEDDD7-E285-4168-9B3F-09AF66C93FFE": "S3Resume.pei",
    "EF22F8A9-267E-4840-BC32-F0CFDFDFA426": "PeiSmmControl.pei",
    "9950A4C8-F315-4FCE-ADC8-E1BB61F1CCCB": "PeiHeci.pei",
    "C2998CC8-A0AA-46E6-A634-EE32BF113188": "AmtDriverPeim.pei",
    "52F934EE-7F15-4723-90CF-4E37127718A5": "TcgPei.pei",
    "882C5E65-D37B-441B-A1D9-6C89C5CC3AE1": "UsbDongle.pei",
    "A8CF6278-8758-458D-ADFB-3471F5AD50B1": "HdPwdPeim.pei",
    "DC38DF16-8280-49C1-B253-D7DBB301CF78": "UserCredentialPwd.dxe",
    "EF33C296-F64C-4146-AD04-347899702C84": "SmmUsbLegacy.dxe",
    "B3B88F4B-7042-488E-A255-66F965E8D435": "PasswordPopup.dxe",
    "ABAA46B8-84A3-4E74-882F-6368F6EDC9B8": "HddPwd.dxe",
    "A5288050-8828-46C4-8F72-1CD735A56520": "Slp20.dxe",
    "547C5CAE-2640-4ACF-9532-0E25B3F03F05": "Whea.dxe",
    "5112A2AA-E175-477E-A4E4-D0B7E689BA9F": "EventLog.dxe",
    "4F821C7C-8E33-412A-AE63-D149F376CD1B": "SmmWhea.dxe",
    "25F49067-A65B-48F5-BBBE-35418C488836": "TcgDxeMain.dxe",
    "21AF95E1-371F-4712-9C07-798E3CB019E4": "LockSMRAMEntry.dxe",
    "1CF40D19-EEAD-4C73-93DB-BBB8B6ACF929": "UserIdentification.dxe",
    "BD9320EB-7BB9-4AED-A682-CF4F96BE244C": "IntelMchFieldAcpiTables.ffs",
    "5FCEA791-516E-4B61-892C-7229D4FF23D4": "Int15ActiveLFP.FFS",
    "A3CD8EAC-B4E6-4B68-9641-0D3763799890": "Int15Backlight.FFS",
    "BCD9DF8C-BE89-4007-986F-FA401A4AF94E": "Int15PanelColor.FFS",
    "9E5628D5-ECD5-41A2-868B-99EB933A326E": "AhciRom.FFS",
    "9CBA9D12-A029-4366-AB1E-172B81914757": "OntarioGenericVBios.FFS",
    "3FA0BB4A-180B-4458-9F12-6EA68F69E6CC": "PxeRomB571699.FFS",
    "8D463051-692F-4924-9AEC-0A833B1BA49B": "PxeRomAr8132.FFS",
    "8A78B107-0FDD-4CC8-B7BA-DC3E13CB8524": "PeiCpuIo.PEI",
    "ED52984E-6ED7-4445-9D5D-200C3201F51E": "PlatformStage0.PEI",
    "5074C00E-698B-4763-91E6-41663F6CC7C9": "PBSPeiInit.PEI",
    "DE3E049C-A218-4891-8658-5FC06A84C783": "SBCbsPEIEntry.PEI",
    "A9759271-49CD-49BE-8764-5DEBFBE68F73": "AmdResetManager.PEI",
    "2894EC46-C67A-4256-87DE-34A741D85982": "Mct.PEI",
    "E92C4950-A483-445A-B6A8-B7029CA910AA": "PlatformStage1.PEI",
    "8803FA9A-0D33-4022-856B-AB5932A0F8BF": "AmdInitPostPeim.PEI",
    "7CC1567C-CCB8-4C50-80BA-D44A3B667415": "AmdSb800_PeiInterface.PEI",
    "3543EC9D-4B27-4FA9-ADBD-1DF118078FA7": "AmdSb800_Pei.PEI",
    "DE3E049C-A218-4891-8658-5FC0FA84C788": "AmdProcessorInitPeim.PEI",
    "821D8B77-246D-4E96-8E10-3467D56AB1BB": "SetupMain.FFS",
    "821D8B77-246D-4E96-8E10-3467D56AB1BA": "SetupAdvanced.FFS",
    "EF6619EE-F77D-4A8C-8693-D60D6AA56702": "SetupSecurity.FFS",
    "721C8B66-426C-4E86-8E99-3457C46AB0B9": "TextSetup.dxe",
    "348CA223-637B-4430-BAF3-1CE5D322B3FD": "SetupBoot.FFS",
    "687A830D-55FB-415A-9520-182789353284": "SetupExit.FFS",
    "A673005A-69F6-4597-8AF9-7AACA0039296": "Int15BootDisplay.ffs",
    "8D1AE715-7F82-449D-A26C-62AC650AF73F": "Int15PanelType.ffs",
    "E974833F-A4AE-4E39-BE37-8B6780DFAD01": "Int15PanelFitting.ffs",
    "E9F05D70-9946-4AB9-A7F7-070E92C415BD": "Int15BootTV.ffs",
    "D024BCD2-59EA-48AC-A17F-B3221EC23A11": "Int15GetMisc.ffs",
    "145372BC-66B9-476D-81BC-2127C376BB66": "FFS.pad",
    "15FE2940-B426-479A-A002-5454A34C7A6E": "FlashMapBin.FFS",
    "1B2C4952-D778-4B64-BDA1-15A36F5FA545": "Slp20PubKey",
    "127C1C4E-9135-46E3-B006-F9808B0559A5": "Slp20Markers",
    "7CE75114-8272-45AF-B536-761BD38852CE": "Slp21PubKey",
    "071A3DBE-CFF4-4B73-83F0-598C13DCFDD5": "Slp21Markers",
    "FD3F690E-B4B0-4D68-89DB-19A1A3318F90": "MICROCODE",
    "9EE4CD62-7FA7-4183-9012-F6C4CF6E2C7D": "NVBIOSINFO",
    "FACFB110-7BFD-4EFB-873E-88B6B23B97EA": "PhDefEfiVar",
    "C22E6B8A-8159-49A3-B353-E84B79DF19C0": "VARIABLE",
    "B6B5FAB9-75C4-4AAE-8314-7FFFA7156EAA": "VARBAK",
    "8CB71915-531F-4AF5-82BF-A09140817BAA": "FLASHMAPBIN",
    "B091E7D2-05A0-4198-94F0-74B7B8C55459": "UNUSED",
    "4B3828AE-0ACE-45B6-8CDB-DAFC28BBF8C5": "VAROEM",
    "46310243-7B03-4132-BE44-2243FACA7CDD": "CMDB",
    "E68DC11A-A5F4-4AC3-AA2E-29E298BFF645": "BCP",
    "919B9699-8DD0-4376-AA0B-0E54CCA47D8F": "FPVARIABLE",
    "58A90A52-929F-44F8-AC35-A7E1AB18AC91": "FPVARBAK",
    "2CB4F37A-0026-43AF-A948-D71976A96860": "CpuIo.dxe",
    "EE993080-5197-4D4E-B63C-F1F7413E33CE": "Cpu.dxe",
    "154CAB4A-52B5-46CD-99C3-4368ABBACFFD": "Metronome.dxe",
    "C3811036-710B-4E39-8CF1-0AF9BE3A8198": "Timer.dxe",
    "27F05AF5-1644-4EF4-8944-48C4F75675A0": "RealTimeClock.dxe",
    "BA929954-35B0-4DD3-90CD-9634BD7E1CF1": "Reset.dxe",
    "BDFE5FAA-2A35-44BB-B17A-8084D4E2B9E9": "FwBlockService.dxe",
    "96B5C032-DF4C-4B6E-8232-438DCF448D0E": "NullGenericMemoryTest.dxe",
    "93B80004-9FB3-11D4-9A3A-0090273FC14D": "PciBus.dxe",
    "FE3542FE-C1D3-4EF8-657C-8048606FF670": "DriverSample.dxe",
    "F479E147-A125-11D4-BCFC-0080C73C8881": "WinNtBlockIo.dxe",
    "263631D7-5836-4B74-BE48-EE22E92CE5D3": "WinNtConsole.dxe",
    "6B41B553-A649-11D4-BD02-0080C73C8881": "WinNtSerialIo.dxe",
    "9C25E18B-76BA-43DA-A132-DBB0997CEFEF": "WinNtSimpleFileSystem.dxe",
    "0C95A940-A006-11D4-BCFA-0080C73C8881": "WinNtBusDriver.dxe",
    "0C95A916-A006-11D4-BCFA-0080C73C8881": "WinNtThunk.dxe",
    "AB248E8D-ABE1-11D4-BD0D-0080C73C8881": "WinNtUga.dxe",
    "4A9B9DB8-EC62-4A92-818F-8AA0246D246E": "MiscSubclass.dxe",
    "9FB4B4A7-42C0-4BCD-8540-9BCC6711F83E": "UsbMassStorage.dxe",
    "221521AE-0A35-44CD-B580-5AEDBB770B1D": "glyphs.FFS",
    "ED2DE537-7823-4CB1-B687-85BA9BBEF0B4": "RaidRom.ffs",
    "166C533A-8F1E-4D34-A60E-0F68D8D61308": "OemKey.raw",
    "B7BC0E96-57D2-4310-AEEF-74AC77DF0DAF": "SetupXpBoot",
    "17772369-D262-4B90-9F31-BDC41F2663A5": "LegacyMebxMain.ffs",
    "7C81C66A-4F11-47AB-82D3-67C4D635AED1": "LegacyMebxLaunch.ffs",
    "B579B530-C797-4839-883E-EFCABD7756E9": "VerbTable.RAW",
    "2928D39C-917D-4F2F-9510-16AB73F204B2": "BiosAcm_Field.RAW",
    "FD36FEE3-7B33-4C9E-836E-9AA26A9E3149": "BiosAcm_Dale.RAW",
    "29206FC2-9EAB-4612-ACA1-1E3D098FB1B3": "LegacyVideoRom.ffs",
    "CA49B5C8-E977-4612-8706-91B82CD14C87": "IntelMchAcpiTables.ffs",
    "161BE597-E9C5-49DB-AE50-C462AB54EEDA": "PowerManagementAcpiTables2.ffs",
    "F65354B9-1FF0-46D7-A5F7-0926CB238048": "MonoStatusCode.pei",
    "66DE8584-DE01-4BAB-B5D0-8B99594372FC": "IchUhci.pei",
    "078F54D4-CC22-4048-9E94-879C214D562F": "Pad",
    "B017C09D-EDC1-4940-B13E-57E95660C90F": "AhciRom.ffs",
    "6048B8EC-6D17-45C0-9BCF-63D164B41AB3": "LanRom.ffs",
    "63017E66-D790-4EE6-A0AC-6192AA74ACF7": "UCR.ffs",
    "0E00B084-2D16-4A27-B172-B1F68C2CC55D": "MicrocodeUpdates.raw",
    "BA102EAD-5308-4F9B-9E22-C1CE4DC44F49": "RSAKey.raw",
    "8EB48F19-CC92-4031-8D3D-EE473CCC87EB": "SystemPrivateKey.RAW",
    "C8F23B39-C95C-4318-9233-53FB3AC44592": "VariableVsr.RAW",
    "0DCF3594-318C-4596-B00F-BE61842DE3E2": "SystemBootTypePei.PEI",
    "E6F4F8F7-4992-47B2-8302-8508745E4A23": "OemPir.bin",
    "FE612B72-203C-47B1-8560-A66D946EB371": "setupdata.bin",
    "2EBE0275-6458-4AF9-91ED-D3F4EDB100AA": "sgn.bin",
    ";2EBE0275-6458-4AF9-91ED-D3F4EDB100AA": "Fid.bin",
    "88A15A4F-977D-4682-B17C-DA1F316C1F32": "RomLayout.bin",
    "9BA21891-7E7D-4E94-B8DF-F4D2D320801C": "ROMss.bin",
    "16B45DA2-7D70-4AEA-A58D-760E9ECB841D": "FD_Drv_X86",
    "E360BDBA-C3CE-46BE-8F37-B231E5CB9F35": "FD_Drv_X64",
}
