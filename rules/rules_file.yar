import "pe"	
rule is_pe32 
{
	meta: 
		description = "Executable File 32 bits" 
	condition:
		uint16(0) == 0x5A4D and	uint16(uint32(0x3C) + 0x18) == 0x010B 
} 

rule is_pe64 
{
	meta: 
		description = "Executable File 64 bits" 
	condition:
		uint16(0) == 0x5A4D and	uint16(uint32(0x3C)+0x18) == 0x020B0 
} 

rule is_pe_dll 
{
	meta: 
		description = "DLL File" 
	condition:
		uint16(0) == 0x5A4D and	(uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000 
}

rule is_net_exe 
{
	meta: 
		description = "DotNet Executable File"
	condition:
		pe.imports ("mscoree.dll","_CorExeMain") 
} 

rule is_net_dll	
{
	meta: 
		description = "DotNet DLL File" 
	condition:
		pe.imports ("mscoree.dll","_CorDllMain") 
}

rule is_lzip 
{
	meta: 
		description = "LZip compressed file" 
	strings: 
		$header = {4C 5A 49 50} 
	condition: 
		$header at 0
}

rule is_zip 
{
	meta: 
		description = "Zip compressed file" 
	strings: 
		$header = { 50 4B ( 03 04 | 05 06 | 07 08) } 
	condition: 
		$header at 0
}

rule is_rar 
{
	meta: 
		description = "RAR file" 
	strings: 
		$header = { 52 61 72 21 1A 07 ( 00 | 01 00) } 
	condition: 
		$header at 0
}

rule is_tar 
{
	meta: 
		description = "TAR archive" 
	strings: 
		$header = { 75 73 74 61 72 ( 00 30 30 | 20 20 00) } 
	condition: 
		$header at 0
}

rule is_zlib 
{
	meta: 
		description = "ZLIB Compression " 
	strings: 
		$header = { 78 ( 01 | 5E | 9C | DA | 20 | 7D | BB | F9 ) } 
	condition: 
		$header at 0
}

rule is_pdf 
{
	meta: 
		description = "PDF document" 
	strings: 
		$header = { 25 50 44 46 2D } 
	condition: 
		$header at 0
}
