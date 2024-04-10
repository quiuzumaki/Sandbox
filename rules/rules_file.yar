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