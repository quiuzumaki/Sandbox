import "pe"	
rule is_pe32 
{
	meta: 
		description = "Executable File 32 bits" 
	strings:
        $pe_signature = { 4D 5A } 
    condition:
		$pe_signature and
        uint16(@pe_signature + uint32(@pe_signature + 0x3C) + 0x18) == 0x010B
}

rule is_pe64 
{
	meta: 
		description = "Executable File 64 bits" 
	strings:
		$pe_signature = { 4D 5A } 
	condition:
		$pe_signature and
		uint16(@pe_signature + uint32(@pe_signature + 0x3C) + 0x18) == 0x020B0 
} 

rule is_pe_dll 
{
	meta: 
		description = "DLL File" 
	strings:
		$pe_signature = { 4D 5A } 
	condition:
		$pe_signature and
		(uint16(@pe_signature + uint32(@pe_signature + 0x3C) + 0x16) & 0x2000) == 0x2000 
}

rule is_net_exe 
{
	meta: 
		description = "DotNet Executable File"
	strings:
		$pe_signature = { 4D 5A } 
	condition:
		$pe_signature and
		pe.imports ("mscoree.dll","_CorExeMain") 
} 

rule is_net_dll	
{
	meta: 
		description = "DotNet DLL File" 
	strings:
		$pe_signature = { 4D 5A } 
	condition:
		$pe_signature and
		pe.imports ("mscoree.dll","_CorDllMain") 
}

rule is_lzip 
{
	meta: 
		description = "LZip compressed file" 
	strings: 
		$header = {4C 5A 49 50} 
	condition: 
		$header
}

rule is_zip 
{
	meta: 
		description = "Zip compressed file" 
	strings: 
		$header = { 50 4B ( 03 04 | 05 06 | 07 08) } 
	condition: 
		$header
}

rule is_rar 
{
	meta: 
		description = "RAR file" 
	strings: 
		$header = { 52 61 72 21 1A 07 ( 00 | 01 00) } 
	condition: 
		$header
}

rule is_tar 
{
	meta: 
		description = "TAR archive" 
	strings: 
		$header = { 75 73 74 61 72 ( 00 30 30 | 20 20 00) } 
	condition: 
		$header
}

rule is_pdf 
{
	meta: 
		description = "PDF document" 
	strings: 
		$header = { 25 50 44 46 2D } 
	condition: 
		$header
}

rule is_powershell
{
	meta:
		description = "Powershell Malware"
	strings:
        $ps1_cmd1 = "powershell.exe -nop -w hidden -c" nocase
        $ps1_cmd2 = "powershell -nop -w hidden -c" nocase
        $ps1_cmd3 = "Start-Process" nocase
        $ps1_cmd4 = "Invoke-Expression" nocase
        $ps1_cmd5 = "New-Object System.Net.WebClient" nocase
        $ps1_cmd6 = "DownloadString" nocase
        $ps1_cmd7 = "iex" nocase
        $ps1_cmd8 = "Reflection.Assembly" nocase
        $ps1_cmd9 = "System.Management.Automation" nocase
		$ps1_cmd10 = "powershell.exe -ep bypass" nocase
        $ps1_cmd11 = "powershell -ep bypass" nocase
    condition:
        any of them
}