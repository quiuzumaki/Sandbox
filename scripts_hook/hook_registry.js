
const REG_KEYS = {
	0x80000000: "HKEY_CLASSES_ROOT",
	0x80000001: "HKEY_CURRENT_USER",
	0x80000002: "HKEY_LOCAL_MACHINE",
	0x80000003: "HKEY_USERS",
	0x80000004: "HKEY_PERFORMANCE_DATA",
	0x80000005: "HKEY_CURRENT_CONFIG",
	0x80000006: "HKEY_DYN_DATA",
	0x80000050: "HKEY_PERFORMANCE_TEXT",
	0x80000060: "HKEY_PERFORMANCE_NLSTEXT"
}

const REG_DISPOSITION = { 
    'REG_CREATED_NEW_KEY': 0x00000001,
    'REG_OPENED_EXISTING_KEY': 0x00000002
}

/*
LSTATUS RegCreateKeyW(
  HKEY    hKey,
  LPCWSTR lpSubKey,
  PHKEY   phkResult
);
*/

function RegCreateKey(unicode) {
	var pRegCreateKey = unicode ? Module.findExportByName(null, "RegCreateKeyW") : Module.findExportByName(null, "RegCreateKeyA");    	
	Interceptor.attach(pRegCreateKey, {
		onEnter: function(args) {
			this.keyname = unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			this.hKey = REG_KEYS[args[0].toInt32()>>>0];
			this.keyname = ((this.hKey != undefined) ? this.hKey : '') + "\\" + this.keyname;
			this.handle = args[2];
		},
		onLeave: function(retval) {
			send({
				'RegCreateKey': this.keyname,
				'Handle': this.handle.readPointer().toInt32(),
				'hKey': this.hKey
			});
		}
	});
}

RegCreateKey(0);
RegCreateKey(1);

/*
LSTATUS RegCreateKeyExW(
	HKEY                        hKey,
	LPCWSTR                     lpSubKey,
	DWORD                       Reserved,
	LPWSTR                      lpClass,  // None
	DWORD                       dwOptions,
	REGSAM                      samDesired,
	const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	PHKEY                       phkResult,
	LPDWORD                     lpdwDisposition
);
*/

function RegCreateKeyEx(unicode) {
    var pRegCreateKeyEx = unicode ? Module.findExportByName(null, "RegCreateKeyExW") : Module.findExportByName(null, "RegCreateKeyExA");    	
	Interceptor.attach(pRegCreateKeyEx, {
		onEnter: function(args) {
			this.keyname = unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			this.hKey = parseInt(args[0].toInt32());
			this.keyname = "\\" + this.keyname;
            this.handle = args[7];
            this.disposition = args[8];
		},
		onLeave: function(retval) {
            if (REG_DISPOSITION['REG_CREATED_NEW_KEY'] == this.disposition.readPointer().toInt32()) {
                send({
                    'RegCreateKey': this.keyname,
                    'Handle': this.handle.readPointer().toInt32(),
					'hKey' : this.hKey
                });
            } else {
                send({
                    'RegOpenKey': this.keyname,
                    'Handle': this.handle.readPointer().toInt32(),
					'hKey': this.hKey
                });
            }
			
		}
	});
}

RegCreateKeyEx(0);
RegCreateKeyEx(1);

/*
LSTATUS RegOpenKeyW(
  HKEY    hKey,
  LPCWSTR lpSubKey,
  PHKEY   phkResult
);
*/

function RegOpenKey(unicode) {
	var pRegOpenKey = unicode ? Module.findExportByName(null, "RegOpenKeyW") : Module.findExportByName(null, "RegOpenKeyA");    	
	Interceptor.attach(pRegOpenKey, {
		onEnter: function(args) {
			this.keyname = unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			this.hKey = REG_KEYS[args[0].toInt32()>>>0];

			this.keyname = ((this.hKey != undefined) ? this.hKey : '') + "\\" + this.keyname;

			this.handle = args[2];
		},
		onLeave: function(retval) {
			send({
				'RegOpenKey': this.keyname,
				'Handle': this.handle.readPointer().toInt32(),
				'hKey': this.hKey
			});
		}
	});
}

RegOpenKey(0);
RegOpenKey(1);

/*
LSTATUS RegOpenKeyExW(
	HKEY    hKey,
	LPCWSTR lpSubKey,
	DWORD   ulOptions,
	REGSAM  samDesired,
	PHKEY   phkResult
);
*/

function RegOpenKeyEx(unicode) {
	var pRegOpenKeyEx = unicode ? Module.findExportByName(null, "RegOpenKeyExW") : Module.findExportByName(null, "RegOpenKeyExA");    	
	Interceptor.attach(pRegOpenKeyEx, {
		onEnter: function(args) {
			this.keyname = unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			this.hKey = REG_KEYS[args[0].toInt32()>>>0];

			this.keyname = ((this.hKey != undefined) ? this.hKey : '') + "\\" + this.keyname;
			this.handle = args[4];
		},
		onLeave: function(retval) {
			send({
				'RegOpenKey': this.keyname,
				'Handle': this.handle.readPointer().toInt32(),
				'hKey': this.hKey
			});
		}
	});
}

RegOpenKeyEx(0);
RegOpenKeyEx(1);

/*
LSTATUS RegQueryValueExW(
	HKEY    hKey,
	LPCWSTR lpValueName,
	LPDWORD lpReserved,
	LPDWORD lpType,
	LPBYTE  lpData,
	LPDWORD lpcbData
);
*/

function RegQueryValueEx(unicode) {
	var pRegQueryValueEx = unicode ? Module.findExportByName(null, "RegQueryValueExW")
                                        : Module.findExportByName(null, "RegQueryValueExA");
	Interceptor.attach(pRegQueryValueEx, {
		onEnter: function(args) {
			var regvalue = unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var handle = args[0].toInt32();
			send({
				'RegQueryValueEx': regvalue,
				'Handle': handle
			});
		}
	});
}

RegQueryValueEx(0);
RegQueryValueEx(1);

/*
LSTATUS RegSetValueA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    DWORD  dwType,
    LPCSTR lpData,
    DWORD  cbData
);
*/

function RegSetValue(unicode) {
	var pRegSetValue = unicode ? Module.findExportByName(null, "RegSetValueW")
                                      : Module.findExportByName(null, "RegSetValueA");
	Interceptor.attach(pRegSetValue, {
		onEnter: function(args) {
			this.subkey = unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			this.handle = args[0].toInt32();
            var hKey = REG_KEYS[args[0].toInt32()];
			
            if(hKey != undefined)
				this.keyname = hKey + "\\" + this.subkey;
			else
				this.keyname = "\\" + this.subkey;
            
            send({
				'RegSetValue': this.keyname,
				'Handle': this.handle
			}, args[3].readByteArray(args[4].toInt32()));

			var result;
			recv('scan_result', value => {
				result = Boolean(value.result);
			}).wait();
			
			// if (result) {
				args[3] = Memory.alloc(1);
				args[4] = ptr(0);
			// }
		}
	});
}

RegSetValue(0);
RegSetValue(1);

/*
LSTATUS RegSetValueExW(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE *lpData,
    DWORD      cbData
);
*/

function RegSetValueEx(unicode) {
	var pRegSetValueEx = unicode ? Module.findExportByName(null, "RegSetValueExW")
                                      : Module.findExportByName(null, "RegSetValueExA");
	Interceptor.attach(pRegSetValueEx, {
		onEnter: function(args) {
			this.valuename = unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			this.handle = args[0].toInt32();
            // var hKey = REG_KEYS[args[0].toInt32()];
			
            // if(hKey != undefined)
			// 	this.keyname = hKey + "\\" + this.valuename;
			// else
			// 	this.keyname = "\\" + this.valuename;
            
            send({
				'RegSetValueEx': this.valuename,
				'Handle': this.handle
			}, args[4].readByteArray(args[5].toInt32()));

			var result = false;
			recv('scan_result', value => {
				result = Boolean(value.result);
			}).wait();
			
			// if (result) {
				args[4] = Memory.alloc(1);
				args[5] = ptr(0);
			// }
		}
	});
}

RegSetValueEx(0);
RegSetValueEx(1);

/*
LSTATUS RegDeleteKeyW(
    HKEY    hKey,
    LPCWSTR lpSubKey
);
*/

function RegDeleteKey(unicode) {
	var pRegDeleteKey = unicode ? Module.findExportByName(null, "RegDeleteKeyW") : Module.findExportByName(null, "RegDeleteKeyA");
	Interceptor.replace(pRegDeleteKey, new NativeCallback( (hKey, lpSubKey) => {

        var subkey = unicode ? lpSubKey.readUtf16String() : lpSubKey.readUtf8String();
        send({  
            'RegDeleteKey': subkey,
            'Handle': parseInt(hKey)
        })
        return 1;

    }, 'int', ['int', 'pointer']));
}

RegDeleteKey(0);
RegDeleteKey(1);

/*
LSTATUS RegDeleteKeyExA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    REGSAM samDesired,
    DWORD  Reserved
)
*/

function RegDeleteKeyEx(unicode) {
	var RegDeleteKeyEx = unicode ? Module.findExportByName(null, "RegDeleteKeyExW")
                                       : Module.findExportByName(null, "RegDeleteKeyExA");
	Interceptor.replace(RegDeleteKeyEx, new NativeCallback( (hKey, lpSubKey, samDesired, Reserved) => {

        var subkey = unicode ? lpSubKey.readUtf16String() : lpSubKey.readUtf8String();
        send({  
            'RegDeleteKey': subkey,
            'Handle': parseInt(hKey)
        })
        return 1;

    }, 'int', ['int', 'pointer', 'pointer', 'int']));
}

RegDeleteKeyEx(0);
RegDeleteKeyEx(1);

/*
LSTATUS RegDeleteValueW(
  HKEY    hKey,
  LPCWSTR lpValueName
);
*/

function RegDeleteValue(unicode) {
	var pRegDeleteValue = unicode ? Module.findExportByName(null, "RegDeleteValueW")
                                       : Module.findExportByName(null, "RegDeleteValueA");
	Interceptor.replace(pRegDeleteValue, new NativeCallback( (hKey, lpValueName) => {

        var valuename = unicode ? lpValueName.readUtf16String() : lpValueName.readUtf8String();
        send({  
            'RegDeleteValue': valuename,
            'Handle': parseInt(hKey)
        });
        return 1;

    }, 'int', ['int', 'pointer']));
}

RegDeleteValue(0);
RegDeleteValue(1);

/*
LSTATUS RegDeleteKeyValueA(
    HKEY   hKey,
    LPCSTR lpSubKey,
    LPCSTR lpValueName
)
*/

function RegDeleteKeyValue(unicode) {
	var RegDeleteKeyValue = unicode ? Module.findExportByName(null, "RegDeleteKeyValueW")
                                       : Module.findExportByName(null, "RegDeleteKeyValueA");
	Interceptor.replace(RegDeleteKeyValue, new NativeCallback((hKey, lpSubKey, lpValueName) => {
        var subkey = unicode ? lpSubKey.readUtf16String() : lpSubKey.readUtf8String();
        var valuename = unicode ? lpValueName.readUtf16String() : lpValueName.readUtf8String();
        send({  
            'RegDeleteKeyValue': valuename,
            'SubKey': subkey,
            'ValueName': valuename,
            'Handle': parseInt(hKey)
        })
        return 1;

    }, 'int', ['int', 'pointer', 'pointer']));
}

RegDeleteKeyValue(0);
RegDeleteKeyValue(1);