
/*
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
*/
var pOpenProcess = Module.findExportByName(null, "OpenProcess");
Interceptor.attach(pOpenProcess, {
	onEnter: function(args) {
		this.pid = args[2].toInt32();
	},
	onLeave: function(retval) {
		send({
			'OpenProcess': retval.toInt32(),
			'PID': this.pid
		});
	}
});

/**
BOOL CreateProcessA(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);
 */

function CreateProcess(unicode) {
	var pCreateProcess = unicode ? Module.findExportByName(null, 'CreateProcessW') : Module.findExportByName(null, 'CreateProcessA');
	// Interceptor.attach(pCreateProcess, {
	// 	onEnter: function(args) {
	// 		this.lpApplicationName = unicode ? args[0].readUtf16String() : args[0].readUtf8String();
	// 		this.lpCommandLine = unicode ? args[1].readUtf16String() : args[1].readUtf8String();

	// 		send({
	// 			'CreateProcess' : {
	// 				'lpApplicationName': this.lpApplicationName,
	// 				'lpCommandLine': this.lpCommandLine
	// 			}
	// 		})
	// 	}
	// })
	Interceptor.replace(pCreateProcess, new NativeCallback((lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) => {
		var ApplicationName = unicode ? lpApplicationName.readUtf16String() : lpApplicationName.readUtf8String();
		var CommandLine = unicode ? lpCommandLine.readUtf16String() : lpCommandLine.readUtf8String();
		send({
			'CreateProcess' : {
				'lpApplicationName': ApplicationName,
				'lpCommandLine': CommandLine
			}
		});
		return 1;
	}, 'bool', ['pointer', 'pointer', 'pointer', 'pointer', 'bool', 'int', 'pointer', 'pointer', 'pointer', 'pointer']))
}

CreateProcess(0);
CreateProcess(1);