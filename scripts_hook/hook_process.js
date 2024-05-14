
/*
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
*/
function OpenProcess() {
	var pOpenProcess = Module.findExportByName('kernel32.dll', "OpenProcess");
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
}

OpenProcess()

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
	var pCreateProcess = unicode ? Module.findExportByName('kernel32.dll', 'CreateProcessW') : Module.findExportByName('kernel32.dll', 'CreateProcessA')
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

/**
HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess,
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  [in]  SIZE_T                 dwStackSize,
  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
  [in]  LPVOID                 lpParameter,
  [in]  DWORD                  dwCreationFlags,
  [out] LPDWORD                lpThreadId
);
 */

/**
HANDLE CreateRemoteThreadEx(
  [in]            HANDLE                       hProcess,
  [in, optional]  LPSECURITY_ATTRIBUTES        lpThreadAttributes,
  [in]            SIZE_T                       dwStackSize,
  [in]            LPTHREAD_START_ROUTINE       lpStartAddress,
  [in, optional]  LPVOID                       lpParameter,
  [in]            DWORD                        dwCreationFlags,
  [in, optional]  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  [out, optional] LPDWORD                      lpThreadId
);
 */

function CreateRemoteThread() {
	var pCreateRemoteThread = Module.findExportByName(null, 'CreateRemoteThread');
	Interceptor.replace(pCreateRemoteThread, new NativeCallback((hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) => {
		send({
			'CreateRemoteThread' : {
				'hProcess': hProcess.toInt32()
			}
		});
		return ptr(1);
	}, 'pointer', ['pointer', 'pointer', 'size_t', 'pointer', 'pointer', 'int', 'pointer']));
}

function CreateRemoteThreadEx() {
	var pCreateRemoteThreadEx = Module.findExportByName(null, 'CreateRemoteThreadEx');
	
	Interceptor.replace(pCreateRemoteThreadEx, new NativeCallback((hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId) => {
		send({
			'CreateRemoteThreadEx' : {
				'hProcess': hProcess.toInt32()
			}
		});
		return ptr(1);
	}, 'pointer', ['pointer', 'pointer', 'size_t', 'pointer', 'pointer', 'int', 'pointer', 'pointer']));
}

CreateRemoteThread();
// CreateRemoteThreadEx();