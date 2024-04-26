
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

/*
LPVOID VirtualAllocEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
*/
var pVirtualAllocEx = Module.findExportByName(null, "VirtualAllocEx");
Interceptor.attach(pVirtualAllocEx, {
	onEnter: function(args) {
		send({
			'VirtualAllocEx' : args[0].toInt32()
		});
	}
});

function CreateProcess(unicode) {
	var pCreateProcess = unicode ? Module.findExportByName(null, 'CreateProcessW') : Module.findExportByName(null, 'CreateProcessA');
	Interceptor.attach(pCreateProcess, {
		onEnter: function(args) {
			this.lpApplicationName = unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			this.lpCommandLine = unicode ? args[1].readUtf16String() : args[1].readUtf8String();

			send({
				'CreateProcess' : {
					'lpApplicationName': this.lpApplicationName,
					'lpCommandLine': this.lpCommandLine
				}
			})
		}
	})
}

CreateProcess(0);
CreateProcess(1);
