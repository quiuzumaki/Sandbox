/*
void InternetOpenUrlW(
  HINTERNET hInternet,
  LPCWSTR   lpszUrl,
  LPCWSTR   lpszHeaders,
  DWORD     dwHeadersLength,
  DWORD     dwFlags,
  DWORD_PTR dwContext
);
*/
function InternetOpenUrl(opts) {
	var pInternetOpenUrl = opts.unicode ? Module.findExportByName("wininet.dll", "InternetOpenUrlW")
                                        : Module.findExportByName("wininet.dll", "InternetOpenUrlA");
	if(null == pInternetOpenUrl)
		return 0;

	Interceptor.attach(pInternetOpenUrl, {
		onEnter: function(args) {
			var url = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			send({
				'InternetOpenUrl': url
			});
		}
	});
	return 1;
}

/*
INT WSAAPI GetAddrInfoW(
  PCWSTR          pNodeName,
  PCWSTR          pServiceName,
  const ADDRINFOW *pHints,
  PADDRINFOW      *ppResult
);
INT WSAAPI GetAddrInfoExW(
  PCWSTR                             pName,
  PCWSTR                             pServiceName,
  DWORD                              dwNameSpace,
  LPGUID                             lpNspId,
  const ADDRINFOEXW                  *hints,
  PADDRINFOEXW                       *ppResult,
  timeval                            *timeout,
  LPOVERLAPPED                       lpOverlapped,
  LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
  LPHANDLE                           lpHandle
);
*/

function GetAddrInfo(opts) {
	if(opts.ex) {
		var pGetAddrInfo = opts.unicode ? Module.findExportByName("ws2_32.dll", "GetAddrInfoExW")
                                        : Module.findExportByName("ws2_32.dll", "GetAddrInfoExA");
    } else {
		var pGetAddrInfo = opts.unicode ? Module.findExportByName("ws2_32.dll", "GetAddrInfoW")
                                        : Module.findExportByName("ws2_32.dll", "getaddrinfo");
    }

	if(null == pGetAddrInfo)
		return 0;

	Interceptor.attach(pGetAddrInfo, {
		onEnter: function(args) {
			var domain = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			send({
				'GetAddrInfo': domain
			});
		}
	});
	return 1;
}

// WINHTTPAPI HINTERNET WinHttpOpen(
//     [in, optional] LPCWSTR pszAgentW,
//     [in]           DWORD   dwAccessType,
//     [in]           LPCWSTR pszProxyW,
//     [in]           LPCWSTR pszProxyBypassW,
//     [in]           DWORD   dwFlags
//   );

function WinHttp() {
    var pWinHttpOpen = Module.findExportByName("winhttp.dll", "WinHttpOpen");
    var pWinHttpCreateUrl = Module.findExportByName("winhttp.dll", "WinHttpCreateUrl");
    Interceptor.attach(pWinHttpOpen, {
        onEnter: function(args) {
            var agent = args[0].readUtf16String();
            send({
                'WinHttpOpen' : agent
            })
        }
    });
    Interceptor.attach(pWinHttpCreateUrl, {
        onEnter: function(args) {
            var agent = args[2].readUtf16String();
            send({
                'WinHttpCreateUrl' : agent
            })
        }
    });
}


var InternetOpenUrl_ed = 0;
var GetAddrInfo_ed = 0;

/*
HMODULE LoadLibraryW(
  LPCWSTR lpLibFileName
);
*/
function LoadLibrary(opts) {
	var pLoadLibrary = opts.unicode ? Module.findExportByName(null, "LoadLibraryW")
	                                : Module.findExportByName(null, "LoadLibraryA")
	Interceptor.attach(pLoadLibrary, {
		onEnter: function(args) {
			this.wininet = 0;
			this.ws2_32  = 0;
			this.winhttp = 0
			var libName = (opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String()).toLowerCase();
			if(libName.startsWith("wininet"))
				this.wininet = 1;
			else if(libName.startsWith("ws2_32"))
				this.ws2_32 = 1;
			else if (libName.startsWith('winhttp')) {
				this.winhttp = 1
			}
		},
		onLeave: function(retval) {
			if(this.wininet == 1 && !InternetOpenUrl_ed) {
				InternetOpenUrl({unicode: 0});
				InternetOpenUrl({unicode: 1});
			} else if(this.ws2_32 == 1 && !GetAddrInfo_ed) {
				GetAddrInfo({unicode: 0, ex: 0});
				GetAddrInfo({unicode: 1, ex: 0});
				GetAddrInfo({unicode: 0, ex: 1});
				GetAddrInfo({unicode: 1, ex: 1});
			} else if (this.winhttp == 1) {
				WinHttp()
			}
		}
	});
}

InternetOpenUrl_ed = (InternetOpenUrl({unicode: 0}) && InternetOpenUrl({unicode: 1}));

GetAddrInfo_ed = (GetAddrInfo({unicode: 0, ex: 0}) && 
                    GetAddrInfo({unicode: 1, ex: 0}) && 
                    GetAddrInfo({unicode: 0, ex: 1}) && 
                    GetAddrInfo({unicode: 1, ex: 1}));

if(!InternetOpenUrl_ed || !GetAddrInfo_ed) {       // (wininet.dll | ws2_32.dll) not imported yet
	LoadLibrary({unicode: 0});
	LoadLibrary({unicode: 1});
}

