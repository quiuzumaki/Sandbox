
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
function InternetOpenUrl(unicode) {
	var pInternetOpenUrl = unicode ? Module.findExportByName("wininet.dll", "InternetOpenUrlW")
                                        : Module.findExportByName("wininet.dll", "InternetOpenUrlA");
	if(pInternetOpenUrl == undefined)
		return 0;

	Interceptor.attach(pInternetOpenUrl, {
		onEnter: function(args) {
			var url = unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			send({
				'InternetOpenUrl': url
			});
		}
	});
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

	if(pGetAddrInfo == undefined) send({'error': 'GetAddrInfo'});

	Interceptor.attach(pGetAddrInfo, {
		onEnter: function(args) {
			var domain = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			this.ppResult = args[3];
			send({
				'GetAddrInfo': domain,
			});
		}
	});
}

// WINHTTPAPI HINTERNET WinHttpOpen(
//     [in, optional] LPCWSTR pszAgentW,
//     [in]           DWORD   dwAccessType,
//     [in]           LPCWSTR pszProxyW,
//     [in]           LPCWSTR pszProxyBypassW,
//     [in]           DWORD   dwFlags
//   );

// WINHTTPAPI BOOL WinHttpCreateUrl(
// 	[in]      LPURL_COMPONENTS lpUrlComponents,
// 	[in]      DWORD            dwFlags,
// 	[out]     LPWSTR           pwszUrl,
// 	[in, out] LPDWORD          pdwUrlLength
//);

function WinHttp() {
    var pWinHttpOpen = Module.findExportByName("winhttp.dll", "WinHttpOpen");
    var pWinHttpCreateUrl = Module.findExportByName("winhttp.dll", "WinHttpCreateUrl");
	
	if (pWinHttpOpen == undefined) send({'error': 'WinHttpOpen'});
	if (pWinHttpCreateUrl == undefined) send({'error': 'WinHttpCreateUrl'});

    Interceptor.attach(pWinHttpOpen, {
        onEnter: function(args) {
            var agent = args[0].readUtf16String();
			var proxy = args[2].readUtf16String();
            send({
                'WinHttpOpen' : agent,
				'Proxy': proxy
            })
        }
    });
    Interceptor.attach(pWinHttpCreateUrl, {
        onEnter: function(args) {
            var url = args[2].readUtf16String();
            send({
                'WinHttpCreateUrl' : url
            })
        }
    });
}

function WinHttpGetProxyForUrl() {
	var pWinHttpGetProxyForUrl = Module.findExportByName("winhttp.dll", "WinHttpGetProxyForUrl");
	Interceptor.attach(pWinHttpGetProxyForUrl, {
		onEnter: function(args) {
			var url = args[1].readUtf16String();
			send({
				'WinHttpGetProxyForUrl': url
			})
		}
	})
}

function GetProcAddress() {
	var pGetProcAddress = Module.findExportByName(null, 'GetProcAddress');
	if (pGetProcAddress == undefined) send({'error': 'GetProcAddress'});

	Interceptor.attach(pGetProcAddress, {
		onEnter: function(args) {
			var function_name = args[1].readUtf8String();
			// send({
			// 	'Function': function_name
			// })
			if (function_name.includes('WinHttpOpen')) {
				WinHttpGetProxyForUrl();
			} else if (function_name.toLowerCase().includes('getaddrinfo')) {
				GetAddrInfo({unicode: 0, ex: 0});
				GetAddrInfo({unicode: 1, ex: 0});
				GetAddrInfo({unicode: 0, ex: 1});
				GetAddrInfo({unicode: 1, ex: 1});
			}
		}
	})
}

GetProcAddress();
