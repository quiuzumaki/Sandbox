/**
BOOL PathFileExistsW(
  [in] LPCWSTR pszPath
);
 */

function PathFileExists(unicode) {
    var pPathFileExists = unicode ? Module.findExportByName(null, 'PathFileExistsW') : Module.findExportByName(null, 'PathFileExistsA')
    Interceptor.attach(pPathFileExists, {
        onEnter: function(args) {
            this.filename = unicode ? args[0].readUtf16String() : args[0].readUtf8String();
            send({
                'PathFileExists' : this.filename
            })
        }
    })
}

// PathFileExists(0);
// PathFileExists(1);

/**
HANDLE FindFirstFileA(
  [in]  LPCSTR             lpFileName,
  [out] LPWIN32_FIND_DATAA lpFindFileData
);
 */

function FindFirstFile(unicode) {
    var pFindFirstFile = unicode ? Module.findExportByName(null, 'FindFirstFileW') : Module.findExportByName(null, 'FindFirstFileA');
    Interceptor.attach(pFindFirstFile, {
        onEnter: function(args) {
            this.lpFileName = unicode ? args[0].readUtf16String() : args[0].readUtf8String();
            send({
                'FindFirstFile' : this.lpFileName
            })
        }
    })
}

// FindFirstFile(0);
// FindFirstFile(1);

/**
HANDLE FindFirstFileExA(
  [in]  LPCSTR             lpFileName,
  [in]  FINDEX_INFO_LEVELS fInfoLevelId,
  [out] LPVOID             lpFindFileData,
  [in]  FINDEX_SEARCH_OPS  fSearchOp,
        LPVOID             lpSearchFilter,
  [in]  DWORD              dwAdditionalFlags
);
 */

function FindFirstFileEx(unicode) {
    var FindFirstFileEx = unicode ? Module.findExportByName(null, 'FindFirstFileExW') : Module.findExportByName(null, 'FindFirstFileExA');
    Interceptor.attach(FindFirstFileEx, {
        onEnter: function(args) {
            this.lpFileName = unicode ? args[0].readUtf16String() : args[0].readUtf8String();
            send({
                'FindFirstFileEx' : this.lpFileName
            })
        }
    })
}

// FindFirstFileEx(0);
// FindFirstFileEx(1);

/**
DWORD GetFullPathNameA(
  [in]  LPCSTR lpFileName,
  [in]  DWORD  nBufferLength,
  [out] LPSTR  lpBuffer,
  [out] LPSTR  *lpFilePart
);
 */

function GetFullPathName(unicode) {
    var pGetFullPathName = unicode ? Module.findExportByName(null, 'GetFullPathNameW') : Module.findExportByName(null, 'GetFullPathNameA');
    Interceptor.attach(pGetFullPathName, {
        onEnter: function(args) {
            this.lpFileName = unicode ? args[0].readUtf16String() : args[0].readUtf8String();
            this.lpBuffer = unicode ? args[2].readUtf16String() : args[2].readUtf8String();
            this.lpFilePart = args[3]
            send({
                'GetFullPathName' : this.lpFileName,
                'Buffer' : this.lpBuffer,
                'FilePart': this.lpFilePart
            })
        }
    })
}

// GetFullPathName(0);
// GetFullPathName(1);