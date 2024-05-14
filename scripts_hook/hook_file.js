const FILE_CREATION_DISPOSITION = {
	"CREATE_ALWAYS": 2,
	"CREATE_NEW": 1,
	"OPEN_ALWAYS": 4,
	"OPEN_EXISTING": 3,
	"TRUNCATE_EXISTING": 5
};

function CreateFile(unicode) {
    var pCreateFile = unicode ? Module.findExportByName(null, "CreateFileW") : Module.findExportByName(null, "CreateFileA");
    Interceptor.attach(pCreateFile, {
        onEnter: function(args) {
            this.filename = unicode ? args[0].readUtf16String() : args[0].readUtf8String();
            this.disposition = args[4].toInt32();
        }, 
        onLeave: function(args) {
            if ((FILE_CREATION_DISPOSITION['CREATE_NEW'] == this.disposition) || (FILE_CREATION_DISPOSITION['CREATE_ALWAYS'] == this.disposition)) {
                send({
                    'CreateFile': this.filename,
                    'Handle': args
                });
            } else {
                send({
                    'OpenFile' : this.filename,
                    'Handle': args
                });
            }
        }
    })
}

/**
BOOL WriteFile(
  [in]                HANDLE       hFile,
  [in]                LPCVOID      lpBuffer,
  [in]                DWORD        nNumberOfBytesToWrite,
  [out, optional]     LPDWORD      lpNumberOfBytesWritten,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
*/
function WriteFile(unicode) {
    var pWriteFile = unicode ? Module.findExportByName(null, 'WriteFile') : Module.findExportByName(null, 'WriteFileEx');
    Interceptor.attach(pWriteFile, {
        onEnter: function(args) {
            this.hFile  = args[0].toInt32();
            send({
                'WriteFile': this.hFile
            }, args[1].readByteArray(args[2].toInt32()));

            var result = false;
            recv('scan_result', value => {
                result = Boolean(value.is_allowed);
            }).wait();

            if (result) {
                args[1] = Memory.alloc(1);
                args[2] = ptr(0);
            }
        }
    })
}

function ReadFile(unicode) {
    var pReadFile = unicode ? Module.findExportByName(null, 'ReadFile') : Module.findExportByName(null, 'ReadFileEx');
    Interceptor.attach(pReadFile, {
        onEnter: function(args) {
            this.hFile = args[0].toInt32();
            this.lpBuffer = args[1];
            this.nNumberOfBytesToRead = args[2]
            this.lpNumberOfBytesRead = args[3];
            send({
                'ReadFile': this.hFile,
            });
        }, 
        onLeave: function(ret) {
            var buffer = [];
            var result = false;
            recv('scan_result', value => {
                result = Boolean(value.is_allowed);
                buffer = String(value.content);
            }).wait();

            if (result) {
                buffer = stringToBytes(Base64.decode(buffer));
                this.lpBuffer.writeByteArray(buffer);
                // buffer = Base64.decode(buffer)
                // unicode ? this.lpBuffer.writeUtf16String(buffer) : this.lpBuffer.writeUtf8String(buffer);
                this.nNumberOfBytesToRead = ptr(buffer.length);
                this.lpNumberOfBytesRead = Memory.alloc(Process.pointerSize).writeU32(buffer.length);
                // console.log(this.nNumberOfBytesToRead.toInt32());
                // console.log(this.lpNumberOfBytesRead.readInt());
                // console.log(unicode ? this.lpBuffer.readUtf16String() : this.lpBuffer.readUtf8String());
            }
        }
    });
}

function DeleteFile(unicode) {
    var pDeleteFile = unicode ? Module.findExportByName(null, 'DeleteFileW') : Module.findExportByName(null, 'DeleteFileA');
    Interceptor.replace(pDeleteFile, new NativeCallback( (lpFileName) => {
        var filename = unicode ? lpFileName.readUtf16String() : lpFileName.readUtf8String();
        send({
            'DeleteFile': filename
        });
        return 1;
    }, 'bool', ['pointer']));
    // Interceptor.attach(pDeleteFile, {
    //     onEnter: function(args) {
    //         var filename = unicode ? args[0].readUtf16String() : args[0].readUtf8String();
    //         send({
    //             'DeleteFile': filename
    //         });
    //     }
    // });
};

// BOOL MoveFile(
//     [in] LPCTSTR lpExistingFileName,
//     [in] LPCTSTR lpNewFileName
//   );

function MoveFile(unicode) {
    var pMoveFile = unicode ? Module.findExportByName(null, 'MoveFileW') : Module.findExportByName(null, 'MoveFileA');
    Interceptor.replace(pMoveFile, new NativeCallback( (lpExistingFileName, lpNewFileName) => {
        var ExistingFileName = unicode ? lpExistingFileName.readUtf16String() : lpExistingFileName.readUtf8String();
        var NewFileName = unicode ? lpNewFileName.readUtf16String() : lpNewFileName.readUtf8String(); 
        send({
            'MoveFile': {
                'ExistingFileName' : ExistingFileName,
                'NewFileName' : NewFileName
            }
        });
        return 1;
    }, 'bool', ['pointer', 'pointer']));
}

// BOOL CopyFile(
//     [in] LPCTSTR lpExistingFileName,
//     [in] LPCTSTR lpNewFileName,
//     [in] BOOL    bFailIfExists
//   );

function CopyFile(unicode) {
    var pCopyFile = unicode ? Module.findExportByName(null, 'CopyFileW') : Module.findExportByName(null, 'CopyFileA');
    Interceptor.replace(pCopyFile, new NativeCallback( (lpExistingFileName, lpNewFileName, bFailIfExists) => {
        var ExistingFileName = unicode ? lpExistingFileName.readUtf16String() : lpExistingFileName.readUtf8String();
        var NewFileName = unicode ? lpNewFileName.readUtf16String() : lpNewFileName.readUtf8String(); 
        send({
            'CopyFile': {
                'ExistingFileName' : ExistingFileName,
                'NewFileName' : NewFileName
            }
        });
        return 1;
    }, 'bool', ['pointer', 'pointer', 'bool']));
}

CreateFile(0);
CreateFile(1);

WriteFile(0);
WriteFile(1);

ReadFile(0);
ReadFile(1);

DeleteFile(0);
DeleteFile(1);

MoveFile(0);
MoveFile(1);

CopyFile(0);
CopyFile(1);
