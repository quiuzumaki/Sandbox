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
            if ((FILE_CREATION_DISPOSITION['CREATE_NEW'] == this.disposition) || (FILE_CREATION_DISPOSITION['CREATE_ALWAYS'] == this.disposition)) {
                send({
                    'CreateFile': this.filename,
                    'Handle': '-1'
                });
                
                var result;
                var tmp_file = String();
                recv('scan_result', value => {
                    result = Boolean(value.result);
                    tmp_file = String(value.tmp_file);
                }).wait();

                if (result) {
                    args[0] = unicode ? ptr(args[0]).writeUtf16String(tmp_file) : ptr(args[0]).writeUtf8String(tmp_file);
                }
            }
        }, 
        onLeave: function(args) {
            var handle = args;
            if ((FILE_CREATION_DISPOSITION['CREATE_NEW'] == this.disposition) || (FILE_CREATION_DISPOSITION['CREATE_ALWAYS'] == this.disposition)) {
                send({
                    'CreateFile': this.filename,
                    'Handle': handle
                });
            } else {
                send({
                    'OpenFile' : this.filename,
                    'Handle': handle
                });
            }
        }
    })
}

function WriteFile(extend) {
    var pWriteFile = extend ? Module.getExportByName(null, 'WriteFile') : Module.getExportByName(null, 'WriteFileEx');
    Interceptor.attach(pWriteFile, {
        onEnter: function(args) {
            this.hFile  = args[0].toInt32();
            send({
                'WriteFile': this.hFile
            }, args[1].readByteArray(args[2].toInt32()));
    
            var result;
            recv('scan_result', value => {
                result = Boolean(value.result);
            }).wait();
    
            if (result) {
                args[1] = Memory.alloc(1);
                args[2] = ptr(0);
            }
        }
    })
}

function ReadFile(extend) {
    var pReadFile = extend ? Module.getExportByName(null, 'ReadFile') : Module.getExportByName(null, 'ReadFileEx');
    Interceptor.attach(pReadFile, {
        onEnter: function(args) {
            this.hFile = args[0].toInt32();
            this.Buffer = args[1];
            this.size = args[2].toInt32();
        }, 
        onLeave: function(args){
            send({
                'ReadFile': this.hFile,
            }, this.Buffer.readByteArray(this.size))

            var result;
            recv('scan_result', value => {
                result = Boolean(value.result);
            }).wait();

            // if (result) {
            //     args[1] = Memory.alloc(1);
            //     args[2] = ptr(0);
            // }
        }
    });
}

function DeleteFile(unicode) {
    var pDeleteFile = unicode ? Module.getExportByName(null, 'DeleteFileW') 
                                : Module.getExportByName(null, 'DeleteFileA');

    Interceptor.replace(pDeleteFile, new NativeCallback( (lpFileName) => {
        var filename = unicode ? lpFileName.readUtf16String() : lpFileName.readUtf8String();
        send({
            'DeleteFile': filename
        });
        return 1;
    }, 'bool', ['pointer']));
};

// BOOL MoveFile(
//     [in] LPCTSTR lpExistingFileName,
//     [in] LPCTSTR lpNewFileName
//   );

function MoveFile(unicode) {
    var pMoveFile = unicode ? Module.getExportByName(null, 'MoveFileW') 
                                : Module.getExportByName(null, 'MoveFileA');

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
    var pCopyFile = unicode ? Module.getExportByName(null, 'CopyFileW') 
                                : Module.getExportByName(null, 'CopyFileA');

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

// ReadFile(0);
// ReadFile(1);

DeleteFile(0);
DeleteFile(1);

MoveFile(0);
MoveFile(1);

CopyFile(0);
CopyFile(1);
