
function paser_object_attributes(ObjectAttributes) {
    var result = {
        'Length': ObjectAttributes.add(0).readULong(),
        'RootDirectory': ObjectAttributes.add(8).readU64(),
        'ObjectName' : paser_unicode_string(ObjectAttributes.add(16).readPointer()),
        'Attributes' : ObjectAttributes.add(0x18).readULong(),
        'SecurityDescriptor' : ObjectAttributes.add(0x20).readPointer(),
        'SecurityQualityOfService' : ObjectAttributes.add(0x28).readPointer()
    }
    return result;
}

function paser_unicode_string(ObjectName) {
    var result = {
        'Length' : ObjectName.add(0).readUShort(),
        'MaxLength' : ObjectName.add(4).readUShort(),
        'Buffer' : ObjectName.add(8).readPointer().readUtf16String()
    }
    return result;
}

const module = 'ntdll.dll';
const NtCreateFile = Module.getExportByName(module, 'NtCreateFile');
const NtOpenFile = Module.getExportByName(module, 'NtOpenFile');
const NtWriteFile = Module.getExportByName(module, 'NtWriteFile');
const NtReadFile = Module.getExportByName(module, 'NtReadFile');

// __kernel_entry NTSYSCALLAPI NTSTATUS NtCreateFile(
//     [out]          PHANDLE            FileHandle,
//     [in]           ACCESS_MASK        DesiredAccess,
//     [in]           POBJECT_ATTRIBUTES ObjectAttributes,
//     [out]          PIO_STATUS_BLOCK   IoStatusBlock,
//     [in, optional] PLARGE_INTEGER     AllocationSize,
//     [in]           ULONG              FileAttributes,
//     [in]           ULONG              ShareAccess,
//     [in]           ULONG              CreateDisposition,
//     [in]           ULONG              CreateOptions,
//     [in, optional] PVOID              EaBuffer,
//     [in]           ULONG              EaLength
//   );

Interceptor.attach(NtCreateFile, {
    onEnter: function(args) {
        this.FileHandle = args[0];
        var object_attributes = paser_object_attributes(args[2]);
        this.path_to_filename = (object_attributes['ObjectName'])['Buffer'];
    }, 
    onLeave: function(args){
        this.FileHandle = this.FileHandle.readS64();
        send({
            'CreateFile': this.path_to_filename,
            'Handle': this.FileHandle,
        })
    }
})

// __kernel_entry NTSYSCALLAPI NTSTATUS NtOpenFile(
//     [out] PHANDLE            FileHandle,
//     [in]  ACCESS_MASK        DesiredAccess,
//     [in]  POBJECT_ATTRIBUTES ObjectAttributes,
//     [out] PIO_STATUS_BLOCK   IoStatusBlock,
//     [in]  ULONG              ShareAccess,
//     [in]  ULONG              OpenOptions
//   );

Interceptor.attach(NtOpenFile, {
    onEnter: function(args) {
        this.FileHandle = args[0];
        var object_attributes = paser_object_attributes(args[2]);
        this.path_to_filename = (object_attributes['ObjectName'])['Buffer'];    
    }, 
    onLeave: function(args){
        this.FileHandle = this.FileHandle.readS64();
        send({
            'OpenFile': this.path_to_filename,
            'Handle': this.FileHandle
        })
    }
})

// __kernel_entry NTSYSCALLAPI NTSTATUS NtWriteFile(
//     [in]           HANDLE           FileHandle,
//     [in, optional] HANDLE           Event,
//     [in, optional] PIO_APC_ROUTINE  ApcRoutine,
//     [in, optional] PVOID            ApcContext,
//     [out]          PIO_STATUS_BLOCK IoStatusBlock,
//     [in]           PVOID            Buffer,
//     [in]           ULONG            Length,
//     [in, optional] PLARGE_INTEGER   ByteOffset,
//     [in, optional] PULONG           Key
//   );

Interceptor.attach(NtWriteFile, {
    onEnter: function(args) {
        this.FileHandle = args[0].toInt32();
        send({
            'WriteFile': this.FileHandle
        }, args[5].readByteArray(args[6].toInt32()));

        // recv('scan_result', function (value) {
        //     var data = value.payload;
        //     console.log('received bytes from python:', data);
        // }).wait();
    }, 
    onLeave: function(args){
    }
})

// __kernel_entry NTSYSCALLAPI NTSTATUS NtReadFile(
//     [in]           HANDLE           FileHandle,
//     [in, optional] HANDLE           Event,
//     [in, optional] PIO_APC_ROUTINE  ApcRoutine,
//     [in, optional] PVOID            ApcContext,
//     [out]          PIO_STATUS_BLOCK IoStatusBlock,
//     [out]          PVOID            Buffer,
//     [in]           ULONG            Length,
//     [in, optional] PLARGE_INTEGER   ByteOffset,
//     [in, optional] PULONG           Key
//   );

Interceptor.attach(NtReadFile, {
    onEnter: function(args) {
        this.FileHandle = args[0].toInt32();
        
        send({
            'ReadFile': this.FileHandle,
        }, args[5].readByteArray(args[6].toInt32()))
    }, 
    onLeave: function(args){
    }
})