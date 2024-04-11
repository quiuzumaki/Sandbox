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

function dump(addr, size) {
    console.log(hexdump(ptr(addr), {
        offset: 0,
        length: size,
        header: true,
        ansi: true
    }), '\n')
}


const module = 'ntdll.dll';
const NtCreateKey = Module.getExportByName(module, 'NtCreateKey');
const NtOpenKey = Module.getExportByName(module, 'NtOpenKey');
const NtOpenKeyEx = Module.getExportByName(module, 'NtOpenKeyEx');
const NtSetValueKey = Module.getExportByName(module, 'NtSetValueKey');
// const NtQueryValueKey = Module.getExportByName(module, 'NtQueryValueKey');
const NtDeleteKey = Module.getExportByName(module, 'NtDeleteKey');
const NtDeleteValueKey = Module.getExportByName(module, 'NtDeleteValueKey');

// NTSYSAPI NTSTATUS ZwCreateKey(
//     [out]           PHANDLE            KeyHandle,
//     [in]            ACCESS_MASK        DesiredAccess,
//     [in]            POBJECT_ATTRIBUTES ObjectAttributes,
//                     ULONG              TitleIndex,
//     [in, optional]  PUNICODE_STRING    Class,
//     [in]            ULONG              CreateOptions,
//     [out, optional] PULONG             Disposition
//   );

Interceptor.attach(NtCreateKey, {
    onEnter: function(args) {
        this.KeyHandle = args[0];
        var object_attributes = paser_object_attributes(args[2]);
        this.keyname = (object_attributes['ObjectName'])['Buffer'];
    }, 
    onLeave: function(args){
        this.KeyHandle = this.KeyHandle.toInt32();
        send({
            'CreateKey': this.keyname,
            'Handle' : this.KeyHandle
        });
    }
})

// NTSYSAPI NTSTATUS ZwOpenKey(
//     [out] PHANDLE            KeyHandle,
//     [in]  ACCESS_MASK        DesiredAccess,
//     [in]  POBJECT_ATTRIBUTES ObjectAttributes
//   );

Interceptor.attach(NtOpenKey, {
    onEnter: function(args) {
        this.KeyHandle = args[0];
        var object_attributes = paser_object_attributes(args[2]);
        this.keyname = (object_attributes['ObjectName'])['Buffer'];
    }, 
    onLeave: function(args){
        this.KeyHandle = this.KeyHandle.toInt32();
        send({
            'OpenKey': this.keyname,
            'Handle' : this.KeyHandle
        });
    }
})

// NTSYSAPI NTSTATUS ZwOpenKeyEx(
//     [out] PHANDLE            KeyHandle,
//     [in]  ACCESS_MASK        DesiredAccess,
//     [in]  POBJECT_ATTRIBUTES ObjectAttributes,
//     [in]  ULONG              OpenOptions
//   );

Interceptor.attach(NtOpenKeyEx, {
    onEnter: function(args) {
        this.KeyHandle = args[0];
        var object_attributes = paser_object_attributes(args[2]);
        this.keyname = (object_attributes['ObjectName'])['Buffer'];
    }, 
    onLeave: function(args){
        this.KeyHandle = this.KeyHandle.toInt32();
        send({
            'OpenKeyEx': this.keyname,
            'Handle' : this.KeyHandle
        });
    }
})

// NTSYSAPI NTSTATUS ZwSetValueKey(
//     [in]           HANDLE          KeyHandle,
//     [in]           PUNICODE_STRING ValueName,
//     [in, optional] ULONG           TitleIndex,
//     [in]           ULONG           Type,
//     [in, optional] PVOID           Data,
//     [in]           ULONG           DataSize
//   );

Interceptor.attach(NtSetValueKey, {
    onEnter: function(args) {
        this.KeyHandle = args[0].toInt32();
        send({
            'SetValueKey' : this.KeyHandle
        }, args[4].readByteArray(args[5].toInt32()));

        var result;
        
        recv('scan_result', value => {
            result = Boolean(value.result);
        }).wait();

        if (result) {
            args[4] = Memory.alloc(1);
            args[5] = ptr(0);
        }
    }, 
    onLeave: function(args){
    }
})

// NTSYSAPI NTSTATUS ZwDeleteKey(
//     [in] HANDLE KeyHandle
//   );

Interceptor.attach(NtDeleteKey, {
    onEnter: function(args) {
        this.KeyHandle = args[0].toInt32();

        send({
            'DeleteKey' : this.KeyHandle
        })
    }, 
    onLeave: function(args){
    }
})

// NTSYSAPI NTSTATUS ZwDeleteValueKey(
//     [in] HANDLE          KeyHandle,
//     [in] PUNICODE_STRING ValueName
//   );

Interceptor.attach(NtDeleteValueKey, {
    onEnter: function(args) {
        this.KeyHandle = args[0].toInt32();
        if (!args[1].isNull()) {
            this.ValueName = paser_unicode_string(args[1])['Buffer'];
        }
        send({
            'DeleteValueKey' : this.KeyHandle,
            'ValueName' : this.ValueName
        })
    }, 
    onLeave: function(args){
    }
})