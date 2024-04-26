import sys

from ObjectsManager import ObjectFile, ObjectRegistry, ObjectProcess
from Sandbox import Sandbox
from Report import Report
from Interceptor import Interceptor

sandbox = Sandbox()
report = Report()
interceptor = Interceptor(sys.argv[1])

def create_dir() -> str:
    import os
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, r'tmp')
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)
    return final_directory

tmp_dir = create_dir()
tmp_filename =  None

def file(payload: dict, data = None):
    keys = list(payload.keys())
    meta = []
    if keys[0] == 'CreateFile':
        result = False
        handle = int(payload['Handle'], 16)
        path_file = payload['CreateFile']
        if handle == -1:
            if not sandbox.filter_file(path_file):
                filename = str(path_file).split('\\')[-1]
                tmp_filename = tmp_dir + '\\' + filename
                report.add_create_file(path_file)
                interceptor.send({'type': 'scan_result', 'result': True, 'tmp_file': tmp_filename})
        else:
            sandbox.insert_entry(handle, ObjectFile(path_file))
            tmp_filename = None

    elif keys[0] == 'OpenFile':
        handle = int(payload['Handle'], 16)
        if sandbox.filter(handle, ObjectFile(payload['OpenFile'])) == False:
            report.add_open_file(payload['OpenFile'])

    elif keys[0] == 'ReadFile':
        result = False
        handle = int(payload['ReadFile'])

        if sandbox.scan_memory(handle, data, meta): 
            ob_name = sandbox.get_objects_manager().get_object_name(handle)
            report.add_read_file({'FileName': ob_name})
        
        interceptor.send({'type': 'scan_result', 'result': result})

    elif keys[0] == 'WriteFile':
        result = False
        handle = int(payload['WriteFile'])
        
        if sandbox.scan_memory(handle, data, meta):
            result = True
            ob_name = sandbox.get_objects_manager().get_object_name(handle)
            report.add_write_file({'FileName': ob_name, 'Detected Harmful Data' : meta[0]['description']})
        
        interceptor.send({'type': 'scan_result', 'result': result})

    elif keys[0] == 'DeleteFile':
        report.add_delete_file(payload['DeleteFile'])

    elif keys[0] == 'MoveFile':
        report.add_move_file(payload['MoveFile'])

    elif keys[0] == 'CopyFile':
        report.add_copy_file(payload['CopyFile'])

def registry(payload: dict, data = None):
    keys = list(payload.keys()) 
    meta = []
    if 'RegCreateKey' in keys[0]:
        if sandbox.filter(payload['Handle'], ObjectRegistry(payload['RegCreateKey'])) == False:
            report.add_create_key(payload['RegCreateKey'])

    elif 'RegOpenKey' in keys[0]:
        if sandbox.filter(payload['Handle'], ObjectRegistry(payload['RegOpenKey'])) == False:
            report.add_open_key(payload['RegOpenKey'])

    elif keys[0] == 'RegSetValue':
        result = False
        if sandbox.scan_memory(payload['RegSetValue'], data, meta):
            result = True
            report.add_set_value(payload['RegSetValue'])
        interceptor.send({'type': 'scan_result', 'result': result})

    elif keys[0] == 'RegDeleteKey':
        report.add_delete_key(payload['RegDeleteKey'])

    elif keys[0] == 'RegDeleteValue':
        report.add_delete_value(payload['RegDeleteValue'])

    elif keys[0] == 'RegDeleteKeyValue':
        value = payload['SubKey'] + payload['ValueName']
        report.add_delete_value_key(value)

def internet(payload: dict):
    keys = list(payload.keys())
    if keys[0] == 'GetAddrInfo':
        report.add_internet_domain(payload['GetAddrInfo'])
    elif keys[0] == 'InternetOpenUrl':
        pass
    elif keys[0] == 'WinHttpGetProxyForUrl':
        report.add_internet_url(payload['WinHttpGetProxyForUrl'])

def process(payload: dict):
    keys = list(payload.keys())
    if keys[0] == 'CreateProcess':
        report.add_create_process(payload['CreateProcess'])
    else:
        report.add_open_process(payload['OpenProcess'])

def on_detached():
    print("The process has terminated!")
    report.dump()
    sys.exit()

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        print(payload)
        keys = list(payload.keys())
        if 'File' in keys[0]:
            file(payload, data)
        elif 'Reg' in keys[0]:
            registry(payload, data)
        elif 'Process' in keys[0]:
            process(payload)
        else:
            internet(payload)
        print(sandbox)
    else:
        print('something error here')
        print(message)

interceptor.recv(on_message)
interceptor.on_detached(on_detached)
interceptor.run()