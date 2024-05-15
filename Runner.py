import sys, argparse

from ObjectsManager import *
from Sandbox import Sandbox
from Report import Report
from Interceptor import Interceptor
from Utils import *
from Detector import Detector


sandbox = Sandbox()
report = None
interceptor = None

tmp_filename =  None
SCRIPT_PS_NAME = None

def file(payload: dict, data = None):
    keys = list(payload.keys())
    if keys[0] == 'CreateFile':
        handle = int(payload['Handle'], 16)
        path_file = payload['CreateFile']
        payload['Handle'] = handle

        if not sandbox.filter(handle, ObjectFile(path_file, FILE_CREATION_DISPOSITION['CREATE'])):
            report.add_record(payload)

    elif keys[0] == 'OpenFile':
        handle = int(payload['Handle'], 16)
        path_file = payload['OpenFile']
        payload['Handle'] = handle
        if path_file == SCRIPT_PS_NAME:
            return
        
        if not sandbox.filter(handle, ObjectFile(path_file, FILE_CREATION_DISPOSITION['OPEN'])):
            report.add_record(payload)

    elif keys[0] == 'ReadFile':
        handle = int(payload['ReadFile'])
        ob = sandbox.get_objects_manager().get_object(handle)
        if ob != None:
            report.add_record({'ReadFile': ob.get_name(), 'Handle': handle})
        
        interceptor.send({
            'type': 'scan_result',
            'is_allowed': True if ob != None else False,
            'content': b64encode(ob.read_buffer() if ob != None else b'')
        })

    elif keys[0] == 'WriteFile':
        handle = int(payload['WriteFile'])
        _, meta = sandbox.scan_memory(handle, data) 
        ob = sandbox.get_objects_manager().get_object(handle)
        if ob != None:
            report.add_record({'WriteFile': ob.get_name(), 'Handle': handle, 'Yara Detector': meta})
        interceptor.send({
            'type': 'scan_result',
            'is_allowed': True if ob != None else False
        })
        
    else:
        report.add_record(payload)

def registry(payload: dict, data = None):
    keys = list(payload.keys()) 
    if 'RegCreateKey' in keys[0]:
        if not sandbox.filter(payload['Handle'], ObjectRegistry(payload['RegCreateKey'])):
            report.add_record(payload)

    elif 'RegOpenKey' in keys[0]:
        if not sandbox.filter(payload['Handle'], ObjectRegistry(payload['RegOpenKey'])):
            report.add_record(payload)

    elif keys[0] == 'RegSetValue':
        result, meta = sandbox.scan_memory(payload['Handle'], data)
        if result:
            payload.update({'Yara Detector': meta})
            report.add_record(payload)
        interceptor.send({
            'type': 'scan_result', 
            'result': result
        })

    elif keys[0] == 'RegSetValueEx':
        data = data.replace(b'\x00', b'')
        result, meta = sandbox.scan_memory(payload['Handle'], data)
        if result:
            payload.update({'Yara Detector': meta})
            report.add_record(payload)
        interceptor.send({
            'type': 'scan_result', 
            'result': result
        })

    elif keys[0] == 'RegDeleteKey':
        report.add_record(payload)

    elif keys[0] == 'RegDeleteValue':
        report.add_record(payload)

    elif keys[0] == 'RegDeleteKeyValue':
        value = payload['SubKey'] + payload['ValueName']
        report.add_record(payload)

def internet(payload: dict):
    report.add_record(payload)

def process(payload: dict):
    report.add_record(payload)

def on_detached():
    print("The process has terminated!")
    report.dump()
    Detector(report.get_record()).analysis()
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
        print(message)

def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-p', '--pid', type=int , help="PID of the process", required=True)
    parser.add_argument('-f', '--file', type=str, help='path to the Script PowerShell')

    args = parser.parse_args()
    pid = args.pid
    path_file = args.file

    if path_file != None:
        global SCRIPT_PS_NAME
        SCRIPT_PS_NAME = os.path.abspath(path_file)

    global interceptor, report

    report = Report(pid)
    interceptor = Interceptor(pid)
    interceptor.recv(on_message)
    interceptor.on_detached(on_detached)
    interceptor.run()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        report.dump()
        # Detector(report.get_record()).analysis()
        exit(0)