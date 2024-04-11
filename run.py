import frida
import sys

from ObjectsManager import ObjectFile, ObjectRegistry, ObjectProcess
from Sandbox import Sandbox

sandbox = Sandbox()
session = frida.attach(4240)
source = open('./scripts_hook/hook_internet.js', 'r').read()
script = session.create_script(source)

def handle_is_valid(handle: int):
    return True if handle > 0 else False

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']

        print(payload, type(payload))
        keys = list(payload.keys())
        meta = []
        match keys[0]:
            case 'CreateFile':
                sandbox.filter(payload['Handle'], ObjectFile(payload['CreateFile']))

            case 'OpenFile':
                sandbox.filter(payload['Handle'], ObjectFile(payload['OpenFile']))

            case 'ReadFile':
                sandbox.scan_memory(payload['ReadFile'], data=data, meta=meta)

            case 'WriteFile':
                result = False
                if sandbox.scan_memory(payload['WriteFile'], data=data, meta=meta):
                    result = True
                script.post({'type': 'scan_result', 'result': result})

            case 'DeleteFile':
                pass

            case 'MoveFile':
                pass

            case 'CopyFile':
                pass

            case 'CreateKey':
                sandbox.filter(payload['Handle'], ObjectRegistry(payload['CreateKey']))

            case 'OpenKey':
                sandbox.filter(payload['Handle'], ObjectRegistry(payload['OpenKey']))

            case 'OpenKeyEx':
                sandbox.filter(payload['Handle'], ObjectRegistry(payload['OpenKeyEx']))

            case 'SetValueKey':
                result = False
                if sandbox.scan_memory(payload['SetValueKey'], data=data, meta=meta):
                    result = True
                script.post({'type': 'scan_result', 'result': result})

            case _:
                pass
        
        print(sandbox)

        if len(meta) != 0:
            print('\t' + meta[0]['description'])

    elif message['type'] == 'error':
        print('something error here')
        print(message)


script.on('message', on_message)
script.load()

sys.stdin.read()