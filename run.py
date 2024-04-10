import frida
import sys

from Sandbox import *
from ObjectsManager import ObjectFile, ObjectRegistry, ObjectProcess

sandbox = Sandbox()

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']

        print(payload, type(payload))
        keys = list(payload.keys())
        print(keys)
        meta = []
        match keys[0]:
            case 'CreateFile':
                sandbox.filter(payload['Handle'], ObjectFile(payload['CreateFile']))
            case 'ReadFile':
                sandbox.scan_memory(data=data, meta=meta)
            case 'WriteFile':
                sandbox.scan_memory(data=data, meta=meta)
            case 'DeleteFile':
                pass
            case 'CreateKey':
                sandbox.filter(payload['Handle'], ObjectRegistry(payload['CreateKey']))
            case 'OpenKey':
                sandbox.filter(payload['Handle'], ObjectRegistry(payload['OpenKey']))
            case 'OpenKeyEx':
                sandbox.filter(payload['Handle'], ObjectRegistry(payload['OpenKeyEx']))
            case 'SetValueKey':
                # print(data)
                sandbox.scan_memory(data=data, meta=meta)
            case _:
                pass
        
        if len(meta) != 0:
            print(meta[0]['description'])

        # if isinstance(payload.get('WriteFile'), int):
        #     pass
            # script.post(script.post({'type': 'scan_result', 'payload': 'scan oke'}))
    elif message['type'] == 'error':
        print('something error here')
        print(message['description'])

session = frida.attach(7416)
source = open('./scripts_hook/hook_nt_registry.js', 'r').read()

script = session.create_script(source)
script.on('message', on_message)
script.load()

sys.stdin.read()