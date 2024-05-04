import frida
import sys
import os

def test(filename):
    return open(filename, 'r').read()

class Interceptor:
    def __init__(self, pid) -> None:
        source = self.__build__()
        self.session = frida.attach(int(pid))
        self.script = self.session.create_script(source)

    def __build__(self) -> str:
        script_js = ""
        for root, _, files in os.walk('scripts_hook'):
            for file in files:
                hook_script = os.path.join(root, file)
                script_js += open(hook_script, 'r').read()
        return script_js

    def on_detached(self, func) -> None:
        self.session.on('detached', func)

    def run(self) -> None:
        self.script.load()
        sys.stdin.read()

    def send(self, data) -> None:
        self.script.post(data)

    def recv(self, func) -> None:
        self.script.on('message', func)
