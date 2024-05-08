import json, os

REPORT_PATH = 'reports/report.json'

class Detector:
    def __init__(self) -> None:
        self.content = self.load()
        self.files = list()
        self.registries = list()
        self.processes = list()
        self.networks = list()

    def load(self):
        f = open(REPORT_PATH, 'r').read()
        return json.loads(f)
    
    def _process_analysis(self, data: dict):
        if data['CreateProcess']:
            self.processes['CreateProcess'] = len(data['CreateProcess'])
        else:
            self.processes['OpenProcess'] = len(data['OpenProcess'])

    def analysis(self):
        pass
    
    def __str__(self) -> str:
        return str(self.content)

detector = Detector()
print(detector)