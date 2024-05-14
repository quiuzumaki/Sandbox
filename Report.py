import json
from Utils import *

REPORT_PATH = 'reports'

class Report:
    def __init__(self, pid:int) -> None:
        self.pid = pid
        # self.process_name = get_process_name(pid)
        self.record = {}
        self.id = 1

    def add_record(self, record):
        self.record[self.id] = record
        self.id += 1

    def get_record(self):
        return self.record
    
    def dump(self) -> None:
        create_dir(REPORT_PATH)
        # f = open(REPORT_PATH + f'/report_{self.process_name}_{self.pid}.json', 'w')
        f = open(REPORT_PATH + '/report.json', 'w')
        f.write(json.dumps(self.record, indent=4))
        