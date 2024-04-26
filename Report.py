import json

class Report:
    def __init__(self) -> None:
        self.report = {
            'Files': {
                'CreateFile' : [],
                'OpenFile' : [], 
                'WriteFile' : [],
                'ReadFile': [],
                'DeleteFile' : [],
                'MoveFile': [],
                'CopyFile' : []
            }, 
            'Registry': {
                'RegCreateKey' : [], 
                'RegOpenKey' :[],
                'RegSetValueKey': [],
                'RegDeleteKey': [], 
                'RegDeleteValueKey': []
            }, 
            'Process': {
                'CreateProcess': [],
                'OpenProcess': []
            }, 
            'Network': {
                'Domain' : [],
                'URL' : []
            }
        }
    # report for Files
    def add_create_file(self, data) -> None:
        self.report['Files']['CreateFile'].append(data)
    
    def add_open_file(self, data) -> None:
        self.report['Files']['OpenFile'].append(data)

    def add_write_file(self, data) -> None:
        self.report['Files']['WriteFile'].append(data)

    def add_read_file(self, data) -> None:
        self.report['Files']['ReadFile'].append(data)
    
    def add_delete_file(self, data) -> None:
        self.report['Files']['DeleteFile'].append(data)
    
    def add_move_file(self, data) -> None:
        self.report['Files']['MoveFile'].append(data)
    
    def add_copy_file(self, data) -> None:
        self.report['Files']['CopyFile'].append(data)
    
    # report for Registry
    def add_create_key(self, data) -> None:
        self.report['Registry']['RegCreateKey'].append(data)
    
    def add_open_key(self, data) -> None:
        self.report['Registry']['RegOpenKey'].append(data)
    
    def add_set_value(self, data) -> None:
        self.report['Registry']['RegSetValueKey'].append(data)

    def add_delete_key(self, data) -> None:
        self.report['Registry']['RegDeleteKey'].append(data)
    
    def add_delete_value(self, data) -> None:
        self.report['Registry']['RegDeleteValue'].append(data)
    
    def add_delete_value_key(self, data) -> None:
        self.report['Registry']['RegDeleteValueKey'].append(data)

    # report for Process
    def add_create_process(self, data) -> None:
        process_name = data['lpApplicationName'] + ' ' + data['lpCommandLine']
        self.report['Process']['CreateProcess'].append(process_name)

    def add_open_process(self, data)-> None:
        self.report['Process']['OpenProcess'].append(data)

    def add_internet_domain(self, data) -> None:
        self.report['Network']['Domain'].append(data)

    def add_internet_url(self, data) -> None:
        self.report['Network']['URL'].append(data)

    def dump(self) -> None:
        f = open('report.json', 'w')
        f.write(json.dumps(self.report, indent=4))
        