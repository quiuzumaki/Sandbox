from Filter import *    
from ObjectsManager import *
from YaraScanner import *

class Sandbox:
    def __init__(self) -> None:
        self.om = ObjectsManager()
        self.ys = YaraScanner()

    def is_valid(self, handle):
        return True if (int(handle) > 0) else False
    
    def filter_file(self, path: str):
        tokens = path.split('\\')
        if (tokens[-1][-1] == '*') or \
                (tokens[-1].lower() in filenames) or \
                        ('\\'.join(tokens[0:2]).lower() in system_paths):
            return True
        return False
    
    def filter_registry(self, value: str):
        for path in persistence_path:
            if value.lower().find(path) != -1:
                return False
        return True

    def filter(self, handle: int, object: Object):
        if self.is_valid(handle) == False:
            return True
        
        value = object.get_name()

        if isinstance(object, ObjectFile):
            if self.filter_file(value):
                return True

        elif isinstance(object, ObjectRegistry):
            if self.filter_registry(value):
                return True

        self.om.insert_entry(handle, object)

        return False

    def scan_memory(self, handle: int, data: bytes, meta: list):
        if not self.om.is_exist(handle):
            return False
        
        if self.ys.scan_memory(data):
            meta.append(self.ys.get_meta())
            return True
        
        return False

    def insert_entry(self, handle, object: Object) -> None:
        self.om.insert_entry(handle, object)

    def get_objects_manager(self) -> ObjectsManager:
        return self.om

    def __str__(self) -> str:
        return str(self.om)
    