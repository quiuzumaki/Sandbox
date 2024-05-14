from Filter import *    
from ObjectsManager import *
from YaraScanner import *

class Sandbox:
    def __init__(self) -> None:
        self.om = ObjectsManager()
        self.ys = YaraScanner()

    def is_valid(self, handle):
        return True if (int(handle) > 0) else False
    
    def filter_file(self, path_file: str):
        tokens = path_file.split('\\')
        if (tokens[-1][-1] == '*') or \
                (tokens[-1].lower() in FILENAMES):
            return True
        for i in SYSTEM_PATHS:
            if i in path_file.lower():
                return True
        return False
    
    def filter_registry(self, value: str):
        for path in PERSISTENCE_PATH:
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
            if object.is_open():
                object.init_buffer()
        else:
            if self.filter_registry(value):
                return True
        
        self.om.insert_entry(handle, object)

        return False

    def scan_memory(self, handle: int, data: bytes):
        if not self.om.is_exist_handle(handle):
            return (False, None)
        
        self.om.get_object(handle).write_buffer(data)

        if self.ys.scan_memory(data):
            return (True, self.ys.get_meta())
        
        return (True, None)

    def insert_entry(self, handle: int, object: Object) -> None:
        self.om.insert_entry(handle, object)

    def get_objects_manager(self) -> ObjectsManager:
        return self.om

    def __str__(self) -> str:
        return str(self.om)
    