from Filter import *    
from ObjectsManager import *
from YaraScanner import *


class Sandbox:
    def __init__(self) -> None:
        self.om = ObjectsManager()
        self.ys = Yara()

    def is_valid(self, handle):
        return True if (int(handle) > 0) else False

    def filter(self, handle: int, object: Object):
        if self.is_valid(handle) == False:
            return True

        file_is_valid = False
        registry_is_valid = False

        if isinstance(object, ObjectFile):
            tokens = object.get_name().split('\\')
            if (tokens[-1][-1] == '*') or \
                    (tokens[-1].lower() in filenames) or \
                        ('\\'.join(tokens[0:2]).lower() != '\\??') or \
                            ('\\'.join(tokens[2:4]).lower() in system_paths):
                file_is_valid = True

        elif isinstance(object, ObjectRegistry):
            
            for path in persistence_path:
                if object.get_name().lower().find(path) != -1:
                    registry_is_valid = False
                    break
                else:
                    registry_is_valid = True

        elif isinstance(object, ObjectProcess):
            pass
        
        if file_is_valid or registry_is_valid:
            return True
        
        self.om.insert_entry(handle, object)

        return False

    def scan_memory(self, handle: int, data: bytes, meta: list):
        if self.om.is_exist(handle) == False:
            return False
        
        if self.ys.scan_memory(data):
            meta.append(self.ys.get_meta())
            return True
        return False
    
    def __str__(self) -> str:
        return str(self.om)
    