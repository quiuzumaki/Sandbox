from Filter import *    
from ObjectsManager import *
from YaraScanner import *

class Sandbox:
    def __init__(self) -> None:
        self.om = ObjectsManager()
        self.ys = Yara()

    def filter(self, handle, object):
        if isinstance(object, ObjectFile):
            tokens = object.get_name().split('\\')
            if (tokens[-1].lower() in filenames) or (''.join(tokens[1:2]).lower() in system_paths):
                return True

        elif isinstance(object, ObjectRegistry):
            for path in persistence_path:
                if path.find(object.get_name().lower()) == -1:
                    continue
                
        elif isinstance(object, ObjectProcess):
            pass

        self.om.insert_entry(handle, object)

        return False
            
    def scan_memory(self, data: bytes, meta: list):
        if self.ys.scan_memory(data):
            meta.append(self.ys.get_meta())
            return True
        return False
    