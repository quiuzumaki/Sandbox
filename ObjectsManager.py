class Object:
    def __init__(self) -> None:
        pass
    def __str__(self) -> str:
        return 'Object'

class ObjectFile(Object):
    def __init__(self, filename: str) -> None:
        super().__init__()
        self.filename = filename

    def __str__(self) -> str:
        return 'ObjectFile({0})'.format(self.filename)
    
    def get_name(self):
        return self.filename
    

class ObjectRegistry(Object):
    def __init__(self, keyname) -> None:
        super().__init__()
        self.keyname = keyname

    def __str__(self) -> str:
        return 'ObjectRegistry({0})'.format(self.keyname)
    
    def get_name(self):
        return self.keyname
    
class ObjectProcess(Object):
    def __init__(self, process) -> None:
        super().__init__()
        self.process = process
    
    def __str__(self) -> str:
        return 'ObjectProcess({0})'.format(self.process)

    def get_name(self):
        return self.process

class ObjectsManager:
    def __init__(self) -> None:
        self.handle_table = dict()
        self.size = 0
    
    def __str__(self) -> str:
        return 'HandleTable(\n{0}\n)'.format('\n'.join(['\tHandle: {0}\n\t\t{1}'.format(key, value) for key, value in self.handle_table.items()]))

    def insert_entry(self, hanle: int, object: Object):
        self.handle_table[hanle] = object

    def is_exist(self, handle) -> bool:
        return True if (handle in self.handle_table.keys()) else False

    def keys(self):
        return self.handle_table.keys()
    
    def get_object(self, handle) -> Object:
        return self.handle_table.get(handle)
        
    def remove(self, handle) -> None:
        self.handle_table.pop(handle)

    def size(self) -> int:
        return len(self.handle_table)
