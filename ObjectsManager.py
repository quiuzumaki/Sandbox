class Object:
    def __init__(self) -> None:
        pass
    def __str__(self) -> str:
        pass
    def get_name(self):
        pass

class ObjectFile(Object):
    def __init__(self, filename: str) -> None:
        super().__init__()
        self.filename = filename

    def __str__(self) -> str:
        return 'ObjectFile({0})'.format(self.filename)
    
    def get_name(self) -> str:
        return self.filename

class ObjectRegistry(Object):
    def __init__(self, keyname) -> None:
        super().__init__()
        self.keyname = keyname

    def __str__(self) -> str:
        return 'ObjectRegistry({0})'.format(self.keyname)
    
    def get_name(self) -> str:
        return self.keyname
    
class ObjectProcess(Object):
    def __init__(self, processname) -> None:
        super().__init__()
        self.processname = processname
    
    def __str__(self) -> str:
        return 'ObjectProcess({0})'.format(self.processname)

    def get_name(self) -> str:
        return self.processname

class ObjectsManager:
    def __init__(self) -> None:
        self.handle_table: dict[int, Object] = {}
    
    def __str__(self) -> str:
        return 'HandleTable(\n{0}\n)'.format('\n'.join(['\tHandle: {0}\n\t\t{1}'.format(key, value) for key, value in self.handle_table.items()]))

    def insert_entry(self, hanle: int, object: Object):
        self.handle_table[hanle] = object

    def is_exist(self, handle) -> bool:
        return True if (handle in self.handle_table.keys()) else False

    def keys(self):
        return self.handle_table.keys()
    
    def get_object(self, handle) -> Object:
        return self.handle_table[handle]
    
    def get_object_name(self, handle) -> str:
        if self.is_exist(handle): 
            ob = self.get_object(handle)
            return ob.get_name()
        return ''

    def remove(self, handle) -> None:
        self.handle_table.pop(handle)

    def size(self) -> int:
        return len(self.handle_table)