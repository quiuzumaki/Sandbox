from Utils import md5hash, sha256hash

FILE_CREATION_DISPOSITION = {"CREATE": 1, "OPEN": 2}

# Structure to save content of a file
table: dict[str, bytes] = {}

def get_buffer(hash):
    if hash in table.keys():
        return table[hash]
    return b''
def write_buffer_table(hash, content):
    table[hash] = content

class Object:
    __table__: dict[str, bytes] = {}
    
    @staticmethod
    def get_buffer(hash):
        return Object.__table__.get(hash) if hash in Object.__table__.keys() else b''

    @staticmethod
    def write_buffer(hash, content):
        Object.__table__[hash] = content

    def __init__(self, hash = None) -> None:
        self.hash = hash
        self.buffer: bytes = Object.get_buffer(hash)

    def __str__(self) -> str:
        pass
    
    def get_name(self) -> str:
        pass

    def __eq__(self, value) -> bool:
        pass

    def read_buffer(self) -> bytes:
        return self.buffer
    
    def write_buffer(self, content: bytes, offset = -1):
        arr = bytearray(self.buffer)
        if offset == -1:
            arr.extend(content)
        else:
            arr[offset:offset+len(content)] = content
        self.buffer = bytes(arr)
        # table[self.hash] = self.buffer
        write_buffer_table(self.hash, self.buffer)

class ObjectFile(Object):
    def __init__(self, filename: str, disposition = None) -> None:
        super().__init__(md5hash(filename.encode()))
        self.filename = filename
        self.disposition = disposition

    def __str__(self) -> str:
        return 'ObjectFile({0})'.format(self.filename)

    def __eq__(self, value: Object) -> bool:
        if isinstance(value, ObjectFile):
            return self.filename == value.get_name()
        return False

    def init_buffer(self):
        # if self.buffer == b'':
        super().write_buffer(open(self.filename, 'rb').read())

    def is_open(self):
        return self.disposition == FILE_CREATION_DISPOSITION['OPEN']

    def get_name(self) -> str:
        return self.filename

class ObjectRegistry(Object):
    def __init__(self, keyname: str) -> None:
        super().__init__(md5hash(keyname.encode()))
        self.keyname = keyname

    def __str__(self) -> str:
        return 'ObjectRegistry({0})'.format(self.keyname)
    
    def __eq__(self, value: Object) -> bool:
        if isinstance(value, ObjectRegistry):
            return self.keyname == value.get_name()
        return False
    
    def get_name(self) -> str:
        return self.keyname
    
class ObjectsManager:
    def __init__(self) -> None:
        self.handle_table: dict[int, Object] = {}
    
    def __str__(self) -> str:
        return 'HandleTable(\n{0}\n)'.format('\n'.join(['\tHandle: {0}\n\t\t{1}'.format(key, value) for key, value in self.handle_table.items()]))

    def insert_entry(self, hanle: int, object: Object):
        self.handle_table[hanle] = object

    def is_exist_handle(self, handle: int) -> bool:
        return True if (handle in self.handle_table.keys()) else False
    
    def is_exist_object(self, object: Object)->bool:
        for k, v in self.handle_table.items():
            if object == v:
                return True
        return False

    def keys(self):
        return self.handle_table.keys()
    
    def get_object(self, handle) -> Object:
        return self.handle_table.get(handle)
    
    def get_object_name(self, handle) -> str:
        if self.is_exist(handle): 
            ob = self.get_object(handle)
            return ob.get_name()
        return ''

    def remove(self, handle) -> None:
        self.handle_table.pop(handle)

    def size(self) -> int:
        return len(self.handle_table)
    