import os, hashlib, base64

def get_process_name(pid: int):
    import psutil
    p = psutil.Process(pid)
    if p != None:
        return p.name()
    return ''

def create_dir(dir) -> str:
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, dir)
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)
    return final_directory

def is_exist(file):
    return os.path.exists(file)

def get_folder_path(relative_path):
    return os.path.dirname(relative_path)

def sha256hash(buffer: bytes):
    hash256 = hashlib.sha256()
    hash256.update(buffer)
    return hash256.hexdigest()

def md5hash(buffer: bytes):
    hashmd5 = hashlib.md5()
    hashmd5.update(buffer)
    return hashmd5.hexdigest()

def b64encode(buffer:bytes) -> str:
    return base64.b64encode(buffer).decode()

def b64decode(buffer: bytes):
    return base64.b64decode(buffer)
