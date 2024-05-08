def get_process_name(pid: int):
    import psutil
    p = psutil.Process(pid)
    if p != None:
        return p.name()
    return ''

def create_dir(dir) -> str:
    import os
    current_directory = os.getcwd()
    final_directory = os.path.join(current_directory, dir)
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)
    return final_directory
