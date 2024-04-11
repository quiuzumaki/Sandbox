import yara

class Yara:
    def __init__(self) -> None:
        self.rules = yara.compile(filepath='./rules/rules_file.yar')
        self.matches = list()

    def scan_memory(self, data: bytes) -> bool:
        if not isinstance(data, bytes): return False
        self.matches = self.rules.match(data=data)
        return True if len(self.matches) != 0 else False

    def get_matches(self) -> list:
        return self.matches
    
    def get_meta(self):
        return self.matches[0].meta
    