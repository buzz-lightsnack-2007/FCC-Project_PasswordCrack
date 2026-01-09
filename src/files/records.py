# records.py
# Hash records management

# Imports
# Standard library modules
from pathlib import Path
import io, json

# Project modules
from security.generator import HashFactory

PATH_HASHES: Path = Path(__file__).resolve().parents[2] / "data" / "hashes.JSONC"

def read_file_set(function): 
    def export(self, *args, **kwargs): 
        file: io.TextIOBase = self.files[function(self, *args, **kwargs)]
        file.seek(0) # reset reading
        return set(self.files[function(self, *args, **kwargs)].read().split('\n'))

    return export

class RecordHash: 
    algorithm: str = 'sha1'
    sources: dict[str, Path] = dict([[
            name, Path(__file__).resolve().parents[2] / "data" / filename
        ] for name, filename in {
            "salts": "known-salts.txt",
            "passwords": "top-10000-passwords.txt"
        }.items()])
    output: Path = PATH_HASHES

    def __init__(self): 
        self.__files: dict[str, io.TextIOBase] = {}
        self.__factory: HashFactory = HashFactory()

    @property
    def files(self): 
        self.__files = self.__files or dict([[name, open(file, 'r')] for name, file in self.sources.items()] + [['output', open(self.output, "w+")]])
        return self.__files
    
    @property
    @read_file_set
    def salts(self): return 'salts'

    @property
    @read_file_set
    def passwords(self): return 'passwords'

    @property
    def hashes(self) -> dict[str, dict[str, set[str]]]: 
        hashes: dict[str, dict[str, set[str]]] = {}

        def config(salted: bool = True): 
            self.__factory.passwords = set(self.passwords)
            self.__factory.salts = set(self.salts) if salted else set()

        # Unsalted
        config(False)
        hashes['unsalted'] = self.__factory.all

        # With salts
        config(True)
        hashes['salted'] = self.__factory.all
        return hashes
    
    def export(self): 
        result: dict[str, list[str]] = dict([[type, dict([
            [password, list(hashes)] for password, hashes in results.items()
        ])] for type, results in self.hashes.items()])
        json.dump(result, self.files['output'])
        return result

    def __del__(self): 
        if self.__files: 
            for name, file in self.__files.items(): 
                file.close() # close the file
            self.__files = {}
        
class ReadHash: 
    source: Path = PATH_HASHES
    salted: bool = False

    def __init__(self): 
        self.__file: io.TextIOBase = None
        self.__hashes: dict = {}

    @property
    def file(self): 
        self.__file = self.__file or open(self.source, 'r')
        return self.__file
    
    @property
    def hashes(self): 
        self.file.seek(0) # reset pointer location
        self.__hashes = self.__hashes or json.load(self.file)
        return self.__hashes[f'{'' if self.salted else 'un'}salted']

    def __getitem__(self, hash: str) -> set: 
        return set([password for password, hashes in self.hashes.items() if hash in hashes])

    def __contains__(self, hash: str) -> bool: 
        return (self.__getitem__(hash)) or False

    def __del__(self): 
        self.__file.close()
        self.__hashes = None # uncache