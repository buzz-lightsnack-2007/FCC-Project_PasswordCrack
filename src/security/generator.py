# generator.py
# Generates hashes for multiple combinations

# Project modules
from security.multihash import HashEncoder

class HashFactory: 
	salts: set[str] = set()
	passwords: set[str] = set()
	algorithm: str = 'sha1'
	_verbose: bool = True

	@property
	def all(self) -> dict[str, set[str]]: 
		"""
			Generate hashes for all combinations of passwords and salts.

			Returns:
				dict: A dictionary with algorithms as keys and sets of hashed values as values.
		"""
		def generate(password): 
			print(f"Hashing “\033[1m{password}\033[0m”\033[5m with{'' if self.salts else 'out'} salts…\033[0m") if self._verbose else None
			result: [str|set[str]] = [password, self[password]]
			print(f"\033[F\033[KHashing “\033[1m{password}\033[0m” with{'' if self.salts else 'out'} salts \033[32mcomplete\033[0m.") if self._verbose else None

			return result

		hashes: dict[str, set[str]] = dict([generate(password) for password in self.passwords])
		return hashes

	def __getitem__(self, password: str) -> set[str]: 
		hashes: set[str] = set()
		
		def encode(salt: str = '') -> list[str]: 
			nonlocal password
			hash: HashEncoder = HashEncoder(password)
			hash.encoding, hash.salt = dict, salt

			hashes: dict[str, str|None] = hash[self.algorithm]
			return set([hx for hx in hashes.values() if hx])

		for salt in self.salts.union(set([''])): 
			hashes.update(encode(salt))
		
		return hashes

	def __lt__(self, hash: str) -> set[str]: 
		matches: list[str] = []
		try: 
			for password, hashes in self.all.items():
				matches += [password] if hash in hashes else []
		except KeyboardInterrupt: 
			pass # If the program is stopped, only show return has been found so far. 
		
		return set(matches) # deduplicate