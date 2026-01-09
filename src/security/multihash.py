# multihash.py
# Hash functions for various encodings

import encodings, hashlib, pkgutil

def list_encodings() -> set[str]:
	"""
		List all available encodings in the Python environment.

		Returns:
			set: A set of encoding names.	
	"""
	encodings_list = sorted({module.name for module in pkgutil.iter_modules(encodings.__path__)})
	[encodings_list.remove(item) for item in ['undefined', 'aliases']]
	return set(encodings_list)

AVAILABLE_ENCODINGS = list_encodings()

class HashEncoder(str): 
	"""
		A class to access hash encodings for a string.

		Attributes:
			salt (str): A salt value to be used in hashing.
	"""

	salt: str = ''
	encoding: str = 'utf_8'

	@property
	def __content(self): 
		return self.salt + str(self)

	def __setattr__(self, name, value):
		if name == 'encoding': 
			if (value == dict or not value): 
				return super().__setattr__(name, value or 'utf_8')
			elif (value not in AVAILABLE_ENCODINGS):
				raise LookupError(f"Encoding '{value}' is not available.")
		return super().__setattr__(name, value)

	def encode(self, algorithm: str = 'sha1') -> str|dict[str, str]:
		"""
			Encode the string using the specified hashing algorithm.

			Args:
				algorithm (str): The name of the hashing algorithm to use.

			Returns:
				str: The hashed value as a hexadecimal string.
		"""
		if not hasattr(hashlib, algorithm):
			raise LookupError(f"Hash algorithm ‘{algorithm}’ isn’t available.")

		hasher = getattr(hashlib, algorithm)
		encodings: list[str]|set[str] = AVAILABLE_ENCODINGS if self.encoding == dict else [self.encoding]

		hashes: dict[str, str] = {}
		
		for encoding in encodings: 
			encoded: bytes = None
			try: 
				encoded = self.__content.encode(encoding, errors='strict')
			except Exception:
				continue
			
			hashes[encoding] = hasher(encoded).hexdigest() if encoded else None
		
		return hashes if self.encoding == dict else hashes[self.encoding]
	
	def __getitem__(self, algorithm: str) -> str:
		return self.encode(algorithm)
	
	def __radd__(self, new_salt: str): 
		self.salt = new_salt
		return self
