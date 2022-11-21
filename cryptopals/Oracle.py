from abc import ABC, abstractmethod


class Oracle(ABC):
    @abstractmethod
    def encrypt(self, plaintext=b"") -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext=b"", key=b"", iv=b"") -> bytes:
        pass


class HashOracle(ABC):
    @abstractmethod
    def validate(self, plaintext: bytes, digest: bytes) -> bool:
        pass

    @abstractmethod
    def digest(self, plaintext: bytes) -> bytes:
        pass
