from presidio_anonymizer.operators import Decrypt, Encrypt


VALID_AES_KEY_BYTE_LENGTHS = {16, 24, 32}


class TextCryptoKeyError(ValueError):
    pass


class TextCryptoService:
    """Encrypt/decrypt full text using Presidio's AES encrypt/decrypt operators."""

    def __init__(self) -> None:
        self._encrypt = Encrypt()
        self._decrypt = Decrypt()

    @staticmethod
    def validate_crypto_key(crypto_key: str) -> None:
        key_length = len(crypto_key.encode("utf-8"))
        if key_length not in VALID_AES_KEY_BYTE_LENGTHS:
            valid_lengths = ", ".join(str(length) for length in sorted(VALID_AES_KEY_BYTE_LENGTHS))
            raise TextCryptoKeyError(
                f"crypto_key must be {valid_lengths} bytes for Presidio AES encryption; got {key_length} bytes"
            )

    def encrypt(self, content: str, crypto_key: str) -> str:
        self.validate_crypto_key(crypto_key)
        return self._encrypt.operate(text=content, params={"key": crypto_key})

    def decrypt(self, content: str, crypto_key: str) -> str:
        self.validate_crypto_key(crypto_key)
        return self._decrypt.operate(text=content, params={"key": crypto_key})
