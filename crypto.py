# crypto.py
# Модуль криптографии: деривация ключа и шифрование AES-256-GCM

import os
import hashlib
import hmac
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PBKDF2_ITERATIONS = 310_000   # Рекомендовано OWASP 2023
SALT_LENGTH       = 32        # 256 бит
NONCE_LENGTH      = 12        # 96 бит — стандарт GCM
KEY_LENGTH        = 32        # 256 бит


class CryptoManager:
    """
    Управляет криптографическими операциями менеджера паролей.
    Использует PBKDF2-HMAC-SHA256 для деривации ключа
    и AES-256-GCM для аутентифицированного шифрования.
    """

    def __init__(self):
        self._key: bytes | None = None

    # ── Деривация ключа ──────────────────────────────────────────

    def derive_key(self, master_password: str,
                   salt: bytes) -> bytes:
        """
        Дерировать 256-битный ключ из мастер-пароля.
        Использует PBKDF2-HMAC-SHA256 с 310 000 итерациями.

        Args:
            master_password: мастер-пароль пользователя.
            salt: случайная соль (32 байта).
        Returns:
            32-байтный ключ шифрования.
        """
        key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=master_password.encode("utf-8"),
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            dklen=KEY_LENGTH,
        )
        return key

    def generate_salt(self) -> bytes:
        """Сгенерировать криптографически случайную соль."""
        return os.urandom(SALT_LENGTH)

    def hash_password(self, master_password: str,
                      salt: bytes) -> str:
        """
        Вычислить хэш мастер-пароля для проверки при входе.
        Хранится в БД вместо самого пароля.
        """
        key = self.derive_key(master_password, salt)
        return hmac.new(key, b"master_verify",
                        hashlib.sha256).hexdigest()

    def verify_password(self, master_password: str,
                        salt: bytes,
                        stored_hash: str) -> bool:
        """Проверить мастер-пароль по сохранённому хэшу."""
        candidate = self.hash_password(master_password, salt)
        return hmac.compare_digest(candidate, stored_hash)

    def set_key(self, master_password: str, salt: bytes) -> None:
        """Установить рабочий ключ сессии из мастер-пароля."""
        self._key = self.derive_key(master_password, salt)

    def clear_key(self) -> None:
        """Очистить ключ из памяти при завершении сессии."""
        self._key = None

    # ── Шифрование / Дешифрование ────────────────────────────────

    def encrypt(self, plaintext: str) -> Tuple[bytes, bytes]:
        """
        Зашифровать строку алгоритмом AES-256-GCM.

        Args:
            plaintext: открытый текст для шифрования.
        Returns:
            Кортеж (ciphertext_with_tag, nonce):
              ciphertext_with_tag — шифртекст + 16-байтный тег GCM,
              nonce — уникальное значение 12 байт.
        Raises:
            RuntimeError: если ключ сессии не установлен.
        """
        if self._key is None:
            raise RuntimeError("Ключ сессии не установлен. "
                               "Вызовите set_key() перед шифрованием.")
        nonce = os.urandom(NONCE_LENGTH)
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            None,   # дополнительные данные не используются
        )
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        """
        Расшифровать данные, зашифрованные методом encrypt().

        Args:
            ciphertext: шифртекст с тегом GCM.
            nonce: nonce, использованный при шифровании.
        Returns:
            Исходный открытый текст.
        Raises:
            RuntimeError: если ключ не установлен.
            cryptography.exceptions.InvalidTag: при неверном ключе.
        """
        if self._key is None:
            raise RuntimeError("Ключ сессии не установлен.")
        aesgcm = AESGCM(self._key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    def encrypt_file(self, src_path: str,
                     dst_path: str) -> None:
        """
        Зашифровать файл целиком (для резервного копирования).
        Формат: [12 байт nonce][шифртекст+тег].
        """
        if self._key is None:
            raise RuntimeError("Ключ сессии не установлен.")
        nonce = os.urandom(NONCE_LENGTH)
        aesgcm = AESGCM(self._key)
        with open(src_path, "rb") as f:
            data = f.read()
        ciphertext = aesgcm.encrypt(nonce, data, None)
        with open(dst_path, "wb") as f:
            f.write(nonce + ciphertext)

    def decrypt_file(self, src_path: str,
                     dst_path: str) -> None:
        """
        Расшифровать файл резервной копии.
        """
        if self._key is None:
            raise RuntimeError("Ключ сессии не установлен.")
        with open(src_path, "rb") as f:
            data = f.read()
        nonce, ciphertext = data[:NONCE_LENGTH], data[NONCE_LENGTH:]
        aesgcm = AESGCM(self._key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        with open(dst_path, "wb") as f:
            f.write(plaintext)
