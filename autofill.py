# autofill.py
# Модуль автозаполнения и генератора паролей

import secrets
import string
import math
import pyperclip
from typing import List, Optional
from passmanager.vault import Vault, PasswordEntry


class AutofillManager:
    """
    Управляет автозаполнением учётных данных.
    Поиск записей по домену/приложению,
    копирование пароля в буфер обмена.
    """

    def __init__(self, vault: Vault):
        self.vault = vault

    def find_for_site(self, domain: str) -> List[PasswordEntry]:
        """
        Найти учётные данные для заданного домена или приложения.
        Поиск по частичному совпадению в title и url.
        Args:
            domain: домен или название приложения.
        Returns:
            Список подходящих записей.
        """
        return self.vault.search_entries(domain)

    def copy_password(self, entry: PasswordEntry) -> None:
        """
        Скопировать пароль записи в буфер обмена.
        Пароль не выводится на экран.
        Args:
            entry: запись хранилища.
        """
        pyperclip.copy(entry.password)
        print(f"Пароль для '{entry.title}' скопирован в буфер обмена.")

    def autofill(self, domain: str) -> Optional[PasswordEntry]:
        """
        Автоматически найти запись для домена.
        Если найдена одна запись — скопировать пароль.
        Если найдено несколько — предложить выбор.
        Returns:
            Выбранную запись или None.
        """
        entries = self.find_for_site(domain)
        if not entries:
            print(f"Записи для '{domain}' не найдены.")
            return None
        if len(entries) == 1:
            self.copy_password(entries[0])
            return entries[0]
        # Несколько совпадений — вывести список
        print(f"Найдено {len(entries)} записей для '{domain}':")
        for i, e in enumerate(entries, 1):
            print(f"  {i}. {e.title} ({e.username})")
        try:
            choice = int(input("Выберите номер: ")) - 1
            if 0 <= choice < len(entries):
                self.copy_password(entries[choice])
                return entries[choice]
        except (ValueError, IndexError):
            print("Неверный выбор.")
        return None


class PasswordGenerator:
    """
    Генератор криптографически стойких случайных паролей.
    Использует модуль secrets (CSPRNG).
    """

    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS    = string.digits
    SYMBOLS   = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    @classmethod
    def generate(cls,
                 length: int = 20,
                 use_upper: bool = True,
                 use_digits: bool = True,
                 use_symbols: bool = True) -> str:
        """
        Сгенерировать случайный пароль.
        Args:
            length: длина пароля (не менее 12).
            use_upper: включать ли заглавные буквы.
            use_digits: включать ли цифры.
            use_symbols: включать ли специальные символы.
        Returns:
            Строка-пароль.
        """
        if length < 12:
            raise ValueError("Длина пароля должна быть не менее 12.")
        alphabet = cls.LOWERCASE
        required = [secrets.choice(cls.LOWERCASE)]
        if use_upper:
            alphabet += cls.UPPERCASE
            required.append(secrets.choice(cls.UPPERCASE))
        if use_digits:
            alphabet += cls.DIGITS
            required.append(secrets.choice(cls.DIGITS))
        if use_symbols:
            alphabet += cls.SYMBOLS
            required.append(secrets.choice(cls.SYMBOLS))
        remaining = [secrets.choice(alphabet)
                     for _ in range(length - len(required))]
        password_list = required + remaining
        # Перемешать, чтобы обязательные символы
        # не стояли в начале
        secrets.SystemRandom().shuffle(password_list)
        return "".join(password_list)

    @classmethod
    def estimate_entropy(cls, password: str) -> float:
        """
        Оценить энтропию пароля в битах.
        E = log2(N^L), где N — размер алфавита, L — длина.
        """
        alphabet_size = 0
        if any(c in cls.LOWERCASE for c in password):
            alphabet_size += len(cls.LOWERCASE)
        if any(c in cls.UPPERCASE for c in password):
            alphabet_size += len(cls.UPPERCASE)
        if any(c in cls.DIGITS for c in password):
            alphabet_size += len(cls.DIGITS)
        if any(c in cls.SYMBOLS for c in password):
            alphabet_size += len(cls.SYMBOLS)
        if alphabet_size == 0:
            return 0.0
        return math.log2(alphabet_size) * len(password)
