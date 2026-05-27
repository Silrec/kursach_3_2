# backup.py
# Модуль резервного копирования

import os
import shutil
import hashlib
from datetime import datetime
from typing import List
from passmanager.crypto import CryptoManager


class BackupManager:
    """
    Управляет резервными копиями зашифрованного хранилища.
    Копии хранятся в зашифрованном виде (.enc).
    Поддерживает ротацию: удаляет самые старые копии
    при превышении лимита.
    """

    def __init__(self, db_path: str,
                 backup_dir: str,
                 crypto: CryptoManager,
                 max_backups: int = 5):
        """
        Args:
            db_path: путь к основному файлу БД.
            backup_dir: директория для хранения копий.
            crypto: инициализированный CryptoManager.
            max_backups: максимальное число хранимых копий.
        """
        self.db_path     = db_path
        self.backup_dir  = backup_dir
        self.crypto      = crypto
        self.max_backups = max_backups
        os.makedirs(backup_dir, exist_ok=True)

    # ── Создание резервной копии ──────────────────────────────────

    def create_backup(self) -> str:
        """
        Создать зашифрованную резервную копию хранилища.
        Имя файла: backup_YYYY-MM-DD_HH-MM-SS.db.enc
        Returns:
            Путь к созданному файлу резервной копии.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename  = f"backup_{timestamp}.db.enc"
        dst_path  = os.path.join(self.backup_dir, filename)
        # Зашифровать файл БД
        self.crypto.encrypt_file(self.db_path, dst_path)
        size     = os.path.getsize(dst_path)
        checksum = self._checksum(dst_path)
        print(f"Резервная копия создана: {filename}")
        print(f"  Размер: {size} байт, контрольная сумма: {checksum[:16]}...")
        # Ротация старых копий
        self._rotate()
        return dst_path

    # ── Восстановление ───────────────────────────────────────────

    def restore_backup(self, backup_path: str) -> bool:
        """
        Восстановить хранилище из резервной копии.
        Перед восстановлением создаётся копия текущего состояния.
        Args:
            backup_path: путь к файлу резервной копии (.enc).
        Returns:
            True при успехе.
        """
        if not os.path.exists(backup_path):
            raise FileNotFoundError(
                f"Файл резервной копии не найден: {backup_path}")
        # Проверить контрольную сумму
        checksum = self._checksum(backup_path)
        print(f"Восстановление из {os.path.basename(backup_path)}...")
        print(f"  Контрольная сумма: {checksum[:16]}...")
        # Создать временную копию текущей БД
        temp_path = self.db_path + ".bak_before_restore"
        if os.path.exists(self.db_path):
            shutil.copy2(self.db_path, temp_path)
        try:
            self.crypto.decrypt_file(backup_path, self.db_path)
            # Удалить временную копию при успехе
            if os.path.exists(temp_path):
                os.remove(temp_path)
            print("Восстановление завершено успешно.")
            return True
        except Exception as exc:
            # Откатить при ошибке
            if os.path.exists(temp_path):
                shutil.move(temp_path, self.db_path)
            raise RuntimeError(
                f"Ошибка восстановления: {exc}") from exc

    # ── Список и ротация ─────────────────────────────────────────

    def list_backups(self) -> List[str]:
        """
        Вернуть список файлов резервных копий, отсортированных
        по дате создания (новые в начале).
        """
        files = [
            f for f in os.listdir(self.backup_dir)
            if f.startswith("backup_") and f.endswith(".db.enc")
        ]
        files.sort(reverse=True)
        return [os.path.join(self.backup_dir, f) for f in files]

    def _rotate(self) -> None:
        """
        Удалить самые старые резервные копии,
        если их число превышает max_backups.
        """
        backups = self.list_backups()
        while len(backups) > self.max_backups:
            oldest = backups.pop()
            os.remove(oldest)
            print(f"Удалена старая копия: {os.path.basename(oldest)}")

    @staticmethod
    def _checksum(file_path: str) -> str:
        """Вычислить SHA-256 контрольную сумму файла."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
