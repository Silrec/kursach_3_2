# cli.py
# CLI-интерфейс менеджера паролей (библиотека Click)

import click
import getpass
import os
from passmanager.crypto import CryptoManager
from passmanager.vault import Vault
from passmanager.autofill import AutofillManager, PasswordGenerator
from passmanager.backup import BackupManager


DB_PATH    = os.path.expanduser("~/.passmanager/vault.db")
BACKUP_DIR = os.path.expanduser("~/.passmanager/backups")


def get_vault() -> tuple[Vault, CryptoManager]:
    """Создать и разблокировать хранилище."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    crypto = CryptoManager()
    vault  = Vault(DB_PATH, crypto)
    vault.connect()
    vault.init_schema()
    return vault, crypto


@click.group()
def cli():
    """Менеджер паролей с AES-256-GCM шифрованием."""
    pass


@cli.command()
def init():
    """Инициализировать новое хранилище."""
    vault, _ = get_vault()
    password = getpass.getpass("Введите мастер-пароль: ")
    confirm  = getpass.getpass("Подтвердите мастер-пароль: ")
    if password != confirm:
        click.echo("Пароли не совпадают.", err=True)
        return
    if len(password) < 8:
        click.echo("Мастер-пароль должен быть не менее 8 символов.",
                   err=True)
        return
    vault.setup_master_password(password)
    click.echo("Хранилище успешно инициализировано.")
    vault.close()


@cli.command()
@click.option("--title",    "-t", required=True,  help="Название записи")
@click.option("--username", "-u", required=True,  help="Имя пользователя")
@click.option("--url",      "-l", default="",     help="URL сайта")
@click.option("--notes",    "-n", default="",     help="Примечания")
def add(title, username, url, notes):
    """Добавить новую запись."""
    vault, _ = get_vault()
    master   = getpass.getpass("Мастер-пароль: ")
    if not vault.unlock(master):
        click.echo("Неверный мастер-пароль.", err=True)
        vault.close()
        return
    password = getpass.getpass("Пароль для записи"
                               " (Enter — сгенерировать): ")
    if not password:
        password = PasswordGenerator.generate()
        click.echo(f"Сгенерирован пароль длиной"
                   f" {len(password)} символов.")
    entry_id = vault.add_entry(title, username, password,
                               url, notes)
    click.echo(f"Запись добавлена (id={entry_id}).")
    vault.close()


@cli.command()
@click.argument("query")
def search(query):
    """Найти записи по домену или названию."""
    vault, _ = get_vault()
    master   = getpass.getpass("Мастер-пароль: ")
    if not vault.unlock(master):
        click.echo("Неверный мастер-пароль.", err=True)
        vault.close()
        return
    entries = vault.search_entries(query)
    if not entries:
        click.echo("Записи не найдены.")
    else:
        for e in entries:
            click.echo(f"[{e.id}] {e.title}"
                       f"  Пользователь: {e.username}"
                       f"  URL: {e.url}")
    vault.close()


@cli.command()
@click.argument("query")
def copy(query):
    """Найти запись и скопировать пароль в буфер обмена."""
    vault, _ = get_vault()
    master   = getpass.getpass("Мастер-пароль: ")
    if not vault.unlock(master):
        click.echo("Неверный мастер-пароль.", err=True)
        vault.close()
        return
    af = AutofillManager(vault)
    af.autofill(query)
    vault.close()


@cli.command()
@click.argument("entry_id", type=int)
def delete(entry_id):
    """Удалить запись по id."""
    vault, _ = get_vault()
    master   = getpass.getpass("Мастер-пароль: ")
    if not vault.unlock(master):
        click.echo("Неверный мастер-пароль.", err=True)
        vault.close()
        return
    if vault.delete_entry(entry_id):
        click.echo(f"Запись {entry_id} удалена.")
    else:
        click.echo(f"Запись {entry_id} не найдена.", err=True)
    vault.close()


@cli.command()
@click.option("--length", "-l", default=20,
              help="Длина пароля (мин. 12)")
@click.option("--no-symbols", is_flag=True,
              help="Без спецсимволов")
def generate(length, no_symbols):
    """Сгенерировать случайный пароль."""
    password = PasswordGenerator.generate(
        length=length,
        use_symbols=not no_symbols
    )
    entropy = PasswordGenerator.estimate_entropy(password)
    click.echo(f"Пароль: {password}")
    click.echo(f"Энтропия: {entropy:.1f} бит")


@cli.command()
def backup():
    """Создать резервную копию хранилища."""
    vault, crypto = get_vault()
    master = getpass.getpass("Мастер-пароль: ")
    if not vault.unlock(master):
        click.echo("Неверный мастер-пароль.", err=True)
        vault.close()
        return
    bm = BackupManager(DB_PATH, BACKUP_DIR, crypto)
    bm.create_backup()
    vault.close()


@cli.command()
@click.argument("backup_file")
def restore(backup_file):
    """Восстановить хранилище из резервной копии."""
    vault, crypto = get_vault()
    master = getpass.getpass("Мастер-пароль: ")
    if not vault.unlock(master):
        click.echo("Неверный мастер-пароль.", err=True)
        vault.close()
        return
    vault.close()
    bm = BackupManager(DB_PATH, BACKUP_DIR, crypto)
    bm.restore_backup(backup_file)


@cli.command("list")
def list_entries():
    """Показать список всех записей."""
    vault, _ = get_vault()
    master   = getpass.getpass("Мастер-пароль: ")
    if not vault.unlock(master):
        click.echo("Неверный мастер-пароль.", err=True)
        vault.close()
        return
    entries = vault.list_entries()
    if not entries:
        click.echo("Хранилище пусто.")
    else:
        click.echo(f"Всего записей: {len(entries)}")
        click.echo("-" * 50)
        for e in entries:
            click.echo(f"[{e.id}] {e.title}"
                       f"  ({e.username})"
                       f"  {e.url or '—'}")
    vault.close()


if __name__ == "__main__":
    cli()
