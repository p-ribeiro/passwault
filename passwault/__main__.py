from passwault.core.utils.database import init_db
from passwault.core.cli import cli

if __name__ == "__main__":
    init_db()
    cli()