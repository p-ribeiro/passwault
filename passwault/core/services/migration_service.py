"""Migration service for exporting data to a portable SQLite database.

Copies all users and encrypted passwords from the source database
to a new SQLite file. Encrypted data is copied as-is — no decryption needed.
"""

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from passwault.core.database.models import Base, PasswordManager, SessionLocal, User
from passwault.core.utils.logger import Logger


class MigrationService:
    """Service for migrating database contents to a portable SQLite file."""

    def migrate_to_sqlite(self, output_path: str) -> Path:
        """Migrate all data from the current database to a SQLite file.

        Args:
            output_path: Destination path for the SQLite database file.

        Returns:
            Path to the created SQLite file.

        Raises:
            FileExistsError: If the output file already exists.
            RuntimeError: If migration fails.
        """
        output = Path(output_path).resolve()

        if output.exists():
            raise FileExistsError(f"Output file already exists: {output}")

        # Ensure parent directory exists
        output.parent.mkdir(parents=True, exist_ok=True)

        target_engine = create_engine(
            f"sqlite:///{output}",
            echo=False,
            poolclass=NullPool,
        )

        @event.listens_for(target_engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        try:
            # Create schema in target
            Base.metadata.create_all(target_engine)

            TargetSession = sessionmaker(bind=target_engine)
            target_session = TargetSession()
            source_session = SessionLocal()

            try:
                # Copy users
                users = source_session.query(User).all()
                for user in users:
                    target_session.execute(
                        User.__table__.insert().values(
                            id=user.id,
                            username=user.username,
                            email=user.email,
                            master_password_hash=user.master_password_hash,
                            salt=user.salt,
                            kdf_algorithm=user.kdf_algorithm,
                            kdf_iterations=user.kdf_iterations,
                            created_at=user.created_at,
                            updated_at=user.updated_at,
                            last_login=user.last_login,
                        )
                    )

                target_session.flush()

                # Copy passwords
                passwords = source_session.query(PasswordManager).all()
                for pw in passwords:
                    target_session.execute(
                        PasswordManager.__table__.insert().values(
                            id=pw.id,
                            user_id=pw.user_id,
                            resource_name=pw.resource_name,
                            username=pw.username,
                            encrypted_password=pw.encrypted_password,
                            nonce=pw.nonce,
                            website=pw.website,
                            description=pw.description,
                            tags=pw.tags,
                            created_at=pw.created_at,
                            updated_at=pw.updated_at,
                        )
                    )

                target_session.commit()
                Logger.info(
                    f"Migrated {len(users)} user(s) and {len(passwords)} password(s)"
                )
                return output

            except Exception:
                target_session.rollback()
                raise
            finally:
                target_session.close()
                source_session.close()

        except Exception as e:
            # Clean up partial file on failure
            output.unlink(missing_ok=True)
            raise RuntimeError(f"Migration failed: {e}") from e
        finally:
            target_engine.dispose()
