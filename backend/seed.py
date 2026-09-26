"""One-off script to create a local dev admin account.

Run after migrations: python seed.py
Creates the same tester1 / 1234 login the frontend's login.js used as its
placeholder credentials, so the existing UI keeps working once it's wired
to the real API.
"""

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models.user import AdminUser


def main() -> None:
    db = SessionLocal()
    try:
        existing = db.query(AdminUser).filter(AdminUser.username == "tester1").first()
        if existing:
            print("tester1 already exists, skipping.")
            return

        admin = AdminUser(
            username="tester1",
            display_name="tester1",
            password_hash=hash_password("1234"),
        )
        db.add(admin)
        db.commit()
        print("Created admin user tester1 / 1234")
    finally:
        db.close()


if __name__ == "__main__":
    main()
