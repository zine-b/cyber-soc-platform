from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv
import os
# -------------------------
# Database configuration
# -------------------------
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyber_soc.db")

# l’objet qui gère la connexion entre app Python et la base de données
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Une session SQLAlchemy sert à parler avec la base de données : ajouter, lire, modifier, supprimer des données.
SessionLocal = sessionmaker(
    # les changements ne sont pas validés automatiquement --> db.commit()
    # synchronise pas automatiquement les changements avec la base avant certaines requêtes
    autocommit=False,
    autoflush=False,
    bind=engine
)

# crée la classe de base pour définir tes tables.
Base = declarative_base()

def get_db():
    return SessionLocal()