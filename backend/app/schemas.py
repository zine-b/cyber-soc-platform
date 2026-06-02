from pydantic import BaseModel

# -------------------------
# Request schemas
# -------------------------
class LogInput(BaseModel):
    source: str
    log_type: str
    message: str