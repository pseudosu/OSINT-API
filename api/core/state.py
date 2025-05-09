import httpx

# Global application state to be shared across modules
class AppState:
    def __init__(self):
        self.redis = None
        self.http_client = None

# Single instance to be imported by other modules
app_state = AppState()