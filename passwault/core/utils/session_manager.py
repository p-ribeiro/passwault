class SessionManager:
    def __init__(self):
        self.session = None

    def is_logged_in(self):
        return self.session is not None

    def create_session(self, user_data):
        self.session = user_data

    def logout(self):
        self.session = None

    def get_session(self):
        return self.session
