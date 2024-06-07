from flask_login import current_user

class CheckRights:
    ADMIN_ROLE_ID = 1
    USER_ROLE_ID = 2

    def __init__(self, record):
        self._record = record
    
    def show(self):
        return True
    
    def create(self):
        return current_user.is_admin()
    
    def delete(self):
        return current_user.is_admin()
    
    def edit(self):
        if current_user.id == self._record.id:
            return True
        return current_user.is_admin()
    
    def show_log(self):
        if current_user.role_id == CheckRights.ADMIN_ROLE_ID:
            return True
        return False

        

    