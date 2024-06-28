from django.apps import AppConfig


class DjIntgConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'dj_intg'
    
    def ready(self):
        import dj_intg.signals
