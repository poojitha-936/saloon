from django.contrib import admin
from .models import CustomUser,MenuSelection, Service, Appointment

admin.site.register(CustomUser)
admin.site.register(MenuSelection)
admin.site.register(Service)
admin.site.register(Appointment)
# Register your models here.
