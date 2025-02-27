from django.contrib import admin
from .models import CustomUser,MenuSelection, Service, Appointment, Booking

admin.site.register(CustomUser)
admin.site.register(MenuSelection)
admin.site.register(Service)
admin.site.register(Appointment)
admin.site.register(Booking)
# Register your models here.
