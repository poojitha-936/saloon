from datetime import timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken





class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email= self.normalize_email(email)

        if CustomUser.objects.filter(email=email).exists():
            raise ValueError('A user with this email already exists.')
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self,email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(username, email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, blank=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']


    objects = CustomUserManager()

    def __str__(self):
        return self.email
    

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }


class MenuSelection(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name


class Service(models.Model):
    name = models.CharField(max_length=255)                              # Name of the service (e.g., "Men's Haircut")
    description = models.TextField(blank=True, null=True)                                     # Description of the service
    price = models.DecimalField(max_digits=10, decimal_places=2)          # Price for the service
    duration_minutes = models.PositiveIntegerField()                             # Duration of the service in minutes

    def __str__(self):
        return self.name


class Appointment(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE,null=True)    # Link to a user (customer)
    service = models.ManyToManyField(Service)                         # This is a ManyToMany relationship
    date = models.DateField()                                         # The date of the appointment
    time = models.TimeField()                                         # The time of the appointment
    status = models.CharField(
        max_length=20,
        choices=[('pending', 'pending'),('confirmed', 'confirmed'),('canceled','canceled')],
        default='pending'
    )     
    
    def __str__(self):
        return f"Appointment for {self.user.username} - {self.service.name} on {self.date} at {self.time}"


class Booking(models.Model):
    PENDING = 'pending',
    CONFIRMED = 'confirmed',
    CANCELED = 'canceled',

    STATUS_CHOICES = [
       (PENDING, 'pending'),
       (CONFIRMED, 'confirmed'),
       (CANCELED, 'canceled')
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE,null=True)    # Link to a user (customer)
    service = models.ManyToManyField(Service)                         # This is a ManyToMany relationship
    date = models.DateField()                                         # The date of the appointment
    time = models.TimeField()   











# Create your models here.
