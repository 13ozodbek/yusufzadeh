import uuid

from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models

gender_types = (
    (1, 'male'),
    (2, 'female'),
    (3, 'other'),
)

otp_types = (
    (1, 'register'),
    (2, 'resend'),
    (3, 'reset'),
)
user_type = (
    (1, 'admin'),
    (2, 'user'),
    (3, 'superuser'),
    (4, 'staff'),
)


class Authentication(AbstractUser):
    username = models.CharField(unique=True, max_length=255)
    image = models.ImageField(upload_to='images/', blank=True, null=True)
    age = models.IntegerField(default=1, null=True)
    gender = models.IntegerField(choices=gender_types, default=1, null=True)
    workplace = models.CharField(max_length=255, default='Apple', null=True)
    user_type = models.IntegerField(choices=user_type, default=2)

    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username


class OTP(models.Model):
    otp_user = models.OneToOneField(Authentication, on_delete=models.CASCADE)
    otp_code = models.IntegerField(default=0)
    otp_key = models.UUIDField(default=uuid.uuid4, editable=False)
    otp_type = models.IntegerField(choices=otp_types, default=1)
    otp_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.otp_user)


class FollowUser(models.Model):
    user = models.ForeignKey(Authentication, on_delete=models.CASCADE, related_name='follower')
    followers = models.ManyToManyField(Authentication)

    def __str__(self):
        return str(self.user.username)
