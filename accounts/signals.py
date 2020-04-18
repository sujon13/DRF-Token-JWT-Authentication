from django.db.models.signals import post_save
from django.dispatch import receiver
from accounts.models import CustomUser
from rest_framework.authtoken.models import Token


@receiver(post_save, sender=CustomUser)
def create_auth_token(sender, instance, created, **kwargs):
    if created:
        Token.objects.create(user=instance)

