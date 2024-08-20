from datetime import datetime

from django.contrib.auth.models import User
from django.db import models

from management.models import Authentication


class Post(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    image = models.ImageField(upload_to="images/")
    is_published = models.BooleanField(default=False)

    date_posted = datetime.now().strftime("%B %d, %Y")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class UserProfile(models.Model):
    user = models.OneToOneField(User,
                                on_delete=models.CASCADE)

    def __str__(self):
        return self.user.first_name


class Comment(models.Model):
    post = models.ForeignKey(Post,
                             on_delete=models.CASCADE)
    user = models.ForeignKey(UserProfile,
                             on_delete=models.CASCADE)
    content = models.TextField()
    date_posted = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.user.first_name


class AboutMe(models.Model):
    content_p1 = models.TextField()
    content_p2 = models.TextField(null=True,
                                  blank=True)
    content_p3 = models.TextField(null=True,
                                  blank=True)
    image = models.ImageField(upload_to="images/")

    def save(self, *args, **kwargs):
        if not self.pk and AboutMe.objects.exists():
            return 'Only one instance can be create'
        return super(AboutMe, self).save(*args, **kwargs)



class HomeViewInfo(models.Model):
    profile_picture = models.ImageField(upload_to="images/")
    full_name = models.TextField()
    role = models.TextField()
    little_description = models.TextField(max_length=100,
                                          null=True,
                                          blank=True)
    yt_link = models.URLField(null=True,
                              blank=True)
    tg_link = models.URLField(null=True,
                              blank=True)
    ig_link = models.URLField(default='https://www.instagram.com/o.tulkinovich/')
    github_link = models.URLField(default='https://github.com/13ozodbek')
    linkedin_link = models.URLField(default='https://www.linkedin.com/in/ozodbek-yusupov-021919317/')

    def save(self, *args, **kwargs):
        if not self.pk and HomeViewInfo.objects.exists():
            return 'Only one instance can be create'
        return super(HomeViewInfo, self).save(*args, **kwargs)


class Contact(models.Model):
    name = models.TextField()
    email = models.EmailField()
    message = models.TextField()
    phone = models.TextField()


    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return (f'{self.name} :: {self.phone}')