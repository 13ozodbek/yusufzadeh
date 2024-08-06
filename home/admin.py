from django.contrib import admin
from .models import Post, UserProfile, AboutMe, HomeViewInfo, Contact


admin.site.register(Post)
admin.site.register(UserProfile)
admin.site.register(AboutMe)
admin.site.register(HomeViewInfo)
admin.site.register(Contact)