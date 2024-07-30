from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from .views import home, about, blog, blog_post, comments

urlpatterns = [
    path('', home),
    path('about/', about),
    path('blog/', blog),
    path('blog_post/<int:pk>/', blog_post),
    path('comments/<int:pk>/', comments),


]


urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
