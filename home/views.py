from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import (render,
                              get_object_or_404)
from rest_framework import status
from rest_framework.response import Response

from home.models import (Post,
                         Comment,
                         UserProfile,
                         AboutMe,
                         HomeViewInfo,
                         Contact)
from .serializers import CommentSerializer


def home(request):
    home_info = HomeViewInfo.objects.all().first()
    return render(request,
                  'index.html',
                  {'home_info': home_info},
                  status=status.HTTP_200_OK)


def about(request):
    about = AboutMe.objects.all().first()
    return render(request,
                  'about.html',
                  {'about': about},
                  status=status.HTTP_200_OK)


def blog(request):
    posts = Post.objects.filter(is_published=True)

    p = {
        'posts': posts,
    }
    return render(request,
                  'blog.html',
                  context=p,
                  status=status.HTTP_200_OK)


def blog_post(request, pk):
    post = get_object_or_404(Post, pk=pk)
    comment = Comment.objects.create(content=request.get['message'],
                                     user=request.user,
                                     post=post
                                     )
    posts = Post.objects.all()

    paginator = Paginator(posts, 1)
    page_number = request.GET.get('page', pk)
    page_obj = paginator.get_page(page_number)
    # post = paginator.get_page(pk)
    context = {
        'post': post,
        'page_obj': page_obj,
        'comment': comment
    }

    return render(request, 'article.html', context=context)


def comments(request, pk):
    if not request.user.is_authenticated:
        return Response('First you need to login',
                        status=status.HTTP_401_UNAUTHORIZED)

    post = Post.objects.get(pk=pk)
    serializer = CommentSerializer(post, data=request.data)

    if not post:
        return HttpResponse(data={'page not found'},
                            status=status.HTTP_404_NOT_FOUND)
    if not UserProfile.objects.filter(user=request.user).first():
        return HttpResponse(data={'user not found'},
                            status=status.HTTP_404_NOT_FOUND)
    if request.data['content'] is None:
        return HttpResponse(data={'None'},
                            status=status.HTTP_404_NOT_FOUND)

    comment = Comment.objects.create(author=request.user,
                                     post=serializer.data['post'],
                                     content=serializer.data['content'],
                                     )

    comment.save()

    return render(request,
                  'blog.html',
                  'Comment saved',
                  status=status.HTTP_200_OK)

def contact(request):
    if request.method == 'POST':
        contact = Contact.objects.create(name=request.POST['name'],
                                         message=request.POST['message'],
                                         email=request.POST['email'],
                                         phone=request.POST['phone'],)
        contact.save()

    return render(request,
                  'contact.html',
                  status=status.HTTP_200_OK)