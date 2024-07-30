from rest_framework import serializers

from home.models import Post, Comment


class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = 'title', 'content', 'date_posted'

class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = 'content', 'post'
