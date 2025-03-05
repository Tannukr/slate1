import jwt
import datetime
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .serializers import UserSerializer, LoginSerializer
from rest_framework.permissions import AllowAny

# MongoDB collection reference
users_collection = settings.MONGO_COLLECTION["users"]

class LoginView(APIView):
    permission_classes = [AllowAny]  

    def generate_jwt_token(self, email):
        """Generate JWT token manually"""
        payload = {
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),  # Token valid for 1 day
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        return token

    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = users_collection.find_one({"email": email})

        if user:
            if password == user["password"]:  
                access_token = self.generate_jwt_token(email)

                return Response({
                    'access_token': access_token,
                    "email": user["email"],
                    "role": user["role"]
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Incorrect password"}, status=status.HTTP_400_BAD_REQUEST)

        if "role" not in request.data:
            return Response({"error": "New user detected. Please provide a role."}, status=status.HTTP_400_BAD_REQUEST)

        role_serializer = UserSerializer(data=request.data)
        if not role_serializer.is_valid():
            return Response(role_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        
        new_user = {
            "email": email,
            "password": password,  
            "role": request.data["role"]
        }
        users_collection.insert_one(new_user)

        access_token = self.generate_jwt_token(email)

        return Response({
            "access_token": access_token,
            "email": email,
            "role": request.data["role"]
        }, status=status.HTTP_201_CREATED)
