import jwt
import datetime
import uuid
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .serializers import UserSerializer, LoginSerializer
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
users_collection = settings.MONGO_COLLECTION["users"]
parents_collection = settings.MONGO_COLLECTION["parents"]
children_collection = settings.MONGO_COLLECTION["children"]
achievements_collection = settings.MONGO_COLLECTION["achievements"]
award_collection = settings.MONGO_COLLECTION["award"]
schools_collection = settings.MONGO_COLLECTION["schools"]
students_collection = settings.MONGO_COLLECTION["students"]

from rest_framework_simplejwt.tokens import AccessToken

class LoginView(APIView):
    permission_classes = [AllowAny]  


    def generate_jwt_token(self, userid, email, role):
    
        token = RefreshToken()
        token["userid"] = userid
        token["email"] = email
        token["role"] = role
        return str(token.access_token)


    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = users_collection.find_one({"email": email})

        if user:
            if password == user["password"]:  
                userid = user.get("userId")  
                access_token = self.generate_jwt_token(userid, email, user["role"])

                return Response({
                    'access_token': access_token,
                    "userid": userid,
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

        last_user = users_collection.find_one({}, sort=[("userid", -1)])  
        new_userid = (last_user["userid"] + 1) if last_user else 1  

        new_user = {
            "userid": new_userid,
            "email": email,
            "password": password,  
            "role": request.data["role"]
        }
        inserted_user = users_collection.insert_one(new_user)

        access_token = self.generate_jwt_token(new_userid, email, request.data["role"])

        return Response({
            "_id": str(inserted_user.inserted_id),
            "access_token": access_token,
            "userid": new_userid,
            "email": email,
            "role": request.data["role"]
        }, status=status.HTTP_201_CREATED)



class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, role, userId):
        """Fetch user dashboard based on role and userid"""
        
        # Get Authorization token from request headers
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return Response({"error": "Authorization header is required."}, status=status.HTTP_401_UNAUTHORIZED)

        token = auth_header.split()[1]  # Extract JWT token
        try:
            # Decode JWT token
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])

            # Validate token content
            if 'userid' not in payload or 'role' not in payload:
                return Response({"error": "Invalid token payload"}, status=status.HTTP_401_UNAUTHORIZED)

            if payload["userid"] != userId or payload["role"] != role:
                return Response({"error": "Token does not match user details"}, status=status.HTTP_403_FORBIDDEN)

            # Retrieve user from the database
            user = users_collection.find_one({"userid": userId}, {"_id": 0, "password": 0})
            if not user:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            dashboard_data = {"user_info": user}

            # Fetch additional data based on role
            if role == "STUDENT":
                student_data = students_collection.find_one({"userid": userId}, {"_id": 0})
                dashboard_data["student_data"] = student_data or {}

            elif role == "TEACHER":
                teacher_data = achievements_collection.find({"teacher_id": userId}, {"_id": 0})
                dashboard_data["teacher_achievements"] = list(teacher_data)

            elif role == "PARENT":
                children_data = list(children_collection.find({"parent_id": userId}, {"_id": 0}))
                dashboard_data["children"] = children_data if children_data else []

            return Response({"dashboard": dashboard_data}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({"error": "Token has expired."}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.DecodeError:
            return Response({"error": "Invalid token."}, status=status.HTTP_401_UNAUTHORIZED)