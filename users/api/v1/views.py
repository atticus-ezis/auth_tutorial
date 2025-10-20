from rest_framework.views import APIView
from dj_rest_auth.views import PasswordResetConfirmView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from allauth.account.utils import url_str_to_user_pk 
from rest_framework_simplejwt.tokens import RefreshToken
import traceback
from dj_rest_auth.jwt_auth import set_jwt_cookies
from allauth.account.models import EmailConfirmation, EmailConfirmationHMAC
from rest_framework.exceptions import ValidationError 
from django.contrib.auth import get_user_model


class CustomVerifyEmailView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []  
    def post(self, request):
        key = request.data.get("key")
        print(f"Key: {key}")
        if not key:
            raise ValidationError({"key": [("Missing verification key.")]})

        try:
            emailconfirmation = EmailConfirmation.objects.filter(
                key=key
            ).first() or EmailConfirmationHMAC.from_key(key)
            if not emailconfirmation:
                raise ValidationError({"key": [("Invalid verification key.")]})

            # Confirm the email address (marks it as verified in the database)
            emailconfirmation.confirm(request)
            
            user = emailconfirmation.email_address.user

            refresh = RefreshToken.for_user(user)
            access = refresh.access_token

            resp = Response(
                {
                    "detail": "Email confirmed successfully",
                    "access": str(access),
                    "refresh": str(refresh),
                },
                status=status.HTTP_200_OK,
            )
            set_jwt_cookies(resp, str(access), str(refresh))
            return resp

        except Exception as e:
            print(f"Error: {e}")
            print(traceback.format_exc())
            return Response(
                {"key": [f"Error: {str(e)}"]},
                status=status.HTTP_400_BAD_REQUEST,
            )


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    """
    Custom password reset confirm view that automatically logs the user in
    after successful password reset by returning JWT tokens and setting cookies.
    """
    permission_classes = [AllowAny]  
    authentication_classes = [] 
    
    def post(self, request, *args, **kwargs):
        
        try:
            response = super().post(request, *args, **kwargs)   

            if response.status_code == status.HTTP_200_OK:
                User = get_user_model()
                uid = request.data.get("uid")
                
                # Decode uid using allauth's base36 decoder
                user_pk = url_str_to_user_pk(uid)
                user = User.objects.get(pk=user_pk)
                
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                access = refresh.access_token
                
                # Add tokens to response data
                response.data["access"] = str(access)
                response.data["refresh"] = str(refresh)
                
                # Set JWT cookies
                set_jwt_cookies(response, str(access), str(refresh))
            
            return response
            
        except Exception as e:
            print(f"Error in CustomPasswordResetConfirmView: {e}")
            print(traceback.format_exc())
            return Response(
                {"detail": [f"Error: {str(e)}"]},
                status=status.HTTP_400_BAD_REQUEST,
            )