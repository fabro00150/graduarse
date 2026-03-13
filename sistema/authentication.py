# sistema/authentication.py

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User


class AppMovilJWTAuthentication(JWTAuthentication):
    """
    Autenticación JWT personalizada para la app móvil.
    Verifica que el usuario pertenezca al grupo 'Operador' o sea superuser.
    """
    
    def authenticate(self, request):
        # Primero autenticar con JWT normal
        result = super().authenticate(request)
        
        if result is None:
            return None
        
        user, validated_token = result
        
        # Verificar que el usuario puede usar la API móvil
        es_operador = user.groups.filter(name='Operador').exists()
        es_superuser = user.is_superuser
        
        if not (es_operador or es_superuser):
            raise AuthenticationFailed(
                'No tienes permisos para acceder a la API móvil.'
            )
        
        return (user, validated_token)