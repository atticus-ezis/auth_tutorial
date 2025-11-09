from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.utils import user_pk_to_url_str
from allauth.account.forms import default_token_generator
from django.conf import settings


# creates url for email confirmation


class CustomAccountAdapter(DefaultAccountAdapter):
    def send_mail(self, template_prefix, email, context):
        if "email_confirmation" in template_prefix:
            if "key" in context:
                key = context["key"]
                context["activate_url"] = (
                    f"{settings.FRONTEND_URL}{settings.VERIFY_EMAIL_URL}{key}"
                )

        if "password_reset_key" in template_prefix:
            user = context.get("user")
            if user:
                uid = user_pk_to_url_str(user)
                token = default_token_generator.make_token(user)
                context["password_reset_url"] = (
                    f"{settings.FRONTEND_URL}{settings.PASSWORD_RESET_URL}{uid}/{token}/"
                )

        return super().send_mail(template_prefix, email, context)
