from django.middleware.csrf import CsrfViewMiddleware

from users.core import client_wants_app_tokens


class ConditionalCsrfMiddleware(CsrfViewMiddleware):
    def process_view(self, request, callback, callback_args, callback_kwargs):
        if client_wants_app_tokens(request):
            setattr(request, "_skip_csrf_mw", True)
            return None
        return super().process_view(request, callback, callback_args, callback_kwargs)

    def process_response(self, request, response):
        if getattr(request, "_skip_csrf_mw", False):
            return response
        return super().process_response(request, response)
