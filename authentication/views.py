from django.views.generic import TemplateView

class PasswordResetView(TemplateView):
    template_name = 'password_reset_confirm.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context
