# core/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy, reverse
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from .models import Item


from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes

from django.utils.html import strip_tags
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.exceptions import ValidationError
from django.contrib import messages  # Importar o módulo de mensagens
from django.contrib.sites.shortcuts import get_current_site


def register(request):
    User = get_user_model()
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.error(request, 'As senhas não coincidem.')
            return render(request, 'core/register.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Este e-mail já está em uso.')
            return render(request, 'core/register.html')

        user = User.objects.create_user(username=username, email=email, password=password1)
        user.is_active = False  # O usuário deve confirmar o e-mail para ativar a conta
        user.save()

        # Enviar e-mail de verificação
        subject = 'Confirme seu endereço de e-mail'
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        current_site = get_current_site(request)
        protocol = 'https' if request.is_secure() else 'http'
        full_url = f"{protocol}://{current_site.domain}{reverse('email_confirm', kwargs={'uid': uid, 'token': token})}"

        html_message = render_to_string('core/email_confirm.html', {
            'user': user,
            'full_url': full_url,
        })
        plain_message = strip_tags(html_message)
        from_email = 'norepry@example.com'
        send_mail(subject, plain_message, from_email, [email], html_message=html_message)

        messages.success(request, 'Por favor, verifique seu e-mail para confirmar sua conta.')
        return redirect('login')

    return render(request, 'core/register.html')

def email_confirm(request, uid, token):
    User = get_user_model()
    try:
        uid = urlsafe_base64_decode(uid).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Sua conta foi ativada com sucesso!')
        return redirect('login')
    else:
        messages.error(request, 'O link de confirmação é inválido ou expirou.')
        return render(request, 'core/email_confirm_failed.html')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('item_list')

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            next_url = request.POST.get('next', '')
            if not next_url or next_url == '/':
                next_url = reverse('item_list')
            return redirect(next_url)
        else:
            messages.error(request, 'Nome de usuário ou senha inválidos.')
            return render(request, 'core/login.html', {'next': request.POST.get('next', '')})

    next_url = request.GET.get('next', '')
    return render(request, 'core/login.html', {'next': next_url})

def logout_view(request):
    logout(request)
    return redirect('login')

class ItemListView(LoginRequiredMixin, ListView):
    model = Item
    template_name = 'core/item_list.html'
    context_object_name = 'items'
    login_url = 'login'

    def get_queryset(self):
        queryset = super().get_queryset()
        # Filtrar por nome do item se o parâmetro de filtro estiver presente
        filter_name = self.request.GET.get('name')
        if filter_name:
            queryset = queryset.filter(name__icontains=filter_name)
        return queryset

class ItemDetailView(LoginRequiredMixin, DetailView):
    model = Item
    template_name = 'core/item_detail.html'
    login_url = 'login'

class ItemCreateView(LoginRequiredMixin, CreateView):
    model = Item
    fields = ['name', 'description']  # Use os campos do modelo diretamente
    login_url = 'login'

    def form_valid(self, form):
        form.instance.owner = self.request.user  # Define o owner como o usuário atual
        return super().form_valid(form)

    def get_success_url(self):
        return reverse_lazy('item_list')

class ItemUpdateView(LoginRequiredMixin, UpdateView):
    model = Item
    fields = ['name', 'description']
    template_name = 'core/item_form.html'
    success_url = reverse_lazy('item_list')
    login_url = 'login'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Edit Item'
        context['button_text'] = 'Update'
        return context

class ItemDeleteView(LoginRequiredMixin, DeleteView):
    model = Item
    template_name = 'core/item_confirm_delete.html'
    success_url = reverse_lazy('item_list')
    login_url = 'login'
