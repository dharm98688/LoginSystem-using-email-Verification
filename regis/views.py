from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.template.loader import render_to_string
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from LoginSystem import settings
from django.core.mail import send_mail, EmailMessage

from .tokens import generate_token


# Create your views here.


def home(request):
    return render(request, "regis/home.html")


def signup(request):
    if request.method == 'POST':
        # username = request.POST.get('username') #both are same work
        username = request.POST['username']
        firstname = request.POST['first_name']
        lastname = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if User.objects.filter(username=username):
            messages.error(request, "Username already exists")
            return redirect('home')
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is Already Exists!")
            return redirect('home')
        if len(username) > 20:
            messages.info(request, 'Username must be under 20 characters')
            return redirect('home')
        if password != confirm_password:
            messages.error(request, "Password did not matched!")
            return redirect("home")
        if not username.isalnum():
            messages.error(request, "Username is in alpha- numeric")

        myuser = User.objects.create_user(username, email, password)
        myuser.first_name = firstname
        myuser.last_name = lastname
        myuser.is_active = False

        myuser.save()
        messages.success(request,
                         "Your Account is successfully created!!, we have sent you the confirmation email to confirm your email")

        # Welcome Message
        subject = "Welcome to Django Login"
        message = "Hello" + myuser.first_name + \
                  "!! \n " + \
                  "Welcome to Django!! \n Thank you for the visiting our websites, we have also sent confirmation email ," \
                  " please confirm your email inorder to activate your account! thank you"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        # Email Address Confirmation Mail
        current_site = get_current_site(request)
        email_subject = "Confirm your email @Blog- Django Login!!"
        message2 = render_to_string('emailconfirmation.html', {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email]
        )
        email.fail_silently = True
        email.send()

        return redirect("signin")

    return render(request, "regis/signup.html")


def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            firstname = user.first_name
            return render(request, "regis/home.html", {"first_name": firstname})
        else:
            messages.error(request, "Bad Credentials")
            return redirect("home")

    return render(request, "regis/signin.html")


def signout(request):
    logout(request)
    messages.success(request, "Logout Successfully")
    return redirect("home")


def activate(request, uidb64, token):
    # try:
    #     uid = force_str(urlsafe_base64_decode(uidb64))
    #     myuser = User.objects.get(pk=uid)
    # except (TypeError, ValueError, OverflowError, User.DoesNotExist):
    #     myuser = None
    #
    # if myuser is None and generate_token.check_token(myuser, token):
    #     myuser.is_active = True
    #     myuser.save()
    #     login(request, myuser)
    #     return redirect('home')
    # else:
    #     return render(request, 'activation_failed.html')
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request, myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request, 'activation_failed.html')
