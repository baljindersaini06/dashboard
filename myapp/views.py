from django.shortcuts import render, reverse, redirect, get_object_or_404
from .models import *
from .forms import (
    UserCreateForm, LoginForm, PasswordChangedForm, UserForm,SmtpForm,SiteForm, 
    ImageForm,UpdateSiteForm, SignUpForm, SetPasswordForm, CompanyForm, EmployeeForm)
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from django.template.response import TemplateResponse
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model
User = get_user_model()
from myapp.models import SiteConfiguration,SmtpConfiguration
from django_otp.decorators import otp_required
from two_factor.models import PhoneDevice
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from .tokens import account_activation_token
from django.core.mail import EmailMessage, send_mail
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User,Group
from django.contrib.auth import get_user_model
User = get_user_model()
from django.utils import six
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import permission_required




def group_required(group, login_url=None, raise_exception=False):
    """
    Decorator for views that checks whether a user has a group permission,
    redirecting to the log-in page if necessary.
    If the raise_exception parameter is given the PermissionDenied exception
    is raised.
    """
    def check_perms(user):
        if isinstance(group, six.string_types):
            groups = (group, )
        else:
            groups = group
        # First check if the user has the permission (even anon users)

        if user.groups.filter(name__in=groups).exists():
            return True
        # In case the 403 handler should be called raise the exception
        if raise_exception:
            raise PermissionDenied
        # As the last resort, show the login form
        return False
    return user_passes_test(check_perms, login_url='profile')


# def signup(request):
#     if request.method == 'POST':
#         form = UserCreateForm(request.POST)
#         if form.is_valid():
#             user= form.save(commit=False)
#             user.save()
#             return redirect('dashboard')

#     else:
#         form = UserCreateForm()
#     return render(request, 'auth/user_form.html', {'form': form})

@login_required
def signup(request):
    a=Group.objects.all()
    if request.method == 'POST':
        print("hello")
        form = SignUpForm(request.POST)
        if form.is_valid():
            print("hi")
            user= form.save(commit=False)
            user.phone_no = form.cleaned_data.get('phone_no')
            user.is_active = False
            user.save()
            role = form.cleaned_data.get('role')
            group = Group.objects.get(name=role)
            user.groups.add(group)
            current_site = get_current_site(request)
            mail_subject = 'Activate your Account.'
            message = render_to_string('account_activation_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)) ,
                'token':account_activation_token.make_token(user),
            })
            to_email = form.cleaned_data.get('email')
          
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.send()
            return HttpResponse('Please confirm your email address to complete the registration')
    else:      
        form = SignUpForm()
        
    return render(request, 'registration/user_registration.html', {'form': form,'a':a})



def activates(request, uidb64, token, backend='django.contrib.auth.backends.ModelBackend'):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        return HttpResponseRedirect(reverse('setpassword',args=(uid,)))
    else:
        return HttpResponse('Activation link is invalid!')


def setpassword(request,uid, backend='django.contrib.auth.backends.ModelBackend'):
    if request.method=='POST':
        form = SetPasswordForm(request.POST)
        if form.is_valid():
            user = User.objects.get(pk=uid)
            password = request.POST.get('password')
            password = form.cleaned_data['password']
            user.set_password(password)
            user.save()
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return redirect('/')
    else:
        form = SetPasswordForm()
    return render(request,"passwordset.html",{'form':form})


#@otp_required
@login_required
def index(request):
    try:
        a=PhoneDevice.objects.filter(user=request.user)
        if a:
            return render(request, 'myapp/index.html')
        else:
            return render(request, 'myapp/index.html')

    except PhoneDevice.DoesNotExist:
        a = None


@login_required
def profile(request):
    return render(request, 'myapp/profile.html')


@login_required
def calender(request):
    return render(request, 'myapp/page_calender.html')

def login_user(request):
    if request.method == 'POST':
        login_form = LoginForm(request.POST)
        if login_form.is_valid:
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request,username=username, password=password)          
            if user is not None:
                if user.is_active:
                    login(request, user)    
                    return redirect('/')
                    
    else:
        login_form = LoginForm()
    return render(request, 'registration/login.html', {'login_form': login_form,})


def success(request):
    return render(request, 'myapp/success.html')


@login_required
def profile_account(request):
    password_form = PasswordChangedForm(request.POST)
    profile_form = UserForm(request.POST)
    image_form = ImageForm(request.POST)
    site_form = SiteForm()
    smtp_form = SmtpForm()

    try:
        site_set=SiteConfiguration.objects.get(user=request.user) 
    except SiteConfiguration.DoesNotExist:
        site_set = None

    try:
        smtp_set=SmtpConfiguration.objects.get(user=request.user)
    except SmtpConfiguration.DoesNotExist:
        smtp_set = None

    if request.method == "POST":
        old_password = request.POST.get("old_password")
        if 'btnform2' in request.POST:
            password_form = PasswordChangedForm(request.user, request.POST)
            if request.POST.get("old_password"):
                user = User.objects.get(username= request.user.username)
                if user.check_password('{}'.format(old_password)) == False:
                    password_form.set_old_password_flag()
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)  # Important!
                messages.success(request, 'Your password was successfully updated!')
                return HttpResponseRedirect(reverse('profile_account'))
            else:
                messages.error(request, 'Please correct the error below.')
        elif 'btnform1' in request.POST:
            profile_form = UserForm(request.POST, instance=request.user)
            if profile_form.is_valid():
                profile_form.save()
        elif 'btnform3' in request.POST:
            image_form = ImageForm(request.POST, request.FILES , instance=request.user)
            if (image_form.is_valid()):
                image_form.save()            
                return HttpResponseRedirect(reverse('profile_account'))
        elif 'btnform4' in request.POST:
            if SiteConfiguration.objects.filter(user=request.user).exists():
                try:
                    site_sett=SiteConfiguration.objects.get(user=request.user) 
                except SiteConfiguration.DoesNotExist:
                    site_sett = None
                site_form = SiteForm(request.POST, request.FILES , instance=site_sett)        
                if site_form.is_valid():
                    site_form.save()            
                    return HttpResponseRedirect(reverse('profile_account'))                     
            else:       
                site_form = SiteForm(request.POST, request.FILES)
                if site_form.is_valid():
                    post = site_form.save(commit=False)
                    post.user = request.user
                    post.save()  
                    messages.success(request, 'Your site settings are successfully added !')
                    return HttpResponseRedirect(reverse('profile_account'))  
    
        elif 'btnform5' in request.POST:
            if SmtpConfiguration.objects.filter(user=request.user).exists(): 
                try:
                    smtp_sett=SmtpConfiguration.objects.get(user=request.user)
                except SmtpConfiguration.DoesNotExist:
                    smtp_sett = None              
                smtp_form = SmtpForm(request.POST, request.FILES , instance=smtp_sett)        
                if smtp_form.is_valid():
                    smtp_form.save()            
                    return HttpResponseRedirect(reverse('profile_account'))                      
            else:       
                smtp_form = SmtpForm(request.POST, request.FILES)
                if smtp_form.is_valid():
                    smtp_post = smtp_form.save(commit=False)
                    smtp_post.user = request.user
                    smtp_post.save()  
                    messages.success(request, 'Your smtp settings are successfully added !')
                    return HttpResponseRedirect(reverse('profile_account'))     
        else:
            raise Http404
    else:
        if SiteConfiguration.objects.filter(user=request.user).exists():
            site_profile_form = SiteForm(instance=SiteConfiguration.objects.get(user=request.user)) 
        elif SmtpConfiguration.objects.filter(user=request.user).exists():
            smtp_form = SmtpForm(instance=SmtpConfiguration.objects.get(user=request.user))        

    return TemplateResponse(request, template="myapp/extra_profile_account.html", context={
        'password_form': password_form,
        'profile_form': profile_form,
        'site_form': site_form,
        'smtp_form': smtp_form,
        'image_form': image_form,
        'site_set':site_set,
        'smtp_set':smtp_set,
    })


def test(request):
  response_str = "false"
  if request.is_ajax():
    old_password = request.GET.get("old_password")
    request_user = User.objects.get(id=request.user.id)
    if(request_user.check_password(old_password) == True):
        response_str = "true"
    return HttpResponse(response_str)

@login_required
@user_passes_test(lambda u: u.is_superuser)
@group_required('HR')
def create_company(request):
    if request.method == "POST":
        form1 = CompanyForm(request.POST, request.FILES)
        if form1.is_valid():
            print("hello")
            form1.save()
            return HttpResponseRedirect(reverse('dashboard'))

    else:
        form1 = CompanyForm()
    return render(request, 'registration/company_registration.html', {'form1': form1})

@login_required
def create_employee(request):
    if request.method == "POST":
        form2 = EmployeeForm(request.POST)
        if form2.is_valid():
            print("hello")
            form2.save()
            return HttpResponseRedirect(reverse('dashboard'))

    else:
        form2 = EmployeeForm()
    return render(request, 'registration/employee_registration.html', {'form2': form2})





