from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from .validators import validate_file_extension
from django.core.validators import RegexValidator

# Create your models here.

EMPLOYEE_TYPE_CHOICES = (
    ('hr', 'HR'),
    ('admin', 'ADMIN'),
    ('accountant', 'ACCOUNTANT'),
    ('sales manager', 'SALES MANAGER')
)


class User(AbstractUser):
    profile_image = models.ImageField(upload_to='images/', default='images/image.jpg')
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be upto 10 digits")
    phone_no = models.CharField(validators=[phone_regex], max_length=10, blank=True) 


class SiteConfiguration(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,null=True)
    site_name = models.CharField(max_length=50,default="")
    site_email = models.EmailField(max_length=50,default="")
    site_favicon = models.ImageField(upload_to='images/',validators=[validate_file_extension],default="")
    site_logo = models.ImageField(upload_to='images/',validators=[validate_file_extension],default="")
    site_address = models.CharField(max_length=200,default="")
    copy_right = models.CharField(max_length=50,default="")

   
    def __str__(self):
        return self.site_name

class SmtpConfiguration(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,null=True)
    smtp_email = models.EmailField(max_length=50,default="")
    smtp_password = models.CharField(max_length=50,default="")


    def __str__(self):
        return self.smtp_email



class Company(models.Model):
    company_name = models.CharField(max_length=48)
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be upto 10 digits")
    contact_number = models.CharField(validators=[phone_regex], max_length=10, default="")
    description = models.CharField(max_length=48)
    company_website = models.URLField()
    company_logo = models.ImageField(upload_to='images/', default="")
    company_address = models.CharField(max_length=100)
    company_location = models.CharField(max_length=20)
    company_pincode = models.CharField(max_length=6, validators=[RegexValidator(r'^\d{1,10}$')])

    def __str__(self):
        return self.company_name


class Employee(models.Model):
    company_name = models.ForeignKey(Company, on_delete=True, null=True)
    employee_name = models.CharField(max_length=32)
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be upto 10 digits")
    phone_number = models.CharField(validators=[phone_regex], max_length=10, default="")
    note = models.CharField(max_length=48)
    designation = models.CharField(max_length=32)
    employee_email = models.EmailField()

    def __str__(self):
        return self.employee_name