from django.contrib import admin
from myapp.models import User,SiteConfiguration,SmtpConfiguration, Company, Employee

# Register your models here.
admin.site.register(User)
admin.site.register(SiteConfiguration)
admin.site.register(SmtpConfiguration)
admin.site.register(Company)
admin.site.register(Employee)