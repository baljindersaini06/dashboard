# Generated by Django 2.2.6 on 2019-12-06 11:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0006_auto_20191206_1114'),
    ]

    operations = [
        migrations.AlterField(
            model_name='company',
            name='company_website',
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
    ]
