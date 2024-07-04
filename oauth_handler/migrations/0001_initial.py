# Generated by Django 5.0.6 on 2024-06-23 21:14

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Brand',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='TaxClass',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Vendor',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Item',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.TextField()),
                ('system_sku', models.CharField(max_length=255)),
                ('manufacturer_sku', models.CharField(max_length=255, unique=True)),
                ('default_cost', models.DecimalField(decimal_places=2, max_digits=10)),
                ('average_cost', models.DecimalField(decimal_places=2, max_digits=10)),
                ('quantity_on_hand', models.IntegerField()),
                ('price_default', models.DecimalField(decimal_places=2, max_digits=10)),
                ('price_msrp', models.DecimalField(decimal_places=2, max_digits=10)),
                ('price_online', models.DecimalField(decimal_places=2, max_digits=10)),
                ('brand', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='oauth_handler.brand')),
                ('tax_class', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='oauth_handler.taxclass')),
                ('vendor', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='oauth_handler.vendor')),
            ],
        ),
    ]
