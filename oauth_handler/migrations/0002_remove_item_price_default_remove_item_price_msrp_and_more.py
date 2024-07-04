# Generated by Django 5.0.6 on 2024-06-23 21:28

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth_handler', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='item',
            name='price_default',
        ),
        migrations.RemoveField(
            model_name='item',
            name='price_msrp',
        ),
        migrations.RemoveField(
            model_name='item',
            name='price_online',
        ),
        migrations.CreateModel(
            name='PriceRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('price', models.DecimalField(decimal_places=2, max_digits=10)),
                ('currency', models.CharField(choices=[('USD', 'US Dollars'), ('CAD', 'Canadian Dollars')], max_length=3)),
                ('record_date', models.DateField(auto_now_add=True)),
                ('item', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='price_records', to='oauth_handler.item')),
            ],
        ),
    ]