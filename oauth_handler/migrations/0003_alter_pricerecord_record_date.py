# Generated by Django 5.0.6 on 2024-06-23 21:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth_handler', '0002_remove_item_price_default_remove_item_price_msrp_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pricerecord',
            name='record_date',
            field=models.DateField(),
        ),
    ]
