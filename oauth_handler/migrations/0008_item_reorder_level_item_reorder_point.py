# Generated by Django 5.0.6 on 2024-06-29 19:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth_handler', '0007_item_category'),
    ]

    operations = [
        migrations.AddField(
            model_name='item',
            name='reorder_level',
            field=models.IntegerField(default=0, verbose_name='Reorder Level'),
        ),
        migrations.AddField(
            model_name='item',
            name='reorder_point',
            field=models.IntegerField(default=0, verbose_name='Reorder Point'),
        ),
    ]
