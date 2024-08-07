# Generated by Django 5.0.6 on 2024-06-24 20:19

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth_handler', '0005_item_price_default_item_price_msrp_item_price_online'),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('category_id', models.IntegerField(unique=True)),
                ('name', models.CharField(max_length=255)),
                ('node_depth', models.IntegerField(default=0)),
                ('full_path_name', models.CharField(max_length=255)),
                ('left_node', models.IntegerField()),
                ('right_node', models.IntegerField()),
                ('create_time', models.DateTimeField()),
                ('last_modified', models.DateTimeField()),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='oauth_handler.category')),
            ],
        ),
    ]
