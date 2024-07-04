from django.db import models

class Vendor(models.Model):
    name = models.CharField(max_length=255)
    def __str__(self):
        return self.name

class Brand(models.Model):
    name = models.CharField(max_length=255)
    def __str__(self):
        return self.name

class TaxClass(models.Model):
    name = models.CharField(max_length=255)
    def __str__(self):
        return self.name

class Category(models.Model):
    category_id = models.IntegerField(unique=True)
    name = models.CharField(max_length=255)
    node_depth = models.IntegerField(default=0)
    full_path_name = models.CharField(max_length=255)
    left_node = models.IntegerField()
    right_node = models.IntegerField()
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    create_time = models.DateTimeField()
    last_modified = models.DateTimeField()
    def __str__(self):
        return self.full_path_name

class Item(models.Model):
    description = models.TextField()
    system_sku = models.CharField(max_length=255)
    manufacturer_sku = models.CharField(max_length=255, unique=True)
    default_cost = models.DecimalField(max_digits=10, decimal_places=2)
    average_cost = models.DecimalField(max_digits=10, decimal_places=2)
    quantity_on_hand = models.IntegerField()
    reorder_point = models.IntegerField(default=0, verbose_name="Reorder Point")
    reorder_level = models.IntegerField(default=0, verbose_name="Reorder Level")
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    vendor = models.ForeignKey(Vendor, on_delete=models.SET_NULL, null=True)
    brand = models.ForeignKey(Brand, on_delete=models.SET_NULL, null=True)
    tax_class = models.ForeignKey(TaxClass, on_delete=models.SET_NULL, null=True)
    price_default = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    price_msrp = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    price_online = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    def __str__(self):
        return f"{self.description} - {self.manufacturer_sku}"

class PriceRecord(models.Model):
    item = models.ForeignKey(Item, related_name='price_records', on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, choices=(('USD', 'US Dollars'), ('CAD', 'Canadian Dollars')))
    record_date = models.DateField()
    brand = models.ForeignKey(Brand, on_delete=models.SET_NULL, null=True)
    def __str__(self):
        return f"{self.item.manufacturer_sku} - {self.currency} {self.price} on {self.record_date}"
