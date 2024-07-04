from django.contrib import admin
from .models import Item, Vendor, Brand, TaxClass, PriceRecord

class PriceRecordInline(admin.TabularInline):
    model = PriceRecord
    extra = 1  # How many rows to show

@admin.register(Item)
class ItemAdmin(admin.ModelAdmin):
    list_display = ('description', 'system_sku', 'manufacturer_sku', 'default_cost', 'average_cost', 'vendor', 'brand', 'tax_class')
    search_fields = ('description', 'manufacturer_sku')
    list_filter = ('vendor', 'brand', 'tax_class')
    inlines = [PriceRecordInline]

admin.site.register(Vendor)
admin.site.register(Brand)
admin.site.register(TaxClass)
admin.site.register(PriceRecord)
