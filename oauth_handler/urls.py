from django.urls import path
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('enter_password/', enter_password, name='enter_password'),
    path('start/', start_refresh_and_redirect, name='start_refresh_and_redirect'),
    path('exchange-token/', exchange_token, name='exchange_token'),
    path('refresh-token/', refresh_token, name='refresh_token'),
    path('account-info/', get_account_info, name='account_info'),
    path('get-item-details/', get_item_details, name='get_item_details'),
    path('update-item-quantity/', update_item_quantity, name='update_item_quantity'),
    path('add-quantity-to-item/', add_quantity_to_item, name='add_quantity_to_item'),
    path('update-multiple-items/', update_multiple_items_preview, name='update_multiple_items'),
    path('update-multiple-items-preview/', update_multiple_items_preview, name='update_multiple_items_preview'),
    path('confirm-update-items/', confirm_update_items, name='confirm_update_items'),
    path('credit-account-details/', get_credit_account_details, name='credit_account_details'),
    path('customer-details/<int:customer_id>/', get_customer_details, name='customer_details'),
    path('fetch-items/', fetch_all_items, name='fetch_items'),
    path('fetch-all-vendors/', fetch_all_vendors_view, name='fetch_all_vendors'),
    path('items/', list_items, name='list_items'),
    path('items/<int:item_id>/', item_detail, name='item_detail'),
    path('categories/', fetch_all_categories, name='fetch-categories'),
    path('items/reorder/', list_reorder_items, name='list-reorder-items'),

]
