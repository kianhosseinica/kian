import logging
from datetime import datetime

import requests
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.core.management import call_command
from django.db import IntegrityError
from .forms import PasswordForm
from .models import *

PASSWORD = 'morris#sia@mehran$mohammad'  # Replace with your actual password

def home(request):
    if not request.session.get('authenticated', False):
        return redirect('enter_password')
    return render(request, 'oauth_handler/home.html')

@csrf_exempt
def enter_password(request):
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['password'] == PASSWORD:
                request.session['authenticated'] = True
                return redirect('home')
            else:
                form.add_error('password', 'Incorrect password')
    else:
        form = PasswordForm()
    return render(request, 'oauth_handler/enter_password.html', {'form': form})

@csrf_exempt
def start_refresh_and_redirect(request):
    if request.method == 'POST':
        call_command('refresh_token')
        redirect_url = request.POST.get('redirect_url')
        return redirect(redirect_url)
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def exchange_token(request):
    if request.method == 'POST':
        client_id = request.POST.get('client_id')
        client_secret = request.POST.get('client_secret')
        code = request.POST.get('code')
        grant_type = request.POST.get('grant_type')

        url = "https://cloud.lightspeedapp.com/oauth/access_token.php"
        payload = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'grant_type': grant_type
        }

        response = requests.post(url, data=payload)
        data = response.json()
        settings.ACCESS_TOKEN = data.get('access_token')
        return JsonResponse(data)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

def refresh_token():
    url = 'https://cloud.lightspeedapp.com/oauth/access_token.php'
    payload = {
        'client_id': settings.CLIENT_ID,
        'client_secret': settings.CLIENT_SECRET,
        'refresh_token': settings.REFRESH_TOKEN,
        'grant_type': 'refresh_token'
    }
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        data = response.json()
        settings.ACCESS_TOKEN = data['access_token']
    else:
        raise Exception('Failed to refresh token')

def get_account_info(request):
    def fetch_account_info():
        url = "https://api.lightspeedapp.com/API/V3/Account.json"
        headers = {
            'Authorization': f'Bearer {settings.ACCESS_TOKEN}'
        }
        return requests.get(url, headers=headers)

    response = fetch_account_info()
    if response.status_code == 401:  # Unauthorized error
        call_command('refresh_token')
        response = fetch_account_info()

    if response.status_code == 200:
        return render(request, 'oauth_handler/account_info.html', {'account_info': response.json()})
    else:
        return JsonResponse({'error': 'Failed to fetch account information'}, status=response.status_code)

@csrf_exempt
def get_item_details(request):
    if request.method == 'POST':
        manufacturer_sku = request.POST.get('manufacturer_sku')
        if settings.ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item.json"
        params = {
            'load_relations': '["ItemShops"]',
            'manufacturerSku': manufacturer_sku
        }
        headers = {
            'Authorization': f'Bearer {settings.ACCESS_TOKEN}'
        }

        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 401:  # Unauthorized error
            call_command('refresh_token')
            headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
            response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'error': 'Failed to fetch item details'}, status=response.status_code)
    else:
        return render(request, 'oauth_handler/get_item_details.html')

@csrf_exempt
def update_item_quantity(request):
    if request.method == 'POST':
        item_id = request.POST.get('item_id')
        item_shop_id = request.POST.get('item_shop_id')
        quantity = request.POST.get('quantity')

        if settings.ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item/{item_id}.json"
        payload = {
            "ItemShops": {
                "ItemShop": [
                    {
                        "itemShopID": item_shop_id,
                        "qoh": quantity
                    }
                ]
            }
        }
        headers = {
            'Authorization': f'Bearer {settings.ACCESS_TOKEN}',
            'Content-Type': 'application/json'
        }

        response = requests.put(url, headers=headers, json=payload)
        if response.status_code == 401:  # Unauthorized error
            call_command('refresh_token')
            headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
            response = requests.put(url, headers=headers, json=payload)

        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'error': 'Failed to update item quantity', 'details': response.text}, status=response.status_code)
    else:
        return render(request, 'oauth_handler/update_item_quantity.html')

@csrf_exempt
def add_quantity_to_item(request):
    if request.method == 'POST':
        manufacturer_sku = request.POST.get('manufacturer_sku')
        quantity_to_add = int(request.POST.get('quantity'))

        if settings.ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        # Get item details
        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item.json"
        params = {
            'load_relations': '["ItemShops"]',
            'manufacturerSku': manufacturer_sku
        }
        headers = {
            'Authorization': f'Bearer {settings.ACCESS_TOKEN}'
        }

        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 401:  # Unauthorized error
            call_command('refresh_token')
            headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
            response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            return JsonResponse({'error': 'Failed to fetch item details', 'details': response.text}, status=response.status_code)

        item_data = response.json()
        if '@attributes' in item_data and 'count' in item_data['@attributes'] and int(item_data['@attributes']['count']) == 0:
            return JsonResponse({'error': 'Item not found'}, status=404)

        item = item_data['Item']
        if not isinstance(item, list):
            item = [item]
        item = item[0]
        item_id = item['itemID']
        # Find the correct ItemShop
        item_shop = next((shop for shop in item['ItemShops']['ItemShop'] if shop['shopID'] != '0'), None)
        if not item_shop:
            return JsonResponse({'error': 'Valid ItemShop not found'}, status=400)

        item_shop_id = item_shop['itemShopID']
        current_qoh = int(item_shop['qoh'])

        # Calculate new quantity
        new_quantity = current_qoh + quantity_to_add

        # Update item quantity
        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item/{item_id}.json"
        payload = {
            "ItemShops": {
                "ItemShop": [
                    {
                        "itemShopID": item_shop_id,
                        "qoh": new_quantity
                    }
                ]
            }
        }

        response = requests.put(url, headers=headers, json=payload)
        if response.status_code == 401:  # Unauthorized error
            call_command('refresh_token')
            headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
            response = requests.put(url, headers=headers, json=payload)

        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'error': 'Failed to update item quantity', 'details': response.text}, status=response.status_code)
    else:
        return render(request, 'oauth_handler/add_quantity_to_item.html')

@csrf_exempt
def update_multiple_items_preview(request):
    if request.method == 'POST':
        updates = []
        for key, value in request.POST.items():
            if key.startswith('manufacturer_sku_') or key.startswith('upc_'):
                index = key.split('_')[-1]
                manufacturer_sku = request.POST.get(f'manufacturer_sku_{index}')
                upc = request.POST.get(f'upc_{index}')
                quantity = request.POST.get(f'quantity_{index}')
                if (manufacturer_sku or upc) and quantity:
                    updates.append({
                        'manufacturer_sku': manufacturer_sku,
                        'upc': upc,
                        'quantity': int(quantity)
                    })

        request.session['updates'] = updates
        request.session['toggle_choice'] = request.POST.get('global_toggle', 'sku')

        if settings.ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        item_details = []
        for update in updates:
            identifier = update.get('manufacturer_sku') or update.get('upc')
            quantity_to_add = int(update.get('quantity'))
            search_field = 'manufacturerSku' if update.get('manufacturer_sku') else 'upc'

            # Get item details
            url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item.json"
            params = {
                'load_relations': '["ItemShops"]',
                search_field: identifier
            }
            headers = {
                'Authorization': f'Bearer {settings.ACCESS_TOKEN}'
            }

            response = requests.get(url, headers=headers, params=params)
            response_data = response.json()
            logging.info(f"Response data for {search_field} {identifier}: {response_data}")

            if response.status_code == 401:  # Unauthorized error
                call_command('refresh_token')
                headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
                response = requests.get(url, headers=headers, params=params)
                response_data = response.json()

            if response.status_code != 200 or 'Item' not in response_data:
                item_details.append({'identifier': identifier, 'status': 'failed', 'reason': 'Failed to fetch item details'})
                continue

            item_data = response_data['Item']
            if not isinstance(item_data, list):
                item_data = [item_data]
            item_data = item_data[0]
            item_id = item_data['itemID']
            description = item_data.get('description', 'No description available')

            # Find the correct ItemShop
            item_shop = next((shop for shop in item_data['ItemShops']['ItemShop'] if shop['shopID'] != '0'), None)
            if not item_shop:
                item_details.append({'identifier': identifier, 'status': 'failed', 'reason': 'Valid ItemShop not found'})
                continue

            item_shop_id = item_shop['itemShopID']
            current_qoh = int(item_shop['qoh'])

            item_details.append({
                'identifier': identifier,
                'quantity_to_add': quantity_to_add,
                'current_qoh': current_qoh,
                'new_qoh': current_qoh + quantity_to_add,
                'description': description,
                'item_id': item_id,
                'item_shop_id': item_shop_id,
                'search_field': search_field
            })

        request.session['item_details'] = item_details
        return redirect('confirm_update_items')
    else:
        updates = request.session.get('updates', [])
        toggle_choice = request.session.get('toggle_choice', 'sku')
        return render(request, 'oauth_handler/update_multiple_items.html', {'updates': updates, 'toggle_choice': toggle_choice})

@csrf_exempt
def confirm_update_items(request):
    if request.method == 'POST':
        item_details = request.session.get('item_details', [])

        if settings.ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        results = []
        for item in item_details:
            identifier = item['identifier']
            new_quantity = item['new_qoh']
            item_id = item['item_id']
            item_shop_id = item['item_shop_id']

            # Update item quantity
            url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item/{item_id}.json"
            payload = {
                "ItemShops": {
                    "ItemShop": [
                        {
                            "itemShopID": item_shop_id,
                            "qoh": new_quantity
                        }
                    ]
                }
            }
            headers = {
                'Authorization': f'Bearer {settings.ACCESS_TOKEN}',
                'Content-Type': 'application/json'
            }

            response = requests.put(url, headers=headers, json=payload)
            if response.status_code == 401:  # Unauthorized error
                call_command('refresh_token')
                headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
                response = requests.put(url, headers=headers, json=payload)

            if response.status_code == 200:
                results.append({'identifier': identifier, 'status': 'success'})
            else:
                results.append({'identifier': identifier, 'status': 'failed', 'reason': response.text})

        all_success = all(result['status'] == 'success' for result in results)

        if all_success:
            request.session.pop('item_details', None)  # Clear session data after successful update
            request.session.pop('updates', None)
            request.session.pop('toggle_choice', None)
            return render(request, 'oauth_handler/confirm_success.html')
        else:
            return JsonResponse({'results': results})
    else:
        item_details = request.session.get('item_details', [])
        toggle_choice = request.session.get('toggle_choice', 'sku')
        return render(request, 'oauth_handler/confirm_update_items.html', {'item_details': item_details, 'toggle_choice': toggle_choice})

@csrf_exempt
def get_customer_details(request, customer_id):
    if request.method == 'GET':
        if settings.ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Customer/{customer_id}.json"
        headers = {
            'Authorization': f'Bearer {settings.ACCESS_TOKEN}'
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 401:  # Unauthorized error
            call_command('refresh_token')
            headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
            response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'error': 'Failed to fetch customer details'}, status=response.status_code)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def get_credit_account_details(request):
    if request.method == 'GET':
        if settings.ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/CreditAccount.json"
        headers = {
            'Authorization': f'Bearer {settings.ACCESS_TOKEN}'
        }

        all_credit_accounts = []
        response = requests.get(url, headers=headers)
        while response.status_code == 200:
            data = response.json()
            credit_accounts = data.get('CreditAccount', [])
            if not isinstance(credit_accounts, list):
                credit_accounts = [credit_accounts]

            all_credit_accounts.extend(credit_accounts)
            next_url = data['@attributes'].get('next', '')
            if not next_url:
                break
            response = requests.get(next_url, headers=headers)

            if response.status_code == 401:  # Unauthorized error
                call_command('refresh_token')
                headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
                response = requests.get(next_url, headers=headers)

        customer_details = []
        for account in all_credit_accounts:
            if float(account.get('balance', 0)) > 0 and float(account.get('creditLimit', 0)) > 0:
                customer_id = account.get('customerID')
                customer_info = get_customer_info(customer_id)
                if customer_info:
                    customer_info['creditLimit'] = account.get('creditLimit')
                    customer_info['balance'] = account.get('balance')
                    customer_info['percentageUsed'] = round((float(account.get('balance')) / float(account.get('creditLimit'))) * 100, 2)
                    customer_details.append(customer_info)

        # Sort customers by balance in descending order
        customer_details = sorted(customer_details, key=lambda x: float(x['balance']), reverse=True)

        return render(request, 'oauth_handler/credit_account_details.html', {'customer_details': customer_details})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

def get_customer_info(customer_id):
    url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Customer/{customer_id}.json"
    headers = {
        'Authorization': f'Bearer {settings.ACCESS_TOKEN}'
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 401:  # Unauthorized error
        call_command('refresh_token')
        headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
        response = requests.get(url, headers=headers)

    if response.status_code == 200:
        customer_data = response.json().get('Customer', {})
        phone = next((phone['number'] for phone in customer_data.get('Contact', {}).get('Phones', {}).get('Phone', []) if phone['useType'] == 'Work'), '')
        email = next((email['address'] for email in customer_data.get('Contact', {}).get('Emails', {}).get('Email', []) if email['useType'] == 'Other'), '')
        return {
            'email': email,
            'firstName': customer_data.get('firstName'),
            'lastName': customer_data.get('lastName'),
            'phone': phone,
            'customerID': customer_id
        }
    else:
        return None

def fetch_all_vendors_view(request):
    endpoint_url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Vendor.json"
    headers = {'Authorization': f'Bearer {settings.ACCESS_TOKEN}'}
    response = requests.get(endpoint_url, headers=headers)
    if response.status_code == 401:  # Unauthorized error
        call_command('refresh_token')
        headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
        response = requests.get(endpoint_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        vendor_map = {vendor['vendorID']: Vendor.objects.get_or_create(name=vendor['name'])[0] for vendor in data.get('Vendor', [])}
        return vendor_map
    else:
        return {}

def fetch_all_items(request):
    vendor_map = fetch_all_vendors_view(request)
    category_map = fetch_all_categories(request)

    next_page_url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item.json?load_relations=[\"Manufacturer\",\"Category\",\"TaxClass\",\"ItemShops\",\"ItemVendorNums\",\"ItemComponents\",\"ItemAttributes\"]"
    headers = {'Authorization': f'Bearer {settings.ACCESS_TOKEN}'}

    missing_items = []
    while next_page_url:
        response = requests.get(next_page_url, headers=headers)
        if response.status_code == 401:  # Unauthorized error
            call_command('refresh_token')
            headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
            response = requests.get(next_page_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            for item_data in data.get('Item', []):
                try:
                    item_shops = item_data.get('ItemShops', {}).get('ItemShop', [])
                    qoh = sum(int(shop['qoh']) for shop in item_shops if shop['qoh'])  # Sum of all quantities across shops

                    # Calculate maximum reorder point and reorder level across all shops
                    reorder_point = max(int(shop['reorderPoint']) for shop in item_shops if 'reorderPoint' in shop) if item_shops else 0
                    reorder_level = max(int(shop['reorderLevel']) for shop in item_shops if 'reorderLevel' in shop) if item_shops else 0

                    # Parse and extract prices
                    price_info = {}
                    for price in item_data.get('Prices', {}).get('ItemPrice', []):
                        if price['useType'].lower() == 'default':
                            price_info['default'] = float(price['amount'])
                        elif price['useType'].lower() == 'msrp':
                            price_info['msrp'] = float(price['amount'])
                        elif price['useType'].lower() == 'online':
                            price_info['online'] = float(price['amount'])

                    default_vendor_id = item_data.get('defaultVendorID', None)
                    vendor = vendor_map.get(default_vendor_id, Vendor.objects.get_or_create(name='Unknown')[0])
                    category_id = item_data.get('categoryID', None)
                    category = category_map.get(category_id, Category.objects.get_or_create(name='Unknown')[0])

                    item, created = Item.objects.update_or_create(
                        manufacturer_sku=item_data['manufacturerSku'],
                        defaults={
                            'description': item_data.get('description', ''),
                            'system_sku': item_data.get('systemSku', ''),
                            'default_cost': item_data.get('defaultCost', 0),
                            'average_cost': item_data.get('avgCost', 0),
                            'quantity_on_hand': qoh,
                            'reorder_point': reorder_point,
                            'reorder_level': reorder_level,
                            'vendor': vendor,
                            'category': category,
                            'brand': Brand.objects.get_or_create(name=item_data.get('Manufacturer', {}).get('name', 'Unknown'))[0],
                            'tax_class': TaxClass.objects.get_or_create(name=item_data.get('TaxClass', {}).get('name', 'Unknown'))[0],
                            'price_default': price_info.get('default', 0),
                            'price_msrp': price_info.get('msrp', 0),
                            'price_online': price_info.get('online', 0),
                        }
                    )
                    if created:
                        print(f"Created new item: {item}")
                    else:
                        print(f"Updated existing item: {item}")
                except IntegrityError as e:
                    print(f"Failed to process item {item_data['manufacturerSku']} due to database error: {str(e)}")
                    missing_items.append(item_data['manufacturerSku'])
                except Exception as e:
                    print(f"Failed to process item {item_data['manufacturerSku']} due to error: {str(e)}")
                    missing_items.append(item_data['manufacturerSku'])

            next_page_url = data.get('@attributes', {}).get('next', None)
        else:
            print(f"Failed to fetch items with status code: {response.status_code}")
            break

    if missing_items:
        print(f"Missing items SKUs: {missing_items}")
    return JsonResponse({'message': 'Items fetched and updated successfully', 'missing_items': missing_items})

def list_items(request):
    items = Item.objects.all()
    brands = Brand.objects.all()
    vendors = Vendor.objects.all()
    categories = Category.objects.all()

    # Filtering logic
    brand_query = request.GET.get('brand')
    if brand_query:
        items = items.filter(brand__name=brand_query)

    vendor_query = request.GET.get('vendor')
    if vendor_query:
        items = items.filter(vendor__name=vendor_query)

    category_query = request.GET.get('category')
    if category_query:
        items = items.filter(category__name=category_query)

    search_query = request.GET.get('search')
    if search_query:
        items = items.filter(
            models.Q(manufacturer_sku__icontains=search_query) |
            models.Q(system_sku__icontains=search_query) |
            models.Q(description__icontains=search_query)
        )

    return render(request, 'oauth_handler/items_list.html', {
        'items': items,
        'brands': brands,
        'vendors': vendors,
        'categories': categories  # Ensure categories are passed to the template
    })

def item_detail(request, item_id):
    item = get_object_or_404(Item, id=item_id)
    price_records = item.price_records.all()  # Assuming this is your related name for PriceRecord

    # Prepare price data
    price_data = {
        'default_price': item.price_default,
        'msrp_price': item.price_msrp,
        'online_price': item.price_online
    }

    return render(request, 'oauth_handler/item_detail.html', {
        'item': item,
        'price_records': price_records,
        'price_data': price_data  # Add this to pass price data to the template
    })

def fetch_all_categories(request):
    endpoint_url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Category.json"
    headers = {'Authorization': f'Bearer {settings.ACCESS_TOKEN}'}
    response = requests.get(endpoint_url, headers=headers)
    if response.status_code == 401:  # Unauthorized error
        call_command('refresh_token')
        headers['Authorization'] = f'Bearer {settings.ACCESS_TOKEN}'
        response = requests.get(endpoint_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        categories = data.get('Category', [])

        category_map = {}
        for category_data in categories:
            category_id = category_data['categoryID']
            category, created = Category.objects.update_or_create(
                category_id=category_id,
                defaults={
                    'name': category_data['name'],
                    'node_depth': int(category_data['nodeDepth']),
                    'full_path_name': category_data['fullPathName'],
                    'left_node': int(category_data['leftNode']),
                    'right_node': int(category_data['rightNode']),
                    'create_time': parse_datetime(category_data['createTime']),
                    'last_modified': parse_datetime(category_data['timeStamp'])
                }
            )
            category_map[category_id] = category

        for category_data in categories:
            category_id = category_data['categoryID']
            parent_id = category_data.get('parentID')
            category = category_map[category_id]
            if parent_id and parent_id in category_map:
                category.parent = category_map[parent_id]
                category.save()

        return category_map
    else:
        return {}

def list_reorder_items(request):
    items = Item.objects.filter(quantity_on_hand__lte=models.F('reorder_point'))

    # Filtering by Brand, Vendor, Category
    brand_query = request.GET.get('brand')
    if brand_query:
        items = items.filter(brand__name=brand_query)

    vendor_query = request.GET.get('vendor')
    if vendor_query:
        items = items.filter(vendor__name=vendor_query)

    category_query = request.GET.get('category')
    if category_query:
        items = items.filter(category__name=category_query)

    # Search by Item Description or Manufacturer SKU
    search_query = request.GET.get('search')
    if search_query:
        items = items.filter(
            models.Q(description__icontains=search_query) |
            models.Q(manufacturer_sku__icontains=search_query)
        )

    brands = Brand.objects.all()
    vendors = Vendor.objects.all()
    categories = Category.objects.all()

    return render(request, 'oauth_handler/reorder_list.html', {
        'items': items,
        'brands': brands,
        'vendors': vendors,
        'categories': categories
    })
