import logging
import requests
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from .forms import PasswordForm
ACCESS_TOKEN = None
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
    global ACCESS_TOKEN
    if request.method == 'POST':
        refresh_token()
        redirect_url = request.POST.get('redirect_url')
        return redirect(redirect_url)
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def exchange_token(request):
    global ACCESS_TOKEN
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
        ACCESS_TOKEN = data.get('access_token')
        return JsonResponse(data)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

def refresh_token():
    global ACCESS_TOKEN
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
        ACCESS_TOKEN = data['access_token']
    else:
        raise Exception('Failed to refresh token')

def get_account_info(request):
    global ACCESS_TOKEN
    if request.method == 'GET':
        if ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        url = "https://api.lightspeedapp.com/API/V3/Account.json"
        headers = {
            'Authorization': f'Bearer {ACCESS_TOKEN}'
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return render(request, 'oauth_handler/account_info.html', {'account_info': response.json()})
        else:
            return JsonResponse({'error': 'Failed to fetch account information'}, status=response.status_code)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def get_item_details(request):
    global ACCESS_TOKEN
    if request.method == 'POST':
        manufacturer_sku = request.POST.get('manufacturer_sku')
        if ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item.json"
        params = {
            'load_relations': '["ItemShops"]',
            'manufacturerSku': manufacturer_sku
        }
        headers = {
            'Authorization': f'Bearer {ACCESS_TOKEN}'
        }

        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'error': 'Failed to fetch item details'}, status=response.status_code)
    else:
        return render(request, 'oauth_handler/get_item_details.html')

@csrf_exempt
def update_item_quantity(request):
    global ACCESS_TOKEN
    if request.method == 'POST':
        item_id = request.POST.get('item_id')
        item_shop_id = request.POST.get('item_shop_id')
        quantity = request.POST.get('quantity')

        if ACCESS_TOKEN is None:
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
            'Authorization': f'Bearer {ACCESS_TOKEN}',
            'Content-Type': 'application/json'
        }

        response = requests.put(url, headers=headers, json=payload)
        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'error': 'Failed to update item quantity', 'details': response.text}, status=response.status_code)
    else:
        return render(request, 'oauth_handler/update_item_quantity.html')

@csrf_exempt
def add_quantity_to_item(request):
    global ACCESS_TOKEN
    if request.method == 'POST':
        manufacturer_sku = request.POST.get('manufacturer_sku')
        quantity_to_add = int(request.POST.get('quantity'))

        if ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        # Get item details
        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item.json"
        params = {
            'load_relations': '["ItemShops"]',
            'manufacturerSku': manufacturer_sku
        }
        headers = {
            'Authorization': f'Bearer {ACCESS_TOKEN}'
        }

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
        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'error': 'Failed to update item quantity', 'details': response.text}, status=response.status_code)
    else:
        return render(request, 'oauth_handler/add_quantity_to_item.html')

@csrf_exempt
def update_multiple_items_preview(request):
    global ACCESS_TOKEN
    if request.method == 'POST':
        updates = []
        for key, value in request.POST.items():
            if key.startswith('manufacturer_sku_') or key.startswith('upc_'):
                index = key.split('_')[-1]
                manufacturer_sku = request.POST.get(f'manufacturer_sku_{index}', '').strip()
                upc = request.POST.get(f'upc_{index}', '').strip()
                quantity = request.POST.get(f'quantity_{index}', '')
                if (manufacturer_sku or upc) and quantity:
                    updates.append({
                        'manufacturer_sku': manufacturer_sku,
                        'upc': upc,
                        'quantity': int(quantity)
                    })

        request.session['updates'] = updates

        if ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        item_details = []
        unique_items = set()
        for update in updates:
            manufacturer_sku = update.get('manufacturer_sku')
            upc = update.get('upc')
            quantity_to_add = int(update.get('quantity'))

            if (manufacturer_sku, upc) in unique_items:
                continue  # Skip duplicates
            unique_items.add((manufacturer_sku, upc))

            # Get item details
            url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Item.json"
            params = {
                'load_relations': '["ItemShops"]',
                'manufacturerSku': manufacturer_sku,
                'upc': upc
            }
            headers = {
                'Authorization': f'Bearer {ACCESS_TOKEN}'
            }

            response = requests.get(url, headers=headers, params=params)
            response_data = response.json()
            logging.info(f"Response data for SKU {manufacturer_sku or upc}: {response_data}")

            if response.status_code != 200 or 'Item' not in response_data:
                item_details.append({'manufacturer_sku': manufacturer_sku, 'upc': upc, 'status': 'failed', 'reason': 'Failed to fetch item details'})
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
                item_details.append({'manufacturer_sku': manufacturer_sku, 'upc': upc, 'status': 'failed', 'reason': 'Valid ItemShop not found'})
                continue

            item_shop_id = item_shop['itemShopID']
            current_qoh = int(item_shop['qoh'])

            item_details.append({
                'manufacturer_sku': manufacturer_sku,
                'upc': upc,
                'quantity_to_add': quantity_to_add,
                'current_qoh': current_qoh,
                'new_qoh': current_qoh + quantity_to_add,
                'description': description,
                'item_id': item_id,
                'item_shop_id': item_shop_id
            })

        request.session['item_details'] = item_details
        return redirect('confirm_update_items')
    else:
        updates = request.session.get('updates', [])
        return render(request, 'oauth_handler/update_multiple_items.html', {'updates': updates})

@csrf_exempt
def confirm_update_items(request):
    if request.method == 'POST':
        global ACCESS_TOKEN
        item_details = request.session.get('item_details', [])

        if ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        results = []
        for item in item_details:
            manufacturer_sku = item['manufacturer_sku']
            upc = item['upc']
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
                'Authorization': f'Bearer {ACCESS_TOKEN}',
                'Content-Type': 'application/json'
            }

            response = requests.put(url, headers=headers, json=payload)
            if response.status_code == 200:
                results.append({'manufacturer_sku': manufacturer_sku, 'upc': upc, 'status': 'success'})
            else:
                results.append({'manufacturer_sku': manufacturer_sku, 'upc': upc, 'status': 'failed', 'reason': response.text})

        all_success = all(result['status'] == 'success' for result in results)

        if all_success:
            request.session.pop('item_details', None)  # Clear session data after successful update
            request.session.pop('updates', None)
            return render(request, 'oauth_handler/confirm_success.html')
        else:
            return JsonResponse({'results': results})
    else:
        item_details = request.session.get('item_details', [])
        return render(request, 'oauth_handler/confirm_update_items.html', {'item_details': item_details})

@csrf_exempt
def get_customer_details(request, customer_id):
    global ACCESS_TOKEN
    if request.method == 'GET':
        if ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/Customer/{customer_id}.json"
        headers = {
            'Authorization': f'Bearer {ACCESS_TOKEN}'
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'error': 'Failed to fetch customer details'}, status=response.status_code)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def get_credit_account_details(request):
    global ACCESS_TOKEN
    if request.method == 'GET':
        if ACCESS_TOKEN is None:
            return JsonResponse({'error': 'Access token not available'}, status=400)

        url = f"https://api.lightspeedapp.com/API/V3/Account/{settings.LIGHTSPEED_ACCOUNT_ID}/CreditAccount.json"
        headers = {
            'Authorization': f'Bearer {ACCESS_TOKEN}'
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
        'Authorization': f'Bearer {ACCESS_TOKEN}'
    }

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
