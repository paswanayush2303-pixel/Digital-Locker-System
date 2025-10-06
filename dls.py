import json
import hashlib
import time
from datetime import datetime

ITEM_CATEGORIES = ['Password', 'Docs', 'Notes', 'Reminder']
DATA_FILE = "locker_data.json"
XOR_KEY = "SafestLockerDataKey1234567890" 

def xor_cipher(data,key):
    """Encrypts  string using XOR cipher."""
    ''' copied from gemini'''
    data_bytes = data.encode('utf-8')
    key_bytes = key.encode('utf-8')
    
    result_bytes = bytearray(len(data_bytes))
    
    key_len = len(key_bytes)
    
    for i, data_byte in enumerate(data_bytes):
        key_byte_index = i % key_len
        key_byte = key_bytes[key_byte_index]
        
        result_bytes[i] = data_byte ^ key_byte
    
    return result_bytes.decode('utf-8', errors='ignore')
    


def xor_decipher(encrypted_data, key):
  """Decrypts  string using XOR cipher."""
  return xor_cipher(encrypted_data,key)


def hash_pin(pin):
    """Hashes the user PIN using SHA256."""
    h = hashlib.new("SHA256")
    h.update(pin.encode())
    return h.hexdigest() 

def check_pin(user_id, pin, data):
    """Verifies a user's PIN against the stored hash."""
    if user_id not in data:
        return False
    return hash_pin(pin) == data[user_id]['pin']


def load_data():
    """Loads user data from a JSON file. Returns an empty dictionary if the file doesn't exist."""
    try:
        with open(DATA_FILE, 'r') as fd:
            js = fd.read()
            if not js:
                return {}
            data = json.loads(js)
            return data
    except FileNotFoundError:
        return {}


def save_data(data):
    """Saves user data to a JSON file."""
    with open(DATA_FILE, 'w') as fd:
        json.dump(data, fd, indent=4)#

# --- Core Locker Functions ---

def register_user(data):
    """ Prompts the user to register with a new ID and PIN."""
    print("--- Registration ---")
    
    # --- Create Unique ID ---
    while True:
        user = input("Create a Unique Locker ID: ").strip()
        if not user:
            print("Locker ID cannot be empty.")
        if user in data:
            print('Locker ID already used.')
        else:
            break 

    # --- Create 4-digit PIN ---
    while True:
        pin = input("Create a 4-digit PIN: ").strip()
        if len(pin) != 4 or not pin.isdigit():
            print("Invalid PIN. Please enter a 4-digit number.")
        else:
            break 
            
    # Hash the PIN
    password_hash = hash_pin(pin) 
    
    # Initialize the user's data structure
    data[user] = {
        "pin": password_hash,
        "items": {cat: [] for cat in ITEM_CATEGORIES} # Initialize empty lists for all categories
    }
    save_data(data)
    print("Registration successful! Please log in.")


def login_user(data):
    """ Prompts the user for their ID and PIN to log in.
    Returns (True, user_id) if the PIN is correct, otherwise (False, None)."""
    
    user = None
    while True:
        user_input = input('Enter your Unique Locker ID: ').strip()
        if user_input in data:
            user = user_input
            break
        else:
            print('''Unique ID Not Found
            Press 1 to Register
            Press Any Other Key to re-Enter The Unique ID
            ''')
            choice = input("Enter your Choice: ").strip()
            if choice == "1":
                register_user(data)
                continue # Go back to trying to log in
            else:
                continue # Re-enter ID

    pin = input("Enter your 4-digit PIN to log in: ").strip()
    
    if check_pin(user, pin, data):
        print("Login successful!")
        return True, user
    else:
        print("Locker ID and PIN do not match.")
        return False, None


def verify_pin(user, data):
    """Prompts for PIN verification for sensitive actions."""
    print("--- Security Verification ---")
    pin =input("Enter your 4-digit PIN to confirm action: ").strip()
    if check_pin(user, pin, data):
        print("Verification successful.")
        return True
    else:
        print("Verification failed. Incorrect PIN.")
        return False


def add_item(data, user):
    """Allows the user to add a new item, encrypting and optionally setting an expiry."""
    
    # 1. PIN Verification
    if not verify_pin(user, data):
        return

    print("--- Add New Item ---")
    
    # 2. Choose Category
    print("Available Categories:")
    for i, cat in enumerate(ITEM_CATEGORIES):
        print(f"{i+1}. {cat}")

    while True:
        try:
            cat_choice = input("Select category number: ").strip()
            if not cat_choice: continue    
            cat_choice = int(cat_choice)
            if 1 <= cat_choice <= len(ITEM_CATEGORIES):
                category = ITEM_CATEGORIES[cat_choice - 1]
                break
            else:
               print("Invalid category number.")
        except ValueError:
            print("Invalid input. Please enter a number.")
            
    # 3. Get Item Details
    item_text = input(f"Enter the text for this '{category}' item: ").strip()
    if not item_text:
        print("Item text cannot be empty. Item not added.")
        return
    
    # 4. Expiry Option
    expiry_seconds = 0
    while True:
        expiry_input = input("Set expiry (e.g.60m, 2h, 1d) or leave blank for permanent: ").strip().lower()
        if not expiry_input:
            break
        
        try:
            unit = expiry_input[-1]
            value = int(expiry_input[:-1])
            
            if unit == 'm': # Minutes
                expiry_seconds = value * 60
            elif unit == 'h': # Hours
                expiry_seconds = value * 3600
            elif unit == 'd': # Days
                expiry_seconds = value * 86400
            else:
                raise ValueError
            
            break
        except:
            print("Invalid format. Use integer followed by 'm', 'h', or 'd' (e.g., 30m, 1h).")

    # 5. Encrypt and Store
    encrypted_item = xor_cipher(item_text, XOR_KEY)
    
    expiry_time = 0
    if expiry_seconds > 0:
        expiry_time = int(time.time()) + expiry_seconds
    
    item_data = {
        "data": encrypted_item,
        "expiry": expiry_time, # 0 means permanent
        "created": int(time.time())
    }
    
    data[user]['items'][category].append(item_data)
    print(f"Item added and secured in '{category}'.")
    save_data(data)


def check_and_clean_items(data, user):
    """Checks for expired items and removes them before viewing/removing."""
    items_to_clean = False
    current_time = int(time.time())
    
    for category in ITEM_CATEGORIES:
        items_list = data[user]['items'][category]
        new_items_list = []
        
        for item in items_list:
            
             if item ['expiry'] != 0 and item['expiry'] < current_time:
                print(f"Item in '{category}' has expired and was automatically deleted.")
                items_to_clean = True
             else:
                new_items_list.append(item)

    data[user]['items'][category] = new_items_list
        
    if items_to_clean:
        save_data(data)
        
    return data # Return the potentially updated data structure


def view_items(data, user):
    """Displays all stored, non-expired items for the user."""
    c=0
    # 1. Check and remove expired items
    data = check_and_clean_items(data, user)
    user_items = data[user]['items']
    
    for items in user_items.values():
      if not items :
       c=c+1 
        
    if c==4:    
        print("Your locker is empty.")
        return
    
    print("--- Your Items ---")
    
    # 2. PIN Verification for viewing all items
    if not verify_pin(user, data):
        print("Viewing aborted.")
        return

    # 3. Display and Decrypt
    for category, items_list in user_items.items():
        if items_list:
            print(f"## {category} ({len(items_list)} items)")
            for i, item_obj in enumerate(items_list):
                # Decrypt the stored data
                decrypted_item = xor_decipher(item_obj['data'], XOR_KEY)
                
                # Check expiry status for display
                expiry_status = "Permanent"
                if item_obj['expiry'] != 0:
                    expiry_dt = datetime.fromtimestamp(item_obj['expiry'])
                    expiry_status = f"Expires: {expiry_dt.strftime('%Y-%m-%d %H:%M:%S')}"
                
                # Display 
                print(f" {i+1}. {decrypted_item} [{expiry_status}]")
            print("-" * 20) 


def remove_item(data, user):
    """ Allows the user to remove an item from their locker by category and index."""
    
    # 1. PIN Verification
    if not verify_pin(user, data):
        return
    
    # 2. Check and remove expired items
    data = check_and_clean_items(data, user)
    user_items = data[user]['items']

    print("\n--- Remove Item ---")
    
    has_items = any(len(items) > 0 for items in user_items.values())
    if not has_items:
        print("Your locker is empty. Nothing to remove.")
        return
    
    # 3. Select Category
    print("Available Categories:")
    for i, cat in enumerate(ITEM_CATEGORIES):
        count = len(user_items.get(cat, []))
        print(f"{i+1}. {cat} ({count} items)")
        
    category_to_remove = None
    while True:
        try:
            cat_choice = input("Enter the number of the Category to remove an item from: ").strip()
            if not cat_choice: continue
            
            cat_choice = int(cat_choice) - 1
            
            if 0 <= cat_choice < len(ITEM_CATEGORIES):
                category_to_remove = ITEM_CATEGORIES[cat_choice]
                break
            else:
                print("Invalid category number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    items_list = user_items.get(category_to_remove, [])
    if not items_list:
        print(f"The '{category_to_remove}' category is empty. Nothing to remove.")
        return
    
    # 4. Select Item Index
    print(f"\nItems in '{category_to_remove}':")
    for i, item_obj in enumerate(items_list): 
        # Decrypt for display
        decrypted_item = xor_decipher(item_obj['data'], XOR_KEY)
        print(f" {i+1}. {decrypted_item}")
        
    index_to_remove = None
    while True:
        try:
            index_to_remove_input = input("Enter the number of the item to remove: ").strip()
            if not index_to_remove_input: continue
            
            index_to_remove = int(index_to_remove_input) - 1
            break
        except ValueError:
            print("Invalid input. Please enter a number.")
            
    # 5. Remove Item
    if 0 <= index_to_remove < len(items_list):
        removed_item_obj = items_list.pop(index_to_remove) 
        removed_item_text = xor_decipher(removed_item_obj['data'], XOR_KEY)
        save_data(data)
        print(f"Item '{removed_item_text}' from '{category_to_remove}' removed successfully.")
    else:
        print("Invalid item number.")


def DigitalLockerSystem():
    """Function to run the Digital Locker System."""
    data = load_data()
    user = None
    
    while True:
        if user is None:
            print("<<< Digital Locker System - Phase 2 >>>")
            print("1. Register New User")
            print("2. Login")
            print("3. Exit Program")
            choice = input("Choose an option: ").strip()

            if choice == '1':
                register_user(data)

            elif choice == '2':
                logged_in, user = login_user(data)
                
            elif choice == '3':
                print("Exiting the Digital Locker System. Goodbye!")
                break
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
        
        else: # User is logged in
            print(f"\n--- Welcome back, {user}! ---")
            print("1. Add an item (Requires PIN)")
            print("2. View all items (Requires PIN)")
            print("3. Remove an item (Requires PIN)")
            print("4. Logout")
        
            locker_choice = input("Enter your choice: ").strip()
        
            if locker_choice == '1':
                add_item(data, user)
            elif locker_choice == '2':
                view_items(data, user)
            elif locker_choice == '3':
                remove_item(data, user)
            elif locker_choice == '4':
                print(f"Logging out {user}.")
                user = None
            else:
                print("Invalid choice. Please try again.")




DigitalLockerSystem()
