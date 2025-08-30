from microbit import *
import radio
import urandom

# Constants
GROUP_NUMBER = 1
MESSAGE_1 = "Hello World"
MESSAGE_2 = "Goodbye World"

# DHKE Parameters (small for educational purposes and Micro:bit constraints)
# In practice, these should be much larger!
DHKE_PRIME = 23  # Prime p
DHKE_GENERATOR = 5  # Generator for the group

# Global variables for key management
shared_secret = None
derived_key = None
key_exchange_complete = False

def select_mode():
    display.scroll('Press A button for Sender | Press B button For Reciever\n', 
                   wait=False,
                   delay=50
                  )
    while True:
        if button_a.was_pressed():
            return 1 # Send mode
        elif button_b.was_pressed():
            return 2 # Receive mode

def send_mode():
    global shared_secret, derived_key, key_exchange_complete
    
    display.scroll("SEND MODE ACTIVATED!", delay=50)
    
    if not perform_dhke_as_sender():
        display.scroll("KEY EXCHANGE FAILED!", delay=50)
        return
    
    display.scroll("KEY EXCHANGE SUCCESS!", delay=50)
    
    while True: 
        if button_a.was_pressed():
            on_send(MESSAGE_1)
        elif button_b.was_pressed():
            on_send(MESSAGE_2)
        
        received_msg = radio.receive_bytes()
        if received_msg:
            data = on_receive(received_msg)
            display.scroll(data, delay=50) 
        sleep(500)

def receive_mode():
    global shared_secret, derived_key, key_exchange_complete
    
    display.scroll("RECEIVE MODE ACTIVATED!", delay=50)
    
    if not perform_dhke_as_receiver():
        display.scroll("KEY EXCHANGE FAILED!", delay=50)
        return
        
    display.scroll("KEY EXCHANGE SUCCESS!", delay=50)
    
    while True:
        received_msg = radio.receive_bytes()
        if received_msg:
            data = on_receive(received_msg)
            display.scroll(data, delay=50)

def perform_dhke_as_sender():
    """
    TODO: 
    Implement the sender's side of the Diffie-Hellman Key Exchange.
    
    Steps:
    1. Generate a private key using generate_private_key()
    2. Calculate your public key using calculate_public_key()
    3. Send your public key to the receiver
    4. Wait for and receive the receiver's public key
    5. Calculate the shared secret using calculate_shared_secret()
    6. Derive the encryption key using derive_key_from_shared_secret()
    
    Return True if successful, False otherwise.
    """
    global shared_secret, derived_key, key_exchange_complete
    
    try:
        # Step 1: Generate private key
        
        # Step 2: Calculate public key
        
        # Step 3: Send public key
        
        # Step 4: Wait for receiver's public key
        
        # Step 5: Calculate shared secret
        
        # Step 6: Derive encryption key
        
        return 
        
    except Exception as e:
        display.scroll("DHKE Error", delay=50)
        return False

def perform_dhke_as_receiver():
    """
    This is the receiver's side of the Diffie-Hellman Key Exchange.
      
    Steps:
    1. Generate a private key using generate_private_key()
    2. Calculate your public key using calculate_public_key()
    3. Wait for and receive the sender's public key
    4. Send your public key to the sender
    5. Calculate the shared secret using calculate_shared_secret()
    6. Derive the encryption key using derive_key_from_shared_secret()
    
    Return True if successful, False otherwise.
    """
    global shared_secret, derived_key, key_exchange_complete
    
    try:
        # Step 1: Generate private key
        
        # Step 2: Calculate public key
        
        # Step 3: Wait for sender's public key
        timeout = 0
        sender_public_key = None
        
        while timeout < 10:  # 5 second timeout
            received = radio.receive_bytes()
            if received and len(received) == 2:
                sender_public_key = int.from_bytes(received, 'big')
                break
            sleep(500)
            timeout += 1
        
        if sender_public_key is None:
            return False

        # Step 4: Send public key
        
        # Step 5: Calculate shared secret
        shared_secret = calculate_shared_secret(private_key, sender_public_key)
        
        # Step 6: Derive encryption key
        derived_key = derive_key_from_shared_secret(shared_secret)
        key_exchange_complete = True
        
        return True
        
    except Exception as e:
        display.scroll("DHKE Error", delay=50)
        return False

def generate_private_key():
    """
    Generates a random private key for DHKE - a random integer between 1 and (DHKE_PRIME - 1).
    """
    return urandom.randint(1, DHKE_PRIME - 1)

def calculate_public_key(private_key):
  """
    Calculates the public key using the formula:
    public_key = (DHKE_GENERATOR ^ private_key) mod DHKE_PRIME
    
    Args:
        private_key (int): Your private key
    
    Returns:
        int: Your public key
    """
    return pow(DHKE_GENERATOR, private_key, DHKE_PRIME)

def calculate_shared_secret(private_key, other_public_key):
    """
    TODO:
    This function should calculate the shared secret using the formula:
    shared_secret = (other_public_key ^ private_key) mod DHKE_PRIME
 
    Hint: Take a look at how we calculated the public key. 
    Is there anything we can use from that function?
    """
    return # Something is missing here...

def derive_key_from_shared_secret(secret):
    """
    This derives a 32-byte encryption key from the shared secret.
    Since our shared secret is just an integer, we need to
    expand it to create a proper 32-byte key for ChaCha20 to use.
    
    This is a simplified approach - in practice, you'd use a proper
    Key Derivation Function (KDF) like PBKDF2 or HKDF.
    
    Args:
        secret (int): The shared secret from DHKE
    
    Returns:
        bytes: A 32-byte key for encryption
    """
    secret_str = str(secret)
    expanded = (secret_str * (32 // len(secret_str) + 1))[:32]
    return expanded.encode('utf-8')

def on_send(msg):
    """
    Send function that encodes the message, encrypts it using ChaCha20
    with the derived key, adds a MAC, and sends it over radio.
    """
    global derived_key
    
    if not key_exchange_complete or derived_key is None:
        display.scroll("NO KEY!", delay=50)
        return
    
    mac = generate_mac(derived_key.decode('utf-8'), msg)
    encrypted_bytes = chacha20_encrypt(msg.encode('utf-8'), derived_key)
    data = mac + encrypted_bytes 
    radio.send_bytes(data)
    
def on_receive(received_bytes):
    """
    Receive function that decrypts received bytes and verifies MAC.
    """
    global derived_key
    
    if not key_exchange_complete or derived_key is None:
        return "NO KEY!"
    
    try:
        mac, msg = split_data(received_bytes)
        decrypted_bytes = chacha20_encrypt(msg, derived_key)
        data = decrypted_bytes.decode('utf-8')

        if verify_mac(derived_key.decode('utf-8'), data, mac):
            return data
        else:
            return "INVALID MAC"
    except TypeError:
        return "TYPE ERROR"
    except:
        return "UNEXPECTED ERROR"

def split_data(data):
    mac = data[0:2]
    msg = data[2:]
    return mac, msg

def main():
    radio.config(group=GROUP_NUMBER)
    radio.on()

    mode = select_mode()
    
    if mode == 1:
        send_mode()
    elif mode == 2:
        receive_mode()

# ---
# MAC Functions (from Part 3)
# ---
def simple_hash(input_string):
    """
    Calculates a simple hash value for a string.
    """
    table_size = 65536
    hash_value = 0
    for char in input_string:
        hash_value += ord(char)
    hash = hash_value % table_size
    return hash.to_bytes(2, byteorder='big')

def generate_mac(key, message):
    """
    Create a message authentication code (MAC) using the provided key and message.
    """
    return simple_hash(key + message)

def verify_mac(key, message, mac):
    """
    Verify a message authentication code (MAC).
    """
    return simple_hash(key + message) == mac

# ---
# CHACHA20 Module (from part 2 and 3)
# ---
import struct

def yield_chacha20_xor_stream(key, iv, position=0):
    """Generate the xor stream with the ChaCha20 cipher."""
    if not isinstance(position, int):
        raise TypeError
    if position & ~0xffffffff:
        raise ValueError('Position is not uint32.')
    if not isinstance(key, bytes):
        raise TypeError
    if not isinstance(iv, bytes):
        raise TypeError
    if len(key) != 32:
        raise ValueError
    if len(iv) != 8:
        raise ValueError

    def rotate(v, c):
        return ((v << c) & 0xffffffff) | v >> (32 - c)

    def quarter_round(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotate(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotate(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotate(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotate(x[b] ^ x[c], 7)

    ctx = [0] * 16
    ctx[:4] = (1634760805, 857760878, 2036477234, 1797285236)
    ctx[4 : 12] = struct.unpack('<8L', key)
    ctx[12] = ctx[13] = position
    ctx[14 : 16] = struct.unpack('<LL', iv)
    while 1:
        x = list(ctx)
        for i in range(10):
            quarter_round(x, 0, 4,  8, 12)
            quarter_round(x, 1, 5,  9, 13)
            quarter_round(x, 2, 6, 10, 14)
            quarter_round(x, 3, 7, 11, 15)
            quarter_round(x, 0, 5, 10, 15)
            quarter_round(x, 1, 6, 11, 12)
            quarter_round(x, 2, 7,  8, 13)
            quarter_round(x, 3, 4,  9, 14)
        for c in struct.pack('<16L', *(
            (x[i] + ctx[i]) & 0xffffffff for i in range(16))):
            yield c
        ctx[12] = (ctx[12] + 1) & 0xffffffff
        if ctx[12] == 0:
            ctx[13] = (ctx[13] + 1) & 0xffffffff

def chacha20_encrypt(data, key, iv=None, position=0):
    """Encrypt (or decrypt) with the ChaCha20 cipher."""
    if not isinstance(data, bytes):
        raise TypeError
    if iv is None:
        iv = b'\0' * 8
    if isinstance(key, bytes):
        if not key:
            raise ValueError('Key is empty.')
        if len(key) < 32:
            key = (key * (32 // len(key) + 1))[:32]
        if len(key) > 32:
            raise ValueError('Key too long.')

    return bytes(a ^ b for a, b in
        zip(data, yield_chacha20_xor_stream(key, iv, position)))

if __name__ == "__main__":
    main()