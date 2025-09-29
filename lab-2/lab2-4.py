from microbit import *
import radio
from random import random

# Constants
GROUP_NUMBER = 1 #TODO: Change group number to your group
GLOBAL_KEY = None
MESSAGE_1 = "Hello World"
MESSAGE_2 = "Goodbye World"

def select_mode():
    display.scroll('Press A button for Sender | Press B button For Reciever\n', 
                   wait=False,
                   delay=50
                  )
    while True:
        if button_a.was_pressed():
            return 1
        elif button_b.was_pressed():
            return 2

def send_mode():
    display.scroll("SEND MODE ACTIVATED!", 
                  delay=50
                  )
    while True: 
        if button_a.was_pressed():
            on_send(MESSAGE_1)
        elif button_b.was_pressed():
            on_send(MESSAGE_2)
        received_msg = radio.receive_bytes()
        if received_msg:
            data = on_receive(received_msg)
            display.scroll(data,
                          delay=50
                          ) 
        sleep(500)

def receive_mode():
    display.scroll("RECEIVE MODE ACTIVATED!",
                  delay=50
                  )

    while True:
        received_msg = radio.receive_bytes()
        if received_msg:
            data = on_receive(received_msg)
            display.scroll(data,
                          delay=50
                          )     

def on_send(msg):
    """
    TODO: 
    Implement a send function that encodes the inputted
    message to bytes, encrypts the bytes using chacha20_encrypt()
    and then sends the encrypted bytes over the radio.
    """
    pass # Remove this line and implement your solution here
    
def on_receive(received_bytes):
    try:
        mac, msg = split_data(received_bytes)
        decrypted_bytes = chacha20_encrypt(
            msg, GLOBAL_KEY)
        data = decrypted_bytes.decode('utf-8')

        if verify_mac(GLOBAL_KEY.decode('utf-8'),
                  data,
                  mac):
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
        initialize_send_mode()

    elif mode ==  2:
        initialize_receive_mode()

# --------------------------------------------- 

# DHKE (Diffie-Hellman Key Exchange)
# Constants for DHKE
g = 5
p = 97

def initialize_send_mode():
    """
    TASK: Fix DHKE sender protocol
    TODO:
    1. Generate random private key 'a' (integer from 1 to p-1)
    2. Calculate public key A = g^a mod p using generate_A()
    3. Send A to receiver as string
    4. Wait for B from receiver
    5. Calculate shared secret using generate_and_set_K()
    6. Set GLOBAL_KEY and start send_mode()
    """
    global GLOBAL_KEY
    
    # TODO: Fix random number generation 
    a = int(random() * (p-1)) + 1 # generate the private share "a" random integer from 1 to p-1
    A = generate_A(a, g, p) # generate the public share A using the private a, g and p
    
    display.scroll("DHKE SEND")
    display.scroll("A=" + str(A))
    
    attempts = 0
    max_attempts = 20
    
    while GLOBAL_KEY is None and attempts < max_attempts:
        # Send A as string via radio using UTF-8 encoding
        radio.send_bytes(str(A).encode('utf-8'))  
        
        sleep(5000)  # Wait 5 seconds
        
        # TODO: Wait for B from receiver
        received_msg = radio.receive()
        if received_msg:
            try:
                # TODO: Parse B as integer
                B = int(received_msg)  
                
                # TODO: Calculate shared secret K
                K = generate_K(B, a, p)
                GLOBAL_KEY = K
                
                display.scroll("K=" + str(K))
                display.show(Image.YES)
                break
            except:
                # Invalid message, continue trying
                pass
        
        attempts += 1
    
    if GLOBAL_KEY is not None:
        display.scroll("KEY OK!")
        send_mode()
    else:
        display.scroll("KEY FAIL!")

def initialize_receive_mode(): 
    """
    TASK: Fix DHKE receiver protocol  
    TODO:
    1. Generate random private key 'b' (integer from 1 to p-1)
    2. Wait for A from sender
    3. Calculate public key B = g^b mod p using generate_B()
    4. Send B to sender as string
    5. Calculate shared secret using generate_and_set_K()
    6. Set GLOBAL_KEY and start receive_mode()
    """
    global GLOBAL_KEY
    
    # TODO: Fix random number generation
    b = int(random() * (p-1)) + 1
    
    display.scroll("DHKE RECV")
    
    attempts = 0
    max_attempts = 30
    
    while GLOBAL_KEY is None and attempts < max_attempts:
        # Wait for A from sender
        received_msg = radio.receive()
        if received_msg:
            try:
                # Parse A as integer
                A = int(received_msg)
                
                display.scroll("A=" + str(A))
                
                # TODO: Generate public key B
                B = 0 # generate the public share B using the private b, g and p
                display.scroll("B=" + str(B))
                
                # Send B to sender as string
                radio.send(str(B)) 
                
                # TODO: Calculate shared secret K
                K = 0 # generate the public share K using A, b and p
                GLOBAL_KEY = K
                
                display.scroll("K=" + str(K))
                display.show(Image.YES)
                break
            except:
                # Invalid message, continue waiting
                pass
        
        sleep(500)  # Check every 0.5 seconds
        attempts += 1
    
    if GLOBAL_KEY is not None:
        display.scroll("KEY OK!")
        receive_mode()
    else:
        display.scroll("KEY FAIL!")

def generate_A(a, g, p):
    # TODO: Generate A
    A = 0 # A = g^a mod p
    return A

def generate_B(b, g, p):
    # TODO: Generate B
    B = 0 # B = g^b mod p
    return B

def generate_K(X, y, p):
    # TODO: Generate X
    K = 0 # K = X^y mod p
    return K


# --------------------------------------------- 

# MAC (Message Authentication Code)
"""
TODO: 
Implement your own MAC functinality here.
Use the provided 'simple_hash()' function to generate your hash
and then make sure this hash is prepended to the bytes sent 
in the 'on_send()' function.  
"""
def simple_hash(input_string):
    """
    Calculates a simple hash value for a string.
    Args:
        input_string (str): The string to be hashed.
        table_size (int): The size of the hash table (determines the range of the hash).
    Returns:
        int: The calculated hash value.
    """
    table_size = 65536 # As we use a 2-byte hashing functions, we want to map our input string to a value between 0-65535.
    hash_value = 0
    for char in input_string:
        hash_value += ord(char)  # Add the ASCII value of each character

    hash = hash_value % table_size  # Apply modulo to fit within table_size
    byte1 = (hash >> 8) & 0xFF  # High byte (bits 15-8)
    byte2 = hash & 0xFF         # Low byte (bits 7-0)
    return bytes([byte1, byte2])  # Return the final hash value

def generate_mac(key, message):
    """
    TODO:
    Implement a function to create a message authentication code (MAC) using the provided key and message.
    """
    pass # Remove this line and implement your solution here

def verify_mac(key, message, mac):
    """
    TODO:
    Implement a function to verify a message authentication code (MAC) using the provided key, message, and MAC.
    This function should return True if the MAC is valid, and False otherwise.
    """
    pass # Remove this line and implement your solution here

# --------------------------------------------- 

# CHACHA20 Module
""" Retrieved from: https://github.com/pts/chacha20/tree/master"""
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
      # TODO(pts): Do key derivation with PBKDF2 or something similar.
      key = (key * (32 // len(key) + 1))[:32]
    if len(key) > 32:
      raise ValueError('Key too long.')

  return bytes(a ^ b for a, b in
      zip(data, yield_chacha20_xor_stream(key, iv, position)))


assert chacha20_encrypt(
    b'Hello World', b'chacha20!') == b'\xeb\xe78\xad\xd5\xab\x18R\xe2O~'
assert chacha20_encrypt(
    b'\xeb\xe78\xad\xd5\xab\x18R\xe2O~', b'chacha20!') == b'Hello World'


if __name__ == "__main__":
    main()

