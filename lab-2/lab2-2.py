from microbit import *
import radio

# Constants
GROUP_NUMBER = 1
GLOBAL_KEY = b'chacha20!'
MESSAGE_1 = "Hello World"   # Change these if you like!
MESSAGE_2 = "Goodbye World" # Change these if you like!

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
        received_msg = radio.receive()
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
        decrypted_bytes = chacha20_encrypt(
            received_bytes, GLOBAL_KEY)
        data = decrypted_bytes.decode('utf-8')
        return data
    except TypeError:
        return "TYPE ERROR"
    except:
        return "WEIRD ERROR"

def main():
    radio.config(group=GROUP_NUMBER)
    radio.on()

    mode = select_mode()
    
    if mode == 1:
        send_mode()

    elif mode ==  2:
        receive_mode()
        

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

