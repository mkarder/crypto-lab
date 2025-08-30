from microbit import *
import radio

# Constants
GROUP_NUMBER = 1 #TODO: Change group number to your group

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
            radio.send("A")
        elif button_b.was_pressed():
            radio.send("B")
        received_msg = radio.receive()
        if received_msg:
            display.scroll(received_msg,
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
            display.scroll(received_msg,
                          delay=50
                          )    
            
def main():
    radio.config(group=GROUP_NUMBER)
    radio.on()

    mode = select_mode()
    
    if mode == 1:
        send_mode()

    elif mode ==  2:
        receive_mode()
        
        

if __name__ == "__main__":
    main()

