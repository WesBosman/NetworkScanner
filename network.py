'''
Created on Feb 11, 2016
@author: Wes
    This Program is made for scanning IP addresses and finding open ports on those 
    addresses. This program provides a GUI interface for dealing with scanning.
    Services and host names can also be scanned.
    
'''
import os
import platform
import socket, struct
import datetime
import Tkinter
import subprocess
import multiprocessing.dummy
#import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#from scapy.all import *
from multiprocessing import Pool
from threading import *
from Tkinter import *
from ttk import Button, Style, Label, Entry, Progressbar
from ScrolledText import ScrolledText

# Lists and variables -----------------------------------------------------------------------------------------------
# Determine my host name.
s = socket.gethostname()

# Determine IP address.
ip = socket.gethostbyname(s)

# List containing all my active ports
my_ports = []

# Instantiate a list of IP Addresses
ip_address_up = []

# Instantiate a list of Hosts
target_host_name = []

# Intantiate a list of ports belonging to other internet addresses.
target_port_up = []

# Dictionary to be used to find services on ports.
serv = {}

# Dictionary for my services
my_serv = {}

my_playform = platform.system()


# Get the ass many octets of any ip address that is passed into it that you want.
# needs bounds checking
def ip_octets(passed_ip, num_dots):
    count = 0
    new_ip = ""
    for i in range(0, len(passed_ip)):
        if passed_ip[i] == ".":
            count += 1
            if count == num_dots:
                new_ip = passed_ip[0:i + 1]

    return new_ip

# Does the same thing as the function above it except it gets the last octet instead of the first three
def ip_octets_backwards(passed, number_dots):
    count = 0
    new_ip = ""
    # Iterate through string
    for i in range(0, len(passed)):
        if passed[i] == ".":
            count += 1
            if count == number_dots:
                # Make new string starting after the dot and going to the end of the string.
                new_ip = passed[i + 1: len(passed)]
                
    return new_ip

# Global variables for the IP range to scan
start_ip = str(ip_octets(ip, 3)) + "0"
end_ip = str(ip_octets(ip, 3)) + "255"

# Methods for scanning localhost-------------------------------------------------------------------------------------
def my_host_name():
    # Print the name of the localhost machine.
    return "The name of this machine is: \t\t %s" % socket.gethostname() + "\n"

def my_ip():
    # Print the internet address of the localhost machine.
    return "The IP address of %s is: \t\t\t  %s" % (s , ip) + "\n"

def my_gateway():
    # Determine my netmask and print it.
    mask_length = 24
    mask = (1 << 32) - (1 <<32>>mask_length)
    return "Sub net mask: \t\t\t\t%s" % socket.inet_ntoa(struct.pack(">L", mask)) + "\n"

def port(arg):
    ip, i = arg
    
    try:
        # Address Family here IPv4, TCP connections.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, i))
        
        if(result == 0) :
            my_ports.append("Port %d: OPEN " % (i))
            my_serv.setdefault(ip, []).append(i)
        else:
            pass
        
    except socket.herror:
        print "An error occured."

    finally:
        # Close connections.
        sock.close()

    
# Scan reserved TCP ports.
def scan_my_ports(start, end):
    start_time = datetime.datetime.now()
    # Use multiple threads to scan ports in parallel.
    num_threads = 128
    num_port = range(start, end)
    pool = multiprocessing.dummy.Pool(num_threads)
    pool.map(port, [(ip, i) for i in num_port])
    pool.close()
    end_time = datetime.datetime.now()
    total_time = end_time - start_time
    return (my_ports, total_time)

def scan_my_services():
    my_msg = []
    my_open_ports = []
    start_time = datetime.datetime.now()
    for i in my_serv:
        my_open_ports = my_serv[i]
        for j in my_open_ports:
            connect_me = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect_me.settimeout(10)
                
            try:
                connect_me.connect((i, j))
                connect_me.send("Testing...\r\n")
                print "Connected to ip: %s on Port: %s" %(i, j)
                rez = connect_me.recv(4096)
                # if a service is discovered then add its message to the list. Otherwise do nothing.
                if rez:
                    msg = "The address " + str(i) + " is running => " + str(rez) + "service on port " + str(j) + "\n"
                    print msg
                    my_msg.append(msg)
                else:
                    pass
                    
            except socket.herror:
                print "- " + "An Error occurred. "
                pass
            except socket.timeout:
                print "- " + "The connection timed out."
                pass
            except Exception:
                pass
            finally:
                connect_me.close()
                
    end_time = datetime.datetime.now()
    total_time = end_time - start_time
    return (my_msg, total_time)
        
    

# Methods for scanning others ---------------------------------------------------------------------------------------

# Run ping command
def ping(ip):
    # Send 4 packets wait 3 milliseconds.
    if platform == "Windows":
        success = subprocess.call(["ping", "-n", "1", "-w", "3",  ip], shell = True)
    else:
        success = subprocess.call(["ping", "-c", "1", "-i", "3", ip])

    # If successful add it to the list.
    if success == 0:
        # Do not want duplicates.
        if ip not in ip_address_up:
            ip_address_up.append(ip)
            print ("{} is awake\n".format(ip))
    else:
        pass
    return success


# Ping nearby IP addresses using multithreading.
def ping_ip_other(start_add, finish_add):
    start = datetime.datetime.now()
    try:
        number_threads = 128
        p = multiprocessing.dummy.Pool(number_threads)
        # Scanning based on your subnet.
        # Get first three octets.
        starting_address = str(ip_octets(start_add, 3)) + "%s"
        p.map(ping, [starting_address % (i) for i in range(0, 255)])
    except Exception, e:
        print "Not a valid IP " + str(e)
    finally:
        p.close()
        
    end = datetime.datetime.now()
    total = end - start
    return (ip_address_up, total)

# Try to resolve host name based on IP address. 
def host(ip):
    # If successful add it the the list. 
    try:
        #turn tuple to a list
        success = socket.gethostbyaddr(ip)
        something = list(success)
        new_success = str(something[0]) + "       " + str(something[2]).replace("'", "").replace("[", "").replace("]", "")
        target_host_name.append(new_success)
        
    except socket.herror:
        pass
        
# Find the hostnames of the ip addresses found using multi-threading.
def scan_host_other(ip_address_up):
    start = datetime.datetime.now()
    number_threads = len(ip_address_up)
    p = multiprocessing.dummy.Pool(number_threads)
    p.map(host, [ i for i in ip_address_up])
    p.close()
    end = datetime.datetime.now()
    total = end - start
    return (target_host_name, total)

def services_other():
    
    # IP address list and Port scan has to be done first!!!
    # use list of found IP's which are keys to find the values of the ports
    list_msgs = []
    start_time = datetime.datetime.now()
    
    for i in serv:
        list_of_ports = serv[i]

        for j in list_of_ports:
            # i is the address j is the port.
            #print "This is i: %s, this is j: %s" %(i, j)
            connect_info = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect_info.settimeout(20)
                
            try:
                connect_info.connect((i, j))
                connect_info.send("Testing...\r\n")
                print "Connected to ip: %s on Port: %s" %(i, j)
                rez = connect_info.recv(4096)
                # if a service is discovered then add its message to the list. Otherwise do nothing.
                if rez:
                    msg = "The address " + str(i) + " is running => " + str(rez) + "service on port " + str(j) + "\n"
                    print msg
                    list_msgs.append(msg)
                else:
                    pass
                    
            except socket.timeout:
                print "- " + "The connection timed out."
                pass
            except Exception, e:
                print str(e)
                pass
            finally:
                connect_info.close()

        end_time = datetime.datetime.now()
        total_time = end_time - start_time
        return (list_msgs, total_time)
        

def port_other(arg):
    ip, i = arg
    
    try:
        # Address Family here IPv4, TCP connections
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, i))

        if(result == 0):
            # If the port is open add it to a list.
            target_port_up.append("Port {:>4} OPEN on address:  {:>7}".format(i, ip))
            print("Port %d: OPEN on address: %s" % (i, ip))
            
            # Add the IP and port to a dictionary where the IP is the key and the ports are values.
            serv.setdefault(ip, []).append(i)
            
        else:
            pass
        
    except socket.herror:
        print "An error occured during tcp port scan."

    # Close connections
    finally:
        sock.close()
        

# Scan other ports using a subset of the ip addresses stored in ip_address_up
def scan_ports_other(start_port, end_port):
    start = datetime.datetime.now()
    number_threads = 512
    number_ports = range(start_port, end_port)
    pool = multiprocessing.dummy.Pool(number_threads)
    # Get subset of IP addresses that are alive to scan.
    if ip_address_up:
        for j in ip_address_up:
            pool.map(port_other, [(j, i) for i in number_ports ] )
    else:
        print "List is empty."
    pool.close()
    end = datetime.datetime.now()
    total_time = end - start
    return (target_port_up, total_time)


# Setting up the GUI ------------------------------------------------------------------------------------------------
class Window(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.initUI()
        
    def initUI(self):
        self.parent.title("Network/Port Scan")
        self.style = Style()
        self.style.configure("TFrame", background = "#000000")
        self.style.configure("TCheckbutton", background = "#000000")
        self.style.configure("TButton", background = "#000000") 
        self.pack(fill=BOTH, expand=1)
        
        # Configure layout
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)
        self.rowconfigure(5, weight = 1)
        self.rowconfigure(6, weight = 1)
        
        # Title of program
        lbl = Label(self, text="Network/Port Scan")
        lbl.grid(sticky = W, pady=5, padx=5)

        # Text Box
        area = ScrolledText(self, height = 20)
        area.grid(row=1, column=0, columnspan=3, rowspan=4, padx=3, sticky = N+S+E+W)
        self.area = area

        # IP Address Button
        self.ip = BooleanVar()
        ip_add_button = Checkbutton(self, text="IP Address",variable=self.ip, width=10)
        ip_add_button.grid(row = 1, column = 3, sticky = N)
        ip_add_button.config(anchor = W, activebackground = "red")

        # Port Button
        self.port = BooleanVar()
        port_button = Checkbutton(self, text="Ports", variable=self.port, width=10)
        port_button.grid(row = 1, column = 3)
        port_button.config(anchor = W, activebackground = "orange")
        
        # Host Name Button
        self.host = BooleanVar()
        host_name_button = Checkbutton(self, text="Host Name",variable=self.host, width=10)
        host_name_button.grid(row = 1, column = 3, sticky = S)
        host_name_button.config(anchor = W, activebackground = "yellow")
        
        # Gateway Button
        self.gateway = BooleanVar()
        gateway_btn = Checkbutton(self, text="Gateway", variable=self.gateway, width=10)
        gateway_btn.grid(row = 2, column = 3, sticky = N)
        gateway_btn.config(anchor = W, activebackground = "green")

        # Services Button
        self.service = BooleanVar()
        service_btn = Checkbutton(self, text="Services", variable = self.service, width=10)
        service_btn.grid(row = 2, column = 3)
        service_btn.config(anchor = W, activebackground = "blue")

        # Starting IP label
        ip_label = Label(self, text = "Starting IP:  ")
        ip_label.grid(row = 5, column = 0, pady = 1, padx = 3, sticky = W)
        self.ip_from = Entry(self, width = 15)
        self.ip_from.insert(0, start_ip)
        self.ip_from.grid(row = 5 , column = 0, pady = 1, padx = 3, sticky = E)

        # Ending IP label
        ip_label_two = Label(self, text = "Ending IP:  ")
        ip_label_two.grid(row = 5, column = 1, pady = 1, padx = 5, sticky = W)
        self.ip_to = Entry(self, width = 15)
        self.ip_to.insert(0, end_ip)
        self.ip_to.grid(row = 5 , column = 1, pady = 1, padx = 5, sticky = E)
        
        # Starting Port Label
        port_label = Label(self, text = "Starting Port:  ")
        port_label.grid(row = 5, column = 0, pady = 3, padx = 5, sticky = S+W)
        self.port_from = Entry(self, width = 15)
        self.port_from.insert(0, 0)
        self.port_from.grid(row = 5 , column = 0, pady = 1, padx = 5, sticky = S+E)

        # Ending Port Label
        port_label_two = Label(self, text = "Ending Port:  ")
        port_label_two.grid(row = 5, column = 1, pady = 3, padx = 5, sticky = S+W)
        self.port_to = Entry(self, width = 15)
        self.port_to.insert(0, 1025)
        self.port_to.grid(row = 5 , column = 1, pady = 1, padx = 5, sticky = S+E)

        # Scan Me 
        self_scan_button = Button(self, text="Scan Me", command = lambda : self.onClick(1), width = 33)
        self_scan_button.grid(row = 6, column = 1, sticky = N)

        # Scan near me Button
        scan_other_button = Button(self, text="Scan Near Me", width = 33, command = lambda : self.onClick(2))
        scan_other_button.grid(row = 6, column = 0, pady=1, sticky = N)
        
        # Clear button
        clear_button = Button(self, text="Clear text", command = self.clear_text, width = 12)
        clear_button.grid(row = 6, column = 3, pady=1, sticky = N)

        # Progress Bar
        self.label_scanning = Progressbar(self, orient = HORIZONTAL, length = 175)
        self.label_scanning.grid(row = 6, column = 0, columnspan = 4, padx = 7, pady = 7, sticky = E+S+W)
        self.label_scanning.config(mode = "determinate")

     
    # Clear what is in the text box.   
    def clear_text(self):
        self.area.delete(0.0, 'end')
        # empty my lists.
        my_ports[:] = []
        ip_address_up[:] = []
        target_host_name[:] = []
        target_port_up[:] = []
        
    # On click methods for scan me and scan others.
    def onClick(self, button_id):
        
        if button_id == 1:
            
            # Check to see if host button is marked
            if self.host.get() == 1:
                message = my_host_name()
                self.area.insert(0.0, message, ("warning"))
                self.area.tag_configure("warning", foreground = "blue")    
                
            # Check to see if ports button is marked   
            if self.port.get() == 1:
                # Check port entry widgets. 
                if self.port_from:
                    if self.port_to:
                        # Get the user input
                        starting_port = self.port_from.get()
                        ending_port = self.port_to.get()                
                        message, total = scan_my_ports(int(starting_port), int(ending_port))
                        for i in message:
                            new_message = "My TCP " + i + "\n"
                            self.area.insert(0.0, new_message, ("ports"))
                            #self.area.tag_configure("ports", foreground = "green")
                    
                    time = "The TCP port scan completed in: " + str(total) + "\n"
                    self.area.insert(0.0, time, ("timing"))
                    self.area.tag_configure("timing", foreground = "red")
                else:
                    self.area.insert(0.0, "No valid ports specified.")
                
            # Check to see if IP button is marked     
            if self.ip.get() == 1:
                message = my_ip()
                self.area.insert(0.0, message)
            
            # Check if gateway button is marked.
            if self.gateway.get() == 1:
                message = my_gateway()
                self.area.insert(0.0, message)

            # Check if service button is marked.
            if self.service.get() == 1:
                message, time = scan_my_services()
                for i in message:
                    new_message = i + "\n"
                    self.area.insert(0.0, new_message)
                new_time = "The local scan completed in: " + str(time) + "\n"
                self.area.insert(0.0. new_time, ("timing"))
                self.area.tag_configure("timing", foreground = "red")
                
        # If Scan other button is clicked. 
        elif button_id == 2:
            
            # Check other IP's 
            if self.ip.get() == 1:
                # Check the entry widgets.
                if self.ip_from:
                    if self.ip_to:
                        # Get the ranges from the entry widgets
                        starting_ipv4_address = self.ip_from.get()
                        ending_ipv4_address = self.ip_to.get()
                        
                        # Pass the values from the entry widgets into the function to scan nearby IP addresses.
                        message, time = ping_ip_other(starting_ipv4_address, ending_ipv4_address)
                        if message:
                            for i in message:
                                new_message = "The address:     {:>15} {:>15}".format(i,"is UP\n")
                                self.area.insert(0.0, new_message)
                        
                        total_time =  "Range scanned: " + str(starting_ipv4_address) +" to " + str(ending_ipv4_address) + "\n" + "The IP scan completed in:  " + str(time) + "\n"
                        self.area.insert(0.0, total_time, ("timing"))
                        self.area.tag_configure("timing", foreground = "red")

                else:
                    self.area.insert(0.0, "No Ip range is specified.")
                
                
            # Check others Ports
            if self.port.get() == 1:
                # Check port entry widgets. 
                if self.port_from:
                    if self.port_to:
                        # Get the user input
                        starting_port = self.port_from.get()
                        ending_port = self.port_to.get()
                        
                        
                        message, time = scan_ports_other(int(starting_port), int(ending_port))
                        if message:
                            for i in message:
                                new_msg = "The " + i +"\n"
                                self.area.insert(0.0, new_msg)
                        else:
                            new_msg = "Must scan nearby IP addresses first.\n"
                    
                    total_time = "TCP Port scan completed in: " + str(time) + "\n"
                    self.area.insert(0.0, total_time, ("timing"))
                    self.area.tag_configure("timing", foreground = "red")
                    
                else:
                    self.area.insert(0.0, "No Port range specified.")
            
            # Check other host names. Based on IP's scanned.
            if self.host.get() == 1:
                message, time = scan_host_other(ip_address_up)
                # Check that IP's of other computers were collected 
                if message:
                    for i in message:
                        new_message = "Host name: "+ str(i) + "\n"
                        self.area.insert(0.0, new_message)

                else:
                    new_msg = "Must scan nearby IP addresses first. \n"
                    self.area.insert(0.0, new_msg)
                    
                total = "The host scan completed in: " + str(time) + "\n"
                self.area.insert(0.0, total, ("timing"))
                self.area.tag_configure("timing", foreground = "red")
                
            # Check gateway return the gateway of the host machine again.
            if self.gateway.get() == 1:
                message = "\n" + str(my_gateway())
                self.area.insert(0.0, message)

            # Check what services are running on which IP and port.
            if self.service.get() == 1:
                message, time = services_other()
                if message:
                    for i in message:
                        new_message = i + "\n"
                        self.area.insert(0.0, new_message)
                    
                else:
                    new_msg = "The IP addresses and ports must be scanned first."
                    self.area.insert(0.0, new_msg)
                    
                new_time = "The service scan completed in: " + str(time) + "\n"
                self.area.insert(0.0, new_time, ("timing"))
                self.area.tag_configure("timing", foreground = "red")
                
        else:
            pass
        
def main():
    top = Tkinter.Tk()
    top.geometry("550x480+400+200")
    application = Window(top)
    top.mainloop()

if __name__ == '__main__':
    main()
sys.exit(1)
