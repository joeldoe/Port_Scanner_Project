'''
Skill Development Lab Project:
PORT SCANNER (GUI)

Created By: 
Joel Eldoe

About:
This is a python(tkinter) application which performs port scans on IPv4 addresses and generates a log file to store the information received.
'''

import socket, time
from datetime import datetime as dt
from tkinter import *
from tkinter import messagebox
import tkinter.font as tkFont

data = []
vulnerabilities = []

def getdate():
    now = dt.now()
    scan_date = now.strftime("%d/%m/%Y %Hh:%Mm:%Ss")
    return scan_date

def scan():
    target = ip_input.get()
    port_range = port_input.get()
    validity = target.split('.')

    if(len(validity) == 4):
        ports = port_range.split('-')

        if(len(ports) != 2 or int(ports[0]) > int(ports[1])):
            messagebox.showerror("Error!","Invalid port range.\nExample: START_PORT-END_PORT")
        else:
            start_port = int(ports[0])
            end_port = int(ports[1])
            
            Label(root, text="", font=font_style2, bg='black', fg='green').grid(row='6', column='0', columnspan='2')

            try:
                target = socket.gethostbyname(target)
            except socket.gaierror:
                Label(root, text=f"Name resolution error!", font=font_style2, bg='black', fg='green').grid(row='7', column='0', columnspan='2')

            f = open('scan_report.txt','a')

            Label(root, text=f"Scanning {target} from {start_port} to {end_port} ports...\n", font=font_style2, bg='black', fg='green').grid(row='8', column='0', columnspan='2')
            row = 9
            
            start_time = time.time()
            scan_date = getdate()
            f.write(f"Date of scan: {scan_date}\n")
            f.write(f"Target: {target}:{start_port}-{end_port}\n\n")

            for port in range(start_port,end_port+1):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    connection = s.connect_ex((target,port))
                    banner = s.recv(1024)
                    if(not connection):
                        Label(root, text=f"Port {port} is OPEN", font=font_style2, bg='black', fg='green').grid(row=row, column='0', columnspan='2')
                        data.append(port)
                        vulnerabilities.append(banner)
                    else:
                        Label(root, text=f"Port {port} is CLOSED", font=font_style2, bg='black', fg='green').grid(row=row, column='0', columnspan='2')
                except Exception as e:
                    if(not connection):
                        Label(root, text=f"Port {port} is OPEN", font=font_style2, bg='black', fg='green').grid(row=row, column='0', columnspan='2')
                    else:
                        Label(root, text=f"Port {port} is CLOSED", font=font_style2, bg='black', fg='green').grid(row=row, column='0', columnspan='2')
                    Label(root, text=f"Error on receiving banner at port {port}: {e}", font=font_style2, bg='black', fg='green').grid(row=row, column='0', columnspan='2')
                s.close()
                row = row + 1

            end_time = time.time()
            total_time = end_time-start_time
            total_time = round(total_time,3)

            Label(root, text="", font=font_style2, bg='black', fg='green').grid(row=row, column='0', columnspan='2')

            for i in range(len(data)):
                row = row + 1
                Label(root, text=f"Port {data[i]} running a maybe vulnerable service: {vulnerabilities[i]}", font=font_style2, bg='black', fg='green').grid(row=row, column='0', columnspan='2')
                f.write(f"Open port: {data[i]}, Service: {vulnerabilities[i].decode()}")

            if(len(data) == 0):
                f.write("No open ports.")
            
            f.write(f"\nScan duration: {total_time}s\n\n")
            f.write("-"*60+"\n")
            f.close()

            row = row + 1
            Label(root, text=f"\nTime taken for this scan: {total_time}s", font=font_style2, bg='black', fg='green').grid(row=row, column='0', columnspan='2')
            row = row + 1
            Label(root, text=f"Scan date: {scan_date}\n", font=font_style2, bg='black', fg='green').grid(row=row, column='0', columnspan='2')
            messagebox.showinfo("Result","Scan complete")

    else:
        messagebox.showerror("Error!","Invalid IP address.\nOnly IPv4 allowed") 

root = Tk()
root.configure(bg='black')
root.title("Port Scanner")

font_style1 = tkFont.Font(family='Candara', size=16)
font_style2 = tkFont.Font(family='Verdana', size=14)

title = Label(root, text="Port Scanner", width='50', pady='10', font=font_style1, bg='black', fg='green')
title.grid(row='0', column='0', columnspan='2')

ask_ip = Label(root, text="Enter the IP address (IPv4) you want to scan: ", font=font_style2, bg='black', fg='green')
ask_ip.grid(row='1',column='0', pady='5')

ip_input = Entry(width='50', font=font_style2)
ip_input.grid(row='1', column='1', padx='5', pady='5')

ask_port_range = Label(root, text="Enter the range of ports (ex. START_PORT-END_PORT): ", font=font_style2, bg='black', fg='green')
ask_port_range.grid(row='2', column='0', pady='5')

port_input = Entry(width='50', font=font_style2)
port_input.grid(row='2', column='1', padx='5', pady='5')

scan_button = Button(root, text="Scan", font=font_style2, padx='30', pady='8', bg='grey', command=scan)
scan_button.grid(row='3', column='0', pady='5')

cancel_button = Button(root, text="Quit", font=font_style2, padx='30', pady='8', bg='grey', command=root.quit)
cancel_button.grid(row='3', column='1', pady='5')

root.mainloop()
