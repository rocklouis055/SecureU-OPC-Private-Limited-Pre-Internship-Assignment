#Importing the required libraries
import os
import ctypes
import sys
import wmi
import winreg
import subprocess
import traceback

#Hosts path for website blocking
hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

#List of websites to be blocked
websites = ["facebook.com","www.facebook.com"]

#USB Registry Editor path and Key Value name
usb_key_path = r"SYSTEM\CurrentControlSet\Services\UsbStor"
usb_value_name = "Start"

#CMD Registry Editor path and Key Value name
cmd_key_path = r"Software\Policies\Microsoft\Windows\System"
cmd_value_name = "DisableCMD"
value_type = winreg.REG_DWORD

#Function to check Administartor Access
def is_admin():
    try:return ctypes.windll.shell32.IsUserAnAdmin()
    except:return False

#This function is to gain Administrator Access
def run_with_admin_privileges(script_path):
    args = " ".join(sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}" {args}', None, 1)

#Blocking website function
def block_website(site):
    with open(hosts_path, "a") as hosts_file:
        hosts_file.write(f"\n127.0.0.1 {site}")
    print(f"{site} blocked.")

#Unblocking function
def unblock_website(site):
    try:
        with open(hosts_path, "r") as hosts_file:
            lines = hosts_file.readlines()

        with open(hosts_path, "w") as hosts_file:
            for line in lines:
                if site not in line:
                    hosts_file.write(line)
        print(f"{site} unblocked.")
    except FileNotFoundError:
        print("Hosts file not found. Can't block websites.")

#Function to get USB device drive Mount Points and eject them
def eject_removable_drives():
    c = wmi.WMI()
    for drive in c.Win32_DiskDrive():
        if drive.InterfaceType == 'USB':
            for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    try:
                        run_command('powershell $driveEject = New-Object -comObject Shell.Application; $driveEject.Namespace(17).ParseName("""'+logical_disk.DeviceID+'""").InvokeVerb("""Eject""")')
                        print(f"Ejected: {logical_disk.DeviceID}")
                    except:
                        print(f"Error ejecting: {logical_disk.DeviceID}")

#Function to modify registery key values
def create_or_modify_registry_key(HKEY_TYPE,key_path, value_name, value_type, value_data):
    try:
        # Opening the registry key or creatint it if it doesn't exist
        reg_key = winreg.OpenKey(HKEY_TYPE, key_path, 0, winreg.KEY_SET_VALUE)
    except FileNotFoundError:
        reg_key = winreg.CreateKey(HKEY_TYPE, key_path)

    # Seting the registry value
    winreg.SetValueEx(reg_key, value_name, 0, value_type, value_data)

    # Closing the registry key
    winreg.CloseKey(reg_key)

#Function to run commands
def run_command(command):
    subprocess.run(command, shell=True, check=True)

#Function to disable bluetooth server
def disable_bluetooth():
    # Disabling Bluetooth
    try:
        run_command("sc stop bthserv")
        run_command("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\BthServ /v Start /t REG_DWORD /d 4 /f")
        print("Bluetooth has been disabled.")
    except Exception:
        print("Not able to disable Bluetooth, Try again after sometime.")
#Function to enable bluetooth server
def enable_bluetooth():
    # Enabling Bluetooth
    try:
        run_command("sc config bthserv start= auto")
        run_command("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\BthServ /v Start /t REG_DWORD /d 2 /f")
        run_command("sc start bthserv")
        print("Bluetooth has been enabled.")
    except Exception:
        print("Not able to enable Bluetooth, Try again after sometime.")

#Main function
def main():
    if is_admin():
        print("Running with administrative privileges.")

        #This is to differentiate running directly the py file or exe file
        n=1
        if sys.argv[0].endswith("exe"):n+=1

        #Evrything will happen inside this try function for debugging purpose.
        try:

            #Blocking or Disabling
            if (len(sys.argv)==n) or (len(sys.argv) > n and (sys.argv[n].lower() == "-block" or sys.argv[n].lower()=="-b")):

                #Blocking all the sites from the website list
                for site in websites:block_website(site)

                #Ejecting USB Devices
                eject_removable_drives()

                #Disabling USB access
                create_or_modify_registry_key(winreg.HKEY_LOCAL_MACHINE,usb_key_path, usb_value_name, value_type, 4)
                print("Registry key modified to disable USB storage.")

                #Disabling Bluetooth
                disable_bluetooth()

                #At last , disabling the CMD, it should be last or else other disabling calls will not work.
                create_or_modify_registry_key(winreg.HKEY_CURRENT_USER,cmd_key_path, cmd_value_name, value_type, 1)
                print("Registry key modified to disable Command Prompt.")

            #Unblocking or Enabling
            elif (len(sys.argv) > n and (sys.argv[n].lower() == "-unblock" or sys.argv[n].lower()=="-u")):

                #At first , Enabling the CMD, it should be first or else other enabling calls will not work.
                create_or_modify_registry_key(winreg.HKEY_CURRENT_USER,cmd_key_path, cmd_value_name, value_type, 0)
                print("Registry key modified to enable Command Prompt.")

                #Unblocking all the sites from the website list
                for site in websites:unblock_website(site)

                #Enabling USB access
                create_or_modify_registry_key(winreg.HKEY_LOCAL_MACHINE,usb_key_path, usb_value_name, value_type,3)
                print("Registry key modified to enable USB storage.")

                #Enabling Bluetooth
                enable_bluetooth()

            #Will be called when the argument is wrong.
            else:
                print("Invalid argument. Use -b,-B,-block,-BLOCK to block or disable and -u,-U,-unblock,-UNBLOCK to unblock or enable.")

        except Exception as e:
            print("Some error occured!")
            traceback.print_exc()

        input("Press Enter to exit...")
    else:
        print("Not running with administrative privileges. Trying to elevate...")
        run_with_admin_privileges(sys.argv[0])

if __name__ == "__main__":
    main()