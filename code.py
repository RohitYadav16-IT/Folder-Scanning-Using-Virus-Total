import os
import hashlib
import requests
from pathlib import Path
import time
from tkinter import Tk, Text, Scrollbar, Label, Frame, Button, filedialog, messagebox, simpledialog
import webbrowser
import tkinter as tk
from tkinter import ttk
from datetime import datetime

total_files_processed = 0  # Global counter for total files processed
root = None  # Global variable for Tkinter root window
text_widget = None  # Global variable for Tkinter Text widget
file_reputation_cache = {}  # Global dictionary to store file hashes and their reputation information

# Function to calculate file hash
def calculate_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # Read in 64k chunks
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()

# Function to submit file hash to VirusTotal and get reputation report
def get_file_reputation(file_hash, api_keys):
    for api_key in api_keys:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': api_key}
        start_time = time.time()
        response = requests.get(url, headers=headers)
        end_time = time.time()
        if response.status_code == 200:
            reputation_info = response.json()
            reputation_info['start_time'] = start_time
            reputation_info['end_time'] = end_time
            return reputation_info
    return None

    
# Function to convert epoch time to standard time
def epoch_to_standard_time(epoch_time):
    if isinstance(epoch_time, int) and epoch_time != 0:
        return datetime.fromtimestamp(epoch_time).strftime('%H-%M-%S | %Y-%m-%d')
    return "NA"    

# Function to generate HTML content for old files reputation information
def generate_html_content():
    html_content = ""
    with open("file_reputation_template.html", "r") as file:
        html_content = file.read()

    serial_number = 1
    with open("scanned_files_info.txt", "r") as file:
        for line in file:
            if line.strip().startswith("File Hash:"):
                file_hash = line.strip().split(": ")[1]
                html_content += f"<div class='file-info'>"
                html_content += f"<h2>{serial_number}. File: {file_hash}</h2>"
                serial_number += 1
            elif line.strip().startswith("Size:"):
                html_content += f"<p>{line.strip()}</p>"
            elif line.strip().startswith("Scan Time:"):
                html_content += f"<p>{line.strip()}</p>"
            elif line.strip().startswith("Reputation Results:"):
                html_content += f"<h3><strong>Reputation Results:</strong></h3>"
            elif line.strip().startswith("Additional Details:"):
                html_content += f"<h3><strong>Additional Details:</strong></h3>"
            elif line.strip():
                html_content += f"<p>{line.strip()}</p>"
            else:
                html_content += "</div>"

    return html_content


# Function to save HTML content to a file
def save_html_file(html_content, file_path):
    with open(file_path, 'w') as f:
        f.write(html_content)

# Function to generate HTML file
def generate_html_file():
    html_content = generate_html_content()
    html_file_path = os.path.join(os.getcwd(), 'files_information.html')
    save_html_file(html_content, html_file_path)
    return html_file_path
    
# Function to generate HTML content for old files reputation information
def old_generate_html_content():
    html_content = ""
    with open("old_file_reputation_template.html", "r") as file:
        html_content = file.read()

    serial_number = 1
    with open("scanned_files_info.txt", "r") as file:
        for line in file:
            if line.strip().startswith("File Hash:"):
                file_hash = line.strip().split(": ")[1]
                html_content += f"<div class='file-info'>"
                html_content += f"<h2>{serial_number}. File: {file_hash}</h2>"
                serial_number += 1
            elif line.strip().startswith("Size:"):
                html_content += f"<p>{line.strip()}</p>"
            elif line.strip().startswith("Scan Time:"):
                html_content += f"<p>{line.strip()}</p>"
            elif line.strip().startswith("Reputation Results:"):
                html_content += f"<h3><strong>Reputation Results:</strong></h3>"
            elif line.strip().startswith("Additional Details:"):
                html_content += f"<h3><strong>Additional Details:</strong></h3>"
            elif line.strip():
                html_content += f"<p>{line.strip()}</p>"
            else:
                html_content += "</div>"

    return html_content


# Function to save HTML content to a file
def old_save_html_file(html_content, file_path):
    with open(file_path, 'w') as f:
        f.write(html_content)

# Function to generate HTML file
def old_generate_html_file():
    html_content = old_generate_html_content()
    html_file_path = os.path.join(os.getcwd(), 'old_files_information.html')
    old_save_html_file(html_content, html_file_path)
    return html_file_path

def refresh():
    global total_files_processed  # Use the global counter
    downloads_path = os.path.join(Path.home(), 'Downloads')
    if not os.path.exists(downloads_path):
        text_widget.insert('end', "Downloads directory not found.", 'error')
    else:
        api_keys = ["bd2cb74845c460dae3b2a5d7d9841b1532d5376c6e0a63b7d6bd80bd1565f046", "a2d225b2f50fb6416edbca75a99b1907208e81dcf1f3eb7e87b48d5d6eeaa230", "d5d44613cfbad74950018ce6e135524f0a428f1cd00ffb4e87b48d5d6eeaa230", "41a8dcc6e36314dfe0a4fe925dbe551af7dd42352cbf0978f52c49a61d57559c"]
        scanned_files_hashes = set()

        # Check if scanned_files_hashes.txt exists, if not, create it
        if not os.path.exists("scanned_files_hashes.txt"):
            with open("scanned_files_hashes.txt", "w"):
                pass

        # Read existing hashes from the text file
        with open("scanned_files_hashes.txt", "r") as file:
            for line in file:
                scanned_files_hashes.add(line.strip())

        new_files = 0
        text_widget.config(state="normal")  # Enable editing
        text_widget.delete('1.0', 'end')  # Clear existing text
        text_widget.config(state="disabled")  # Disable editing

        for file_path in Path(downloads_path).iterdir():
            if file_path.is_file():
                file_hash = calculate_hash(file_path)

                if file_hash in scanned_files_hashes:  # Check if file hash exists in scanned files
                    continue  # Skip scanning if hash is already in the list

                total_files_processed += 1  # Increment global counter
                new_files += 1
                start_time = time.time()
                if file_hash not in file_reputation_cache:
                    reputation_info = get_file_reputation(file_hash, api_keys)
                    if reputation_info:
                        file_reputation_cache[file_hash] = reputation_info
                else:
                    reputation_info = file_reputation_cache[file_hash]
                end_time = time.time()
                scan_time = round(end_time - start_time, 2)
                if reputation_info:
                    # Write the new file hash to the text file
                    with open("scanned_files_hashes.txt", "a") as file:
                        file.write(file_hash + "\n")

                    # Write the file hash and reputation information to the text file
                    with open("scanned_files_info.txt", "a") as file:
                        file.write(f"File Hash: {file_hash}\n")
                        file.write(f"Size: {reputation_info['data']['attributes']['size']} bytes\n")
                        file.write(f"Scan Time: {scan_time} seconds\n")
                        
                        # Calculate risk percentage
                        detected_count = sum(1 for result in reputation_info['data']['attributes']['last_analysis_results'].values() if result['result'] is not None)
                        total_scanners = len(reputation_info['data']['attributes']['last_analysis_results'])
                        risk_percentage = (detected_count / total_scanners) * 100
                        file.write(f"Risk Percentage: {risk_percentage:.2f}%\n")
                        
                        
                        file.write("Reputation Results:\n")
                        for scanner, result in reputation_info['data']['attributes']['last_analysis_results'].items():
                            file.write(f"{scanner} - {result['result']}\n")
                        file.write("Additional Details:\n")
                        if 'md5' in reputation_info['data']['attributes']:
                            file.write(f"MD5: {reputation_info['data']['attributes']['md5']}\n")
                        if 'sha1' in reputation_info['data']['attributes']:
                            file.write(f"SHA-1: {reputation_info['data']['attributes']['sha1']}\n")
                        if 'sha256' in reputation_info['data']['attributes']:
                            file.write(f"SHA-256: {reputation_info['data']['attributes']['sha256']}\n")
                        if 'ssdeep' in reputation_info['data']['attributes']:
                            file.write(f"SSDEEP: {reputation_info['data']['attributes']['ssdeep']}\n")
                        if 'tlsh' in reputation_info['data']['attributes']:
                            file.write(f"TLSH: {reputation_info['data']['attributes']['tlsh']}\n")
                        else:
                            file.write("TLSH: NA\n")
                        if 'magic' in reputation_info['data']['attributes']:
                            file.write(f"Magic: {reputation_info['data']['attributes']['magic']}\n")
                        if 'trid' in reputation_info['data']['attributes']:
                            file.write(f"TrID: {reputation_info['data']['attributes']['trid']}\n")
                        if 'first_submission_date' in reputation_info['data']['attributes']:
                            file.write(f"First Submission: {epoch_to_standard_time(reputation_info['data']['attributes']['first_submission_date'])}\n")
                        if 'last_submission_date' in reputation_info['data']['attributes']:
                            file.write(f"Last Submission: {epoch_to_standard_time(reputation_info['data']['attributes']['last_submission_date'])}\n")
                        if 'last_modification_date' in reputation_info['data']['attributes']:
                            file.write(f"Last Analysis: {epoch_to_standard_time(reputation_info['data']['attributes']['last_modification_date'])}\n")
                        file.write("\n\n")

                if reputation_info:
                    file_size_bytes = os.path.getsize(file_path)
                    file_size_kb = file_size_bytes / 1024  # Convert bytes to kilobytes
                    detected_count = 0
                    total_scanners = len(reputation_info['data']['attributes']['last_analysis_results'])
                    for result in reputation_info['data']['attributes']['last_analysis_results'].values():
                        if result['result'] is not None:
                            detected_count += 1
                    if detected_count == 0:
                        risk_percentage = 0.00
                    else:
                        risk_percentage = (detected_count / total_scanners) * 100

                    # Insert reputation information and additional details into text widget
                    text_widget.config(state="normal")  # Set the Text widget to be editable
                    text_widget.insert('end', f"{total_files_processed}. File: {os.path.basename(file_path)}\nSize: {file_size_kb:.2f} KB\nScan Time: {scan_time} seconds\nRisk Percentage: {risk_percentage:.2f}%\n\nReputation:\n", 'filename')
                    for scanner, result in reputation_info['data']['attributes']['last_analysis_results'].items():
                        bold_scanner = f"{scanner} -"
                        text_widget.insert('end', f"{bold_scanner} {result['result']}\n", 'scanner')

                    # Additional details
                    text_widget.insert('end', '\n\n')  # Add space between additional details and reputation information
                    text_widget.insert('end', 'Additional Details:\n', 'headline')
                    if 'md5' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"MD5: {reputation_info['data']['attributes']['md5']}\n", 'additional_details')
                    if 'sha1' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"SHA-1: {reputation_info['data']['attributes']['sha1']}\n", 'additional_details')
                    if 'sha256' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"SHA-256: {reputation_info['data']['attributes']['sha256']}\n", 'additional_details')
                    if 'ssdeep' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"SSDEEP: {reputation_info['data']['attributes']['ssdeep']}\n", 'additional_details')
                    if 'tlsh' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"TLSH: {reputation_info['data']['attributes']['tlsh']}\n", 'additional_details')
                    else:
                        text_widget.insert('end', "TLSH: NA\n", 'additional_details')
                    if 'magic' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"Magic: {reputation_info['data']['attributes']['magic']}\n", 'additional_details')
                    if 'trid' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"TrID: {reputation_info['data']['attributes']['trid']}\n", 'additional_details')
                    if 'first_submission_date' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"First Submission: {epoch_to_standard_time(reputation_info['data']['attributes']['first_submission_date'])}\n", 'additional_details')
                    if 'last_submission_date' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"Last Submission: {epoch_to_standard_time(reputation_info['data']['attributes']['last_submission_date'])}\n", 'additional_details')
                    if 'last_modification_date' in reputation_info['data']['attributes']:
                        text_widget.insert('end', f"Last Analysis: {epoch_to_standard_time(reputation_info['data']['attributes']['last_modification_date'])}\n", 'additional_details')

                    text_widget.insert('end', '\n\n')  # Add space between files
                    text_widget.config(state="disabled")  # Disable editing

        if new_files == 0:
            # Display message "No new files found. All files are already scanned." at the center of the Text widget
            text_widget.config(state="normal")  # Enable editing
            text_widget.insert('1.0', "No new files found. All files are already scanned.", 'center_bold')
            text_widget.tag_configure('center_bold', justify='center', font=('Arial', 12, 'bold'))
            text_widget.config(state="disabled")  # Disable editing
  # Disable editing  # Set the Text widget to be non-editable after inserting the message

# Function to open HTML file in browser
def open_in_browser():
    html_file_path = generate_html_file()
    webbrowser.open('file://' + os.path.abspath(html_file_path))

# Function to open HTML file in browser
def old_open_in_browser():
    html_file_path = old_generate_html_file()
    webbrowser.open('file://' + os.path.abspath(html_file_path))


def animate_button(button):
    button.config(relief=tk.RAISED, background="#4CAF50", foreground="white")  # Change button relief and color

def animate_button_leave(button):
    button.config(relief=tk.RAISED, background="#90EE90", foreground="black")  # Return to original state

def animate_on_click(button):
    button.config(relief=tk.SUNKEN, background="#4CAF50", foreground="white")  # Change button relief and color
    button.after(100, lambda: animate_button_leave_on_click(button))

def animate_button_leave_on_click(button):
    button.config(relief=tk.RAISED, background="#4CAF50", foreground="white")  # Return to original state
    button.after(100, lambda: animate_button(button))


old_files_window = None
old_text_widget = None

def display_old_files_gui():
    global old_files_window, old_text_widget
    old_files_window = Tk()
    old_files_window.title("Old Files Information")
    old_files_window.geometry("900x700")

    main_frame = Frame(old_files_window, bg="lightgray", relief="solid", bd=1)
    main_frame.pack(fill="both", expand=True)

    text_frame = Frame(main_frame, bg="lightgray")
    text_frame.pack(side='top', fill='both', expand=True, padx=10, pady=10)

    label = Label(text_frame, text="Old Files Information", font=('Arial', 16, 'bold'), bg="lightgray")
    label.pack(pady=(0, 10))

    old_text_widget = Text(text_frame, wrap='word', font=('Arial', 14), bg="white", relief="flat", spacing2=5)  # Increased font size to 12
    old_text_widget.pack(expand=True, fill='both')

    scrollbar = Scrollbar(text_frame, command=old_text_widget.yview, bg="lightgray", troughcolor="lightgray")
    scrollbar.pack(side='right', fill='y')

    old_text_widget.config(yscrollcommand=scrollbar.set)
    
    text_widget.tag_configure('filename', foreground='orange', font=('Arial', 13, 'bold'))
    text_widget.tag_configure('scanner', font=('Arial', 12, 'bold'))
    text_widget.tag_configure('headline', foreground='orange', font=('Arial', 14, 'bold'))
    text_widget.tag_configure('additional_details', font=('Arial', 13, 'bold'))
    text_widget.config(state="disabled")

    open_browser_button = Button(main_frame, text="Open in Browser", command=old_open_in_browser)
    open_browser_button.pack(side='bottom', pady=10)
    open_browser_button.bind('<Enter>', lambda event, b=open_browser_button: animate_button(b))
    open_browser_button.bind('<Leave>', lambda event, b=open_browser_button: animate_button_leave(b))
    open_browser_button.bind('<ButtonPress-1>', lambda event, b=open_browser_button: animate_on_click(b))
    open_browser_button.bind('<ButtonRelease-1>', lambda event, b=open_browser_button: animate_button_leave_on_click(b))

    update_old_files_info()
    old_files_window.mainloop()

def update_old_files_info():
    global old_text_widget
    try:
        with open("scanned_files_info.txt", "r") as file:
            file_info = file.read().split('\n\n\n')  # Split by triple newline to separate each file's information
            old_text_widget.config(state="normal")
            old_text_widget.delete('1.0', 'end')
            for idx, info in enumerate(file_info, start=1):
                old_text_widget.insert('end', f"{idx}. {info.strip()}\n\n\n")  # Insert serial number and add space between files
            old_text_widget.config(state="disabled")
    except FileNotFoundError:
        old_text_widget.config(state="normal")
        old_text_widget.delete('1.0', 'end')
        old_text_widget.insert('end', "No old files information available.")
        old_text_widget.config(state="disabled")
    
    old_files_window.after(15000, update_old_files_info)


# Function to display GUI
def display_all_reputations_gui():
    global root
    root = Tk()
    root.title("File Reputation Information")
    root.geometry("900x700")

    main_frame = Frame(root, bg="lightgray", relief="solid", bd=1)  
    main_frame.pack(fill="both", expand=True)

    text_frame = Frame(main_frame, bg="lightgray")
    text_frame.pack(side='top', fill='both', expand=True, padx=10, pady=10)

    label = Label(text_frame, text="File Reputation Information", font=('Arial', 16, 'bold'), bg="lightgray")
    label.pack(pady=(0, 10))

    global text_widget
    text_widget = Text(text_frame, wrap='word', font=('Arial', 14), bg="white", relief="flat", spacing2=5)
    text_widget.pack(expand=True, fill='both')

    scrollbar = Scrollbar(text_frame, command=text_widget.yview, bg="lightgray", troughcolor="lightgray")  
    scrollbar.pack(side='right', fill='y')

    text_widget.config(yscrollcommand=scrollbar.set)

    buttons_frame = Frame(main_frame, bg="lightgray")  
    buttons_frame.pack(side='bottom', pady=10)

    # Add animation to refresh button
    refresh_button = tk.Button(buttons_frame, text="Refresh", command=refresh)
    refresh_button.pack(side='left', padx=10)
    refresh_button.bind('<Enter>', lambda event, b=refresh_button: animate_button(b))
    refresh_button.bind('<Leave>', lambda event, b=refresh_button: animate_button_leave(b))
    refresh_button.bind('<ButtonPress-1>', lambda event, b=refresh_button: animate_on_click(b))
    refresh_button.bind('<ButtonRelease-1>', lambda event, b=refresh_button: animate_button_leave_on_click(b))

    # Add animation to open browser button
    open_browser_button = tk.Button(buttons_frame, text="Open in Browser", command=open_in_browser)
    open_browser_button.pack(side='left', padx=10)
    open_browser_button.bind('<Enter>', lambda event, b=open_browser_button: animate_button(b))
    open_browser_button.bind('<Leave>', lambda event, b=open_browser_button: animate_button_leave(b))
    open_browser_button.bind('<ButtonPress-1>', lambda event, b=open_browser_button: animate_on_click(b))
    open_browser_button.bind('<ButtonRelease-1>', lambda event, b=open_browser_button: animate_button_leave_on_click(b))

    # Add animation to old files button
    old_files_button = tk.Button(buttons_frame, text="Old Files", command=display_old_files_gui)
    old_files_button.pack(side='left', padx=10)
    old_files_button.bind('<Enter>', lambda event, b=old_files_button: animate_button(b))
    old_files_button.bind('<Leave>', lambda event, b=old_files_button: animate_button_leave(b))
    old_files_button.bind('<ButtonPress-1>', lambda event, b=old_files_button: animate_on_click(b))
    old_files_button.bind('<ButtonRelease-1>', lambda event, b=old_files_button: animate_button_leave_on_click(b))

    refresh()  

    text_widget.tag_configure('filename', foreground='orange', font=('Arial', 13, 'bold'))
    text_widget.tag_configure('scanner', font=('Arial', 12, 'bold'))
    text_widget.tag_configure('headline', foreground='orange', font=('Arial', 14, 'bold'))
    text_widget.tag_configure('additional_details', font=('Arial', 13, 'bold'))
    text_widget.tag_configure('no_new_files', font=('Arial', 16, 'bold'), justify='center')  # Added tag for no new files message
    


    root.mainloop()

if __name__ == "__main__":
    display_all_reputations_gui()
