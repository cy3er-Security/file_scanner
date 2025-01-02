import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox


known_malicious_hashes = {
    'd41d8cd98f00b204e9800998ecf8427e',
  
}


def calculate_file_hash(file_path):
    
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hash_sha256.update(byte_block)
    return hash_sha256.hexdigest()


def scan_files(directory, file_extensions):
   
    suspicious_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file_extensions and not any(file.endswith(ext) for ext in file_extensions):
                continue 
            file_path = os.path.join(root, file)
            try:
                file_hash = calculate_file_hash(file_path)
                if file_hash in known_malicious_hashes:
                    suspicious_files.append(file_path)
            except Exception as e:
                print(f"000000000000000 {file_path}: {e}")
    return suspicious_files


def start_scan():
    
    directory = filedialog.askdirectory()
    if not directory:
        return

    file_extensions = entry_extensions.get().split(',')
    file_extensions = [ext.strip() for ext in file_extensions if ext.strip()]

    suspicious_files = scan_files(directory, file_extensions)

    if suspicious_files:
        result_text = " Suspicious files found:\n" + "\n".join(suspicious_files)
        messagebox.showinfo("Survey results ", result_text)
        save_results(suspicious_files)
    else:
        messagebox.showinfo(" Survey results", "No suspicious files found.")

def save_results(suspicious_files):
   
    with open("suspicious_files.txt", "w") as f:
        for file in suspicious_files:
            f.write(file + "\n")
    print("Results saved in suspicious_files.txt")


root = tk.Tk()
root.title("Suspicious File Scanner")

label = tk.Label(root, text=" Enter file extensions (such as .exe, .dll, .js):")
label.pack(pady=10)

entry_extensions =tk.Entry(root, width=50)
entry_extensions.pack(pady=10)

scan_button = tk.Button(root, text="start scan", command=start_scan)
scan_button.pack(pady=20)

root.mainloop()

#BY CY3ER

