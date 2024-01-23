import tkinter as tk
from tkinter import filedialog, messagebox
import pandas as pd
import dns.resolver

def about():
    messagebox.showinfo("About", "Email Verification Tool\nVersion 1.0\n© 2024 Intent Amplify")

def check_email_validity(email):
    try:
        domain = email.split('@')[1]
        mx_records = dns.resolver.resolve(domain, 'MX')
        return bool(mx_records)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False

def process_bulk_emails(file_path):
    df = pd.read_excel(file_path)
    emails_to_check = df['Email'].tolist()

    results = []
    valid_count = 0
    invalid_count = 0

    for email in emails_to_check:
        is_valid = check_email_validity(email)
        status = 'Valid' if is_valid else 'Invalid'
        results.append({'email': email, 'status': status})

        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1

    return results, valid_count, invalid_count

def download_results(verification_results):
    save_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
    if save_path:
        df = pd.DataFrame(verification_results)
        df.to_excel(save_path, index=False)
        return f"Results saved to {save_path}"
    return "Download canceled"

def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
    if file_path:
        verification_results, valid_count, invalid_count = process_bulk_emails(file_path)
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        for result in verification_results:
            result_text.insert(tk.END, f"Email: {result['email']}, Status: {result['status']}\n")
        result_text.insert(tk.END, f"\nTotal emails: {len(verification_results)}\nValid emails: {valid_count}\nInvalid emails: {invalid_count}\n")
        result_text.config(state=tk.DISABLED)

        download_button.config(state=tk.NORMAL, command=lambda: display_message(download_results(verification_results)))

def display_message(message):
    result_text.config(state=tk.NORMAL)
    result_text.insert(tk.END, f"\n{message}\n")
    result_text.config(state=tk.DISABLED)

# Create main window
root = tk.Tk()
root.title("Email Verification Tool")
root.geometry("500x400")  # Set the initial size of the window

# Set background color
root.configure(bg='Grey')

# Create and configure widgets with colorful styles
upload_button = tk.Button(root, text="Upload Excel File", command=upload_file, bg='#4CAF50', fg='white', relief=tk.GROOVE)
download_button = tk.Button(root, text="Download Results", state=tk.DISABLED, bg='Yellow', fg='Black', relief=tk.GROOVE)
result_text = tk.Text(root, height=10, width=50, state=tk.DISABLED, wrap=tk.WORD, bg='#FFFFFF', fg='#333333', font=('Arial', 10))
about_button = tk.Button(root, text="About", command=about, bg='#555555', fg='white', relief=tk.GROOVE)

# Pack widgets with padding
upload_button.pack(pady=10)
download_button.pack(pady=10)
result_text.pack(padx=10, pady=10)
about_button.pack(pady=5)

# Run the GUI
root.mainloop()
