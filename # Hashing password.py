# Hashing password
import tkinter as tk
import bcrypt

# Function to generate a salt
def generate_salt():
    salt = bcrypt.gensalt()
    salt_entry.delete(0, tk.END)  # Clear the entry field
    salt_entry.insert(0, salt.decode())  # Insert the new salt

# Function to hash the password
def hash_password():
    password = password_entry.get().encode()
    salt = salt_entry.get().encode()

    if salt and password:
        hashed = bcrypt.hashpw(password, salt)
        hash_entry.delete(0, tk.END)  # Clear previous hash
        hash_entry.insert(0, hashed.decode())  # Insert the new hashed password
    else:
        hash_entry.delete(0, tk.END)
        hash_entry.insert(0, "Missing salt or password")  # Error handling

# Function to check if the password is correct
def check_password():
    password = password_check_entry.get().encode()
    stored_hash = hash_entry.get().encode()

    if bcrypt.checkpw(password, stored_hash):
        result_label.config(text="Password is correct", fg="green")
    else:
        result_label.config(text="Password is incorrect", fg="red")

# Create the main window
root = tk.Tk()
root.title("Password Hashing Tool")
root.geometry("450x300")
root.configure(bg="#f4f4f9")

# Styling variables
font_main = ("Arial", 12)
font_button = ("Arial", 10, "bold")
bg_color = "#f4f4f9"
entry_bg = "#ffffff"
button_bg = "#4CAF50"
button_fg = "#ffffff"

# Labels and entry for password input
tk.Label(root, text="Enter Password:", font=font_main, bg=bg_color).grid(row=0, column=0, pady=10, padx=10, sticky="e")
password_entry = tk.Entry(root, width=40, show="*", font=font_main, bg=entry_bg)
password_entry.grid(row=0, column=1, pady=10, padx=10)

# Labels and entry for salt
tk.Label(root, text="Generated Salt:", font=font_main, bg=bg_color).grid(row=1, column=0, pady=10, padx=10, sticky="e")
salt_entry = tk.Entry(root, width=40, font=font_main, bg=entry_bg)
salt_entry.grid(row=1, column=1, pady=10, padx=10)

# Labels and entry for hashed password
tk.Label(root, text="Hashed Password:", font=font_main, bg=bg_color).grid(row=2, column=0, pady=10, padx=10, sticky="e")
hash_entry = tk.Entry(root, width=40, font=font_main, bg=entry_bg)
hash_entry.grid(row=2, column=1, pady=10, padx=10)

# Generate Salt and Hash Password buttons
tk.Button(root, text="Generate Salt", font=font_button, bg=button_bg, fg=button_fg, command=generate_salt).grid(row=3, column=0, pady=10, padx=10)
tk.Button(root, text="Hash Password", font=font_button, bg=button_bg, fg=button_fg, command=hash_password).grid(row=3, column=1, pady=10, padx=10)

# Password validation section
tk.Label(root, text="Check Password:", font=font_main, bg=bg_color).grid(row=4, column=0, pady=10, padx=10, sticky="e")
password_check_entry = tk.Entry(root, width=40, show="*", font=font_main, bg=entry_bg)
password_check_entry.grid(row=4, column=1, pady=10, padx=10)

# Check Password button and result label
tk.Button(root, text="Check Password", font=font_button, bg=button_bg, fg=button_fg, command=check_password).grid(row=5, column=0, pady=10, padx=10)
result_label = tk.Label(root, text="", font=font_main, bg=bg_color)
result_label.grid(row=5, column=1, pady=10, padx=10)

# Start the Tkinter main loop
root.mainloop()

