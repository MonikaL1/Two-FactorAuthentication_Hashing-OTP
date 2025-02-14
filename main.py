from tkinter import *
import bcrypt
import json
import os
import smtplib
import random
import string

# Database file
DB_FILE = "user_data.json"

# Temporary storage for OTPs
otp_storage = {}

# Email Credentials (Replace with your actual email and password)
EMAIL_ADDRESS = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"


# Function to send OTP email
def send_otp(email):
    otp = ''.join(random.choices(string.digits, k=6))  # Generate 6-digit OTP
    otp_storage[email] = otp  # Store OTP temporarily

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            message = f"Subject: Your OTP Code\n\nYour OTP for login is: {otp}"
            server.sendmail(EMAIL_ADDRESS, email, message)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# Function to load user database
def load_users():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as file:
            return json.load(file)
    return {}


# Function to save user database
def save_users(users):
    with open(DB_FILE, "w") as file:
        json.dump(users, file)


# Function to register a new user
def register():
    users = load_users()
    username = reg_username_entry.get()
    password = reg_password_entry.get()
    confirm_password = reg_confirm_password_entry.get()
    email = reg_email_entry.get()

    if not username or not password or not confirm_password or not email:
        reg_result_label.config(text="All fields are required!", fg="red")
        return

    if password != confirm_password:
        reg_result_label.config(text="Passwords do not match!", fg="red")
        return

    if username in users:
        reg_result_label.config(text="Username already exists!", fg="red")
        return

    if email in otp_storage:
        reg_result_label.config(text="Email is already used!", fg="red")
        return

    # Send OTP-One Time Password
    if send_otp(email):
        reg_result_label.config(text="OTP sent! Check your email.", fg="blue")
    else:
        reg_result_label.config(text="Failed to send OTP. Try again.", fg="red")
        return

    # Store user with hashed password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    users[username] = {"password": hashed_password, "email": email}
    save_users(users)

    # Clear fields
    reg_username_entry.delete(0, END)
    reg_password_entry.delete(0, END)
    reg_confirm_password_entry.delete(0, END)
    reg_email_entry.delete(0, END)


# Function to validate login
def login():
    users = load_users()
    username = login_username_entry.get()
    password = login_password_entry.get()
    otp_code = login_otp_entry.get()

    if username in users:
        email = users[username]["email"]
        stored_password = users[username]["password"]

        if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')) and otp_storage.get(
                email) == otp_code:
            login_result_label.config(text="Login Successful!", fg="green")
            otp_storage.pop(email)  # Remove OTP after successful login
        else:
            login_result_label.config(text="Invalid Credentials or OTP!", fg="red")
    else:
        login_result_label.config(text="User not found!", fg="red")


# Function to switch to login page
def show_login():
    reg_frame.pack_forget()
    login_frame.pack()


# Function to switch to registration page
def show_register():
    login_frame.pack_forget()
    reg_frame.pack()


# Create UI
root = Tk()
root.title("Secure Login System with OTP")
root.geometry("400x500")
root.resizable(False, False)

# Registration Frame
reg_frame = Frame(root)
Label(reg_frame, text="Register", font=("Arial", 14, "bold")).pack()
Label(reg_frame, text="Email:").pack()
reg_email_entry = Entry(reg_frame)
reg_email_entry.pack()

Label(reg_frame, text="Username:").pack()
reg_username_entry = Entry(reg_frame)
reg_username_entry.pack()

Label(reg_frame, text="Password:").pack()
reg_password_entry = Entry(reg_frame, show="*")
reg_password_entry.pack()

Label(reg_frame, text="Confirm Password:").pack()
reg_confirm_password_entry = Entry(reg_frame, show="*")
reg_confirm_password_entry.pack()

Button(reg_frame, text="Register", command=register).pack()
reg_result_label = Label(reg_frame, text="", font=("Arial", 12))
reg_result_label.pack()
Button(reg_frame, text="Already have an account? Login", command=show_login).pack()

# Login Frame
login_frame = Frame(root)
Label(login_frame, text="Login", font=("Arial", 14, "bold")).pack()
Label(login_frame, text="Username:").pack()
login_username_entry = Entry(login_frame)
login_username_entry.pack()

Label(login_frame, text="Password:").pack()
login_password_entry = Entry(login_frame, show="*")
login_password_entry.pack()

Label(login_frame, text="OTP Code:").pack()
login_otp_entry = Entry(login_frame)
login_otp_entry.pack()

Button(login_frame, text="Login", command=login).pack()
login_result_label = Label(login_frame, text="", font=("Arial", 12))
login_result_label.pack()
Button(login_frame, text="Don't have an account? Register", command=show_register).pack()

# Show Register Page First
reg_frame.pack()

root.mainloop()
