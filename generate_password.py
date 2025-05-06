from werkzeug.security import generate_password_hash
import secrets
import string

def generate_strong_password(length=35):
    """Generate a strong random password of specified length"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 3
                and sum(c in string.punctuation for c in password) >= 2):
            return password

def main():
    print("Video Streaming Server - Password Setup")
    print("-" * 50)
    
    use_generated = input("Generate a strong password? (y/n): ").strip().lower() == 'y'
    
    if use_generated:
        password = generate_strong_password()
        print(f"\nGenerated password: {password}")
        print("IMPORTANT: Save this password in a secure location!")
    else:
        while True:
            password = input("\nEnter your password: ")
            if len(password) < 8:
                print("Password is too short! Use at least 8 characters.")
                continue
                
            confirm = input("Confirm password: ")
            if password != confirm:
                print("Passwords don't match! Try again.")
                continue
            break
    
    password_hash = generate_password_hash(password)
    print("\nPassword Hash (copy this to your streaming_server.py file):")
    print(password_hash)
    
    print("\nInstructions:")
    print("1. Copy the password hash above")
    print("2. Open streaming_server.py")
    print("3. Replace 'your-generated-hash-goes-here' with the copied hash")
    print("4. Save the file and run with: python streaming_server.py")
    print("\nYou'll use the username 'friend' and your chosen password to log in")

if __name__ == "__main__":
    main()