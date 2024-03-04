import hashlib
import ecdsa
import base58
from multiprocessing import Pool, cpu_count
import random

# ANSI color escape codes
CYAN = '\033[96m'
YELLOW = '\033[93m'
RED = '\033[91m'
GREEN = '\033[92m'
PINK = '\033[95m'
RESET = '\033[0m'  # Reset color to default

# Define the range of private keys
start_hex = "00000000000000000000000000000000000000000000000200000003cf07a062"
end_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"

start_int = int(start_hex, 16)
end_int = int(end_hex, 16)

# Read target addresses from target.txt
with open('target3.txt', 'r') as file:
    target_addresses = {line.strip() for line in file}

num_target_addresses = len(target_addresses)

# Counter for the number of private keys checked
checked_count = 0

# Function to generate compressed address for a given private key
def generate_address(private_key):
    private_key_hex = hex(private_key)[2:].zfill(64)  # Convert to hex and zero fill to 64 characters
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Get the public key
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    public_key_compressed = signing_key.verifying_key.to_string("compressed")  # Compressed public key

    # Compute the hash of the public key
    sha256_hash = hashlib.sha256(public_key_compressed)
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash.digest())
    hash_bytes = ripemd160_hash.digest()

    # Add the version byte (0x00 for mainnet)
    version_byte = b'\x00'
    hash_with_version = version_byte + hash_bytes

    # Calculate the checksum
    checksum = hashlib.sha256(hashlib.sha256(hash_with_version).digest()).digest()[:4]

    # Concatenate the hash and checksum
    binary_address = hash_with_version + checksum

    # Convert the binary address to base58
    address = base58.b58encode(binary_address).decode()

    return private_key_hex, address

# Function to check if address matches any of the target addresses
def check_address(result):
    global checked_count  # Declare checked_count as global to use it in this function
    private_key_hex, address = result
    if address in target_addresses:
        print(f"{GREEN}Target found!{RESET}")
        print(f"{GREEN}Checked Count: {checked_count}{RESET}")
        print(f"{YELLOW}Private Key Hex: {private_key_hex}{RESET}")
        print(f"{PINK}Compressed Address: {address}{RESET}")

        # Remove the found target from the set of targets
        target_addresses.remove(address)

        # If all targets have been found, exit the loop
        if not target_addresses:
            return True

        # Write the result to the file
        with open('results.txt', 'a') as result_file:
            result_file.write(f"Private Key Hex: {private_key_hex}\n")
            result_file.write(f"Compressed Address: {address}\n")
            result_file.write("-----------------------------------------------\n")
        return True  # Stop after finding a target
    else:
        print(f"Checking...{RED}{checked_count}{RESET} | Compressed: {CYAN}{address}{RESET}  ")
        print(f"PrivateKey:{YELLOW}{private_key_hex}{RESET}")

# Pool initialization
pool = Pool(processes=cpu_count())

# Ask for search mode
search_mode = input("Enter search mode (1 for forward, 2 for random, 3 for backward): ")
if search_mode == "1":
    sequential_mode = True
    backward_mode = False
elif search_mode == "2":
    sequential_mode = False
    backward_mode = False
elif search_mode == "3":
    sequential_mode = True
    backward_mode = True
else:
    print("Invalid search mode. Exiting.")
    exit()

# Generate and check addresses
target_found = False
while not target_found:
    if sequential_mode and not backward_mode:
        private_key = start_int + checked_count  # Incremental search in sequential mode
    elif sequential_mode and backward_mode:
        private_key = end_int - checked_count  # Decremental search in sequential mode
    else:
        private_key = random.randint(start_int, end_int)  # Random search in random mode

    result = generate_address(private_key)
    checked_count += 1
    target_found = check_address(result)
    if target_found:
        break

print(f"{GREEN}Done.{RESET}")
