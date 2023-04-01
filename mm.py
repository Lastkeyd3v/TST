import itertools
import time
import threading
from eth_keys import keys
from eth_utils import to_checksum_address
import concurrent.futures


file1 = open("NEwFind" + time.strftime("%H-%M") + ".txt", "a")


def private_key_to_address(private_key):
    pk = keys.PrivateKey(bytes.fromhex(private_key))
    public_key = pk.public_key
    address = public_key.to_checksum_address()
    file1.write(f"{address} : {pk}\n")
    return address

def try_combination(combination, partial_key, missing_count, target_address, state, lock, counter):
    for positions in itertools.combinations(range(len(partial_key) + missing_count), missing_count):
        potential_key = ['?'] * (len(partial_key) + missing_count)
        partial_key_index = 0
        for i in range(len(potential_key)):
            if i in positions:
                potential_key[i] = combination[positions.index(i)]
            else:
                potential_key[i] = partial_key[partial_key_index]
                partial_key_index += 1
        candidate_private_key = "".join(potential_key)
        try:
            candidate_address = private_key_to_address(candidate_private_key)
            with lock:
                state['keys_checked'] += 1
                counter[0] += 1
            if candidate_address == target_address:
                return candidate_private_key
        except ValueError:
            pass
    return None

def brute_force_private_key(partial_key, missing_count, target_address, counter, num_threads=4):
    hex_chars = "0123456789abcdef"

    state = {'start_time': time.time(), 'keys_checked': 0}
    lock = threading.Lock()

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(try_combination, combination, partial_key, missing_count, target_address, state, lock, counter) for combination in itertools.product(hex_chars, repeat=missing_count)]
        for future in concurrent.futures.as_completed(futures):
            found_key = future.result()
            if found_key is not None:
                return found_key

    return None

partial_key = "53cdc7f093c355a8769a06513a20b7e4ce693f8d3da14b74d6aacbcf3f006"
missing_count = 3
target_address = "0x1980De9c02ceF0fB5598208C13c3925bA8d5deB0"

counter = [0]
total_keys_checked = [0]

def print_keys_per_second():
    while True:
        time.sleep(1)
        total_keys_checked[0] += counter[0]
        print("Total keys checked:", total_keys_checked[0], "Keys checked per second:", counter[0])
        counter[0] = 0

counter_thread = threading.Thread(target=print_keys_per_second)
counter_thread.daemon = True
counter_thread.start()

private_key = brute_force_private_key(partial_key, missing_count, target_address, counter, num_threads=4)

if private_key:
    print("Private key found:", private_key)
else:
    print("No private key matches the given address.")
