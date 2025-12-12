import requests #used to make http calls to pwned password api
import hashlib #used to hash passwords
import sys #help us read command-line argument


#Make request to API with first 5 hash characters
"""
   Send the first 5 characters of the SHA1 hash to the 
   Pwned Passwords API and get all matching password hashes.
"""
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    # If API request fails, stop the program with an error
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the api and try again")
    return res

#Count how many times our hash tail appears
"""
    The API returns a long list of 'HASH_TAIL:COUNT'.
    This function loops through all of them and checks
    if the tail matches the one from our password.
"""
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines()) # Generator: Split each line at ':'
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

#Convert password → SHA1 → check with API
"""
    Hash the password using SHA-1, split it into:
    - first 5 characters (sent to API)
    - remaining tail (checked locally)
"""
def pwned_api_checked(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper() #Convert password → SHA1 → HEX → UPPERCASE
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

#Loop through passwords user enters
"""
    Loop through each password passed in at the command line,
    check if it has been leaked, and print the results.
"""
def main(args):
    for password in args:
        count = pwned_api_checked(password)
        if count:
            print(f"{password} was found {count} times....change your password BUDDY!")
        else:
            print(f"{password} was not found....carry on")
    return "done!"

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

