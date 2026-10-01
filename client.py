import socket
import json
import getpass
import struct
import secrets

UDP_PORT = 7700
TCP_PORT = 7700

SHIFT = 7
MAX_PASS_LENGHT = 8

def crc16(data):
	crc = 0xFFFF

	for byte in data:
		crc ^= byte << 8

		for _ in range(8):
			if crc & 0x8000:
				crc = ((crc << 1) ^ 0x1021) & 0xFFFF
			else:
				crc = (crc << 1) & 0xFFFF

	return crc

def encrypt(data):
	return bytes((byte + SHIFT) % 256 for byte in data)


def decrypt(data):
	return bytes((byte - SHIFT) % 256 for byte in data)


def receive_exact(sock, size):
	result = bytearray()

	while len(result) < size:
		chunk = sock.recv(size - len(result))

		if not chunk:
			raise ConnectionError("Server disconnected")

		result.extend(chunk)

	return bytes(result)


def send_plain(sock, data):
	raw = json.dumps(data).encode("utf-8")
	sock.sendall(struct.pack("!I", len(raw)) + raw)


def receive_plain(sock):
	size = struct.unpack("!I", receive_exact(sock, 4))[0]

	if size > 1024 * 1024:
		raise ValueError("Message too large")

	return json.loads(receive_exact(sock, size).decode("utf-8"))


def send_secure(sock, data):
	raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
	encrypted = encrypt(raw)

	packet = {
		"data": encrypted.hex(),
		"crc": crc16(encrypted)
	}

	send_plain(sock, packet)


def receive_secure(sock):
	packet = receive_plain(sock)

	encrypted = bytes.fromhex(packet["data"])

	if crc16(encrypted) != packet["crc"]:
		raise ValueError("CRC16 verification failed")

	return json.loads(decrypt(encrypted).decode("utf-8"))


def find_server():
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
		udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		udp.settimeout(3)

		udp.sendto(
			b"DISCOVER_SERVER",
			("255.255.255.255", UDP_PORT)
		)

		try:
			data, address = udp.recvfrom(1024)
			response = json.loads(data.decode("utf-8"))

			print(f"Server found: {address[0]}")

			return address[0], response["tcp_port"]

		except socket.timeout:
			print("Broadcast search failed. Trying localhost.")

			return "127.0.0.1", TCP_PORT


def show_help():
	print("\n===== HELP =====")
	print("Program: Secure Remote Data Access")
	print("Author: Serhey Kr.")
	print("Task: Development of client-server remote access")
	print("to protected data.")
	print("Encryption: Caesar cipher, shift 7")
	print("Integrity check: CRC16-CCITT-FALSE")
	print("Key exchange demonstration: Diffie-Hellman")
	print("================\n")


def send_command(sock, command, **kwargs):
	send_secure(sock, {
		"command": command,
		**kwargs
	})

	return receive_secure(sock)


def change_password(sock):
	while True:
		new_password = getpass.getpass("New password: ")
		confirm = getpass.getpass("Confirm password: ")

		if new_password != confirm:
			print("Passwords do not match.")
			continue

		if len(new_password) < MAX_PASS_LENGHT:
			print("Password must contain at least 8 characters.")
			continue

		response = send_command(
			sock,
			"CHANGE_PASSWORD",
			new_password=new_password
		)

		print(response.get("message", "Unknown response"))
		return response.get("status") == "OK"


def add_user(sock):
	username = input("New username: ").strip()

	password = getpass.getpass("Initial password: ")
	confirm = getpass.getpass("Confirm initial password: ")

	if password != confirm:
		print("Passwords do not match.")
		return

	response = send_command(
		sock,
		"ADD_USER",
		username=username,
		password=password
	)

	print(response.get("message", "Unknown response"))


def block_user(sock):
	username = input("Username to block: ").strip()

	response = send_command(
		sock,
		"BLOCK_USER",
		username=username
	)

	print(response.get("message", "Unknown response"))


def get_document(sock):
	filename = "document.txt"

	response = send_command(
		sock,
		"GET_DOCUMENT",
		filename=filename
	)

	if response.get("status") == "OK":
		content = response.get("document", "")
		print("\n===== DOCUMENT =====")
		print(content)
		print("====================")

		with open("received_document.txt", "w", encoding="utf-8") as file:
			file.write(content)

		print("Document saved to received_document.txt")
	else:
		print(response.get("message", "Unknown error"))


def admin_menu(sock):
	while True:
		print("\n===== ADMIN MENU =====")
		print("1. Change password")
		print("2. Add user")
		print("3. Block user")
		print("4. Help")
		print("5. Get document")
		print("0. Logout")

		choice = input("Select: ")

		if choice == "1":
			change_password(sock)
		elif choice == "2":
			add_user(sock)
		elif choice == "3":
			block_user(sock)
		elif choice == "4":
			show_help()
		elif choice == "5":
			get_document(sock)
		elif choice == "0":
			send_command(sock, "LOGOUT")
			break
		else:
			print("Invalid choice.")


def user_menu(sock):
	while True:
		print("\n===== USER MENU =====")
		print("1. Change password")
		print("2. Get document")
		print("3. Help")
		print("0. Logout")

		choice = input("Select: ")

		if choice == "1":
			change_password(sock)
		elif choice == "2":
			get_document(sock)
		elif choice == "3":
			show_help()
		elif choice == "0":
			send_command(sock, "LOGOUT")
			break
		else:
			print("Invalid choice.")


def login(sock):
	for attempt in range(3):
		username = input("Username: ").strip()
		password = getpass.getpass("Password: ")

		send_secure(sock, {
			"command": "LOGIN",
			"username": username,
			"password": password
		})

		response = receive_secure(sock)

		if response.get("status") == "OK":
			print("Authentication successful.")
			return username, response

		print(response.get("message", "Authentication failed"))
		remaining = response.get("remaining", 0)
		print(f"Attempts remaining: {remaining}")

	print("Maximum number of attempts exceeded.")
	return None, None


def main():
	show_help()

	try:
		host, port = find_server()

		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
			client.settimeout(30)
			client.connect((host, port))

			print("Connected to server.")

			# Обмін ключами Діффі — Геллмана
			init = receive_plain(client)

			if init.get("command") != "DH_INIT":
				print("Invalid handshake.")
				return

			p = init["p"]
			g = init["g"]
			server_public = init["public"]

			private_key = secrets.randbelow(p - 2) + 1
			public_key = pow(g, private_key, p)

			shared_secret = pow(server_public, private_key, p)

			send_plain(client, {
				"command": "DH_REPLY",
				"public": public_key
			})

			print("DH demonstration completed.")
			print("Shared secret:", shared_secret)

			username, response = login(client)

			if username is None:
				return

			if response.get("must_change"):
				print("\nYou must set a new password.")
				if not change_password(client):
					print("Password change required.")
					return

			if response.get("role") == "ADMIN":
				admin_menu(client)
			else:
				user_menu(client)

	except ConnectionRefusedError:
		print("Server is unavailable.")
		return
	except socket.timeout:
		print("Connection timed out.")
		return
	except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
		print(f"Client error: {error}")
		return
	except Exception as error:
		print(f"Unexpected error: {error}")
		return


if __name__ == "__main__":
	main()