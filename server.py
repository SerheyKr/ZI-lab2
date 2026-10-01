import socket
import threading
import json
import os
import hashlib
import hmac
import secrets
import struct

HOST = "0.0.0.0"
TCP_PORT = 7700
UDP_PORT = 7700

MAX_ATTEMPTS = 3
SHIFT = 7
MAX_PASS_LENGHT = 8

USERS_FILE = "users.json"
DOCUMENT_DIR = "documents"

# Параметри демонстраційного Діффі — Геллмана
DH_P = 23
DH_G = 5

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


def send_plain(sock, data):
	raw = json.dumps(data).encode("utf-8")
	sock.sendall(struct.pack("!I", len(raw)) + raw)


def receive_plain(sock):
	header = receive_exact(sock, 4)
	size = struct.unpack("!I", header)[0]

	if size > 1024 * 1024:
		raise ValueError("Message too large")

	raw = receive_exact(sock, size)
	return json.loads(raw.decode("utf-8"))


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

	raw = decrypt(encrypted)
	return json.loads(raw.decode("utf-8"))


def receive_exact(sock, size):
	result = bytearray()

	while len(result) < size:
		chunk = sock.recv(size - len(result))

		if not chunk:
			raise ConnectionError("Connection closed")

		result.extend(chunk)

	return bytes(result)


def hash_password(password, salt=None):
	if salt is None:
		salt = secrets.token_hex(16)

	digest = hashlib.pbkdf2_hmac(
		"sha256",
		password.encode("utf-8"),
		bytes.fromhex(salt),
		200_000
	).hex()

	return {"salt": salt, "hash": digest}


def verify_password(password, stored):
	calculated = hash_password(password, stored["salt"])
	return hmac.compare_digest(calculated["hash"], stored["hash"])


def load_users():
	if not os.path.exists(USERS_FILE):
		admin_password = secrets.token_urlsafe(16)
		
		print("Initial ADMIN password:", admin_password)

		users = {
			"ADMIN": {
				**hash_password(admin_password),
				"blocked": False,
				"must_change": False
			}
		}

		save_users(users)
		return users

	with open(USERS_FILE, "r", encoding="utf-8") as file:
		return json.load(file)


def save_users(users):
	temporary = USERS_FILE + ".tmp"

	with open(temporary, "w", encoding="utf-8") as file:
		json.dump(users, file, indent=4, ensure_ascii=False)

	os.replace(temporary, USERS_FILE)


users_lock = threading.Lock()


def process_command(username, request):
	command = request.get("command")

	with users_lock:
		users = load_users()

		if username not in users or users[username]["blocked"]:
			return {"status": "ERROR", "message": "Account unavailable"}

		is_admin = username == "ADMIN"

		if command == "HELP":
			return {
				"status": "OK",
				"message": (
					"Secure remote access system. "
					"ADMIN: change password, add user, block user. "
					"User: change password, get document."
				)
			}

		if command == "LOGOUT":
			return {"status": "OK", "message": "Session ended"}

		if command == "CHANGE_PASSWORD":
			new_password = request.get("new_password", "")

			if len(new_password) < 8:
				return {
					"status": "ERROR",
					"message": "Password must contain at least 8 characters"
				}

			users[username] = {
				**hash_password(new_password),
				"blocked": False,
				"must_change": False
			}

			save_users(users)

			return {"status": "OK", "message": "Password changed"}

		if command == "ADD_USER":
			if not is_admin:
				return {"status": "ERROR", "message": "Access denied"}

			new_username = request.get("username", "")
			initial_password = request.get("password", "")

			if not new_username or new_username == "ADMIN":
				return {"status": "ERROR", "message": "Invalid username"}

			if new_username in users:
				return {"status": "ERROR", "message": "User already exists"}

			if len(initial_password) < MAX_PASS_LENGHT:
				return {"status": "ERROR", "message": "Password too short"}

			users[new_username] = {
				**hash_password(initial_password),
				"blocked": False,
				"must_change": True
			}

			save_users(users)

			return {"status": "OK", "message": "User added"}

		if command == "BLOCK_USER":
			if not is_admin:
				return {"status": "ERROR", "message": "Access denied"}

			target = request.get("username", "")

			if target == "ADMIN":
				return {"status": "ERROR", "message": "Cannot block ADMIN"}

			if target not in users:
				return {"status": "ERROR", "message": "User not found"}

			users[target]["blocked"] = True
			save_users(users)

			return {"status": "OK", "message": "User blocked"}

		if command == "GET_DOCUMENT":
			if is_admin:
				return {"status": "ERROR", "message": "Access denied"}

			filename = request.get("filename", "document.txt")

			# Дозволяємо отримання лише файлів із каталогу documents
			if filename != "document.txt":
				return {"status": "ERROR", "message": "Document unavailable"}

			path = os.path.join(DOCUMENT_DIR, filename)

			try:
				with open(path, "r", encoding="utf-8") as file:
					content = file.read()

				return {"status": "OK", "document": content}

			except OSError:
				return {"status": "ERROR", "message": "Cannot read document"}

		return {"status": "ERROR", "message": "Unknown command"}


def authenticate(sock):
	for attempt in range(MAX_ATTEMPTS):
		request = receive_secure(sock)

		if request.get("command") != "LOGIN":
			send_secure(sock, {
				"status": "ERROR",
				"message": "Login required"
			})
			continue

		username = request.get("username", "")
		password = request.get("password", "")

		with users_lock:
			current_users = load_users()
			account = current_users.get(username)

			valid = (
				account is not None
				and not account["blocked"]
				and verify_password(password, account)
			)

			if valid:
				send_secure(sock, {
					"status": "OK",
					"must_change": account.get("must_change", False),
					"role": "ADMIN" if username == "ADMIN" else "USER"
				})
				return username

		remaining = MAX_ATTEMPTS - attempt - 1

		send_secure(sock, {
			"status": "ERROR",
			"message": "Invalid credentials",
			"remaining": remaining
		})

	return None


def handle_client(conn, address):
	print(f"TCP connection: {address}")

	try:
		# Демонстраційний обмін ключами Діффі — Геллмана
		private_key = secrets.randbelow(DH_P - 2) + 1
		public_key = pow(DH_G, private_key, DH_P)

		send_plain(conn, {
			"command": "DH_INIT",
			"p": DH_P,
			"g": DH_G,
			"public": public_key
		})

		client_data = receive_plain(conn)

		if client_data.get("command") != "DH_REPLY":
			return

		client_public = client_data.get("public")

		if not isinstance(client_public, int) or not (1 < client_public < DH_P):
			return

		shared_secret = pow(client_public, private_key, DH_P)
		print("DH shared secret established (demo):", shared_secret)

		# Далі повідомлення використовують формат із CRC16 та шифром Цезаря
		username = authenticate(conn)

		if username is None:
			print(f"Authentication failed: {address}")
			return

		print(f"Authorized: {username}")

		while True:
			request = receive_secure(conn)
			response = process_command(username, request)

			send_secure(conn, response)

			if request.get("command") == "LOGOUT":
				break

	except (ConnectionError, OSError, ValueError, KeyError, json.JSONDecodeError) as error:
		print(f"Client error {address}: {error}")

	finally:
		conn.close()
		print(f"Disconnected: {address}")


def udp_discovery():
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
		udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		udp.bind((HOST, UDP_PORT))

		print(f"UDP discovery listening on {UDP_PORT}")

		while True:
			try:
				data, address = udp.recvfrom(1024)

				if data == b"DISCOVER_SERVER":
					udp.sendto(
						json.dumps({
							"server": "SecureServer",
							"tcp_port": TCP_PORT
						}).encode("utf-8"),
						address
					)

			except OSError as error:
				print("UDP error:", error)


def main():
	os.makedirs(DOCUMENT_DIR, exist_ok=True)
	load_users()

	threading.Thread(
		target=udp_discovery,
		daemon=True
	).start()

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
		server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server.bind((HOST, TCP_PORT))
		server.listen()

		print(f"TCP server listening on port {TCP_PORT}")

		while True:
			conn, address = server.accept()

			threading.Thread(
				target=handle_client,
				args=(conn, address),
				daemon=True
			).start()


if __name__ == "__main__":
	main()