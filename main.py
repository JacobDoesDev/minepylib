import socket
import struct
import uuid as uuid_module


class Packet:
	def __init__(self):
		self.bytes = b""
	
	def pack_bytes(self, bytes):
		self.bytes += bytes
	
	def get_bytes(self):
		return bytes
	
	def gen_bytes(self):
		return self._pack_varint(len(self.bytes)) + self.bytes

	def send_bytes(self, socket: socket.socket):
		socket.sendall(self.gen_bytes())



	@staticmethod
	def _pack_varint(dat):
		total = b''
		if dat < 0:
			dat = (1<<32)+dat
		while dat>=0x80:
			bits = dat&0x7F
			dat >>= 7
			total += struct.pack('B', (0x80|bits))
		bits = dat&0x7F
		total += struct.pack('B', bits)
		return total
	
	@staticmethod
	def _unpack_varint(sock: socket.socket):
		total = 0
		shift = 0
		val = 0x80
		while val&0x80:
			val = struct.unpack('B', sock.recv(1))[0]
			total |= ((val&0x7F)<<shift)
			shift += 7
		if total&(1<<31):
			total = total - (1<<32)
		return total
	


	def pack_varint(self, dat):
		self.pack_bytes(self._pack_varint(dat))

	def pack_string(self, dat: str):
		bt = dat.encode("utf-8")
		self.pack_varint(len(bt))
		self.pack_bytes(bt)
	
	def pack_unsigned_short(self, dat: int):
		self.pack_bytes(struct.pack("H", dat))



def parse_uuid(uuid: str) -> bytes:
	uuid = uuid.replace("-", "")
	

def generate_handshake_bytes(protocol_version=766, packet_host="127.0.0.1", packet_port=25565, nextstate=True) -> bytes:
	# Handshake
	# Example packet:
	# \x10\x00\xfe\x05\tlocalhost\xddc\x02
	# 
	# \x10	  	= 16 packet length
	# \x00	  	= packet id
	# \xfe\x05  = protocol version
	# \t		= 9 (string length)
	# localhost = host (string)
	# \xddc	 	= port (unsigned integer)
	# \x02	  	= nextstate (1: status; 2: login)

	pac = Packet()
	pac.pack_varint(0)								    # Packet ID (handshake)	 
	pac.pack_varint(protocol_version)				    # Protocol Version		  
	pac.pack_string(packet_host)						# Server Address (Host)
	pac.pack_unsigned_short(packet_port)				# Server Port
	pac.pack_bytes(b"\x02" if nextstate else b"\x01")   # Next State (True: login; False: status)
	
	return pac.gen_bytes()

def generate_login_start_bytes(username="Herobrine", uuid=None) -> bytes:
	# Login start
	# Example packet:
	# \x1b\x00\tHerobrine\xf8Ljy\nNE\xe0\x87\x9b\xcdI\xeb\xd4\xc4\xe2
	# 
	# \x1b	  										= 18 packet length
	# \x00	  										= packet id
	# \t											= 9 (string length)
	# Herobrine 									= username (string)
	# \xf8Ljy\nNE\xe0\x87\x9b\xcdI\xeb\xd4\xc4\xe2	= uuid
	

	if uuid is None:
		uuid = b"\x00" * 16
	elif type(uuid) == str:
		uuid = uuid_module.UUID(uuid).bytes

	pac = Packet()
	pac.pack_varint(0)			# Packet ID (login start)	 
	pac.pack_string(username)	# Username	 
	pac.pack_bytes(uuid)		# Player UUID
	
	return pac.gen_bytes()

def generate_status_bytes() -> bytes:
	# Handshake
	# Example packet:
	# \x01\x00
	# 
	# \x01	  	= 1 packet length
	# \x00	  	= packet id

	pac = Packet()
	pac.pack_bytes(b"\x00")
	return pac.gen_bytes()





def login(host="127.0.0.1", port=25565, protocol_version=766, packet_host=None, packet_port=None, username="Herobrine", uuid=None) -> socket.socket:
	if packet_host is None:
		packet_host = host

	if packet_port is None:
		packet_port = port

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((host, port))

	sock.sendall(generate_handshake_bytes(protocol_version=protocol_version, packet_host=packet_host, packet_port=packet_port, nextstate=True))
	sock.sendall(generate_login_start_bytes(username=username, uuid=uuid))

def ping(host="127.0.0.1", port=25565, protocol_version=766, packet_host=None, packet_port=None) -> str:
	if packet_host is None:
		packet_host = host

	if packet_port is None:
		packet_port = port

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((host, port))


	sock.sendall(generate_handshake_bytes(protocol_version=protocol_version, packet_host=packet_host, packet_port=packet_port, nextstate=False))
	sock.sendall(generate_status_bytes())

	Packet._unpack_varint(sock)
	Packet._unpack_varint(sock)

	string_len = Packet._unpack_varint(sock)

	return sock.recv(string_len).decode("utf-8")

def is_cracked(host="127.0.0.1", port=25565):


if __name__ == "__main__":
	login(username="JacobDoes.dev")
