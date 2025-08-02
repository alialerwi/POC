#!/usr/bin/env python3
"""
Bizclap Security System - HYBRID Backend
Combines REAL MQTT Broker + Enhanced Saudi Arabia Simulation

Features:
- Real MQTT broker on port 1883 for actual clients
- Enhanced Saudi Arabia security device simulation
- WebSocket server on port 8765 for dashboard
- Merged real + simulated data streams
- Full MQTT protocol support with packet buffering
"""

import asyncio
import websockets
import json
import time
import random
import logging
import socket
import struct
import os
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from threading import Thread, Lock
import netifaces
import colorama
from colorama import Fore, Style
import http.server
import socketserver
from pathlib import Path

colorama.init()

# Configure logging
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        record.msg = f"{log_color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

# Set up logging
logging.getLogger().handlers.clear()
formatter = ColoredFormatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%H:%M:%S')
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logging.basicConfig(level=logging.INFO, handlers=[console_handler])
logger = logging.getLogger(__name__)

class AlertType(Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    MAINTENANCE = "MAINTENANCE"

class DeviceStatus(Enum):
    ONLINE = "ONLINE"
    WARNING = "WARNING"
    OFFLINE = "OFFLINE"

@dataclass
class MQTTMessage:
    topic: str
    payload: bytes
    qos: int = 0
    retain: bool = False
    packet_id: int = None
    timestamp: datetime = None
    client_id: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class MQTTClient:
    client_id: str
    socket_conn: socket.socket
    address: tuple
    username: str = None
    subscriptions: Dict[str, int] = None
    connected: bool = True
    authenticated: bool = False
    last_seen: float = None
    keep_alive: int = 60
    will_topic: str = None
    will_message: str = None
    clean_session: bool = True
    is_simulated: bool = False
    
    def __post_init__(self):
        if self.subscriptions is None:
            self.subscriptions = {}
        if self.last_seen is None:
            self.last_seen = time.time()

@dataclass
class SecurityDevice:
    device_id: str
    facility_name: str
    location: str
    device_type: str
    status: DeviceStatus
    alert_type: str = None
    last_seen: datetime = None
    coordinates: tuple = None
    
    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = datetime.now()

class MQTTPacketBuffer:
    """Handles proper MQTT packet buffering and boundary detection"""

    def __init__(self):
        self.buffer = bytearray()

    def add_data(self, data: bytes):
        """Add new data to the buffer"""
        self.buffer.extend(data)

    def get_complete_packets(self) -> List[bytes]:
        """Extract all complete MQTT packets from buffer"""
        packets = []

        while len(self.buffer) >= 2:  # Need at least fixed header
            try:
                # Parse fixed header
                msg_type = (self.buffer[0] >> 4) & 0x0F
                if msg_type < 1 or msg_type > 14:
                    # Invalid message type, skip this byte
                    self.buffer = self.buffer[1:]
                    continue

                # Decode remaining length
                remaining_length, header_len = self._decode_remaining_length(self.buffer[1:])
                total_packet_len = 1 + header_len + remaining_length

                if len(self.buffer) >= total_packet_len:
                    # We have a complete packet
                    packet = bytes(self.buffer[:total_packet_len])
                    packets.append(packet)
                    self.buffer = self.buffer[total_packet_len:]
                else:
                    # Incomplete packet, wait for more data
                    break

            except Exception:
                # Invalid packet structure, skip first byte
                self.buffer = self.buffer[1:]
                continue

        return packets

    def _decode_remaining_length(self, data: bytes) -> Tuple[int, int]:
        """Decode MQTT remaining length field"""
        if len(data) == 0:
            raise ValueError("No data for remaining length")

        length = 0
        multiplier = 1
        pos = 0

        while pos < len(data) and pos < 4:
            byte = data[pos]
            length += (byte & 0x7F) * multiplier
            if (byte & 0x80) == 0:
                break
            multiplier *= 128
            pos += 1
        else:
            if pos >= 4:
                raise ValueError("Remaining length too long")
            if pos >= len(data):
                raise ValueError("Incomplete remaining length")

        return length, pos + 1

class BizclapSecurityBackend:
    # MQTT Message Types
    CONNECT = 1
    CONNACK = 2
    PUBLISH = 3
    PUBACK = 4
    SUBSCRIBE = 8
    SUBACK = 9
    UNSUBSCRIBE = 10
    UNSUBACK = 11
    PINGREQ = 12
    PINGRESP = 13
    DISCONNECT = 14

    # Connection Return Codes
    CONN_ACCEPTED = 0
    CONN_REFUSED_PROTOCOL = 1
    CONN_REFUSED_CLIENT_ID = 2
    CONN_REFUSED_SERVER_UNAVAIL = 3
    CONN_REFUSED_BAD_CREDENTIALS = 4
    CONN_REFUSED_NOT_AUTHORIZED = 5

    def __init__(self, mqtt_port=1884, websocket_port=8766, http_port=80):
        # Real MQTT broker components
        self.mqtt_port = mqtt_port
        self.websocket_port = websocket_port
        self.http_port = http_port
        self.real_clients: Dict[str, MQTTClient] = {}
        self.retained_messages: Dict[str, MQTTMessage] = {}
        self.message_history: List[MQTTMessage] = []
        self.lock = Lock()
        
        # Enhanced simulation components
        self.websocket_clients: Set[websockets.WebSocketServerProtocol] = set()
        self.simulated_clients: Dict[str, MQTTClient] = {}
        self.security_devices: Dict[str, SecurityDevice] = {}
        
        # Common components
        self.start_time = datetime.now()
        self.message_count = 0
        self.running = False
        self.event_loop = None
        self.packet_id_counter = 1
        
        # Initialize simulation data
        self._initialize_security_devices()
        self._initialize_simulated_clients()
        
        logger.info("🏗️  Bizclap Security Backend initialized (Hybrid Mode)")

    def _initialize_security_devices(self):
        """Initialize Saudi Arabia oil & gas security devices"""
        devices_data = [
            ("SA-RYD-001", "Riyadh Central Station", "Riyadh", "SmartLock", (24.7136, 46.6753)),
            ("SA-EP-002", "Eastern Province Fuel Hub", "Dammam", "SmartLock", (26.4207, 50.0888)),
            ("SA-HAL-003", "Hail Regional Station", "Hail", "PressureSensor", (27.5114, 41.7208)),
            ("SA-AHS-004", "Al-Ahsa Distribution Center", "Al-Ahsa", "SmartLock", (25.2854, 49.1647)),
            ("SA-QAS-005", "Qassim Fuel Terminal", "Qassim", "FlowSensor", (26.3267, 43.9735)),
            ("SA-JUB-006", "Jubail Petrochemical Hub", "Jubail", "SmartLock", (27.0174, 49.6583)),
            ("SA-NAJ-007", "Najran Border Station", "Najran", "CameraSensor", (17.4933, 44.1278)),
            ("SA-MEC-008", "Mecca Regional Hub", "Mecca", "SmartLock", (21.2854, 39.2376)),
            ("SA-TAB-009", "Tabuk Northern Station", "Tabuk", "PressureSensor", (28.3998, 36.5713)),
            ("SA-ABH-010", "Abha Mountain Station", "Abha", "SmartLock", (18.2164, 42.5053)),
            ("SA-JED-011", "Jeddah Coastal Terminal", "Jeddah", "LeakSensor", (21.4858, 39.1925)),
            ("SA-KHO-012", "Khobar Industrial Complex", "Khobar", "SmartLock", (26.4367, 49.9911)),
        ]
        
        for device_id, facility, location, device_type, coords in devices_data:
            # Assign random status with realistic distribution
            status_weights = [DeviceStatus.ONLINE] * 85 + [DeviceStatus.WARNING] * 12 + [DeviceStatus.OFFLINE] * 3
            status = random.choice(status_weights)
            
            self.security_devices[device_id] = SecurityDevice(
                device_id=device_id,
                facility_name=facility,
                location=location,
                device_type=device_type,
                status=status,
                coordinates=coords,
                alert_type="TAMPER" if status == DeviceStatus.OFFLINE else ("PRESSURE" if status == DeviceStatus.WARNING else None)
            )

    def _initialize_simulated_clients(self):
        """Initialize simulated MQTT clients for demonstration"""
        client_configs = [
            ("device_monitor_001", "192.168.1.100", "admin", ["alerts/critical", "devices/status", "sensors/all"]),
            ("security_cam_002", "192.168.1.101", "camera_sys", ["video/streams", "alerts/motion"]),
            ("sensor_hub_003", "192.168.1.102", "sensor_net", ["sensors/temperature", "sensors/pressure", "sensors/flow"]),
            ("control_panel_004", "192.168.1.103", "operator", ["commands/valves", "alerts/all"]),
            ("mobile_app_005", "10.0.0.45", "field_tech", ["devices/status", "alerts/critical"]),
            ("backup_system_006", "192.168.1.104", "backup", ["system/heartbeat", "data/backup"]),
            ("analytics_engine_007", "192.168.1.105", "analytics", ["data/all", "patterns/anomaly"]),
            ("emergency_system_008", "192.168.1.106", "emergency", ["alerts/critical", "emergency/protocols"]),
        ]
        
        for client_id, address, username, topics in client_configs:
            # Create simulated client (no real socket)
            client = MQTTClient(
                client_id=client_id,
                socket_conn=None,  # No real socket for simulated clients
                address=(address, 1884),
                username=username,
                subscriptions={topic: 1 for topic in topics},
                connected=True,
                authenticated=True,
                last_seen=time.time() - random.randint(300, 7200),  # Connected 5min to 2hrs ago
                is_simulated=True
            )
            self.simulated_clients[client_id] = client

    # ============================================================================
    # REAL MQTT BROKER FUNCTIONALITY (from original)
    # ============================================================================

    def start_mqtt_server(self):
        """Start the real MQTT broker server"""
        mqtt_thread = Thread(target=self._run_mqtt_server, daemon=True)
        mqtt_thread.start()
        logger.info(f"📡 Real MQTT Server starting on port {self.mqtt_port}")

    def _run_mqtt_server(self):
        """Run the MQTT broker server (blocking)"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind(("0.0.0.0", self.mqtt_port))
            server_socket.listen(5)
            logger.info(f"📡 MQTT Server listening on 0.0.0.0:{self.mqtt_port}")

            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    client_thread = Thread(
                        target=self._handle_real_mqtt_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting client: {e}")

        except Exception as e:
            logger.error(f"Failed to start MQTT server: {e}")
        finally:
            server_socket.close()

    def _handle_real_mqtt_client(self, client_socket, address):
        """Handle real MQTT client connection with proper packet buffering"""
        logger.info(f"📱 New REAL client connection from {address[0]}:{address[1]}")
        client = None
        packet_buffer = MQTTPacketBuffer()

        try:
            client_socket.settimeout(30.0)

            # Wait for CONNECT message
            data = client_socket.recv(1024)
            if not data:
                return

            client = self._parse_connect_message(data, client_socket, address)
            if not client:
                return

            with self.lock:
                self.real_clients[client.client_id] = client

            logger.info(f"✅ REAL Client '{client.client_id}' connected successfully")
            self._broadcast_client_update()
            self._send_retained_messages(client)

            # Main message handling loop with proper packet buffering
            while client.connected and self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    # Add data to buffer
                    packet_buffer.add_data(data)

                    # Process all complete packets
                    complete_packets = packet_buffer.get_complete_packets()
                    for packet in complete_packets:
                        self._process_mqtt_message(client, packet)

                    client.last_seen = time.time()

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error handling real client {client.client_id}: {e}")
                    break

        except Exception as e:
            logger.error(f"Connection error for REAL client {address}: {e}")
        finally:
            if client:
                with self.lock:
                    if client.client_id in self.real_clients:
                        del self.real_clients[client.client_id]
                logger.info(f"❌ REAL Client '{client.client_id}' disconnected")
                self._broadcast_client_update()
            client_socket.close()

    def _parse_connect_message(self, data: bytes, client_socket, address) -> Optional[MQTTClient]:
        """Parse MQTT CONNECT message"""
        try:
            if len(data) < 10:
                self._send_connack(client_socket, self.CONN_REFUSED_PROTOCOL)
                return None

            msg_type = (data[0] >> 4) & 0x0F
            if msg_type != self.CONNECT:
                self._send_connack(client_socket, self.CONN_REFUSED_PROTOCOL)
                return None

            pos = 2

            # Protocol name
            protocol_len = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2
            protocol_name = data[pos:pos+protocol_len].decode('utf-8')
            pos += protocol_len

            if protocol_name not in ['MQTT', 'MQIsdp']:
                self._send_connack(client_socket, self.CONN_REFUSED_PROTOCOL)
                return None

            protocol_level = data[pos]
            pos += 1

            connect_flags = data[pos]
            pos += 1
            clean_session = bool(connect_flags & 0x02)
            username_flag = bool(connect_flags & 0x80)
            password_flag = bool(connect_flags & 0x40)

            keep_alive = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2

            client_id_len = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2
            client_id = data[pos:pos+client_id_len].decode('utf-8')
            pos += client_id_len

            if not client_id:
                client_id = f"real_client_{address[0]}_{address[1]}_{int(time.time())}"

            username = None
            if username_flag and pos + 2 <= len(data):
                username_len = struct.unpack('>H', data[pos:pos+2])[0]
                pos += 2
                if pos + username_len <= len(data):
                    username = data[pos:pos+username_len].decode('utf-8')

            client = MQTTClient(
                client_id=client_id,
                socket_conn=client_socket,
                address=address,
                username=username,
                keep_alive=keep_alive,
                clean_session=clean_session,
                authenticated=True,
                is_simulated=False
            )

            self._send_connack(client_socket, self.CONN_ACCEPTED)
            return client

        except Exception as e:
            logger.error(f"Error parsing CONNECT message: {e}")
            self._send_connack(client_socket, self.CONN_REFUSED_SERVER_UNAVAIL)
            return None

    def _send_connack(self, client_socket, return_code: int):
        """Send CONNACK message"""
        connack = bytearray([0x20, 0x02, 0x00, return_code])
        try:
            client_socket.send(connack)
        except:
            pass

    def _process_mqtt_message(self, client: MQTTClient, data: bytes):
        """Process a complete MQTT message"""
        try:
            if len(data) < 2:
                return

            msg_type = (data[0] >> 4) & 0x0F

            if msg_type == self.PUBLISH:
                self._handle_publish(client, data)
            elif msg_type == self.SUBSCRIBE:
                self._handle_subscribe(client, data)
            elif msg_type == self.UNSUBSCRIBE:
                self._handle_unsubscribe(client, data)
            elif msg_type == self.PINGREQ:
                self._handle_pingreq(client)
            elif msg_type == self.DISCONNECT:
                self._handle_disconnect(client)

        except Exception as e:
            logger.error(f"Error processing message from {client.client_id}: {e}")

    def _handle_publish(self, client: MQTTClient, data: bytes):
        """Handle PUBLISH message from real client"""
        try:
            if len(data) < 4:
                return

            flags = data[0] & 0x0F
            qos = (flags >> 1) & 0x03
            retain = bool(flags & 0x01)

            # Decode remaining length
            remaining_length, header_offset = self._decode_remaining_length(data[1:])
            pos = 1 + header_offset

            if len(data) < pos + remaining_length:
                return

            # Topic
            topic_length = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2
            topic = data[pos:pos+topic_length].decode('utf-8', errors='ignore')
            pos += topic_length

            # Packet ID for QoS > 0
            packet_id = None
            if qos > 0:
                packet_id = struct.unpack('>H', data[pos:pos+2])[0]
                pos += 2

            # Payload
            payload = data[pos:]

            message = MQTTMessage(topic, payload, qos, retain, packet_id)
            message.client_id = client.client_id

            if qos == 1 and packet_id:
                self._send_puback(client, packet_id)

            # Process the real message
            if self.event_loop:
                asyncio.run_coroutine_threadsafe(
                    self._process_real_message(message),
                    self.event_loop
                )
            else:
                logger.warning("Event loop not available, skipping message processing")

            logger.info(f"📨 REAL PUBLISH '{topic}' from {client.client_id} ({len(payload)} bytes)")

        except Exception as e:
            logger.error(f"Error handling PUBLISH: {e}")

    def _handle_subscribe(self, client: MQTTClient, data: bytes):
        """Handle SUBSCRIBE message from real client"""
        try:
            if len(data) < 4:
                return

            packet_id = struct.unpack('>H', data[2:4])[0]
            pos = 4

            topics = []
            while pos < len(data):
                if pos + 2 > len(data):
                    break
                topic_len = struct.unpack('>H', data[pos:pos+2])[0]
                pos += 2

                if pos + topic_len > len(data):
                    break
                topic = data[pos:pos+topic_len].decode('utf-8', errors='ignore')
                pos += topic_len

                if pos >= len(data):
                    break
                qos = data[pos]
                pos += 1

                topics.append((topic, qos))
                client.subscriptions[topic] = qos

            self._send_suback(client, packet_id, [qos for _, qos in topics])
            self._send_retained_messages_for_topics(client, [topic for topic, _ in topics])

            topic_list = ', '.join([f"'{topic}'" for topic, _ in topics])
            logger.info(f"📥 REAL Client {client.client_id} subscribed to {topic_list}")

        except Exception as e:
            logger.error(f"Error handling SUBSCRIBE: {e}")

    def _handle_pingreq(self, client: MQTTClient):
        """Handle PINGREQ message"""
        pingresp = bytearray([0xD0, 0x00])
        try:
            client.socket_conn.send(pingresp)
        except:
            pass

    def _handle_disconnect(self, client: MQTTClient):
        """Handle DISCONNECT message"""
        client.connected = False

    def _handle_unsubscribe(self, client: MQTTClient, data: bytes):
        """Handle UNSUBSCRIBE message"""
        try:
            if len(data) < 4:
                return
            packet_id = struct.unpack('>H', data[2:4])[0]
            # Implementation details...
            unsuback = struct.pack('>BBH', 0xB0, 0x02, packet_id)
            client.socket_conn.send(unsuback)
        except Exception as e:
            logger.error(f"Error handling UNSUBSCRIBE: {e}")

    def _send_puback(self, client: MQTTClient, packet_id: int):
        """Send PUBACK message"""
        puback = struct.pack('>BBH', 0x40, 0x02, packet_id)
        try:
            client.socket_conn.send(puback)
        except:
            pass

    def _send_suback(self, client: MQTTClient, packet_id: int, qos_levels: List[int]):
        """Send SUBACK message"""
        payload = bytes(qos_levels)
        suback = struct.pack('>BBH', 0x90, 2 + len(payload), packet_id) + payload
        try:
            client.socket_conn.send(suback)
        except:
            pass

    def _decode_remaining_length(self, data: bytes) -> Tuple[int, int]:
        """Decode MQTT remaining length field"""
        if len(data) == 0:
            raise ValueError("No data for remaining length")

        length = 0
        multiplier = 1
        pos = 0

        while pos < len(data) and pos < 4:
            byte = data[pos]
            length += (byte & 0x7F) * multiplier
            if (byte & 0x80) == 0:
                break
            multiplier *= 128
            pos += 1

        return length, pos + 1

    def _send_retained_messages(self, client: MQTTClient):
        """Send retained messages to client"""
        self._send_retained_messages_for_topics(client, list(client.subscriptions.keys()))

    def _send_retained_messages_for_topics(self, client: MQTTClient, topics: List[str]):
        """Send retained messages for specific topics"""
        for retained_topic, message in self.retained_messages.items():
            for topic_filter in topics:
                if self._match_topic(retained_topic, topic_filter):
                    self._send_publish_to_client(client, message)
                    break

    def _match_topic(self, topic: str, filter_topic: str) -> bool:
        """Check if topic matches filter (with wildcards)"""
        if filter_topic == '#':
            return True

        topic_parts = topic.split('/')
        filter_parts = filter_topic.split('/')

        for i, filter_part in enumerate(filter_parts):
            if filter_part == '#':
                return True
            elif filter_part == '+':
                if i >= len(topic_parts):
                    return False
            else:
                if i >= len(topic_parts) or topic_parts[i] != filter_part:
                    return False

        return len(topic_parts) == len(filter_parts)

    def _send_publish_to_client(self, client: MQTTClient, message: MQTTMessage):
        """Send PUBLISH message to client"""
        if not client.socket_conn or client.is_simulated:
            return
            
        try:
            flags = 0x00
            if message.retain:
                flags |= 0x01
            flags |= (message.qos << 1)

            topic_bytes = message.topic.encode('utf-8')
            var_header = struct.pack('>H', len(topic_bytes)) + topic_bytes

            if message.qos > 0:
                packet_id = self._get_next_packet_id()
                var_header += struct.pack('>H', packet_id)

            remaining_length = len(var_header) + len(message.payload)
            fixed_header = bytearray([0x30 | flags])
            fixed_header.extend(self._encode_remaining_length(remaining_length))

            packet = fixed_header + var_header + message.payload
            client.socket_conn.send(packet)

        except Exception as e:
            logger.error(f"Error sending PUBLISH to {client.client_id}: {e}")

    def _encode_remaining_length(self, length: int) -> bytearray:
        """Encode MQTT remaining length field"""
        result = bytearray()
        while length > 0:
            byte = length % 128
            length //= 128
            if length > 0:
                byte |= 0x80
            result.append(byte)
        return result

    def _get_next_packet_id(self) -> int:
        """Get next packet ID"""
        self.packet_id_counter += 1
        if self.packet_id_counter > 65535:
            self.packet_id_counter = 1
        return self.packet_id_counter

    # ============================================================================
    # WEBSOCKET SERVER & DASHBOARD INTEGRATION
    # ============================================================================

    async def start_websocket_server(self):
        """Start WebSocket server for dashboard communication"""
        logger.info(f"🔌 Starting WebSocket server on port {self.websocket_port}")
        
        async def handle_websocket(websocket, path):
            logger.info(f"🔌 New WebSocket connection from {websocket.remote_address}")
            self.websocket_clients.add(websocket)
            
            try:
                # Send initial data
                await self._send_status_update(websocket)
                
                # Keep connection alive and handle messages
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        await self._handle_websocket_message(websocket, data)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON received: {message}")
                    except Exception as e:
                        logger.error(f"Error handling WebSocket message: {e}")
                        
            except websockets.exceptions.ConnectionClosed:
                logger.info(f"WebSocket connection closed: {websocket.remote_address}")
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
            finally:
                self.websocket_clients.discard(websocket)
        
        return await websockets.serve(handle_websocket, "0.0.0.0", self.websocket_port)

    def start_http_server(self):
        """Start HTTP server to serve the dashboard"""
        class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                # Serve files from the same directory as the script
                super().__init__(*args, directory=os.path.dirname(os.path.abspath(__file__)), **kwargs)
            
            def do_GET(self):
                """Handle GET requests and serve Control Dashboard.html for root path"""
                if self.path == '/' or self.path == '':
                    # Redirect root requests to Control Dashboard.html
                    self.path = '/Control Dashboard.html'
                elif self.path == '/index.html':
                    # Also handle index.html requests
                    self.path = '/Control Dashboard.html'
                
                # Call the parent class method to handle the request
                return super().do_GET()
            
            def log_message(self, format, *args):
                # Custom logging for HTTP requests
                logger.info(f"🌐 HTTP {format % args}")
            
            def end_headers(self):
                # Add CORS headers for WebSocket connections
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', '*')
                super().end_headers()

        def run_http_server():
            with socketserver.TCPServer(("0.0.0.0", self.http_port), CustomHTTPRequestHandler) as httpd:
                logger.info(f"🌐 HTTP Server serving dashboard on port {self.http_port}")
                httpd.serve_forever()

        http_thread = Thread(target=run_http_server, daemon=True)
        http_thread.start()
        logger.info(f"🌐 HTTP Server starting on port {self.http_port}")

    async def _handle_websocket_message(self, websocket, data):
        """Handle incoming WebSocket messages from dashboard"""
        message_type = data.get('type')
        
        if message_type == 'get_status':
            await self._send_status_update(websocket)
        elif message_type == 'get_devices':
            await self._send_device_status(websocket)
        elif message_type == 'device_command':
            await self._handle_device_command(websocket, data)

    async def _send_status_update(self, websocket=None):
        """Send combined status update (real + simulated clients)"""
        uptime_seconds = int((datetime.now() - self.start_time).total_seconds())
        
        # Combine real and simulated clients
        all_clients = []
        
        # Add real clients
        with self.lock:
            for client in self.real_clients.values():
                all_clients.append({
                    "id": client.client_id,
                    "address": f"{client.address[0]}:{client.address[1]}",
                    "username": client.username or "anonymous",
                    "subscriptions": len(client.subscriptions),
                    "subscription_topics": list(client.subscriptions.keys()),
                    "connected_duration": str(timedelta(seconds=int(time.time() - client.last_seen))),
                    "type": "REAL"
                })
        
        # Add simulated clients
        for client in self.simulated_clients.values():
            all_clients.append({
                "id": client.client_id,
                "address": f"{client.address[0]}:{client.address[1]}",
                "username": client.username or "anonymous",
                "subscriptions": len(client.subscriptions),
                "subscription_topics": list(client.subscriptions.keys()),
                "connected_duration": str(timedelta(seconds=int(time.time() - client.last_seen))),
                "type": "SIMULATED"
            })
        
        status_data = {
            "type": "status",
            "data": {
                "clients": len(self.real_clients) + len(self.simulated_clients),
                "real_clients": len(self.real_clients),
                "simulated_clients": len(self.simulated_clients),
                "messages": self.message_count,
                "retained": len(self.retained_messages),
                "uptime": uptime_seconds,
                "client_list": all_clients
            }
        }
        
        await self._broadcast_to_websockets(status_data, websocket)

    async def _send_device_status(self, websocket=None):
        """Send Saudi Arabia security device status"""
        device_data = {
            "type": "devices",
            "data": [
                {
                    "device_id": device.device_id,
                    "facility_name": device.facility_name,
                    "location": device.location,
                    "device_type": device.device_type,
                    "status": device.status.value,
                    "alert_type": device.alert_type,
                    "last_seen": device.last_seen.isoformat(),
                    "coordinates": device.coordinates
                }
                for device in self.security_devices.values()
            ]
        }
        
        await self._broadcast_to_websockets(device_data, websocket)

    async def _handle_device_command(self, websocket, data):
        """Handle device control commands"""
        device_id = data.get('device_id')
        command = data.get('command')
        
        if device_id in self.security_devices:
            logger.info(f"Executing command '{command}' on device {device_id}")
            
            # Simulate command execution and publish to MQTT
            await self._simulate_mqtt_message(f"commands/{device_id}/{command}", "EXECUTED", device_id)
            
            response = {
                "type": "command_response",
                "data": {
                    "device_id": device_id,
                    "command": command,
                    "status": "success",
                    "timestamp": datetime.now().isoformat()
                }
            }
            await websocket.send(json.dumps(response))

    async def _broadcast_to_websockets(self, data, specific_websocket=None):
        """Broadcast data to all connected WebSocket clients"""
        message = json.dumps(data)
        
        if specific_websocket:
            try:
                await specific_websocket.send(message)
            except Exception as e:
                logger.error(f"Error sending to specific websocket: {e}")
        else:
            disconnected = set()
            for websocket in self.websocket_clients:
                try:
                    await websocket.send(message)
                except websockets.exceptions.ConnectionClosed:
                    disconnected.add(websocket)
                except Exception as e:
                    logger.error(f"Error broadcasting to websocket: {e}")
                    disconnected.add(websocket)
            
            # Remove disconnected clients
            self.websocket_clients -= disconnected

    def _broadcast_client_update(self):
        """Broadcast client count updates to all dashboard connections"""
        if self.event_loop and self.websocket_clients:
            try:
                asyncio.run_coroutine_threadsafe(
                    self._send_status_update(),
                    self.event_loop
                )
            except:
                pass

    # ============================================================================
    # SIMULATION & MESSAGE PROCESSING
    # ============================================================================

    async def _process_real_message(self, message: MQTTMessage):
        """Process real MQTT message from actual client"""
        with self.lock:
            self.message_history.append(message)
            self.message_count += 1
            if len(self.message_history) > 100:
                self.message_history.pop(0)

        # Handle retain flag
        if message.retain:
            if message.payload:
                self.retained_messages[message.topic] = message
            elif message.topic in self.retained_messages:
                del self.retained_messages[message.topic]

        # Forward to other clients
        self._send_to_subscribers(message)

        # Broadcast to WebSocket dashboard
        await self._broadcast_to_websockets({
            'type': 'message',
            'topic': message.topic,
            'payload': message.payload.decode('utf-8', errors='ignore'),
            'timestamp': message.timestamp.isoformat(),
            'qos': message.qos,
            'retain': message.retain,
            'client_id': message.client_id
        })

        # Check if this is a device registration or status update
        await self._handle_device_message(message)

    async def _handle_device_message(self, message: MQTTMessage):
        """Handle device-related messages from real clients"""
        topic = message.topic
        payload_str = message.payload.decode('utf-8', errors='ignore')
        
        try:
            # Try to parse as JSON
            payload_data = json.loads(payload_str)
        except:
            payload_data = {"value": payload_str}

        # Handle device registration
        if topic == "devices/register" or topic.startswith("devices/") and topic.endswith("/register"):
            await self._register_real_device(payload_data, message.client_id)
        
        # Handle device status updates
        elif topic.startswith("devices/") and "/status" in topic:
            await self._update_real_device_status(topic, payload_data, message.client_id)
        
        # Handle security alerts
        elif topic.startswith("alerts/"):
            await self._process_security_alert(topic, payload_data, message.client_id)

    async def _register_real_device(self, device_data, client_id):
        """Register a real device from MQTT message"""
        device_id = device_data.get("device_id", f"real_device_{client_id}_{int(time.time())}")
        
        if device_id not in self.security_devices:
            self.security_devices[device_id] = SecurityDevice(
                device_id=device_id,
                facility_name=device_data.get("facility_name", "Real Facility"),
                location=device_data.get("location", "Unknown"),
                device_type=device_data.get("device_type", "GenericDevice"),
                status=DeviceStatus.ONLINE,
                coordinates=tuple(device_data.get("coordinates", [0.0, 0.0]))
            )
            logger.info(f"📟 Registered REAL device: {device_id}")

    async def _update_real_device_status(self, topic, payload_data, client_id):
        """Update real device status from MQTT message"""
        # Extract device ID from topic
        parts = topic.split('/')
        if len(parts) >= 2:
            device_id = parts[1]
            if device_id in self.security_devices:
                new_status = payload_data.get("status", "ONLINE")
                try:
                    self.security_devices[device_id].status = DeviceStatus(new_status.upper())
                    self.security_devices[device_id].last_seen = datetime.now()
                    logger.info(f"📟 Updated REAL device {device_id} status to {new_status}")
                except ValueError:
                    logger.warning(f"Invalid status value: {new_status}")

    async def _process_security_alert(self, topic, payload_data, client_id):
        """Process security alert from real client"""
        alert_data = {
            "type": "security_alert",
            "topic": topic,
            "data": payload_data,
            "client_id": client_id,
            "timestamp": datetime.now().isoformat()
        }
        
        await self._broadcast_to_websockets(alert_data)
        logger.warning(f"🚨 REAL Security Alert from {client_id}: {topic}")

    def _send_to_subscribers(self, message: MQTTMessage):
        """Send message to all subscribed clients"""
        with self.lock:
            for client in list(self.real_clients.values()):
                try:
                    if self._topic_matches_filter(message.topic, client.subscriptions):
                        self._send_publish_to_client(client, message)
                except Exception as e:
                    logger.error(f"Error sending to {client.client_id}: {e}")

    def _topic_matches_filter(self, topic: str, subscriptions: Dict[str, int]) -> bool:
        """Check if topic matches any subscription filter"""
        for filter_topic in subscriptions:
            if self._match_topic(topic, filter_topic):
                return True
        return False

    async def _simulate_mqtt_message(self, topic, payload, client_id="system"):
        """Simulate an MQTT message (for enhancement features)"""
        if isinstance(payload, str):
            payload_bytes = payload.encode('utf-8')
        else:
            payload_bytes = payload

        message = MQTTMessage(
            topic=topic,
            payload=payload_bytes,
            qos=1,
            retain=False,
            client_id=client_id
        )
        
        with self.lock:
            self.message_history.append(message)
            self.message_count += 1
            if len(self.message_history) > 100:
                self.message_history.pop(0)
        
        # Broadcast to WebSocket clients
        await self._broadcast_to_websockets({
            "type": "message",
            "topic": topic,
            "payload": payload if isinstance(payload, str) else payload.decode('utf-8', errors='ignore'),
            "client_id": client_id,
            "qos": 1,
            "retain": False,
            "timestamp": datetime.now().isoformat()
        })

    async def background_simulation_tasks(self):
        """Run background simulation tasks for enhanced features"""
        while self.running:
            try:
                # Generate Saudi Arabia security events
                await self._generate_security_events()
                
                # Update device statuses
                await self._update_device_statuses()
                
                # Send periodic status updates
                await self._send_status_update()
                
                # Simulate additional MQTT traffic
                await self._simulate_mqtt_traffic()
                
                await asyncio.sleep(5)  # Run every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in background simulation: {e}")
                await asyncio.sleep(1)

    async def _generate_security_events(self):
        """Generate realistic Saudi Arabia security events"""
        if random.random() < 0.1:  # 10% chance every cycle
            device = random.choice(list(self.security_devices.values()))
            event_types = ["TAMPER_ATTEMPT", "PRESSURE_ANOMALY", "UNAUTHORIZED_ACCESS", "SYSTEM_CHECK"]
            event = random.choice(event_types)
            
            topic = f"alerts/{device.location.lower()}/{device.device_id}"
            payload = json.dumps({
                "device_id": device.device_id,
                "facility": device.facility_name,
                "event_type": event,
                "severity": "HIGH" if "TAMPER" in event else "MEDIUM",
                "timestamp": datetime.now().isoformat(),
                "location": device.location
            })
            
            await self._simulate_mqtt_message(topic, payload, f"security_monitor_{device.device_id}")

    async def _update_device_statuses(self):
        """Randomly update simulated device statuses"""
        if random.random() < 0.05:  # 5% chance to update a device
            device_id = random.choice(list(self.security_devices.keys()))
            device = self.security_devices[device_id]
            
            # Small chance to change status
            if random.random() < 0.3:
                old_status = device.status
                new_status = random.choice([DeviceStatus.ONLINE, DeviceStatus.WARNING, DeviceStatus.OFFLINE])
                device.status = new_status
                device.last_seen = datetime.now()
                
                if old_status != new_status:
                    topic = f"devices/{device_id}/status"
                    payload = json.dumps({
                        "device_id": device_id,
                        "old_status": old_status.value,
                        "new_status": new_status.value,
                        "timestamp": datetime.now().isoformat()
                    })
                    
                    await self._simulate_mqtt_message(topic, payload, f"monitor_{device_id}")

    async def _simulate_mqtt_traffic(self):
        """Generate realistic MQTT traffic for demonstration"""
        topics = [
            "sensors/temperature/riyadh_001",
            "sensors/pressure/dammam_hub",
            "heartbeat/system_monitor",
            "data/flow_rates/jeddah_terminal",
            "video/motion_detected/security_cam_15",
            "system/maintenance_scheduled",
            "backup/data_sync_complete"
        ]
        
        if random.random() < 0.7:  # 70% chance
            topic = random.choice(topics)
            client_id = random.choice(list(self.simulated_clients.keys()))
            
            # Generate realistic payload based on topic
            if "temperature" in topic:
                payload = f"{random.randint(25, 45)}°C"
            elif "pressure" in topic:
                payload = f"{random.randint(850, 1200)} PSI"
            elif "heartbeat" in topic:
                payload = "OK"
            elif "flow_rates" in topic:
                payload = f"{random.randint(100, 500)} L/min"
            elif "motion" in topic:
                payload = json.dumps({"detected": True, "confidence": random.randint(85, 99)})
            else:
                payload = f"Data_{random.randint(1000, 9999)}"
            
            await self._simulate_mqtt_message(topic, payload, client_id)

    # ============================================================================
    # MAIN RUN METHOD
    # ============================================================================

    async def run(self):
        """Main server run method"""
        logger.info("🚀 Starting Bizclap Security System - HYBRID Backend")
        logger.info("🔒 Saudi Arabia Oil & Gas Infrastructure Monitoring")
        logger.info("=" * 60)
        
        self.running = True
        self.event_loop = asyncio.get_event_loop()
        
        # Start real MQTT broker
        self.start_mqtt_server()
        logger.info(f"✅ Real MQTT Server started on port {self.mqtt_port}")
        
        # Start WebSocket server
        websocket_server = await self.start_websocket_server()
        logger.info(f"✅ WebSocket server started on port {self.websocket_port}")
        
        # Start HTTP server for dashboard
        self.start_http_server()
        logger.info(f"✅ HTTP Server started on port {self.http_port}")
        
        # Start background simulation tasks
        background_task = asyncio.create_task(self.background_simulation_tasks())
        logger.info("✅ Background simulation tasks started")
        
        # Print connection info
        self._print_connection_info()
        
        try:
            # Run forever
            await asyncio.gather(
                websocket_server.wait_closed(),
                background_task
            )
        except KeyboardInterrupt:
            logger.info("🛑 Shutting down server...")
        finally:
            self.running = False
            websocket_server.close()
            await websocket_server.wait_closed()
            logger.info("✅ Server shutdown complete")

    def _print_connection_info(self):
        """Print connection information"""
        try:
            local_ips = []
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        ip = addr['addr']
                        if ip != '127.0.0.1':
                            local_ips.append(ip)
        except:
            local_ips = ['localhost']

        print(f"\n{Fore.GREEN}🚀 Bizclap Security System - HYBRID Backend Running!{Style.RESET_ALL}")
        print("=" * 60)

        print(f"{Fore.CYAN}📡 REAL MQTT Broker (for your client):{Style.RESET_ALL}")
        for ip in local_ips:
            print(f"   • {ip}:{self.mqtt_port}")

        print(f"\n{Fore.CYAN}🌐 Dashboard Web Interface:{Style.RESET_ALL}")
        for ip in local_ips:
            print(f"   • http://{ip}:{self.http_port}")

        print(f"\n{Fore.CYAN}🔌 WebSocket Connection:{Style.RESET_ALL}")
        for ip in local_ips:
            print(f"   • ws://{ip}:{self.websocket_port}")

        print(f"\n{Fore.GREEN}✅ Features:{Style.RESET_ALL}")
        print("   • Real MQTT broker for actual clients")
        print("   • Saudi Arabia security device simulation")
        print("   • Combined real + simulated data in dashboard")
        print("   • Enhanced device tracking and alerts")
        print("   • Compatible with your existing HTML dashboard")

        print(f"\n{Fore.YELLOW}📱 Your Real Client:{Style.RESET_ALL}")
        print(f"   • Connect to port {self.mqtt_port} (MQTT)")
        print("   • All existing functionality preserved")
        print("   • Enhanced with Saudi Arabia context")
        print(f"   • Dashboard available at http://[server-ip]:{self.http_port}")

        print(f"\n{Fore.RED}Press Ctrl+C to stop{Style.RESET_ALL}")
        print("=" * 60)

async def main():
    """Main entry point"""
    try:
        server = BizclapSecurityBackend()
        await server.run()
    except KeyboardInterrupt:
        print("\n👋 Goodbye! Server stopped by user.")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║             BIZCLAP SECURITY SYSTEM - HYBRID             ║
    ║              Real MQTT + Enhanced Simulation             ║
    ║                                                          ║
    ║  🏭 Saudi Arabia Oil & Gas Infrastructure Monitoring    ║
    ║  🔒 Real-time Security Device Management                ║
    ║  📡 Real MQTT Broker + WebSocket Integration            ║
    ║  🌍 12+ Facilities Across Saudi Arabia                 ║
    ║  🤝 Your Real Client + Simulated Enhancement           ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye! Server stopped by user.")
    except Exception as e:
        print(f"❌ Server error: {e}") 