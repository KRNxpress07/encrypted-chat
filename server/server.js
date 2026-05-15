// server.js - E2E Encrypted Chat Server
// This server ONLY relays encrypted messages and public keys - it NEVER sees plaintext or the shared secret

const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

const io = socketIO(server, {
  cors: {
    origin: [
      "http://localhost:3000"
    ],
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());

// Store active rooms: roomId -> Map of userId -> user data
const rooms = new Map();

io.on('connection', (socket) => {
  console.log(`✅ New connection: ${socket.id}`);

  socket.on('join-room', (data) => {
    const { roomId, userId, username, ecdhPublicKey, rsaPublicKey } = data;

    socket.join(roomId);

    if (!rooms.has(roomId)) {
      rooms.set(roomId, new Map());
    }

    // Store user info — ECDH public key replaces raw aesKey
    // The shared AES secret is derived independently on each client; the server never sees it
    rooms.get(roomId).set(userId, {
      socketId: socket.id,
      username,
      ecdhPublicKey,  // public key only — safe to relay
      rsaPublicKey
    });

    console.log(`👤 ${username} joined room: ${roomId} (${rooms.get(roomId).size} users)`);

    // Notify existing peers
    socket.to(roomId).emit('user-joined', {
      userId,
      username,
      ecdhPublicKey,
      rsaPublicKey
    });

    // Send existing users to the new joiner so they can complete the ECDH handshake
    const roomUsers = rooms.get(roomId);
    const existingUsers = Array.from(roomUsers.entries())
      .filter(([id]) => id !== userId)
      .map(([id, user]) => ({
        userId: id,
        username: user.username,
        ecdhPublicKey: user.ecdhPublicKey,
        rsaPublicKey: user.rsaPublicKey
      }));

    if (existingUsers.length > 0) {
      socket.emit('existing-users', existingUsers);
      console.log(`📤 Sent ${existingUsers.length} existing user(s) to ${username}`);
    }
  });

  // Relay encrypted messages — server never decrypts
  socket.on('encrypted-message', (data) => {
    const { roomId, senderName } = data;
    console.log(`📨 Relaying encrypted message from ${senderName} in room: ${roomId}`);
    socket.to(roomId).emit('encrypted-message', data);
  });

  socket.on('disconnect', () => {
    console.log(`❌ Client disconnected: ${socket.id}`);

    rooms.forEach((roomUsers, roomId) => {
      roomUsers.forEach((user, userId) => {
        if (user.socketId === socket.id) {
          const username = user.username;
          roomUsers.delete(userId);
          socket.to(roomId).emit('user-left', { userId, username });
          console.log(`👋 ${username} left room: ${roomId}`);

          if (roomUsers.size === 0) {
            rooms.delete(roomId);
            console.log(`🗑️ Room ${roomId} deleted (empty)`);
          }
        }
      });
    });
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'online',
    activeRooms: rooms.size,
    timestamp: new Date().toISOString()
  });
});

const PORT = process.env.PORT || 3001;

server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════╗
║                                                    ║
║  🔐 E2E ENCRYPTED CHAT SERVER RUNNING             ║
║                                                    ║
║  Port: ${PORT}                                        ║
║  Status: READY FOR CONNECTIONS                    ║
║  Security: Server NEVER sees plaintext            ║
║            or the derived shared secret           ║
║                                                    ║
╚════════════════════════════════════════════════════╝
  `);
});

process.on('SIGTERM', () => {
  console.log('\nShutting down server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});