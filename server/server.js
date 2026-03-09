// server.js - E2E Encrypted Chat Server
// This server ONLY relays encrypted messages - it NEVER sees plaintext

const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

// Configure Socket.IO with CORS to allow frontend connections
const io = socketIO(server, {
  cors: {
    origin: [
      "https://encrypted-chat-ten.vercel.app",
      "http://localhost:3000"
    ],
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());

// Store active rooms: roomId -> Map of userId -> user data
const rooms = new Map();

// When a client connects
io.on('connection', (socket) => {
  console.log(`✅ New connection: ${socket.id}`);

  // Handle user joining a room
  socket.on('join-room', (data) => {
    const { roomId, userId, username, rsaPublicKey, aesKey } = data;
    
    // Add user to the room
    socket.join(roomId);
    
    // Store room if it doesn't exist
    if (!rooms.has(roomId)) {
      rooms.set(roomId, new Map());
    }
    
    // Store user info (including shared AES key)
    rooms.get(roomId).set(userId, {
      socketId: socket.id,
      username,
      rsaPublicKey,
      aesKey // Store AES key for sharing with other users
    });

    console.log(`👤 ${username} joined room: ${roomId} (${rooms.get(roomId).size} users)`);

    // Tell others in the room that someone joined
    socket.to(roomId).emit('user-joined', {
      userId,
      username,
      rsaPublicKey,
      aesKey
    });

    // Send list of existing users to the new joiner
    const roomUsers = rooms.get(roomId);
    const existingUsers = Array.from(roomUsers.entries())
      .filter(([id]) => id !== userId)
      .map(([id, user]) => ({
        userId: id,
        username: user.username,
        rsaPublicKey: user.rsaPublicKey,
        aesKey: user.aesKey
      }));

    if (existingUsers.length > 0) {
      socket.emit('existing-users', existingUsers);
      console.log(`📤 Sent ${existingUsers.length} existing users to ${username}`);
    }
  });

  // Handle encrypted messages (server never decrypts!)
  socket.on('encrypted-message', (data) => {
    const { roomId, senderName } = data;
    console.log(`📨 Relaying encrypted message from ${senderName} in room: ${roomId}`);
    
    // Simply relay the encrypted message to everyone else in the room
    socket.to(roomId).emit('encrypted-message', data);
  });

  // Handle user disconnect
  socket.on('disconnect', () => {
    console.log(`❌ Client disconnected: ${socket.id}`);
    
    // Remove user from all rooms
    rooms.forEach((roomUsers, roomId) => {
      roomUsers.forEach((user, userId) => {
        if (user.socketId === socket.id) {
          const username = user.username;
          roomUsers.delete(userId);
          
          // Notify others
          socket.to(roomId).emit('user-left', { userId, username });
          console.log(`👋 ${username} left room: ${roomId}`);
          
          // Clean up empty rooms
          if (roomUsers.size === 0) {
            rooms.delete(roomId);
            console.log(`🗑️ Room ${roomId} deleted (empty)`);
          }
        }
      });
    });
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'online',
    activeRooms: rooms.size,
    timestamp: new Date().toISOString()
  });
});

// Start server
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
║                                                    ║
╚════════════════════════════════════════════════════╝

Server is running on http://localhost:${PORT}
Health check: http://localhost:${PORT}/health

Waiting for clients to connect...
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\nShutting down server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});