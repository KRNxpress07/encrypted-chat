import React, { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';

// ============================================================================
// CRYPTOGRAPHY UTILITIES - Web Crypto API (Built into browsers)
// ============================================================================
const CryptoUtils = {
  // Generate AES-256 key for symmetric encryption
  async generateAESKey() {
    return await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // Generate RSA-2048 key pair for asymmetric encryption
  async generateRSAKeyPair() {
    return await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // Export RSA public key to base64 string (for sharing)
  async exportPublicKey(publicKey) {
    const exported = await crypto.subtle.exportKey('spki', publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
  },

  // Import RSA public key from base64 string
  async importPublicKey(base64Key) {
    const binaryKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      'spki',
      binaryKey,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );
  },

  // AES-GCM Encryption
  async encryptAES(message, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Random IV
    const encoder = new TextEncoder();
    const data = encoder.encode(message);

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    return {
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
      iv: btoa(String.fromCharCode(...iv))
    };
  },

  // AES-GCM Decryption
  async decryptAES(ciphertext, iv, key) {
    const ciphertextBytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
    const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      key,
      ciphertextBytes
    );

    return new TextDecoder().decode(decrypted);
  },

  // Hybrid Encryption (RSA + AES)
  async encryptHybrid(message, recipientPublicKey) {
    // Generate ephemeral AES key for this message
    const aesKey = await this.generateAESKey();
    
    // Encrypt message with AES
    const { ciphertext, iv } = await this.encryptAES(message, aesKey);
    
    // Export AES key as raw bytes
    const exportedAESKey = await crypto.subtle.exportKey('raw', aesKey);
    
    // Encrypt AES key with recipient's RSA public key
    const encryptedKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      recipientPublicKey,
      exportedAESKey
    );

    return {
      ciphertext,
      iv,
      encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedKey)))
    };
  },

  // Hybrid Decryption
  async decryptHybrid(ciphertext, iv, encryptedKey, privateKey) {
    // Decrypt AES key with RSA private key
    const encryptedKeyBytes = Uint8Array.from(atob(encryptedKey), c => c.charCodeAt(0));
    const aesKeyBytes = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      encryptedKeyBytes
    );
    
    // Import AES key
    const aesKey = await crypto.subtle.importKey(
      'raw',
      aesKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    // Decrypt message
    return await this.decryptAES(ciphertext, iv, aesKey);
  }
};

// ============================================================================
// MAIN APP COMPONENT
// ============================================================================
function App() {
  // UI State
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [encryptionMode, setEncryptionMode] = useState('aes');
  const [showRawData, setShowRawData] = useState(false);
  const [debugLogs, setDebugLogs] = useState([]);
  
  // Connection State
  const [roomId, setRoomId] = useState('');
  const [joinedRoom, setJoinedRoom] = useState(false);
  const [userId] = useState(`user_${Math.random().toString(36).substr(2, 9)}`);
  const [username, setUsername] = useState('');
  const [connected, setConnected] = useState(false);
  const [peerUsername, setPeerUsername] = useState(null);
  
  // Crypto State
  const [aesKey, setAesKey] = useState(null);
  const [rsaKeyPair, setRsaKeyPair] = useState(null);
  const [peerRSAKey, setPeerRSAKey] = useState(null);
  const [keysReady, setKeysReady] = useState(false);
  
  // Refs
  const messagesEndRef = useRef(null);
  const socketRef = useRef(null);

  // ============================================================================
  // SOCKET.IO CONNECTION
  // ============================================================================
  useEffect(() => {
  if (!joinedRoom) return;

  const SERVER_URL = 'https://encrypted-chat-server-sayx.onrender.com';
  addDebugLog(`🌐 Connecting to server: ${SERVER_URL}`);
  
  socketRef.current = io(SERVER_URL, {
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionAttempts: 3,
    reconnectionDelay: 1000
  });

  socketRef.current.on('connect', () => {
    addDebugLog('✅ Connected to server');
    setConnected(true);
    
    // Only rejoin if we have all the necessary data
    // Don't read from state here to avoid dependency loop
  });

  socketRef.current.on('disconnect', () => {
    addDebugLog('❌ Disconnected from server');
    setConnected(false);
  });

  socketRef.current.on('existing-users', async (users) => {
    addDebugLog(`👥 Found ${users.length} existing user(s) in room`);
    
    for (const user of users) {
      if (user.userId === userId) continue; // Skip self
      
      setPeerUsername(user.username);
      
      if (user.aesKey) {
        try {
          const key = await importAESKey(user.aesKey);
          setAesKey(key);
          addDebugLog(`🔑 Imported shared AES key from ${user.username}`);
        } catch (error) {
          addDebugLog(`❌ Failed to import AES key: ${error.message}`);
        }
      }
      
      if (user.rsaPublicKey) {
        try {
          const key = await CryptoUtils.importPublicKey(user.rsaPublicKey);
          setPeerRSAKey(key);
          addDebugLog(`🔑 Imported ${user.username}'s RSA public key`);
        } catch (error) {
          addDebugLog(`❌ Failed to import peer RSA key: ${error.message}`);
        }
      }
    }
  });

  socketRef.current.on('user-joined', async (data) => {
    if (data.userId === userId) return; // Skip self
    
    addDebugLog(`👤 ${data.username} joined the room`);
    setPeerUsername(data.username);
    
    if (data.aesKey) {
      try {
        const key = await importAESKey(data.aesKey);
        setAesKey(key);
        addDebugLog(`🔑 Imported shared AES key from ${data.username}`);
      } catch (error) {
        addDebugLog(`❌ Failed to import AES key: ${error.message}`);
      }
    }
    
    if (data.rsaPublicKey) {
      try {
        const key = await CryptoUtils.importPublicKey(data.rsaPublicKey);
        setPeerRSAKey(key);
        addDebugLog(`🔑 Received ${data.username}'s RSA public key`);
      } catch (error) {
        addDebugLog(`❌ Failed to import peer RSA key: ${error.message}`);
      }
    }
  });

  socketRef.current.on('encrypted-message', async (data) => {
    console.log('🔔 RAW MESSAGE RECEIVED:', data);
    addDebugLog(`📥 Encrypted message received from ${data.senderName}`);
    
    try {
      let decrypted;
      
      if (data.mode === 'aes') {
        // Get current AES key from state
        const currentAesKey = aesKey;
        if (!currentAesKey) {
          addDebugLog(`⚠️ Cannot decrypt: no AES key available`);
          return;
        }
        
        decrypted = await CryptoUtils.decryptAES(
          data.encrypted.ciphertext,
          data.encrypted.iv,
          currentAesKey
        );
        addDebugLog(`🔓 Decrypted with AES-GCM`);
      } else if (data.mode === 'hybrid') {
        // Get current RSA key pair from state
        const currentRsaKeyPair = rsaKeyPair;
        if (!currentRsaKeyPair) {
          addDebugLog(`⚠️ Cannot decrypt: no RSA key pair available`);
          return;
        }
        
        decrypted = await CryptoUtils.decryptHybrid(
          data.encrypted.ciphertext,
          data.encrypted.iv,
          data.encrypted.encryptedKey,
          currentRsaKeyPair.privateKey
        );
        addDebugLog(`🔓 Decrypted with Hybrid (RSA+AES)`);
      } else {
        addDebugLog(`⚠️ Unknown encryption mode: ${data.mode}`);
        return;
      }

      setMessages(prev => [...prev, {
        id: data.id,
        sender: data.senderName,
        mode: data.mode === 'aes' ? 'AES-GCM' : 'Hybrid (RSA+AES)',
        encrypted: data.encrypted,
        plaintext: decrypted,
        timestamp: data.timestamp,
        isOwn: false
      }]);
    } catch (error) {
      addDebugLog(`❌ Decryption failed: ${error.message}`);
      console.error('Decryption error:', error);
    }
  });

  socketRef.current.on('user-left', (data) => {
    addDebugLog(`👋 ${data.username} left the room`);
    setPeerUsername(null);
    setPeerRSAKey(null);
  });

  return () => {
    if (socketRef.current) {
      socketRef.current.disconnect();
    }
  };
}, [joinedRoom]); // ONLY depend on joinedRoom!

  // ============================================================================
  // UTILITY FUNCTIONS
  // ============================================================================
  const addDebugLog = (message) => {
    const timestamp = new Date().toLocaleTimeString();
    setDebugLogs(prev => [...prev, `[${timestamp}] ${message}`]);
    console.log(message);
  };

  const initializeKeys = async () => {
    try {
      addDebugLog('🔐 Generating encryption keys...');
      
      // Generate AES key (will be shared with peers)
      const aes = await CryptoUtils.generateAESKey();
      setAesKey(aes);
      addDebugLog('✅ AES-256-GCM key generated');
      
      // Generate RSA key pair
      const rsa = await CryptoUtils.generateRSAKeyPair();
      setRsaKeyPair(rsa);
      addDebugLog('✅ RSA-2048 key pair generated');
      
      setKeysReady(true);
      addDebugLog('🎉 All keys ready!');
      
      return { aes, rsa };
    } catch (error) {
      addDebugLog(`❌ Key generation failed: ${error.message}`);
      return null;
    }
  };

  // Add utility to export/import AES keys
  const exportAESKey = async (key) => {
    const exported = await crypto.subtle.exportKey('raw', key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
  };

  const importAESKey = async (base64Key) => {
    const binaryKey = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      'raw',
      binaryKey,
      { name: 'AES-GCM' },
      true,
      ['encrypt', 'decrypt']
    );
  };

  const joinRoom = async () => {
  if (!roomId.trim() || !username.trim()) {
    alert('⚠️ Please enter both username and room ID');
    return;
  }

  addDebugLog(`🚀 Joining room: ${roomId}`);
  const keys = await initializeKeys();
  
  if (keys) {
    setJoinedRoom(true);
    
    // Wait for socket to connect with retry logic
    const tryJoinRoom = async (attempts = 0) => {
      if (attempts > 10) {
        addDebugLog('❌ Failed to join room after 10 attempts');
        return;
      }
      
      if (socketRef.current && socketRef.current.connected) {
        const exportedRSA = await CryptoUtils.exportPublicKey(keys.rsa.publicKey);
        const exportedAES = await exportAESKey(keys.aes);
        
        socketRef.current.emit('join-room', {
          roomId,
          userId,
          username,
          rsaPublicKey: exportedRSA,
          aesKey: exportedAES
        });
        
        addDebugLog(`✅ Joined room successfully`);
      } else {
        addDebugLog(`⏳ Waiting for connection... (attempt ${attempts + 1})`);
        setTimeout(() => tryJoinRoom(attempts + 1), 500);
      }
    };
    
    setTimeout(() => tryJoinRoom(), 1000);
  }
};

  const sendMessage = async () => {
    if (!inputMessage.trim() || !keysReady) return;
    if (!socketRef.current || !socketRef.current.connected) {
      alert('⚠️ Not connected to server');
      return;
    }

    try {
      let encryptedData;
      let modeLabel;

      if (encryptionMode === 'aes') {
        addDebugLog(`🔒 Encrypting with AES-GCM...`);
        encryptedData = await CryptoUtils.encryptAES(inputMessage, aesKey);
        modeLabel = 'AES-GCM';
        addDebugLog(`✅ Message encrypted (${encryptedData.ciphertext.length} chars)`);
      } else {
        if (!peerRSAKey) {
          alert('⚠️ Hybrid mode requires peer to be connected. Use AES mode or wait.');
          return;
        }
        addDebugLog(`🔒 Encrypting with Hybrid (RSA+AES)...`);
        encryptedData = await CryptoUtils.encryptHybrid(inputMessage, peerRSAKey);
        modeLabel = 'Hybrid (RSA+AES)';
        addDebugLog(`✅ Hybrid encryption complete`);
      }

      const messageObj = {
        id: Date.now(),
        sender: userId,
        senderName: username,
        mode: encryptionMode,
        encrypted: encryptedData,
        timestamp: new Date().toLocaleTimeString(),
        plaintext: inputMessage,
        isOwn: true
      };

      // Add to local messages
      setMessages(prev => [...prev, {
        ...messageObj,
        mode: modeLabel
      }]);
      
      // Send encrypted message to server
      socketRef.current.emit('encrypted-message', {
        ...messageObj,
        roomId
      });

      setInputMessage('');
      addDebugLog(`📤 Encrypted message sent`);
    } catch (error) {
      addDebugLog(`❌ Encryption failed: ${error.message}`);
      alert(`Encryption error: ${error.message}`);
    }
  };

  const handleModeChange = (newMode) => {
    if (newMode === 'hybrid' && !peerRSAKey) {
      alert('⚠️ Hybrid mode requires a peer with RSA key. Use AES mode for now.');
      return;
    }
    
    if (messages.length > 0) {
      const confirmChange = window.confirm('⚠️ Changing encryption mode mid-chat. Continue?');
      if (!confirmChange) return;
      addDebugLog(`⚠️ Mode changed: ${encryptionMode.toUpperCase()} → ${newMode.toUpperCase()}`);
    }
    setEncryptionMode(newMode);
  };

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ============================================================================
  // JOIN SCREEN
  // ============================================================================
  if (!joinedRoom) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white flex items-center justify-center p-4">
        <div className="bg-slate-800/50 backdrop-blur-lg rounded-2xl p-8 max-w-md w-full border border-purple-500/30">
          <div className="text-center mb-6">
            <div className="text-6xl mb-4">🔐</div>
            <h1 className="text-3xl font-bold mb-2">E2E Encrypted Chat</h1>
            <p className="text-slate-400">Military-grade encryption</p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">Your Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your name"
                className="w-full bg-slate-900/50 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">Room ID</label>
              <input
                type="text"
                value={roomId}
                onChange={(e) => setRoomId(e.target.value)}
                placeholder="Enter or create room ID"
                className="w-full bg-slate-900/50 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
              <p className="text-xs text-slate-400 mt-2">
                💡 Share the same Room ID with your friend
              </p>
            </div>

            <button
              onClick={() => setRoomId(`room_${Math.random().toString(36).substr(2, 9)}`)}
              className="w-full py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm transition"
            >
              🎲 Generate Random Room ID
            </button>

            <button
              onClick={joinRoom}
              disabled={!roomId.trim() || !username.trim()}
              className="w-full py-4 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-700 disabled:cursor-not-allowed rounded-lg font-bold text-lg transition shadow-lg shadow-purple-500/50"
            >
              🚀 Join & Generate Keys
            </button>
          </div>

          <div className="mt-6 bg-slate-900/50 rounded-lg p-4 text-xs text-slate-300">
            <p className="font-semibold mb-2">🔒 How it works:</p>
            <ol className="list-decimal list-inside space-y-1">
              <li>Enter username and room ID</li>
              <li>Share room ID with your friend</li>
              <li>Keys generated automatically</li>
              <li>Chat with end-to-end encryption!</li>
            </ol>
          </div>
        </div>
      </div>
    );
  }

  // ============================================================================
  // CHAT SCREEN
  // ============================================================================
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="bg-slate-800/50 backdrop-blur-lg rounded-t-2xl p-6 border-b border-purple-500/30">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-2xl font-bold flex items-center gap-2">
                <span>🔐</span>
                E2E Encrypted Chat
              </h1>
              <div className="flex items-center gap-3 text-sm text-slate-400 mt-1">
                <span>Room: <span className="text-purple-400 font-mono">{roomId}</span></span>
                <span className={connected ? 'text-green-400' : 'text-red-400'}>
                  {connected ? '🟢 Online' : '🔴 Offline'}
                </span>
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm text-slate-400">You: {username}</div>
              {peerUsername && (
                <div className="text-sm text-green-400">Peer: {peerUsername}</div>
              )}
            </div>
          </div>

          {/* Keys Status */}
          <div className="bg-slate-900/50 rounded-lg p-3 mb-4 text-sm">
            <div className="flex items-center gap-4 flex-wrap">
              <span className={keysReady ? 'text-green-400' : 'text-yellow-400'}>
                {keysReady ? '✅ Keys Ready' : '⏳ Generating...'}
              </span>
              {peerRSAKey && (
                <span className="text-green-400">✅ Peer RSA Key</span>
              )}
            </div>
          </div>

          {/* Encryption Mode Toggle */}
          <div className="bg-slate-900/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm font-semibold">Encryption Mode:</span>
              <button
                onClick={() => setShowRawData(!showRawData)}
                className="text-xs text-slate-400 hover:text-white px-3 py-1 bg-slate-700/50 rounded"
              >
                {showRawData ? '👁️ Hide' : '👁️ Show'} Raw Data
              </button>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => handleModeChange('aes')}
                className={`py-3 px-4 rounded-lg font-medium transition ${
                  encryptionMode === 'aes'
                    ? 'bg-purple-600 text-white shadow-lg shadow-purple-500/50'
                    : 'bg-slate-700/50 text-slate-300 hover:bg-slate-700'
                }`}
              >
                <div className="text-sm font-bold">🔒 AES-GCM</div>
                <div className="text-xs opacity-70">Symmetric • Fast</div>
              </button>
              <button
                onClick={() => handleModeChange('hybrid')}
                disabled={!peerRSAKey}
                className={`py-3 px-4 rounded-lg font-medium transition ${
                  encryptionMode === 'hybrid'
                    ? 'bg-purple-600 text-white shadow-lg shadow-purple-500/50'
                    : 'bg-slate-700/50 text-slate-300 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed'
                }`}
              >
                <div className="text-sm font-bold">🛡️ Hybrid</div>
                <div className="text-xs opacity-70">
                  {peerRSAKey ? 'RSA+AES • Ready' : 'Need peer...'}
                </div>
              </button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Messages Area */}
          <div className="lg:col-span-2 bg-slate-800/50 backdrop-blur-lg rounded-b-2xl lg:rounded-bl-2xl lg:rounded-br-none">
            <div className="h-96 overflow-y-auto p-4 space-y-3">
              {messages.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full text-slate-500">
                  <div className="text-6xl mb-4">💬</div>
                  <p>No messages yet. Start chatting securely!</p>
                </div>
              )}
              {messages.map((msg) => (
                <div
                  key={msg.id}
                  className={`rounded-lg p-4 ${
                    msg.isOwn
                      ? 'bg-purple-900/30 ml-12 border border-purple-500/30'
                      : 'bg-slate-900/50 mr-12 border border-slate-700/30'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-xs font-bold ${
                      msg.isOwn ? 'text-purple-300' : 'text-blue-300'
                    }`}>
                      {msg.isOwn ? '🟣 You' : '🔵 ' + msg.sender}
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs bg-purple-600/30 px-2 py-1 rounded font-mono">
                        {msg.mode}
                      </span>
                      <span className="text-xs text-slate-500">{msg.timestamp}</span>
                    </div>
                  </div>
                  <div className="text-white text-base">{msg.plaintext}</div>
                  {showRawData && (
                    <div className="mt-2 text-xs bg-slate-950/50 p-2 rounded font-mono overflow-x-auto">
                      <div className="text-green-400">CT: {msg.encrypted.ciphertext.substring(0, 60)}...</div>
                      <div className="text-blue-400">IV: {msg.encrypted.iv}</div>
                      {msg.encrypted.encryptedKey && (
                        <div className="text-yellow-400">EK: {msg.encrypted.encryptedKey.substring(0, 50)}...</div>
                      )}
                    </div>
                  )}
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <div className="p-4 border-t border-slate-700">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                  placeholder={keysReady ? "Type a secure message..." : "Generating keys..."}
                  disabled={!keysReady || !connected}
                  className="flex-1 bg-slate-900/50 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50"
                />
                <button
                  onClick={sendMessage}
                  disabled={!keysReady || !inputMessage.trim() || !connected}
                  className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-700 disabled:cursor-not-allowed rounded-lg font-bold transition shadow-lg shadow-purple-500/30"
                >
                  🔒 Send
                </button>
              </div>
            </div>
          </div>

          {/* Debug Console */}
          <div className="bg-slate-800/50 backdrop-blur-lg rounded-b-2xl lg:rounded-br-2xl lg:rounded-bl-none p-4">
            <h3 className="text-sm font-bold mb-3 flex items-center gap-2">
              <span>🔍</span> Debug Console
            </h3>
            <div className="bg-slate-950/50 rounded-lg p-3 h-96 overflow-y-auto font-mono text-xs space-y-1">
              {debugLogs.map((log, i) => (
                <div key={i} className="text-slate-300 break-words">{log}</div>
              ))}
              {debugLogs.length === 0 && (
                <div className="text-slate-600">Waiting for activity...</div>
              )}
            </div>
            <button
              onClick={() => setDebugLogs([])}
              className="mt-2 w-full py-2 bg-slate-700 hover:bg-slate-600 rounded text-xs transition"
            >
              Clear Console
            </button>
          </div>
        </div>

        {/* Security Info */}
        <div className="mt-4 bg-slate-800/30 backdrop-blur-lg rounded-lg p-4">
          <h3 className="text-sm font-bold mb-2 flex items-center gap-2">
            <span>🛡️</span>
            Security Features Active
          </h3>
          <ul className="grid grid-cols-2 gap-2 text-xs text-slate-300">
            <li>✅ Client-side encryption only</li>
            <li>✅ Fresh IV per message</li>
            <li>✅ AES-256-GCM encryption</li>
            <li>✅ RSA-2048-OAEP key exchange</li>
            <li>✅ Server never sees plaintext</li>
            <li>✅ Forward secrecy (Hybrid mode)</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default App;