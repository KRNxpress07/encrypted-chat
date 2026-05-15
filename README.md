# End-to-End Encrypted Chat Application

## Overview

This project is a real-time chat application that uses end-to-end encryption. Messages are encrypted on the client side and decrypted only by the intended recipient. The server acts only as a relay and does not have access to message content or encryption keys.

---

## Project Structure

```
encrypted-chat/
├── client/   # React frontend
├── server/   # Node.js backend
```

---

## Prerequisites

* Node.js (v16 or later recommended)
* npm (comes with Node.js)

---

## Installation and Setup

### 1. Install dependencies

In the server directory:

```bash
cd server
npm install
```

In the client directory:

```bash
cd client
npm install
```

---

### 2. Configure server URL

In `client/src/App.js`, ensure the following line is set for local testing:

```js
const SERVER_URL = 'http://localhost:3001';
```

---

### 3. Start the server

```bash
cd server
node server.js
```

The server will run on:

```
http://localhost:3001
```

---

### 4. Start the client

Open a new terminal and run:

```bash
cd client
npm start
```

The application will open at:

```
http://localhost:3000
```

---

## Usage

* Enter a username and room ID
* Share the same room ID with another user
* Start sending messages

---

## Authors

* Kiran Nambiar
* Bhuvanesh Jatla
