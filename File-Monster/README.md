**CTF Write-Up: File Monster Challenge**

*NNS CTF 2026 \| Category: Web/Misc \| 104 pts \| 63 Solves*

*Author: piprett \| Date: September 6, 2026*

**1. Challenge Description**

*\"The file monster likes files and flags.\"*

The challenge provides a downloadable archive (web-file-monster.tar.gz)
containing the full source code of a web application built with Bun.js
and MongoDB. The application allows users to upload files and stores
metadata in a database. Our goal is to find the hidden flag.

**2. Initial Reconnaissance**

2.1 Project Structure

web_file-monster/

├── Dockerfile \# Docker build configuration

├── entrypoint.sh \# Server startup script

├── init.js \# MongoDB initialization

├── mongod.conf \# MongoDB configuration

**├── src/index.ts \# Backend logic (KEY FILE)**

└── src/index.html \# Frontend page

2.2 Technology Stack

• Bun.js v1 --- JavaScript runtime

• MongoDB 8.2.10 --- Database

• Mongoose \^9.9.2 --- MongoDB ODM library

• TypeScript \^5 --- Programming language

**3. Source Code Analysis**

3.1 Dockerfile Analysis

Both port 3000 (web app) and port 27017 (MongoDB) are exposed
externally. This is a significant misconfiguration --- MongoDB should
never be exposed to the internet.

EXPOSE 3000 \# Web app port

**EXPOSE 27017 \# MongoDB port --- EXPOSED EXTERNALLY!**

3.2 MongoDB Configuration (mongod.conf)

MongoDB is configured to listen on all network interfaces (bindIp:
0.0.0.0), confirming it is accessible remotely.

3.3 Database Initialization (init.js) --- Credential Discovery

**CRITICAL FINDING --- Hardcoded Credentials:**

**• Username: viewer**

**• Password: viewer**

• Access Level: Read-only on file-monster database

3.4 Main Application (index.ts) --- The Critical Vulnerability

**Available API Endpoints:**

• GET / → Serves the homepage

• GET /robots.txt → Serves robots file

• POST /upload → File upload handler

• GET /files → Lists uploaded files from MongoDB

**The vulnerable upload handler code:**

const txt = (await file.text())

.replaceAll(\'\"\', \"\") // removes double quotes

.replaceAll(\"\'\", \"\") // removes single quotes

.replaceAll(\"\`\", \"\") // removes backticks

**.replace(\'FLAG\', process.env.FLAG ?? \'nns{demo_flag}\');**

// ↑↑↑ THIS IS THE VULNERABILITY ↑↑↑

**CRITICAL VULNERABILITY --- Flag Injection:**

When any file is uploaded containing the string \"FLAG\", the server
automatically replaces it with the actual flag from the environment
variable process.env.FLAG. The modified content (now containing the real
flag) is saved to disk at /tmp/{filename}.

**4. Vulnerability Summary**

Three vulnerabilities were identified:

**1. \[CRITICAL\] Flag injection in uploaded file content --- index.ts
line 63**

**2. \[HIGH\] MongoDB database exposed externally --- Dockerfile +
mongod.conf**

**3. \[HIGH\] Hardcoded database credentials --- init.js**

**5. Exploitation Steps**

Step 1: Upload a File Containing \"FLAG\"

I created a simple text file with the content FLAG and uploaded it to
the challenge server:

curl -X POST http://CHALLENGE_HOST:3000/upload -F
\"file=@payload.txt;filename=test.txt\"

**Server Response:**

{ \"ok\": true, \"filename\": \"test.txt\", \"path\": \"/tmp/test.txt\",
\"fileMonster\": \"nom nom tasty file\" }

What happened: The server read the file content (FLAG), replaced it with
the actual flag value, and saved the modified content to /tmp/test.txt.

Step 2: Connect to the Exposed MongoDB

Using the credentials discovered in init.js, I connected to the
externally accessible MongoDB database:

mongosh
\"mongodb://viewer:viewer@CHALLENGE_HOST:MONGO_PORT/file-monster?authSource=file-monster\"

Step 3: Explore the Database

Once connected, I explored all collections:

show collections

db.getCollectionNames().forEach(function(c) {

printjson(db.getCollection(c).find().toArray());

})

Step 4: Retrieve the Flag

By exploring the database collections and correlating with the uploaded
file data, the flag was retrieved.

**6. Attack Flow Diagram**

Attacker → Upload file with \'FLAG\' → Server replaces FLAG with real
flag → Saves to /tmp/

Attacker → Connect to MongoDB (viewer:viewer) → Explore collections →
Find the flag

**7. Tools Used**

• Text Editor / IDE --- Source code analysis and review

• curl / Web Browser --- HTTP requests and file upload

• mongosh / MongoDB Compass --- Database connection and exploration

• Node.js --- Scripting and automation

**8. Lessons Learned**

1\. Always review source code thoroughly --- The vulnerability was
clearly visible in a single line of code (the .replace(\'FLAG\', \...)
call)

2\. Check for exposed services --- EXPOSE 27017 in the Dockerfile and
bindIp: 0.0.0.0 in mongod.conf revealed that MongoDB was externally
accessible

3\. Look for hardcoded credentials --- The viewer:viewer credentials in
init.js provided immediate database access

4\. Read all hints carefully --- The HTML page contained direct hints
about MongoDB analysis and flag injection

5\. Understand the full data flow --- Tracing how user input flows
through the application revealed the flag injection point

**9. Remediation Recommendations**

• Flag injection in content → Never inject secrets into user-controlled
content

• Exposed MongoDB port → Bind MongoDB to 127.0.0.1 only; do not expose
port 27017

• Hardcoded credentials → Use environment variables for all credentials

• No rate limiting → Add request rate limiting to prevent abuse

─────────────────────────────────────────────

*This write-up was prepared as part of the CTF course assignment --- NNS
CTF 2026*

*Challenge: File Monster \| Category: Web/Misc \| September 2026*
