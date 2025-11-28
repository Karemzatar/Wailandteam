const socket = io();
let currentTicket = null;
let isAdmin = false;
let mediaRecorder = null;
let audioChunks = [];

// Get ticket ID from URL
function getTicketId() {
    const path = window.location.pathname;
    const match = path.match(/ticket-([^\.]+)\.html/);
    return match ? match[1] : null;
}

// Load ticket data
async function loadTicket() {
    const ticketId = getTicketId();
    if (!ticketId) {
        alert('Invalid ticket URL');
        return;
    }

    try {
        const response = await fetch(`/api/tickets/${ticketId}`);
        currentTicket = await response.json();
        
        updateTicketDisplay();
        loadMessages();
        setupChat();
        joinTicketRoom();
        
    } catch (error) {
        console.error('Error loading ticket:', error);
        document.getElementById('ticketTitle').textContent = 'Ticket Not Found';
    }
}

function updateTicketDisplay() {
    document.getElementById('ticketTitle').textContent = 
        `Ticket #${currentTicket.id.substring(0, 8)} - ${currentTicket.username}`;
    document.title = `Ticket #${currentTicket.id.substring(0, 8)} - ${currentTicket.username}`;
    
    const metaHtml = `
        <p><strong>Status:</strong> <span class="ticket-status status-${currentTicket.status}">${currentTicket.status.toUpperCase()}</span></p>
        <p><strong>Type:</strong> ${currentTicket.type}</p>
        <p><strong>Subject:</strong> ${currentTicket.subject}</p>
        ${currentTicket.claimedBy ? `<p><strong>Admin:</strong> ${currentTicket.claimedBy}</p>` : ''}
    `;
    
    document.getElementById('ticketMeta').innerHTML = metaHtml;
    
    // Check if current user is the admin who claimed the ticket
    // In a real app, you'd have proper authentication
    isAdmin = currentTicket.claimedBy && confirm('Are you the admin?');
}

function loadMessages() {
    const chatMessages = document.getElementById('chatMessages');
    
    if (!currentTicket.messages || currentTicket.messages.length === 0) {
        // Add welcome message
        addSystemMessage(`Welcome to your support ticket! Our team will assist you shortly. Ticket subject: "${currentTicket.subject}"`);
        return;
    }
    
    chatMessages.innerHTML = '';
    currentTicket.messages.forEach(message => {
        displayMessage(message);
    });
    
    scrollToBottom();
}

function displayMessage(message) {
    const chatMessages = document.getElementById('chatMessages');
    
    let messageClass = 'message';
    let senderName = message.sender;
    
    if (message.sender === 'system') {
        messageClass += ' system';
    } else if (message.sender === currentTicket.claimedBy) {
        messageClass += ' admin';
        senderName = 'Support Agent';
    } else {
        messageClass += ' user';
        senderName = currentTicket.username;
    }
    
    const messageTime = new Date(message.timestamp).toLocaleTimeString();
    
    let contentHtml = '';
    if (message.type === 'file' && message.file) {
        if (message.file.originalname.match(/\.(jpg|jpeg|png|gif)$/i)) {
            contentHtml = `<img src="${message.file.path}" alt="${message.file.originalname}" style="max-width: 200px; border-radius: 8px;">`;
        } else {
            contentHtml = `<a href="${message.file.path}" download="${message.file.originalname}">📎 ${message.file.originalname}</a>`;
        }
    } else if (message.type === 'voice') {
        contentHtml = `🎤 Voice Message <audio controls src="${message.content}" style="margin-top: 5px;"></audio>`;
    } else {
        contentHtml = message.content;
        
        // Check for close command
        if (isAdmin && message.content.startsWith('close - ')) {
            const reason = message.content.substring(8);
            closeTicket(reason);
        }
    }
    
    const messageHtml = `
        <div class="${messageClass}">
            ${message.sender !== 'system' ? `
                <div class="avatar">${senderName.charAt(0).toUpperCase()}</div>
            ` : ''}
            <div class="message-content">
                ${message.sender !== 'system' ? `
                    <div class="message-sender">${senderName}</div>
                ` : ''}
                <div class="message-text">${contentHtml}</div>
                <div class="message-time">${messageTime}</div>
            </div>
        </div>
    `;
    
    chatMessages.innerHTML += messageHtml;
    scrollToBottom();
    
    // Play notification sound for new messages
    if (message.sender !== 'system' && (!isAdmin || message.sender !== currentTicket.claimedBy)) {
        playNotificationSound();
    }
}

function addSystemMessage(content) {
    const systemMessage = {
        id: Date.now().toString(),
        sender: 'system',
        type: 'text',
        content: content,
        timestamp: new Date().toISOString()
    };
    
    displayMessage(systemMessage);
}

function setupChat() {
    const messageInput = document.getElementById('messageInput');
    const sendButton = document.getElementById('sendButton');
    const fileInput = document.getElementById('fileInput');
    
    // Enable chat if ticket is not closed
    if (currentTicket.status !== 'closed') {
        messageInput.disabled = false;
        sendButton.disabled = false;
    }
    
    // Send message on button click
    sendButton.addEventListener('click', sendMessage);
    
    // Send message on Enter key
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
    
    // Handle file upload
    fileInput.addEventListener('change', handleFileUpload);
    
    // Setup voice recording
    setupVoiceRecording();
}

function setupVoiceRecording() {
    const voiceBtn = document.createElement('button');
    voiceBtn.className = 'voice-btn';
    voiceBtn.textContent = '🎤';
    voiceBtn.title = 'Record Voice Message';
    
    const chatInput = document.querySelector('.chat-input');
    chatInput.insertBefore(voiceBtn, document.getElementById('sendButton'));
    
    voiceBtn.addEventListener('click', toggleVoiceRecording);
}

async function toggleVoiceRecording() {
    if (!mediaRecorder) {
        // Start recording
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaRecorder = new MediaRecorder(stream);
            audioChunks = [];
            
            mediaRecorder.ondataavailable = (event) => {
                audioChunks.push(event.data);
            };
            
            mediaRecorder.onstop = async () => {
                const audioBlob = new Blob(audioChunks, { type: 'audio/wav' });
                await sendVoiceMessage(audioBlob);
                
                // Stop all tracks
                stream.getTracks().forEach(track => track.stop());
            };
            
            mediaRecorder.start();
            document.querySelector('.voice-btn').classList.add('recording');
            document.querySelector('.voice-btn').textContent = '⏹️';
            
        } catch (error) {
            console.error('Error accessing microphone:', error);
            alert('Could not access microphone. Please check permissions.');
        }
    } else {
        // Stop recording
        mediaRecorder.stop();
        mediaRecorder = null;
        document.querySelector('.voice-btn').classList.remove('recording');
        document.querySelector('.voice-btn').textContent = '🎤';
    }
}

async function sendVoiceMessage(audioBlob) {
    const formData = new FormData();
    formData.append('audio', audioBlob, 'voice-message.wav');
    formData.append('sender', isAdmin ? currentTicket.claimedBy : currentTicket.username);
    formData.append('type', 'voice');
    
    try {
        // Convert blob to data URL for immediate playback
        const reader = new FileReader();
        reader.onload = async () => {
            const response = await fetch(`/api/tickets/${currentTicket.id}/message`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error('Failed to send voice message');
            }
        };
        reader.readAsDataURL(audioBlob);
        
    } catch (error) {
        console.error('Error sending voice message:', error);
        alert('Error sending voice message');
    }
}

async function sendMessage() {
    const messageInput = document.getElementById('messageInput');
    const message = messageInput.value.trim();
    
    if (!message) return;
    
    // Check for close command (admin only)
    if (isAdmin && message.startsWith('close - ')) {
        const reason = message.substring(8);
        closeTicket(reason);
    }
    
    try {
        const response = await fetch(`/api/tickets/${currentTicket.id}/message`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: message,
                sender: isAdmin ? currentTicket.claimedBy : currentTicket.username,
                type: 'text'
            })
        });
        
        if (response.ok) {
            messageInput.value = '';
        } else {
            throw new Error('Failed to send message');
        }
    } catch (error) {
        console.error('Error sending message:', error);
        alert('Error sending message');
    }
}

async function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('sender', isAdmin ? currentTicket.claimedBy : currentTicket.username);
    formData.append('type', 'file');
    formData.append('message', `File: ${file.name}`);
    
    try {
        const response = await fetch(`/api/tickets/${currentTicket.id}/message`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error('Failed to upload file');
        }
        
        event.target.value = ''; // Clear file input
        
    } catch (error) {
        console.error('Error uploading file:', error);
        alert('Error uploading file');
    }
}

function joinTicketRoom() {
    socket.emit('joinTicket', currentTicket.id);
}

function scrollToBottom() {
    const chatMessages = document.getElementById('chatMessages');
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function playNotificationSound() {
    // Create a simple notification sound
    const context = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = context.createOscillator();
    const gainNode = context.createGain();
    
    oscillator.connect(gainNode);
    gainNode.connect(context.destination);
    
    oscillator.frequency.value = 800;
    gainNode.gain.value = 0.1;
    
    oscillator.start();
    gainNode.gain.exponentialRampToValueAtTime(0.001, context.currentTime + 0.2);
    oscillator.stop(context.currentTime + 0.2);
}

async function closeTicket(reason) {
    if (!isAdmin) return;
    
    try {
        const response = await fetch(`/api/tickets/${currentTicket.id}/close`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                reason: reason,
                adminName: currentTicket.claimedBy
            })
        });
        
        if (!response.ok) {
            throw new Error('Failed to close ticket');
        }
        
    } catch (error) {
        console.error('Error closing ticket:', error);
        alert('Error closing ticket');
    }
}

function startCountdown(reason, adminName) {
    const overlay = document.getElementById('countdownOverlay');
    const countdownNumber = document.getElementById('countdownNumber');
    const closeReason = document.getElementById('closeReason');
    
    closeReason.textContent = `Reason: ${reason} (by ${adminName})`;
    overlay.style.display = 'block';
    
    let countdown = 5;
    countdownNumber.textContent = countdown;
    
    const countdownInterval = setInterval(() => {
        countdown--;
        countdownNumber.textContent = countdown;
        
        if (countdown <= 0) {
            clearInterval(countdownInterval);
            showTicketClosed();
        }
    }, 1000);
}

function showTicketClosed() {
    document.body.innerHTML = `
        <div class="container">
            <div class="card" style="text-align: center; padding: 60px;">
                <h1 style="color: #dc3545; margin-bottom: 20px;">Ticket Closed</h1>
                <p style="font-size: 1.2em; margin-bottom: 30px;">This support ticket has been closed.</p>
                <a href="Tickets.html" class="btn">Return to Main Page</a>
            </div>
        </div>
    `;
}

// Socket event listeners
socket.on('newMessage', (message) => {
    displayMessage(message);
});

socket.on('ticketClosed', (data) => {
    addSystemMessage(`Ticket is being closed: ${data.reason}`);
    document.getElementById('messageInput').disabled = true;
    document.getElementById('sendButton').disabled = true;
    startCountdown(data.reason, data.adminName);
});

// Initialize when page loads
document.addEventListener('DOMContentLoaded', loadTicket);