let currentTicketId = null;
const socket = io();

async function loadTickets() {
    try {
        const response = await fetch('/api/tickets');
        const tickets = await response.json();
        
        const ticketsList = document.getElementById('ticketsList');
        
        if (tickets.length === 0) {
            ticketsList.innerHTML = '<div style="text-align: center; padding: 40px;"><p>No tickets found.</p></div>';
            return;
        }
        
        ticketsList.innerHTML = tickets.map(ticket => `
            <div class="ticket-card">
                <div class="ticket-header">
                    <span class="ticket-id">Ticket #${ticket.id.substring(0, 8)}</span>
                    <span class="ticket-status status-${ticket.status}">${ticket.status.toUpperCase()}</span>
                </div>
                <p><strong>User:</strong> ${ticket.username}</p>
                <p><strong>Type:</strong> ${ticket.type}</p>
                <p><strong>Subject:</strong> ${ticket.subject}</p>
                <p><strong>Created:</strong> ${new Date(ticket.createdAt).toLocaleString()}</p>
                ${ticket.claimedBy ? `<p><strong>Claimed by:</strong> ${ticket.claimedBy}</p>` : ''}
                <div style="margin-top: 15px;">
                    ${ticket.status === 'open' ? 
                        `<button class="btn" onclick="openClaimModal('${ticket.id}')">Claim Ticket</button>` : 
                        `<a href="ticket-${ticket.id}.html" class="btn">View Ticket</a>`
                    }
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading tickets:', error);
        document.getElementById('ticketsList').innerHTML = '<div style="text-align: center; padding: 40px;"><p>Error loading tickets.</p></div>';
    }
}

function openClaimModal(ticketId) {
    currentTicketId = ticketId;
    document.getElementById('claimModal').style.display = 'block';
    document.getElementById('adminName').focus();
}

function closeClaimModal() {
    currentTicketId = null;
    document.getElementById('claimModal').style.display = 'none';
    document.getElementById('adminName').value = '';
}

async function claimTicket() {
    const adminName = document.getElementById('adminName').value.trim();
    
    if (!adminName) {
        alert('Please enter your admin name');
        return;
    }
    
    try {
        const response = await fetch(`/api/tickets/${currentTicketId}/claim`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ adminName })
        });
        
        const result = await response.json();
        
        if (result.success) {
            window.location.href = `ticket-${currentTicketId}.html`;
        } else {
            alert('Error claiming ticket: ' + result.error);
        }
    } catch (error) {
        alert('Error claiming ticket: ' + error.message);
    }
}

// Event listeners
document.getElementById('confirmClaim').addEventListener('click', claimTicket);
document.getElementById('cancelClaim').addEventListener('click', closeClaimModal);
document.getElementById('adminName').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        claimTicket();
    }
});

// Close modal when clicking outside
document.getElementById('claimModal').addEventListener('click', (e) => {
    if (e.target.id === 'claimModal') {
        closeClaimModal();
    }
});

// Load tickets when page loads
loadTickets();

// Refresh tickets every 30 seconds
setInterval(loadTickets, 30000);