document.getElementById('ticketForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = {
        username: document.getElementById('username').value,
        email: document.getElementById('email').value,
        number: document.getElementById('number').value,
        type: document.getElementById('type').value,
        subject: document.getElementById('subject').value
    };
    
    try {
        const response = await fetch('/api/tickets', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            window.location.href = `ticket-${result.ticketId}.html`;
        } else {
            alert('Error creating ticket: ' + result.error);
        }
    } catch (error) {
        alert('Error creating ticket: ' + error.message);
    }
});