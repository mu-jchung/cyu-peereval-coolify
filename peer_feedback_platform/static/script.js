// Main JavaScript file for Peer Feedback Platform

// Close modals when clicking outside
window.onclick = function(event) {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
};

// Form validation
document.addEventListener('DOMContentLoaded', function() {
    // Validate email domains for student signup
    const emailInputs = document.querySelectorAll('input[type="email"][pattern]');
    emailInputs.forEach(input => {
        input.addEventListener('invalid', function(e) {
            if (this.validity.patternMismatch) {
                this.setCustomValidity('Please use a @monmouth.edu email address');
            } else {
                this.setCustomValidity('');
            }
        });
        
        input.addEventListener('input', function() {
            this.setCustomValidity('');
        });
    });
    
    // Confirm before releasing results
    const releaseButtons = document.querySelectorAll('button[type="submit"]');
    releaseButtons.forEach(button => {
        if (button.textContent.includes('Release Results')) {
            button.addEventListener('click', function(e) {
                if (!confirm('Are you sure you want to release results to students? This action cannot be undone.')) {
                    e.preventDefault();
                }
            });
        }
    });
});

// Feedback form validation
function validateFeedbackForm() {
    const form = document.getElementById('feedbackForm');
    if (!form) return true;
    
    const textareas = form.querySelectorAll('textarea');
    let hasContent = false;
    
    textareas.forEach(textarea => {
        if (textarea.value.trim().length > 0) {
            hasContent = true;
        }
    });
    
    if (!hasContent) {
        alert('Please provide at least one feedback comment before submitting.');
        return false;
    }
    
    return true;
}

// Attach validation to feedback form
document.addEventListener('DOMContentLoaded', function() {
    const feedbackForm = document.getElementById('feedbackForm');
    if (feedbackForm) {
        feedbackForm.addEventListener('submit', function(e) {
            if (!validateFeedbackForm()) {
                e.preventDefault();
            }
        });
    }
});

// Auto-save for teacher notes
let autoSaveTimers = {};

function setupAutoSave() {
    const noteForms = document.querySelectorAll('.note-form textarea');
    
    noteForms.forEach(textarea => {
        textarea.addEventListener('input', function() {
            const studentId = this.id.replace('note_', '');
            
            // Clear existing timer
            if (autoSaveTimers[studentId]) {
                clearTimeout(autoSaveTimers[studentId]);
            }
            
            // Set new timer for auto-save after 2 seconds of no typing
            autoSaveTimers[studentId] = setTimeout(() => {
                const form = this.closest('.note-form');
                const statusEl = document.getElementById(`status_${studentId}`);
                
                if (statusEl) {
                    statusEl.textContent = 'Saving...';
                    statusEl.className = 'save-status';
                }
            }, 2000);
        });
    });
}

// Call setup functions when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    setupAutoSave();
});

// Utility function to format dates
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

// Show loading spinner
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = '<div class="loading">Loading...</div>';
    }
}

// Hide loading spinner
function hideLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        const loading = element.querySelector('.loading');
        if (loading) {
            loading.remove();
        }
    }
}