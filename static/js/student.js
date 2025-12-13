// static/js/student.js

let myTeamId = null;
let assignments = [];
let teams = [];

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadAssignments();
    loadTeams();
    startSessionTimer();
});

// Session Timer - Update assignment timers every second
function startSessionTimer() {
    updateAssignmentTimers();
    setInterval(updateAssignmentTimers, 1000);
}

function updateAssignmentTimers() {
    assignments.forEach(assignment => {
        const status = getAssignmentStatus(assignment.start_time, assignment.end_time);
        
        // Update timer display for active assignments
        if (status === 'active') {
            const now = new Date();
            const end = new Date(assignment.end_time);
            const remaining = end - now;
            
            if (remaining > 0) {
                const hours = Math.floor(remaining / (1000 * 60 * 60));
                const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((remaining % (1000 * 60)) / 1000);
                
                // Find and update the timer element for this assignment
                const timerElements = document.querySelectorAll('.assignment-timer');
                timerElements.forEach(el => {
                    if (el.textContent.includes('remaining')) {
                        el.textContent = `${hours}h ${minutes}m ${seconds}s remaining`;
                    }
                });
            }
        }
    });
}

// Load Assignments
async function loadAssignments() {
    try {
        const result = await apiCall('/api/student/assignments');
        assignments = result.assignments;
        renderAssignments();
    } catch (error) {
        console.error('Failed to load assignments:', error);
    }
}

function renderAssignments() {
    const assignmentsList = document.getElementById('assignmentsList');
    
    if (assignments.length === 0) {
        assignmentsList.innerHTML = '<p>No assignments for this class at this time.</p>';
        return;
    }
    
    assignmentsList.innerHTML = assignments.map(assignment => {
        const status = getAssignmentStatus(assignment.start_time, assignment.end_time);
        const statusClass = `status-${status}`;
        const canEvaluate = status === 'active';
        
        // Calculate remaining or time until start
        let timerInfo = '';
        if (status === 'active') {
            const now = new Date();
            const end = new Date(assignment.end_time);
            const remaining = end - now;
            
            if (remaining > 0) {
                const hours = Math.floor(remaining / (1000 * 60 * 60));
                const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((remaining % (1000 * 60)) / 1000);
                timerInfo = `<div class="assignment-timer">${hours}h ${minutes}m ${seconds}s remaining</div>`;
            }
        } else if (status === 'upcoming') {
            const now = new Date();
            const start = new Date(assignment.start_time);
            const remaining = start - now;
            const hours = Math.floor(remaining / (1000 * 60 * 60));
            const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
            timerInfo = `<div class="assignment-timer">⏳ Starts in ${hours}h ${minutes}m</div>`;
        }
        
        return `
            <div class="assignment-card">
                <h4>${assignment.name}</h4>
                <span class="assignment-status ${statusClass}">${status.toUpperCase()}</span>
                ${timerInfo}
                <div class="assignment-info">
                    <div><strong>Start:</strong> ${formatDate(assignment.start_time)}</div>
                    <div><strong>End:</strong> ${formatDate(assignment.end_time)}</div>
                </div>
                ${canEvaluate ? `
                    <div class="assignment-actions">
                        <button class="btn btn-primary btn-small" onclick="startEvaluation(${assignment.id})">Submit Evaluation</button>
                    </div>
                ` : `
                    <div class="assignment-note">
                        ${status === 'upcoming' ? '⏳ This assignment has not started yet.' : '✓ This assignment has ended.'}
                    </div>
                `}
            </div>
        `;
    }).join('');
    
    // Update timers periodically for active assignments
    updateAssignmentTimers();
}

// Load Teams
async function loadTeams() {
    try {
        const result = await apiCall('/api/student/teams');
        console.log('Loaded teams:', result);
        teams = result.teams;
        myTeamId = result.my_team_id;
        console.log('Teams array:', teams);
        console.log('My team ID:', myTeamId);
        renderTeams();
    } catch (error) {
        console.error('Failed to load teams:', error);
    }
}

function renderTeams() {
    const teamsList = document.getElementById('teamsList');
    console.log('Rendering teams. Count:', teams.length);
    console.log('Current user name:', window.currentUserName);
    
    if (teams.length === 0) {
        teamsList.innerHTML = '<p>No teams in this class yet.</p>';
        return;
    }
    
    teamsList.innerHTML = teams.map(team => `
        <div class="team-card ${team.id === myTeamId ? 'active' : ''}">
            <h4>${team.name}</h4>
            <div class="team-members">
                ${team.students && team.students.length > 0 ? 
                    team.students.map(s => {
                        const isCurrentUser = s.name === window.currentUserName;
                        return `<p class="member-item ${isCurrentUser ? 'current-user' : ''}">• ${s.name}${isCurrentUser ? ' (You)' : ''}</p>`;
                    }).join('') :
                    '<p>No members yet</p>'
                }
            </div>
        </div>
    `).join('');
    console.log('Teams rendered successfully');
}

// Evaluation
async function startEvaluation(assignmentId) {
    const assignment = assignments.find(a => a.id === assignmentId);
    if (!assignment) return;
    
    // Get teams excluding: 1) my own team, 2) Guest teams
    const evaluableTeams = teams.filter(t => {
        // Exclude own team
        if (t.id === myTeamId) return false;
        
        // Exclude "Guest" teams (teams with name 'Guests')
        if (t.name === 'Guests') return false;
        
        // Must have members
        return t.students && t.students.length > 0;
    });
    
    if (evaluableTeams.length === 0) {
        showToast('No other teams available to evaluate', 'error');
        return;
    }
    
    renderEvaluationForm(assignment, evaluableTeams);
    openModal('evaluationModal');
}

function renderEvaluationForm(assignment, evaluableTeams) {
    const formContainer = document.getElementById('evaluationForm');
    
    formContainer.innerHTML = `
        <form id="submitEvaluationForm">
            <h3>Select Team to Evaluate</h3>
            <div class="form-group">
                <select id="teamToEvaluate" required onchange="updateMembersList()">
                    <option value="">-- Select a Team --</option>
                    ${evaluableTeams.map(t => `<option value="${t.id}">${t.name}</option>`).join('')}
                </select>
            </div>
            
            <div id="evaluationContent" style="display: none;">
                <div class="evaluation-section">
                    <h3>Overall Team Feedback</h3>
                    <div class="form-group">
                        <label>Team Score (out of 10)</label>
                        <input type="number" id="teamScore" min="0" max="10" required>
                    </div>
                    <div class="form-group">
                        <label>Team Comment</label>
                        <textarea id="teamComment" rows="4" placeholder="Provide overall feedback for the team..."></textarea>
                    </div>
                </div>
                
                <div class="evaluation-section">
                    <h3>Individual Member Feedback</h3>
                    <div id="memberEvaluations">
                        <!-- Member evaluations will be populated here -->
                    </div>
                </div>
                
                <button type="submit" class="btn btn-primary btn-block">Submit Evaluation</button>
            </div>
        </form>
    `;
    
    // Store evaluable teams for later use
    window.evaluableTeams = evaluableTeams;
    window.currentAssignmentId = assignment.id;
    
    // Setup form submission
    document.getElementById('submitEvaluationForm').addEventListener('submit', submitEvaluation);
}

async function updateMembersList() {
    const teamId = parseInt(document.getElementById('teamToEvaluate').value);
    const evaluationContent = document.getElementById('evaluationContent');
    
    if (!teamId) {
        evaluationContent.style.display = 'none';
        return;
    }
    
    const team = window.evaluableTeams.find(t => t.id === teamId);
    if (!team || !team.students || team.students.length === 0) {
        evaluationContent.style.display = 'none';
        return;
    }
    
    // Check if already evaluated
    try {
        const result = await apiCall(`/api/evaluations/check/${window.currentAssignmentId}/${teamId}`);
        const warningDiv = document.getElementById('evaluationWarning');
        
        if (result.exists) {
            if (!warningDiv) {
                const div = document.createElement('div');
                div.id = 'evaluationWarning';
                div.className = 'alert alert-warning';
                div.style.marginBottom = '20px';
                div.style.padding = '10px';
                div.style.backgroundColor = '#fff3cd';
                div.style.border = '1px solid #ffeeba';
                div.style.color = '#856404';
                div.style.borderRadius = '4px';
                div.innerHTML = '<strong>Note:</strong> You have already evaluated this team. Submitting a new evaluation will replace your previous one.';
                evaluationContent.insertBefore(div, evaluationContent.firstChild);
            } else {
                warningDiv.style.display = 'block';
            }
        } else {
            if (warningDiv) warningDiv.style.display = 'none';
        }
    } catch (error) {
        console.error('Failed to check evaluation status:', error);
    }
    
    evaluationContent.style.display = 'block';
    
    const memberEvaluations = document.getElementById('memberEvaluations');
    memberEvaluations.innerHTML = team.students.map(student => {
        const isCurrentUser = student.name === window.currentUserName;
        return `
        <div class="member-evaluation ${isCurrentUser ? 'current-user' : ''}">
            <h4>${student.name}${isCurrentUser ? ' (You)' : ''}</h4>
            <div class="form-group">
                <label>Score (out of 10)</label>
                <input type="number" class="member-score" data-student-id="${student.id}" min="0" max="10" required>
            </div>
            <div class="form-group">
                <label>Comment</label>
                <textarea class="member-comment" data-student-id="${student.id}" rows="3" placeholder="Provide individual feedback..."></textarea>
            </div>
        </div>
    `;
    }).join('');
}

async function submitEvaluation(e) {
    e.preventDefault();
    
    // Check for existing evaluation warning
    const warningDiv = document.getElementById('evaluationWarning');
    if (warningDiv && warningDiv.style.display !== 'none') {
        if (!confirm('You have already evaluated this team. Submitting this new evaluation will replace your previous one. Do you want to continue?')) {
            return;
        }
    }
    
    const teamId = parseInt(document.getElementById('teamToEvaluate').value);
    const teamScore = parseInt(document.getElementById('teamScore').value);
    const teamComment = document.getElementById('teamComment').value;
    
    // Collect member evaluations
    const memberEvaluations = [];
    const scoreInputs = document.querySelectorAll('.member-score');
    const commentInputs = document.querySelectorAll('.member-comment');
    
    scoreInputs.forEach((scoreInput, index) => {
        const studentId = parseInt(scoreInput.dataset.studentId);
        const score = parseInt(scoreInput.value);
        const comment = commentInputs[index].value;
        
        memberEvaluations.push({
            student_id: studentId,
            score: score,
            comment: comment
        });
    });
    
    const evaluationData = {
        assignment_id: window.currentAssignmentId,
        evaluated_team_id: teamId,
        team_score: teamScore,
        team_comment: teamComment,
        member_evaluations: memberEvaluations
    };
    
    try {
        await apiCall('/api/evaluations', 'POST', evaluationData);
        showToast('Evaluation submitted successfully', 'success');
        closeModal('evaluationModal');
        loadAssignments(); // Refresh to show updated status
    } catch (error) {
        console.error('Failed to submit evaluation:', error);
    }
}

// Store session start time
if (!sessionStorage.getItem('session_start')) {
    sessionStorage.setItem('session_start', Date.now());
}