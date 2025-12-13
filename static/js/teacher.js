// static/js/teacher.js

let currentClassId = null;
let classes = [];
let teams = [];
let assignments = [];
let students = [];

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadClasses();
    setupTabs();
});

// Tab Management
function setupTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.dataset.tab;
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}Tab`).classList.add('active');
    
    // Load data for the tab
    if (currentClassId) {
        switch(tabName) {
            case 'teams':
                loadTeams();
                break;
            case 'assignments':
                loadAssignments();
                break;
            case 'evaluations':
                loadAssignmentsForEval();
                break;
            case 'reports':
                loadAssignmentsForReport();
                break;
        }
    }
}

// Class Management
async function loadClasses() {
    try {
        const result = await apiCall('/api/classes');
        classes = result.classes;
        renderClasses();
    } catch (error) {
        console.error('Failed to load classes:', error);
    }
}

function renderClasses() {
    const classList = document.getElementById('classList');
    
    if (classes.length === 0) {
        classList.innerHTML = '<p>No classes yet. Create your first class!</p>';
        return;
    }
    
    classList.innerHTML = classes.map(cls => `
        <div class="class-card ${cls.id === currentClassId ? 'active' : ''}" onclick="selectClass(${cls.id})">
            <h3>${cls.name}</h3>
            <p>Created: ${formatDate(cls.created_at)}</p>
        </div>
    `).join('');
}

function selectClass(classId) {
    currentClassId = classId;
    renderClasses();
    document.getElementById('classDetails').style.display = 'block';
    loadTeams();
}

function showAddClassModal() {
    document.getElementById('addClassForm').reset();
    openModal('addClassModal');
}

document.getElementById('addClassForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const className = document.getElementById('className').value;
    
    try {
        await apiCall('/api/classes', 'POST', { class_name: className });
        showToast('Class created successfully', 'success');
        closeModal('addClassModal');
        loadClasses();
    } catch (error) {
        console.error('Failed to create class:', error);
    }
});

// Team Management
async function loadTeams() {
    if (!currentClassId) return;
    
    try {
        const result = await apiCall(`/api/classes/${currentClassId}/teams`);
        teams = result.teams;
        renderTeams();
    } catch (error) {
        console.error('Failed to load teams:', error);
    }
}

function renderTeams() {
    const teamsList = document.getElementById('teamsList');
    
    if (teams.length === 0) {
        teamsList.innerHTML = '<p>No teams yet.</p>';
        return;
    }
    
    teamsList.innerHTML = teams.map(team => {
        const isGuestsTeam = team.name === 'Guests';
        return `
        <div class="team-card" data-team-id="${team.id}">
            <button class="team-delete-btn" onclick="deleteTeam(${team.id}, '${team.name.replace(/'/g, "\\'")}')" title="Delete Team">
                ×
            </button>
            <h4>${team.name}</h4>
            <div class="team-members">
                <div id="team-${team.id}-members">Loading...</div>
            </div>
            <div style="margin-top: 10px; display: flex; gap: 10px;">
                <button class="btn btn-secondary" onclick="showAddStudentsModal(${team.id})">Add Members</button>
                ${!isGuestsTeam ? `<button class="btn btn-primary" onclick="openEvaluationModal(${team.id})">Evaluate</button>` : ''}
            </div>
        </div>
    `}).join('');
    
    // Load members for each team
    teams.forEach(team => loadTeamMembers(team.id));
}

async function loadTeamMembers(teamId) {
    try {
        const result = await apiCall(`/api/classes/${currentClassId}/teams/${teamId}/members`);
        const teamMembers = result.members || [];
        
        const membersList = document.getElementById(`team-${teamId}-members`);
        if (teamMembers.length === 0) {
            membersList.innerHTML = '<p class="member-item">No members yet</p>';
        } else {
            membersList.innerHTML = teamMembers.map(s => 
                `<div class="member-item" style="display: flex; justify-content: space-between; align-items: center; padding: 2px 0;">
                    <span>• ${s.name}</span>
                    <button class="btn-text delete-btn" onclick="deleteMember(${s.id}, ${teamId})" title="Delete Member" style="color: #dc3545; background: none; border: none; cursor: pointer; font-size: 0.9em;">
                        Delete
                    </button>
                </div>`
            ).join('');
        }
    } catch (error) {
        console.error('Failed to load team members:', error);
        const membersList = document.getElementById(`team-${teamId}-members`);
        if (membersList) {
            membersList.innerHTML = '<p class="member-item">Error loading members</p>';
        }
    }
}

async function deleteMember(studentId, teamId) {
    if (!confirm('Are you sure you want to delete this member?')) {
        return;
    }

    try {
        const result = await apiCall(`/api/classes/${currentClassId}/students/${studentId}`, 'DELETE');
        showToast('Member deleted successfully', 'success');
        loadTeamMembers(teamId); // Reload members
    } catch (error) {
        console.error('Failed to delete member:', error);
        showToast(error.message || 'Failed to delete member', 'error');
    }
}

async function deleteTeam(teamId, teamName) {
    if (!confirm(`Are you sure you want to delete the team "${teamName}"? This will also delete all members in this team.`)) {
        return;
    }

    try {
        await apiCall(`/api/classes/${currentClassId}/teams/${teamId}`, 'DELETE');
        showToast('Team deleted successfully', 'success');
        loadTeams(); // Reload teams list
    } catch (error) {
        console.error('Failed to delete team:', error);
        showToast(error.message || 'Failed to delete team', 'error');
    }
}

function showAddTeamModal() {
    if (!currentClassId) {
        showToast('Please select a class first', 'error');
        return;
    }
    document.getElementById('addTeamForm').reset();
    openModal('addTeamModal');
}

document.getElementById('addTeamForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const teamName = document.getElementById('teamName').value;
    
    try {
        await apiCall(`/api/classes/${currentClassId}/teams`, 'POST', { team_name: teamName });
        showToast('Team created successfully', 'success');
        closeModal('addTeamModal');
        loadTeams();
    } catch (error) {
        console.error('Failed to create team:', error);
    }
});

// Add Students to Team
let currentTeamIdForStudents = null;

function showAddStudentsModal(teamId) {
    currentTeamIdForStudents = teamId;
    document.getElementById('addStudentsForm').reset();
    document.getElementById('studentsTextInput').value = '';
    
    // Find the team in the loaded teams to check its name
    let teamName = '';
    const teamCards = document.querySelectorAll('.team-card');
    teamCards.forEach(card => {
        if (card.getAttribute('data-team-id') == teamId) {
            teamName = card.querySelector('h4').textContent.trim();
        }
    });
    
    const isGuestTeam = teamName === 'Guests';
    
    // Update modal title, label, and button based on team type
    document.getElementById('addMembersModalTitle').textContent = isGuestTeam ? 'Add Guests' : 'Add Students';
    document.getElementById('addMembersLabel').textContent = isGuestTeam ? 'Guest Names' : 'Student Information';
    document.getElementById('addMembersSubmitBtn').textContent = isGuestTeam ? 'Add Guests' : 'Add Students';
    
    // Show/hide instructions based on team type
    document.getElementById('regularTeamInstructions').style.display = isGuestTeam ? 'none' : 'block';
    document.getElementById('guestTeamInstructions').style.display = isGuestTeam ? 'block' : 'none';
    
    // Update placeholder and font based on team type
    const textarea = document.getElementById('studentsTextInput');
    if (isGuestTeam) {
        textarea.placeholder = 'John Smith\nJane Doe\nMike Johnson';
        textarea.style.fontFamily = 'inherit';
    } else {
        textarea.placeholder = 'Mike Lee S123456\nSarah Johnson S123457\nJohn Smith S123458';
        textarea.style.fontFamily = 'monospace';
    }
    
    openModal('addStudentsModal');
}

document.getElementById('addStudentsForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const text = document.getElementById('studentsTextInput').value.trim();
    
    if (!text) {
        showToast('Please enter student information', 'error');
        return;
    }
    
    try {
        const result = await apiCall(`/api/teams/${currentTeamIdForStudents}/add-students`, 'POST', { text });
        showToast(`Added ${result.added.length} member(s) successfully`, 'success');
        closeModal('addStudentsModal');
        loadTeamMembers(currentTeamIdForStudents);  // Refresh members
    } catch (error) {
        console.error('Failed to add students:', error);
        showToast('Error adding students', 'error');
    }
});

// Access Link Generation
async function generateAccessLink() {
    if (!currentClassId) {
        showToast('Please select a class first', 'error');
        return;
    }
    
    const hoursInput = document.getElementById('linkExpirationHours');
    const hours = parseFloat(hoursInput.value) || 2;
    
    // Validate hours
    if (hours <= 0 || hours > 24) {
        showToast('Hours must be between 0.1 and 24', 'error');
        return;
    }
    
    try {
        const result = await apiCall(`/api/classes/${currentClassId}/access-link`, 'POST', { hours });
        
        document.getElementById('accessLink').value = result.link;
        document.getElementById('linkExpires').textContent = formatDate(result.expires_at);
        document.getElementById('accessLinkDisplay').style.display = 'block';
        
        const hoursText = hours === 1 ? '1 hour' : `${hours} hours`;
        showToast(`Access link generated (valid for ${hoursText})`, 'success');
    } catch (error) {
        console.error('Failed to generate access link:', error);
        showToast('Error generating access link', 'error');
    }
}

function copyLink() {
    const linkInput = document.getElementById('accessLink');
    linkInput.select();
    document.execCommand('copy');
    showToast('Link copied to clipboard', 'success');
}

// Assignment Management
async function loadAssignments() {
    if (!currentClassId) return;
    
    try {
        const result = await apiCall(`/api/classes/${currentClassId}/assignments`);
        assignments = result.assignments;
        renderAssignments();
    } catch (error) {
        console.error('Failed to load assignments:', error);
    }
}

function renderAssignments() {
    const assignmentsList = document.getElementById('assignmentsList');
    
    if (assignments.length === 0) {
        assignmentsList.innerHTML = '<p>No assignments yet.</p>';
        return;
    }
    
    assignmentsList.innerHTML = assignments.map(assignment => {
        const status = getAssignmentStatus(assignment.start_time, assignment.end_time);
        const statusClass = `status-${status}`;
        
        return `
            <div class="assignment-card">
                <h4>${assignment.name}</h4>
                <span class="assignment-status ${statusClass}">${status.toUpperCase()}</span>
                <div class="assignment-info">
                    <div><strong>Start:</strong> ${formatDate(assignment.start_time)}</div>
                    <div><strong>End:</strong> ${formatDate(assignment.end_time)}</div>
                </div>
                <div class="assignment-actions">
                    <button class="btn btn-secondary btn-small" onclick="editAssignment(${assignment.id})">Edit</button>
                </div>
            </div>
        `;
    }).join('');
}

function showAddAssignmentModal() {
    if (!currentClassId) {
        showToast('Please select a class first', 'error');
        return;
    }
    document.getElementById('addAssignmentForm').reset();
    document.getElementById('assignmentId').value = '';
    document.getElementById('assignmentModalTitle').textContent = 'Create Assignment';
    document.getElementById('deleteAssignmentBtn').style.display = 'none';
    
    // Prefill with current time and 3 hours later
    const now = new Date();
    const later = new Date(now.getTime() + 3 * 60 * 60 * 1000);
    
    document.getElementById('startTime').value = formatDateForInput(now);
    document.getElementById('endTime').value = formatDateForInput(later);
    
    openModal('addAssignmentModal');
}

function editAssignment(assignmentId) {
    const assignment = assignments.find(a => a.id === assignmentId);
    if (!assignment) return;
    
    document.getElementById('assignmentId').value = assignment.id;
    document.getElementById('assignmentName').value = assignment.name;
    document.getElementById('startTime').value = formatDateForInput(assignment.start_time);
    document.getElementById('endTime').value = formatDateForInput(assignment.end_time);
    document.getElementById('assignmentModalTitle').textContent = 'Edit Assignment';
    document.getElementById('deleteAssignmentBtn').style.display = 'block';
    
    openModal('addAssignmentModal');
}

// Delete assignment button handler
document.getElementById('deleteAssignmentBtn')?.addEventListener('click', function() {
    const assignmentId = document.getElementById('assignmentId').value;
    if (assignmentId) {
        deleteAssignment(assignmentId);
        closeModal('addAssignmentModal');
    }
});

async function deleteAssignment(assignmentId) {
    if (!confirm('Are you sure you want to delete this assignment? This action cannot be undone.')) {
        return;
    }
    
    try {
        await apiCall(`/api/assignments/${assignmentId}`, 'DELETE');
        showToast('Assignment deleted successfully', 'success');
        loadAssignments();
    } catch (error) {
        console.error('Failed to delete assignment:', error);
        showToast('Failed to delete assignment', 'error');
    }
}

document.getElementById('addAssignmentForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const assignmentId = document.getElementById('assignmentId').value;
    const startTimeInput = document.getElementById('startTime');
    const endTimeInput = document.getElementById('endTime');
    
    if (!startTimeInput.value || !endTimeInput.value) {
        showToast('Please select both start and end times', 'error');
        return;
    }
    
    // Convert local datetime to ISO string for EST
    const startLocal = new Date(startTimeInput.value);
    const endLocal = new Date(endTimeInput.value);
    
    if (isNaN(startLocal.getTime()) || isNaN(endLocal.getTime())) {
        showToast('Invalid date format', 'error');
        return;
    }
    
    if (endLocal <= startLocal) {
        showToast('End time must be after start time', 'error');
        return;
    }
    
    // Add timezone offset for EST (UTC-5 in winter, UTC-4 in summer)
    const estOffset = new Date().toLocaleString('en-US', {timeZone: 'America/New_York'});
    const localOffset = new Date().toLocaleString('en-US');
    
    const assignmentData = {
        name: document.getElementById('assignmentName').value,
        start_time: startLocal.toISOString(),
        end_time: endLocal.toISOString()
    };
    
    try {
        if (assignmentId) {
            // Update existing assignment
            await apiCall(`/api/assignments/${assignmentId}`, 'PUT', assignmentData);
            showToast('Assignment updated successfully', 'success');
        } else {
            // Create new assignment
            await apiCall(`/api/classes/${currentClassId}/assignments`, 'POST', assignmentData);
            showToast('Assignment created successfully', 'success');
        }
        
        closeModal('addAssignmentModal');
        loadAssignments();
    } catch (error) {
        console.error('Failed to save assignment:', error);
    }
});

// Add validation for assignment dates
document.getElementById('startTime')?.addEventListener('change', function() {
    const startTime = this.value;
    // document.getElementById('endTime').min = startTime; // Removed browser validation
});

document.getElementById('endTime')?.addEventListener('change', function() {
    const startTime = document.getElementById('startTime').value;
    const endTime = this.value;
    
    // Removed browser validation setCustomValidity
});

// Evaluations
async function loadAssignmentsForEval() {
    if (!currentClassId) return;
    
    try {
        const result = await apiCall(`/api/classes/${currentClassId}/assignments`);
        const select = document.getElementById('evalAssignmentSelect');
        select.innerHTML = '<option value="">-- Select Assignment --</option>' +
            result.assignments.map(a => `<option value="${a.id}">${a.name}</option>`).join('');
    } catch (error) {
        console.error('Failed to load assignments:', error);
    }
}

async function loadEvaluations() {
    const assignmentId = document.getElementById('evalAssignmentSelect').value;
    if (!assignmentId) {
        document.getElementById('evaluationsList').innerHTML = '';
        return;
    }
    
    try {
        const result = await apiCall(`/api/teacher/evaluations/${assignmentId}`);
        renderEvaluations(result.evaluations);
    } catch (error) {
        console.error('Failed to load evaluations:', error);
    }
}

function renderEvaluations(evaluations) {
    const evalList = document.getElementById('evaluationsList');
    
    if (evaluations.length === 0) {
        evalList.innerHTML = '<p>No evaluations submitted yet.</p>';
        return;
    }

    // Group by team name
    const groupedEvaluations = {};
    evaluations.forEach(evaluation => {
        const teamName = evaluation.evaluated_team.name;
        if (!groupedEvaluations[teamName]) {
            groupedEvaluations[teamName] = [];
        }
        groupedEvaluations[teamName].push(evaluation);
    });

    // Sort team names
    const sortedTeamNames = Object.keys(groupedEvaluations).sort();
    
    evalList.innerHTML = sortedTeamNames.map(teamName => {
        const teamEvaluations = groupedEvaluations[teamName];

        // Calculate stats
        const count = teamEvaluations.length;
        const totalScore = teamEvaluations.reduce((sum, evaluation) => sum + (evaluation.team_score || 0), 0);
        const avgScore = count > 0 ? (totalScore / count).toFixed(1) : '0.0';

        // Sort evaluations: Teachers first, then Guests, then others
        teamEvaluations.sort((a, b) => {
            const aIsTeacher = a.evaluator.team && a.evaluator.team.name === 'Teachers';
            const bIsTeacher = b.evaluator.team && b.evaluator.team.name === 'Teachers';
            const aIsGuest = a.evaluator.team && a.evaluator.team.name === 'Guests';
            const bIsGuest = b.evaluator.team && b.evaluator.team.name === 'Guests';
            
            if (aIsTeacher && !bIsTeacher) return -1;
            if (!aIsTeacher && bIsTeacher) return 1;
            
            if (aIsGuest && !bIsGuest) return -1;
            if (!aIsGuest && bIsGuest) return 1;
            
            return 0;
        });

        return `
            <div class="team-evaluation-group" style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <div class="team-group-header" style="border-bottom: 2px solid #dee2e6; padding-bottom: 15px; margin-bottom: 15px; display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; color: #2c3e50;">Team: ${teamName}</h3>
                    <div style="color: #495057; background-color: #e9ecef; padding: 5px 15px; border-radius: 20px; font-size: 0.9em;">
                        <span style="margin-right: 15px;"><strong>${count}</strong> Evaluation${count !== 1 ? 's' : ''}</span>
                        <span>Avg Score: <strong>${avgScore}</strong>/10</span>
                    </div>
                </div>
                <div style="display: flex; flex-direction: column; gap: 15px;">
                ${teamEvaluations.map(evaluation => {
                    const isGuest = evaluation.evaluator.team && evaluation.evaluator.team.name === 'Guests';
                    const isTeacher = evaluation.evaluator.team && evaluation.evaluator.team.name === 'Teachers';
                    
                    let borderColor = '#3498db'; // Default Blue
                    if (isGuest) borderColor = '#ffc107'; // Guest Yellow
                    if (isTeacher) borderColor = '#e74c3c'; // Teacher Red
                    
                    return `
                    <div class="evaluation-card" style="margin: 0; border-left: 5px solid ${borderColor};">
                        <div class="evaluation-header">
                            <div>
                                <h4 style="display: flex; align-items: center;">
                                    Evaluated by: ${evaluation.evaluator.name}
                                    ${isGuest ? '<span style="background-color: #ffc107; color: #000; font-size: 0.7em; padding: 2px 6px; border-radius: 4px; margin-left: 8px; text-transform: uppercase; font-weight: bold;">Guest</span>' : ''}
                                    ${isTeacher ? '<span style="background-color: #e74c3c; color: #fff; font-size: 0.7em; padding: 2px 6px; border-radius: 4px; margin-left: 8px; text-transform: uppercase; font-weight: bold;">Teacher</span>' : ''}
                                </h4>
                                <p class="evaluation-meta">Submitted: ${formatDate(evaluation.created_at)}</p>
                            </div>
                            <div class="evaluation-score">Score: ${evaluation.team_score}/10</div>
                        </div>
                        <div class="evaluation-comment">
                            <strong>Team Comment:</strong>
                            <p>${evaluation.team_comment || 'No comment provided'}</p>
                        </div>
                        ${evaluation.member_evaluations && evaluation.member_evaluations.length > 0 ? `
                            <div style="margin-top: 1rem;">
                                <strong>Individual Evaluations:</strong>
                                ${evaluation.member_evaluations.map(me => `
                                    <div class="evaluation-comment" style="margin-top: 0.5rem;">
                                        <strong>${me.evaluated_student.name}:</strong> ${me.score}/10
                                        <p>${me.comment || 'No comment'}</p>
                                    </div>
                                `).join('')}
                            </div>
                        ` : ''}
                    </div>
                `}).join('')}
                </div>
            </div>
        `;
    }).join('');
}

// Reports
async function loadAssignmentsForReport() {
    if (!currentClassId) return;
    
    try {
        const result = await apiCall(`/api/classes/${currentClassId}/assignments`);
        const select = document.getElementById('reportAssignmentSelect');
        select.innerHTML = '<option value="">-- Select Assignment --</option>' +
            result.assignments.map(a => `<option value="${a.id}">${a.name}</option>`).join('');
    } catch (error) {
        console.error('Failed to load assignments:', error);
    }
}

async function loadStudentsForReport() {
    const assignmentId = document.getElementById('reportAssignmentSelect').value;
    if (!assignmentId) {
        document.getElementById('reportStudentSelect').innerHTML = '<option value="">-- Select Student --</option>';
        return;
    }
    
    try {
        const result = await apiCall(`/api/classes/${currentClassId}/students`);
        const allStudents = result.students || [];
        
        const select = document.getElementById('reportStudentSelect');
        select.innerHTML = '<option value="">-- Select Student --</option>' +
            allStudents.map(s => `<option value="${s.id}">${s.name}</option>`).join('');
    } catch (error) {
        console.error('Failed to load students:', error);
    }
}

async function generateStudentReport() {
    const studentId = document.getElementById('reportStudentSelect').value;
    const assignmentId = document.getElementById('reportAssignmentSelect').value;
    const errorDiv = document.getElementById('reportError');
    
    if (!studentId || !assignmentId) {
        errorDiv.style.display = 'block';
        errorDiv.textContent = 'Please select both assignment and student';
        showToast('Please select both assignment and student', 'error');
        return;
    }
    
    errorDiv.style.display = 'none';
    
    try {
        const result = await apiCall(`/api/teacher/report/${studentId}/${assignmentId}`);
        
        if (!result.report) {
            throw new Error('No report data received');
        }
        
        renderReport(result.report);
        showToast('Report generated successfully', 'success');
    } catch (error) {
        console.error('Failed to generate report:', error);
        errorDiv.style.display = 'block';
        errorDiv.textContent = `Error: ${error.message || 'Failed to generate report'}`;
        showToast(`Error: ${error.message}`, 'error');
    }
}

function renderReport(report) {
    const reportDisplay = document.getElementById('reportDisplay');
    
    // Safely access nested data
    const student = report.student || {};
    const assignment = report.assignment || {};
    const teamEvals = report.team_evaluations || [];
    const memberEvals = report.member_evaluations || [];
    
    const teamName = (student.team && typeof student.team === 'object') ? student.team.name : 'Unknown Team';
    const className = (student.class && typeof student.class === 'object') ? student.class.name : 'Unknown Class';
    
    reportDisplay.innerHTML = `
        <div class="report-container">
            <div class="report-header">
                <h2>Peer Evaluation Report</h2>
                <p><strong>Student:</strong> ${student.name || 'Unknown'}</p>
                <p><strong>Class:</strong> ${className}</p>
                <p><strong>Team:</strong> ${teamName}</p>
                <p><strong>Assignment:</strong> ${assignment.name || 'Unknown'}</p>
                <p><strong>Evaluation Period:</strong> ${formatDate(assignment.start_time)} - ${formatDate(assignment.end_time)}</p>
            </div>
            
            <div class="report-section">
                <h3>Team Evaluations Received</h3>
                ${teamEvals.length === 0 ? '<p>No team evaluations received.</p>' : 
                    teamEvals.map(teamEval => {
                        const evaluator = teamEval.evaluator || {};
                        return `
                            <div class="evaluation-card">
                                <p><strong>From:</strong> ${typeof evaluator === 'object' ? evaluator.name : evaluator}</p>
                                <p><strong>Score:</strong> ${teamEval.team_score}/10</p>
                                <p><strong>Comment:</strong> ${teamEval.team_comment || 'No comment'}</p>
                            </div>
                        `;
                    }).join('')
                }
            </div>
            
            <div class="report-section">
                <h3>Individual Evaluations Received</h3>
                ${memberEvals.length === 0 ? '<p>No individual evaluations received.</p>' :
                    memberEvals.map(memberEval => {
                        const teamEval = memberEval.team_evaluation || {};
                        const evaluator = teamEval.evaluator || {};
                        return `
                            <div class="evaluation-card">
                                <p><strong>From:</strong> ${typeof evaluator === 'object' ? evaluator.name : evaluator}</p>
                                <p><strong>Score:</strong> ${memberEval.score}/10</p>
                                <p><strong>Comment:</strong> ${memberEval.comment || 'No comment'}</p>
                            </div>
                        `;
                    }).join('')
                }
            </div>
            
            <div class="report-summary" style="margin-top: 20px; padding: 15px; background-color: #ecf0f1; border-radius: 4px;">
                <h3>Summary</h3>
                <p><strong>Total Team Evaluations:</strong> ${teamEvals.length}</p>
                <p><strong>Total Individual Evaluations:</strong> ${memberEvals.length}</p>
                ${teamEvals.length > 0 ? `
                    <p><strong>Average Team Score:</strong> ${(teamEvals.reduce((sum, e) => sum + (e.team_score || 0), 0) / teamEvals.length).toFixed(1)}/10</p>
                ` : ''}
                ${memberEvals.length > 0 ? `
                    <p><strong>Average Individual Score:</strong> ${(memberEvals.reduce((sum, e) => sum + (e.score || 0), 0) / memberEvals.length).toFixed(1)}/10</p>
                ` : ''}
            </div>
        </div>
    `;
    
    // Store report data globally for PDF export
    window.currentReport = report;
    
    // Open the modal
    openModal('reportModal');
}

// Teacher Evaluation
let currentEvaluationTeamId = null;

async function openEvaluationModal(teamId) {
    currentEvaluationTeamId = teamId;
    const modal = document.getElementById('evaluationModal');
    const formContainer = document.getElementById('evaluationForm');
    
    // 1. Fetch active assignments
    try {
        const assignmentsResult = await apiCall(`/api/classes/${currentClassId}/assignments`);
        const assignments = assignmentsResult.assignments || [];
        
        if (assignments.length === 0) {
            formContainer.innerHTML = '<p>No assignments available to evaluate.</p>';
            openModal('evaluationModal');
            return;
        }
        
        // 2. Fetch team members
        const membersResult = await apiCall(`/api/classes/${currentClassId}/teams/${teamId}/members`);
        const members = membersResult.members || [];
        
        // 3. Render Form
        let html = `
            <form id="teacherEvaluationForm" onsubmit="submitTeacherEvaluation(event)">
                <div class="form-group">
                    <label>Select Assignment</label>
                    <select id="evalAssignmentId" required class="form-control" style="width: 100%; padding: 8px; margin-bottom: 15px;">
                        <option value="">-- Select Assignment --</option>
                        ${assignments.map(a => `<option value="${a.id}">${a.name}</option>`).join('')}
                    </select>
                </div>
                
                <div class="evaluation-section">
                    <h3>Team Evaluation</h3>
                    <div class="form-group">
                        <label>Team Score (0-10)</label>
                        <input type="number" id="teamScore" min="0" max="10" required class="form-control" style="width: 100px;">
                    </div>
                    <div class="form-group">
                        <label>Team Comment</label>
                        <textarea id="teamComment" rows="3" class="form-control" style="width: 100%;" placeholder="General feedback for the team..."></textarea>
                    </div>
                </div>
                
                <div id="memberEvaluations">
                    <h3>Individual Evaluations</h3>
                    ${members.length === 0 ? '<p>No members in this team.</p>' : members.map(student => `
                        <div class="member-evaluation">
                            <h4>${student.name}</h4>
                            <div class="form-group">
                                <label>Score (0-10)</label>
                                <input type="number" class="member-score" data-student-id="${student.id}" min="0" max="10" required style="width: 100px;">
                            </div>
                            <div class="form-group">
                                <label>Comment</label>
                                <textarea class="member-comment" rows="2" style="width: 100%;" placeholder="Feedback for ${student.name}..."></textarea>
                            </div>
                        </div>
                    `).join('')}
                </div>
                
                <div style="margin-top: 20px; text-align: right;">
                    <button type="button" class="btn btn-secondary" onclick="closeModal('evaluationModal')">Cancel</button>
                    <button type="submit" class="btn btn-primary">Submit Evaluation</button>
                </div>
            </form>
        `;
        
        formContainer.innerHTML = html;
        openModal('evaluationModal');
        
    } catch (error) {
        console.error('Error opening evaluation modal:', error);
        showToast('Error loading evaluation form', 'error');
    }
}

async function submitTeacherEvaluation(e) {
    e.preventDefault();
    
    const assignmentId = document.getElementById('evalAssignmentId').value;
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
        assignment_id: assignmentId,
        evaluated_team_id: currentEvaluationTeamId,
        team_score: teamScore,
        team_comment: teamComment,
        member_evaluations: memberEvaluations
    };
    
    try {
        // We use the same endpoint as students, but the backend handles teacher role
        await apiCall('/api/evaluations', 'POST', evaluationData);
        showToast('Evaluation submitted successfully', 'success');
        closeModal('evaluationModal');
        
        // Refresh evaluations tab if active
        if (document.getElementById('evaluationsTab').classList.contains('active')) {
            loadEvaluations();
        }
    } catch (error) {
        console.error('Failed to submit evaluation:', error);
        showToast('Failed to submit evaluation: ' + error.message, 'error');
    }
}