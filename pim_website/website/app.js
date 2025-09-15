let token = null;

// Utility functions
function showMessage(elementId, message, isSuccess = true) {
  const msgElement = document.getElementById(elementId);
  if (msgElement) {
    msgElement.textContent = message;
    msgElement.style.color = isSuccess ? "green" : "red";
    msgElement.style.display = "block";
    
    // Auto-hide success messages after 3 seconds
    if (isSuccess) {
      setTimeout(() => {
        msgElement.textContent = "";
        msgElement.style.display = "none";
      }, 3000);
    }
  }
}

function clearMessage(elementId) {
  const msgElement = document.getElementById(elementId);
  if (msgElement) {
    msgElement.textContent = "";
    msgElement.style.display = "none";
  }
}

function clearForm(formId) {
  const form = document.getElementById(formId);
  if (form) {
    form.reset();
  }
}

function toggleSection(hideId, showId) {
  const hideElement = document.getElementById(hideId);
  const showElement = document.getElementById(showId);
  
  if (hideElement) hideElement.style.display = "none";
  if (showElement) showElement.style.display = "block";
}

function formatDate(dateString) {
  try {
    return new Date(dateString).toLocaleString();
  } catch (error) {
    return dateString;
  }
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Validate email format
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Register user
async function registerUser(event) {
  event.preventDefault();
  
  const emailInput = document.getElementById("registerEmail");
  const passwordInput = document.getElementById("registerPassword");
  
  if (!emailInput || !passwordInput) {
    console.error("Registration form elements not found");
    return;
  }
  
  const email = emailInput.value.trim();
  const password = passwordInput.value;

  // Clear previous messages
  clearMessage("registerMessage");

  // Validation
  if (!email || !password) {
    showMessage("registerMessage", "❌ Please fill in all fields", false);
    return;
  }

  if (!isValidEmail(email)) {
    showMessage("registerMessage", "❌ Please enter a valid email address", false);
    return;
  }

  if (password.length < 6) {
    showMessage("registerMessage", "❌ Password must be at least 6 characters long", false);
    return;
  }

  // Disable submit button during request
  const submitBtn = event.target.querySelector('button[type="submit"]');
  const originalText = submitBtn ? submitBtn.textContent : "Register";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Registering...";
  }

  try {
    const res = await fetch("/register", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();

    if (res.ok) {
      showMessage("registerMessage", "✅ Registration successful! You can now login.");
      clearForm("registerForm");
      
      // Switch to login form after successful registration
      setTimeout(() => {
        showLogin();
        const loginEmailInput = document.getElementById("loginEmail");
        if (loginEmailInput) {
          loginEmailInput.value = email;
          loginEmailInput.focus();
        }
      }, 1500);
    } else {
      showMessage("registerMessage", `❌ ${data.detail || 'Registration failed'}`, false);
    }
  } catch (error) {
    showMessage("registerMessage", "❌ Network error. Please check your connection.", false);
    console.error("Registration error:", error);
  } finally {
    // Re-enable submit button
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
    }
  }
}

// Login user
async function loginUser(event) {
  event.preventDefault();
  
  const emailInput = document.getElementById("loginEmail");
  const passwordInput = document.getElementById("loginPassword");
  
  if (!emailInput || !passwordInput) {
    console.error("Login form elements not found");
    return;
  }
  
  const email = emailInput.value.trim();
  const password = passwordInput.value;

  // Clear previous messages
  clearMessage("loginMessage");

  // Validation
  if (!email || !password) {
    showMessage("loginMessage", "❌ Please fill in all fields", false);
    return;
  }

  if (!isValidEmail(email)) {
    showMessage("loginMessage", "❌ Please enter a valid email address", false);
    return;
  }

  // Disable submit button during request
  const submitBtn = event.target.querySelector('button[type="submit"]');
  const originalText = submitBtn ? submitBtn.textContent : "Login";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Logging in...";
  }

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();

    if (res.ok && data.token) {
      token = data.token;
      
      // Store token in sessionStorage for page refresh persistence
      try {
        sessionStorage.setItem('authToken', token);
        sessionStorage.setItem('userEmail', email);
      } catch (e) {
        console.warn("Could not store token in sessionStorage:", e);
      }

      // Update UI
      const userEmailElement = document.getElementById("userEmail");
      if (userEmailElement) {
        userEmailElement.textContent = email;
      }
      
      showNotesSection();
      clearForm("loginForm");
      
      // Load notes
      await loadNotes();
      
      showMessage("loginMessage", "✅ Login successful!", true);
    } else {
      showMessage("loginMessage", `❌ ${data.detail || 'Login failed'}`, false);
    }
  } catch (error) {
    showMessage("loginMessage", "❌ Network error. Please check your connection.", false);
    console.error("Login error:", error);
  } finally {
    // Re-enable submit button
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
    }
  }
}

// Show notes section after successful login
function showNotesSection() {
  const authSection = document.getElementById("authSection");
  const notesSection = document.getElementById("notesSection");
  const userInfo = document.getElementById("userInfo");
  
  if (authSection) authSection.style.display = "none";
  if (notesSection) notesSection.style.display = "block";
  if (userInfo) userInfo.classList.remove("hidden");
}

// Show login form
function showLogin() {
  toggleSection("registerSection", "loginSection");
  clearMessage("registerMessage");
  clearMessage("loginMessage");
}

// Show register form
function showRegister() {
  toggleSection("loginSection", "registerSection");
  clearMessage("registerMessage");
  clearMessage("loginMessage");
}

// Logout user
async function logout() {
  // Call logout endpoint if token exists
  if (token) {
    try {
      await fetch("/logout", {
        method: "POST",
        headers: { 
          "Authorization": token,
          "Accept": "application/json"
        },
      });
    } catch (error) {
      console.warn("Logout request failed:", error);
    }
  }
  
  // Clear local state
  token = null;
  
  // Clear sessionStorage
  try {
    sessionStorage.removeItem('authToken');
    sessionStorage.removeItem('userEmail');
  } catch (e) {
    console.warn("Could not clear sessionStorage:", e);
  }
  
  // Reset UI
  const authSection = document.getElementById("authSection");
  const notesSection = document.getElementById("notesSection");
  const userInfo = document.getElementById("userInfo");
  
  if (authSection) authSection.style.display = "flex";
  if (notesSection) notesSection.style.display = "none";
  if (userInfo) userInfo.classList.add("hidden");
  
  // Clear forms and messages
  clearForm("loginForm");
  clearForm("registerForm");
  clearMessage("loginMessage");
  clearMessage("registerMessage");
  
  // Clear notes container
  const notesContainer = document.getElementById("notesContainer");
  if (notesContainer) {
    notesContainer.innerHTML = "";
  }
  
  // Hide note form
  const noteForm = document.getElementById("noteForm");
  if (noteForm) {
    noteForm.style.display = "none";
  }
  
  console.log("User logged out successfully");
}

// Load and display notes
async function loadNotes() {
  if (!token) {
    console.warn("No token available for loading notes");
    return;
  }

  const container = document.getElementById("notesContainer");
  if (!container) {
    console.error("Notes container not found");
    return;
  }

  container.innerHTML = "<p>Loading notes...</p>";

  try {
    const res = await fetch("/notes", {
      method: "GET",
      headers: { 
        "Authorization": token,
        "Accept": "application/json"
      },
    });

    if (res.ok) {
      const data = await res.json();
      const notes = data.notes || [];

      container.innerHTML = "";

      if (notes.length === 0) {
        container.innerHTML = `
          <div class="no-notes">
            <p>📝 No notes yet. Create your first note!</p>
          </div>
        `;
      } else {
        // Notes should already be sorted by the backend, but ensure it
        notes.sort((a, b) => new Date(b.created_time) - new Date(a.created_time));
        
        notes.forEach(note => {
          const noteDiv = document.createElement("div");
          noteDiv.className = "note-card";
          noteDiv.innerHTML = `
            <div class="note-header">
              <h4>${escapeHtml(note.title)}</h4>
            </div>
            <div class="note-body">
              <p>${escapeHtml(note.body) || '<em>No content</em>'}</p>
            </div>
            <div class="note-footer">
              <small>Created: ${formatDate(note.created_time)}</small>
              ${note.updated_time !== note.created_time ? 
                `<small>Updated: ${formatDate(note.updated_time)}</small>` : 
                ''}
            </div>
          `;
          container.appendChild(noteDiv);
        });
      }
    } else if (res.status === 401) {
      // Token expired or invalid
      console.warn("Authentication failed, logging out user");
      logout();
      showMessage("loginMessage", "❌ Session expired. Please login again.", false);
    } else {
      const errorData = await res.json().catch(() => ({}));
      container.innerHTML = `<p>⚠ Failed to load notes: ${errorData.detail || 'Unknown error'}</p>`;
    }
  } catch (error) {
    container.innerHTML = "<p>⚠ Network error. Please check your connection.</p>";
    console.error("Load notes error:", error);
  }
}

// Show note creation form
function showNoteForm() {
  const noteForm = document.getElementById("noteForm");
  const titleInput = document.getElementById("noteTitle");
  
  if (noteForm) {
    noteForm.style.display = "block";
  }
  
  if (titleInput) {
    titleInput.focus();
  }
}

// Cancel note creation
function cancelNoteForm() {
  const titleInput = document.getElementById("noteTitle");
  const bodyInput = document.getElementById("noteBody");
  const noteForm = document.getElementById("noteForm");
  
  if (titleInput) titleInput.value = "";
  if (bodyInput) bodyInput.value = "";
  if (noteForm) noteForm.style.display = "none";
}

// Save new note
async function saveNote() {
  const titleInput = document.getElementById("noteTitle");
  const bodyInput = document.getElementById("noteBody");
  
  if (!titleInput || !bodyInput) {
    console.error("Note form elements not found");
    return;
  }
  
  const title = titleInput.value.trim();
  const body = bodyInput.value.trim();

  if (!title) {
    alert("❌ Please enter a title for your note");
    titleInput.focus();
    return;
  }

  if (!token) {
    alert("❌ Please login first");
    logout();
    return;
  }

  // Find the save button more reliably
  const saveBtn = document.querySelector('button[onclick="saveNote()"]') || 
                  document.querySelector('.save-note-btn') ||
                  Array.from(document.querySelectorAll('button')).find(btn => 
                    btn.textContent.toLowerCase().includes('save'));
  
  const originalText = saveBtn ? saveBtn.textContent : "Save Note";
  
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.textContent = "Saving...";
  }

  try {
    const res = await fetch("/notes", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": token,
        "Accept": "application/json"
      },
      body: JSON.stringify({ title, body }),
    });

    if (res.ok) {
      const data = await res.json();
      console.log("Note saved successfully:", data);
      
      cancelNoteForm();
      await loadNotes();
      
      // Show success message briefly
      const container = document.getElementById("notesContainer");
      if (container && container.children.length > 0) {
        const successMsg = document.createElement("div");
        successMsg.style.cssText = "color: green; font-weight: bold; margin-bottom: 10px;";
        successMsg.textContent = "✅ Note saved successfully!";
        container.insertBefore(successMsg, container.firstChild);
        
        setTimeout(() => {
          if (successMsg.parentNode) {
            successMsg.parentNode.removeChild(successMsg);
          }
        }, 2000);
      }
    } else if (res.status === 401) {
      logout();
      alert("❌ Session expired. Please login again.");
    } else {
      const err = await res.json().catch(() => ({}));
      alert(`❌ Could not save note: ${err.detail || 'Unknown error'}`);
    }
  } catch (error) {
    alert("❌ Network error. Please try again.");
    console.error("Save note error:", error);
  } finally {
    // Re-enable save button
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = originalText;
    }
  }
}

// Check for existing session on page load
function checkExistingSession() {
  try {
    const storedToken = sessionStorage.getItem('authToken');
    const storedEmail = sessionStorage.getItem('userEmail');
    
    if (storedToken && storedEmail) {
      token = storedToken;
      
      // Update UI
      const userEmailElement = document.getElementById("userEmail");
      if (userEmailElement) {
        userEmailElement.textContent = storedEmail;
      }
      
      showNotesSection();
      loadNotes();
      
      console.log("Restored session for user:", storedEmail);
    }
  } catch (error) {
    console.warn("Could not restore session:", error);
  }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log("DOM loaded, initializing app...");
  
  // Check for existing session
  checkExistingSession();
  
  // Attach event listeners
  const registerForm = document.getElementById("registerForm");
  const loginForm = document.getElementById("loginForm");
  
  if (registerForm) {
    registerForm.addEventListener("submit", registerUser);
  } else {
    console.warn("Register form not found");
  }
  
  if (loginForm) {
    loginForm.addEventListener("submit", loginUser);
  } else {
    console.warn("Login form not found");
  }
  
  // Add keyboard shortcuts
  document.addEventListener('keydown', function(event) {
    // Escape key to cancel note form
    if (event.key === 'Escape') {
      const noteForm = document.getElementById("noteForm");
      if (noteForm && noteForm.style.display === "block") {
        cancelNoteForm();
      }
    }
    
    // Ctrl+N to create new note (when logged in)
    if (event.ctrlKey && event.key === 'n' && token) {
      event.preventDefault();
      showNoteForm();
    }
  });
  
  // Auto-focus first input on page load (only if no session exists)
  if (!token) {
    const firstInput = document.querySelector('input[type="email"]:not([style*="display: none"])');
    if (firstInput) {
      setTimeout(() => firstInput.focus(), 100);
    }
  }
  
  console.log("App initialization complete");
});

// Handle page visibility changes (optional feature)
document.addEventListener('visibilitychange', function() {
  if (!document.hidden && token) {
    // Refresh notes when page becomes visible again
    loadNotes();
  }
});

// Export functions for global access (if needed)
window.registerUser = registerUser;
window.loginUser = loginUser;
window.logout = logout;
window.loadNotes = loadNotes;
window.showNoteForm = showNoteForm;
window.cancelNoteForm = cancelNoteForm;
window.saveNote = saveNote;
window.showLogin = showLogin;
window.showRegister = showRegister;