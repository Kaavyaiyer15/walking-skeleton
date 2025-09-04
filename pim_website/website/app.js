let token = null;

// Utility functions
function showMessage(elementId, message, isSuccess = true) {
  const msgElement = document.getElementById(elementId);
  msgElement.textContent = message;
  msgElement.style.color = isSuccess ? "green" : "red";
}

function clearForm(formId) {
  document.getElementById(formId).reset();
}

function toggleSection(hideId, showId) {
  document.getElementById(hideId).style.display = "none";
  document.getElementById(showId).style.display = "block";
}

function formatDate(dateString) {
  return new Date(dateString).toLocaleString();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Register user
async function registerUser(event) {
  event.preventDefault();
  
  const email = document.getElementById("registerEmail").value.trim();
  const password = document.getElementById("registerPassword").value;

  if (!email || !password) {
    showMessage("registerMessage", "❌ Please fill in all fields", false);
    return;
  }

  try {
    const res = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (res.ok) {
      showMessage("registerMessage", "✅ Registered successfully!");
      clearForm("registerForm");
    } else {
      const err = await res.json();
      showMessage("registerMessage", `❌ ${err.detail}`, false);
    }
  } catch (error) {
    showMessage("registerMessage", "❌ Network error occurred", false);
    console.error("Registration error:", error);
  }
}

// Login user
async function loginUser(event) {
  event.preventDefault();
  
  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value;

  if (!email || !password) {
    showMessage("loginMessage", "❌ Please fill in all fields", false);
    return;
  }

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (res.ok) {
      const data = await res.json();
      token = data.token;

      // Update UI
      document.getElementById("userEmail").textContent = email;
      document.getElementById("authSection").style.display = "none";
      document.getElementById("notesSection").style.display = "block";
      document.getElementById("userInfo").classList.remove("hidden");

      // Clear form and load notes
      clearForm("loginForm");
      await loadNotes();
    } else {
      const err = await res.json();
      showMessage("loginMessage", `❌ ${err.detail}`, false);
    }
  } catch (error) {
    showMessage("loginMessage", "❌ Network error occurred", false);
    console.error("Login error:", error);
  }
}

// Logout user
function logout() {
  token = null;
  
  // Reset UI
  document.getElementById("authSection").style.display = "flex";
  document.getElementById("notesSection").style.display = "none";
  document.getElementById("userInfo").classList.add("hidden");
  
  // Clear any forms
  clearForm("loginForm");
  clearForm("registerForm");
  
  // Clear messages
  document.getElementById("loginMessage").textContent = "";
  document.getElementById("registerMessage").textContent = "";
}

// Load and display notes
async function loadNotes() {
  if (!token) {
    console.warn("No token available for loading notes");
    return;
  }

  const container = document.getElementById("notesContainer");
  container.innerHTML = "<p>Loading notes...</p>";

  try {
    const res = await fetch("/notes", {
      headers: { Authorization: token },
    });

    container.innerHTML = "";

    if (res.ok) {
      const data = await res.json();
      const notes = data.notes;

      if (notes.length === 0) {
        container.innerHTML = "<p>No notes yet. Add your first note!</p>";
      } else {
        // Sort notes by creation date (newest first)
        notes.sort((a, b) => new Date(b.created_time) - new Date(a.created_time));
        
        notes.forEach(note => {
          const noteDiv = document.createElement("div");
          noteDiv.className = "note-card";
          noteDiv.innerHTML = `
            <h4>${escapeHtml(note.title)}</h4>
            <p>${escapeHtml(note.body)}</p>
            <small>Created: ${formatDate(note.created_time)}</small>
          `;
          container.appendChild(noteDiv);
        });
      }
    } else if (res.status === 401) {
      // Token expired or invalid
      logout();
      showMessage("loginMessage", "❌ Session expired. Please login again.", false);
    } else {
      container.innerHTML = "<p>⚠ Failed to load notes. Please try again.</p>";
    }
  } catch (error) {
    container.innerHTML = "<p>⚠ Network error. Please check your connection.</p>";
    console.error("Load notes error:", error);
  }
}

// Show note creation form
function showNoteForm() {
  document.getElementById("noteForm").style.display = "block";
  document.getElementById("noteTitle").focus();
}

// Cancel note creation
function cancelNoteForm() {
  document.getElementById("noteTitle").value = "";
  document.getElementById("noteBody").value = "";
  document.getElementById("noteForm").style.display = "none";
}

// Save new note
async function saveNote() {
  const title = document.getElementById("noteTitle").value.trim();
  const body = document.getElementById("noteBody").value.trim();

  if (!title) {
    alert("❌ Please enter a title for your note");
    return;
  }

  if (!token) {
    alert("❌ Please login first");
    logout();
    return;
  }

  try {
    const res = await fetch("/notes", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: token,
      },
      body: JSON.stringify({ title, body }),
    });

    if (res.ok) {
      cancelNoteForm();
      await loadNotes();
    } else if (res.status === 401) {
      logout();
      alert("❌ Session expired. Please login again.");
    } else {
      const err = await res.json();
      alert(`❌ Could not save note: ${err.detail || 'Unknown error'}`);
    }
  } catch (error) {
    alert("❌ Network error. Please try again.");
    console.error("Save note error:", error);
  }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  // Attach event listeners
  document.getElementById("registerForm").addEventListener("submit", registerUser);
  document.getElementById("loginForm").addEventListener("submit", loginUser);
  
  // Add keyboard shortcuts
  document.addEventListener('keydown', function(event) {
    // Escape key to cancel note form
    if (event.key === 'Escape' && document.getElementById("noteForm").style.display === "block") {
      cancelNoteForm();
    }
  });
  
  // Auto-focus first input on page load
  const firstInput = document.querySelector('input[type="email"]');
  if (firstInput) {
    firstInput.focus();
  }
});