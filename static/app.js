// ---------------- TOGGLE LOGIN / REGISTER ----------------
function toggleForm() {
    const login = document.getElementById("loginForm");
    const register = document.getElementById("registerForm");
    const title = document.getElementById("formTitle");

    if (login.style.display === "none") {
        login.style.display = "block";
        register.style.display = "none";
        title.innerText = "Login";
    } else {
        login.style.display = "none";
        register.style.display = "block";
        title.innerText = "Register";
    }
}

// ---------------- LOGIN ----------------
function login() {
    fetch("/login", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: document.getElementById("username").value,
            password: document.getElementById("password").value
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.role === "admin" || data.role === "user") {
            window.location.href = "/";
        } else {
            document.getElementById("msg").innerText = "Invalid credentials";
        }
    });
}

// ---------------- REGISTER ----------------
function register() {
    const pass = document.getElementById("regPassword").value;
    const confirm = document.getElementById("regConfirmPassword").value;

    if (pass !== confirm) {
        document.getElementById("msg").innerText = "Passwords do not match";
        return;
    }

    fetch("/register", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: document.getElementById("regUsername").value,
            email: document.getElementById("regEmail").value,
            password: pass
        })
    })
    .then(res => res.json())
    .then(data => {
        document.getElementById("msg").innerText = data.success
            ? "Registration successful! Login now."
            : data.message;
        if (data.success) toggleForm();
    });
}

// ---------------- JOB PREDICTION + OCR ----------------
function analyzeJob() {
    const text = document.getElementById("jobText").value;
    const image = document.getElementById("imageInput").files[0];

    const formData = new FormData();
    formData.append("text", text);
    if (image) formData.append("image", image);

    fetch("/predict", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        const pred = document.getElementById("prediction");
        pred.innerText = data.result;
        pred.style.color = data.prediction === 1 ? "red" : "green";

        document.getElementById("words").innerText = data.length;

        const flags = document.getElementById("flags");
        flags.innerHTML = "";

        if (data.flags.length === 0) {
            flags.innerHTML = "<li>No suspicious indicators</li>";
        } else {
            data.flags.forEach(f => flags.innerHTML += `<li>${f}</li>`);
        }
    });
}
