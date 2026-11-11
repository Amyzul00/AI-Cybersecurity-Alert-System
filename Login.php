<?php
session_start();
require_once 'config.php';

$login_error = '';

// Handle Login Process for Threat Detection System
if (isset($_POST['login'])) {
    $email = trim($_POST['username']); 
    $password =$_POST['password'];

    $result =$con->query("SELECT * FROM users WHERE email = '$email'");
    if ($result &&$result->num_rows > 0) {
        $user =$result->fetch_assoc();
        if (password_verify($password,$user['password'])) {
            $_SESSION['name'] =$user['name'];
            $_SESSION['email'] =$user['email'];
            $_SESSION['role'] =$user['role'];

            if ($user['role'] === 'admin') {
                header("Location: admin_page.php");
            } else {
                header("Location: dashboard.php"); // Redirect to Threat Detection Dashboard
            }
            exit();
        }
    }
    
    $login_error = "Incorrect email or password!";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Threat Detection System - Login</title>
    <!-- Favicon -->
    <link rel="icon" type="image/png" href="./Logo_4.png">
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Font Awesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        peach: '#F8CEBA',
                        navyCard: '#030528',
                        accentMauve: '#AB8BAB',
                        accentMauveHover: '#987798',
                        inputBorder: 'rgba(255, 255, 255, 0.15)',
                        subtleText: '#9A9EB4',
                        forgotLink: '#A090BA'
                    },
                    fontFamily: {
                        montserrat: ['Montserrat', 'sans-serif'],
                        inter: ['Inter', 'sans-serif'],
                    }
                }
            }
        }
    </script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #F8CEBA;
        }
        .input-group {
            position: relative;
        }
        .input-group input:focus ~ .focus-line {
            width: 100%;
        }
        .focus-line {
            position: absolute;
            bottom: 0;
            left: 0;
            height: 2px;
            width: 0%;
            background: linear-gradient(90deg, #AB8BAB, #E2B6D5);
            transition: width 0.3s ease-in-out;
        }
        .avatar-ring {
            box-shadow: 0 0 25px rgba(171, 139, 171, 0.25);
        }
        img {
            image-rendering: -webkit-optimize-contrast;
            image-rendering: crisp-edges;
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4 sm:p-6 md:p-8">

    <!-- Notification Toast -->
    <div id="toast" class="fixed top-5 right-5 transform translate-y-[-150%] transition-transform duration-300 ease-in-out bg-emerald-600 text-white px-5 py-3 rounded-xl shadow-2xl flex items-center gap-3 z-50">
        <i class="fa-solid fa-circle-check text-xl"></i>
        <span id="toast-message" class="text-sm font-medium">Logged in successfully!</span>
    </div>

    <!-- Main Container -->
    <main class="w-full max-w-[420px]">
        <div class="bg-navyCard text-white rounded-3xl p-8 sm:p-10 shadow-2xl relative overflow-hidden flex flex-col items-center">
            
            <!-- Logo Container -->
            <div class="relative mb-6">
                <div class="w-28 h-28 sm:w-32 sm:h-32 rounded-full overflow-hidden border-2 border-white/20 avatar-ring flex items-center justify-center bg-white p-2">
                    <img 
                        src="./Logo_4.png" 
                        alt="System Logo" 
                        class="w-full h-full object-contain"
                        onerror="this.onerror=null; this.src='https://placehold.co/200x200/030528/ffffff?text=Logo';"
                    />
                </div>
            </div>

            <!-- Header Titles -->
            <h1 class="font-montserrat font-semibold tracking-wider text-xl sm:text-2xl text-white mb-1 text-center">
                THREAT MONITOR
            </h1>
            <p class="text-subtleText text-xs text-center font-light mb-6">
                AI-Based Cybersecurity & Real-Time Alert System
            </p>

            <!-- PHP Error Message Banner -->
            <?php if (!empty($login_error)): ?>
                <div class="w-full bg-rose-500/20 border border-rose-500 text-rose-300 text-xs py-2 px-3 rounded-xl mb-6 text-center">
                    <?php echo $login_error; ?>
                </div>
            <?php endif; ?>

            <!-- Login Form -->
            <form id="loginForm" action="Login.php" method="POST" onsubmit="return handleLogin(event)" class="w-full flex flex-col gap-6" novalidate>
                
                <!-- Email Input -->
                <div class="flex flex-col gap-1">
                    <div class="input-group flex items-center border-b border-inputBorder pb-2 transition-colors duration-200">
                        <i class="fa-regular fa-user text-subtleText text-sm w-6"></i>
                        <input 
                            type="text" 
                            id="username" 
                            name="username" 
                            placeholder="Analyst Email Address" 
                            required
                            class="w-full bg-transparent text-white text-sm placeholder-subtleText focus:outline-none px-2 py-1 font-light"
                            autocomplete="username"
                        />
                        <div class="focus-line"></div>
                    </div>
                    <span id="usernameError" class="text-xs text-rose-400 opacity-0 transition-opacity duration-200 pl-8">Email is required</span>
                </div>

                <!-- Password Input -->
                <div class="flex flex-col gap-1">
                    <div class="input-group flex items-center border-b border-inputBorder pb-2 transition-colors duration-200">
                        <i class="fa-solid fa-lock text-subtleText text-sm w-6"></i>
                        <input 
                            type="password" 
                            id="password" 
                            name="password" 
                            placeholder="Password" 
                            required
                            class="w-full bg-transparent text-white text-sm placeholder-subtleText focus:outline-none px-2 py-1 font-light"
                            autocomplete="current-password"
                        />
                        <button type="button" onclick="togglePasswordVisibility()" class="text-subtleText hover:text-white text-xs px-1 focus:outline-none" title="Toggle password visibility">
                            <i id="eyeIcon" class="fa-regular fa-eye-slash"></i>
                        </button>
                        <div class="focus-line"></div>
                    </div>
                    
                    <div class="flex justify-between items-center mt-1">
                        <span id="passwordError" class="text-xs text-rose-400 opacity-0 transition-opacity duration-200 pl-8">Password is required</span>
                        <a href="#" onclick="handleForgotPassword(event)" class="text-xs text-forgotLink hover:text-white transition-colors duration-200 ml-auto font-light">
                            Forgot Password?
                        </a>
                    </div>
                </div>

                <!-- Submit Button -->
                <button 
                    type="submit" 
                    name="login"
                    id="submitBtn"
                    class="w-full mt-4 bg-accentMauve hover:bg-accentMauveHover active:scale-[0.99] text-white font-medium py-3 px-6 rounded-xl transition-all duration-200 shadow-md hover:shadow-lg flex items-center justify-center gap-2 cursor-pointer"
                >
                    <span id="btnText">Sign In to Dashboard</span>
                    <i id="btnSpinner" class="fa-solid fa-circle-notch fa-spin hidden"></i>
                </button>
            </form>

            <!-- Footer Signup Link -->
            <div class="mt-8 text-center text-xs text-subtleText font-light tracking-wide">
                Need analyst access?
                <div class="mt-1">
                    <a href="./SignUp.php" class="text-white hover:text-accentMauve font-semibold tracking-wider transition-colors duration-200 text-xs">
                        REGISTER ACCOUNT
                    </a>
                </div>
            </div>

        </div>
    </main>

    <script>
        function togglePasswordVisibility() {
            const passwordInput = document.getElementById('password');
            const eyeIcon = document.getElementById('eyeIcon');
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                eyeIcon.classList.remove('fa-eye-slash');
                eyeIcon.classList.add('fa-eye');
            } else {
                passwordInput.type = 'password';
                eyeIcon.classList.remove('fa-eye');
                eyeIcon.classList.add('fa-eye-slash');
            }
        }

        function showToast(message, isError = false) {
            const toast = document.getElementById('toast');
            const toastMessage = document.getElementById('toast-message');
            toastMessage.textContent = message;
            if (isError) {
                toast.classList.remove('bg-emerald-600');
                toast.classList.add('bg-rose-600');
            } else {
                toast.classList.remove('bg-rose-600');
                toast.classList.add('bg-emerald-600');
            }
            toast.classList.remove('translate-y-[-150%]');
            toast.classList.add('translate-y-0');
            setTimeout(() => {
                toast.classList.remove('translate-y-0');
                toast.classList.add('translate-y-[-150%]');
            }, 3500);
        }

        function handleLogin(event) {
            const usernameInput = document.getElementById('username');
            const passwordInput = document.getElementById('password');
            const usernameError = document.getElementById('usernameError');
            const passwordError = document.getElementById('passwordError');
            const submitBtn = document.getElementById('submitBtn');
            const btnText = document.getElementById('btnText');
            const btnSpinner = document.getElementById('btnSpinner');

            let isValid = true;
            usernameError.style.opacity = '0';
            passwordError.style.opacity = '0';

            if (!usernameInput.value.trim()) {
                usernameError.style.opacity = '1';
                isValid = false;
            }
            if (!passwordInput.value.trim()) {
                passwordError.style.opacity = '1';
                isValid = false;
            }
            if (!isValid) {
                event.preventDefault();
                return false;
            }

            btnText.textContent = 'Authenticating...';
            btnSpinner.classList.remove('hidden');
            submitBtn.disabled = true;
            return true;
        }

        function handleForgotPassword(event) {
            event.preventDefault();
            const username = document.getElementById('username').value.trim();
            if (username) {
                showToast(`Password reset instructions sent to ${username}.`);
            } else {
                showToast('Please enter your email address first.', true);
            }
        }
    </script>
</body>
</html>