<?php
session_start();
require_once 'config.php';

$register_error = '';$register_success = '';

// Handle Registration Process for Threat Detection System
if (isset($_POST['register'])) {$name = trim($_POST['fullname']);$email = trim($_POST['email']);$password = $_POST['password'];$role = 'user'; // Default analyst/user role

    $check_email =$con->query("SELECT * FROM users WHERE email = '$email'");
    if ($check_email && $check_email->num_rows > 0) {$register_error = "Email is already registered!";
    } else {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        
        $insert =$con->query("INSERT INTO users (name, email, password, role) VALUES ('$name', '$email', '$hashed_password', '$role')");
        if ($insert) {$register_success = "Account created successfully! Redirecting to login...";
            header("refresh:2;url=Login.php");
        } else {
            $register_error = "Database error: Unable to register user.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Threat Detection System - Register</title>
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
        <span id="toast-message" class="text-sm font-medium">Account created successfully!</span>
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
                ANALYST REGISTER
            </h1>
            <p class="text-subtleText text-xs text-center font-light mb-6">
                Create an account for Threat Detection & Alerts
            </p>

            <!-- PHP Error / Success Messages -->
            <?php if (!empty($register_error)): ?>
                <div class="w-full bg-rose-500/20 border border-rose-500 text-rose-300 text-xs py-2 px-3 rounded-xl mb-6 text-center">
                    <?php echo $register_error; ?>
                </div>
            <?php endif; ?>

            <?php if (!empty($register_success)): ?>
                <div class="w-full bg-emerald-500/20 border border-emerald-500 text-emerald-300 text-xs py-2 px-3 rounded-xl mb-6 text-center">
                    <?php echo $register_success; ?>
                </div>
            <?php endif; ?>

            <!-- Sign Up Form -->
            <form id="signUpForm" action="SignUp.php" method="POST" onsubmit="return handleSignUp(event)" class="w-full flex flex-col gap-5" novalidate>
                
                <!-- Full Name -->
                <div class="flex flex-col gap-1">
                    <div class="input-group flex items-center border-b border-inputBorder pb-2 transition-colors duration-200">
                        <i class="fa-regular fa-user text-subtleText text-sm w-6"></i>
                        <input 
                            type="text" 
                            id="fullname" 
                            name="fullname" 
                            placeholder="Full Name" 
                            required
                            class="w-full bg-transparent text-white text-sm placeholder-subtleText focus:outline-none px-2 py-1 font-light"
                            autocomplete="name"
                        />
                        <div class="focus-line"></div>
                    </div>
                    <span id="fullnameError" class="text-xs text-rose-400 opacity-0 transition-opacity duration-200 pl-8">Full name is required</span>
                </div>

                <!-- Email Address -->
                <div class="flex flex-col gap-1">
                    <div class="input-group flex items-center border-b border-inputBorder pb-2 transition-colors duration-200">
                        <i class="fa-regular fa-envelope text-subtleText text-sm w-6"></i>
                        <input 
                            type="email" 
                            id="email" 
                            name="email" 
                            placeholder="Analyst Email Address" 
                            required
                            class="w-full bg-transparent text-white text-sm placeholder-subtleText focus:outline-none px-2 py-1 font-light"
                            autocomplete="email"
                        />
                        <div class="focus-line"></div>
                    </div>
                    <span id="emailError" class="text-xs text-rose-400 opacity-0 transition-opacity duration-200 pl-8">Valid email is required</span>
                </div>

                <!-- Password -->
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
                            autocomplete="new-password"
                        />
                        <button type="button" onclick="togglePasswordVisibility('password', 'eyeIcon1')" class="text-subtleText hover:text-white text-xs px-1 focus:outline-none" title="Toggle password visibility">
                            <i id="eyeIcon1" class="fa-regular fa-eye-slash"></i>
                        </button>
                        <div class="focus-line"></div>
                    </div>
                    <span id="passwordError" class="text-xs text-rose-400 opacity-0 transition-opacity duration-200 pl-8">Password is required</span>
                </div>

                <!-- Confirm Password -->
                <div class="flex flex-col gap-1">
                    <div class="input-group flex items-center border-b border-inputBorder pb-2 transition-colors duration-200">
                        <i class="fa-solid fa-shield-halved text-subtleText text-sm w-6"></i>
                        <input 
                            type="password" 
                            id="confirmPassword" 
                            name="confirmPassword" 
                            placeholder="Confirm Password" 
                            required
                            class="w-full bg-transparent text-white text-sm placeholder-subtleText focus:outline-none px-2 py-1 font-light"
                            autocomplete="new-password"
                        />
                        <button type="button" onclick="togglePasswordVisibility('confirmPassword', 'eyeIcon2')" class="text-subtleText hover:text-white text-xs px-1 focus:outline-none" title="Toggle password visibility">
                            <i id="eyeIcon2" class="fa-regular fa-eye-slash"></i>
                        </button>
                        <div class="focus-line"></div>
                    </div>
                    <span id="confirmPasswordError" class="text-xs text-rose-400 opacity-0 transition-opacity duration-200 pl-8">Passwords do not match</span>
                </div>

                <!-- Submit Button -->
                <button 
                    type="submit" 
                    name="register"
                    id="submitBtn"
                    class="w-full mt-4 bg-accentMauve hover:bg-accentMauveHover active:scale-[0.99] text-white font-medium py-3 px-6 rounded-xl transition-all duration-200 shadow-md hover:shadow-lg flex items-center justify-center gap-2 cursor-pointer"
                >
                    <span id="btnText">Create Account</span>
                    <i id="btnSpinner" class="fa-solid fa-circle-notch fa-spin hidden"></i>
                </button>
            </form>

            <!-- Footer Login Link -->
            <div class="mt-8 text-center text-xs text-subtleText font-light tracking-wide">
                Already have an account?
                <div class="mt-1">
                    <a href="./Login.php" class="text-white hover:text-accentMauve font-semibold tracking-wider transition-colors duration-200 text-xs">
                        SIGN IN
                    </a>
                </div>
            </div>

        </div>
    </main>

    <script>
        function togglePasswordVisibility(inputId, eyeIconId) {
            const passwordInput = document.getElementById(inputId);
            const eyeIcon = document.getElementById(eyeIconId);