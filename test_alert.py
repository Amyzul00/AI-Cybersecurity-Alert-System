from log_integration import handle_security_event

if __name__ == "__main__":
    print("Triggering test security event...")
    handle_security_event("Testing email and slack integration", is_critical=True)