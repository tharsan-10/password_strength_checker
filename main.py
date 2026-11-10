
import getpass
import re
import string

# ==========================================
# PASSWORD STRENGTH AUDITOR
# Password-Policy Compliance Checker
# ==========================================

MIN_LENGTH = 15
MAX_LENGTH = 128

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "welcome",
    "letmein",
    "iloveyou",
    "abc123",
    "111111",
    "000000"
}


# ==========================================
# 1. DETECT WEAK PASSWORD PATTERNS
# ==========================================

def detect_patterns(password):

    patterns = []
    lower_password = password.lower()

    if re.search(r"(.)\1{2,}", password):
        patterns.append("Repeated characters detected")

    sequences = [
        "123456",
        "abcdef",
        "qwerty",
        "987654",
        "654321",
        "asdfgh"
    ]

    if any(seq in lower_password for seq in sequences):
        patterns.append("Common sequence detected")

    if lower_password in COMMON_PASSWORDS:
        patterns.append("Password found in common password list")

    if re.search(r"19\d{2}|20\d{2}", password):
        patterns.append("Possible year pattern detected")

    if password.isalpha():
        patterns.append("Password contains only letters")

    if password.isdigit():
        patterns.append("Password contains only numbers")

    return patterns


# ==========================================
# 2. CALCULATE PASSWORD STRENGTH
# ==========================================

def calculate_strength(password, patterns):

    score = 0
    length = len(password)

    if length >= 15:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    else:
        score += 5

    if any(char.islower() for char in password):
        score += 10

    if any(char.isupper() for char in password):
        score += 10

    if any(char.isdigit() for char in password):
        score += 10

    if any(char in string.punctuation for char in password):
        score += 10

    if len(set(password)) >= 8:
        score += 10

    if "Password found in common password list" in patterns:
        score -= 40

    if "Repeated characters detected" in patterns:
        score -= 15

    if "Common sequence detected" in patterns:
        score -= 15

    if "Possible year pattern detected" in patterns:
        score -= 5

    return max(0, min(score, 100))


# ==========================================
# 3. CLASSIFY PASSWORD STRENGTH
# ==========================================

def classify_strength(score):

    if score >= 80:
        return "STRONG"

    elif score >= 60:
        return "MODERATE"

    elif score >= 35:
        return "WEAK"

    else:
        return "VERY WEAK"


# ==========================================
# 4. CHECK PASSWORD POLICY
# ==========================================

def check_policy(password):

    issues = []

    if len(password) < MIN_LENGTH:
        issues.append(
            f"Password must contain at least {MIN_LENGTH} characters"
        )

    if len(password) > MAX_LENGTH:
        issues.append(
            f"Password must not exceed {MAX_LENGTH} characters"
        )

    if password.lower() in COMMON_PASSWORDS:
        issues.append("Common passwords are not allowed")

    return issues


# ==========================================
# 5. GENERATE RECOMMENDATIONS
# ==========================================

def generate_recommendations(password, patterns, policy_issues):

    recommendations = []

    if len(password) < MIN_LENGTH:
        recommendations.append(
            f"Use at least {MIN_LENGTH} characters"
        )

    if "Repeated characters detected" in patterns:
        recommendations.append(
            "Avoid repeating the same character several times"
        )

    if "Common sequence detected" in patterns:
        recommendations.append(
            "Avoid predictable sequences such as 123456 or qwerty"
        )

    if "Password found in common password list" in patterns:
        recommendations.append(
            "Choose a unique password that is not commonly used"
        )

    if "Possible year pattern detected" in patterns:
        recommendations.append(
            "Avoid predictable year patterns"
        )

    if not recommendations and not policy_issues:
        recommendations.append(
            "No major issues detected by this basic auditor"
        )

    return recommendations


# ==========================================
# 6. AUDIT PASSWORD
# ==========================================

def audit_password(password):

    patterns = detect_patterns(password)

    score = calculate_strength(password, patterns)

    strength = classify_strength(score)

    policy_issues = check_policy(password)

    recommendations = generate_recommendations(
        password,
        patterns,
        policy_issues
    )

    print("\n" + "=" * 50)
    print("       PASSWORD STRENGTH AUDIT REPORT")
    print("=" * 50)

    print(f"\nPassword Length : {len(password)} characters")
    print(f"Strength Score  : {score}/100")
    print(f"Strength Level  : {strength}")

    print("\n--- Pattern Analysis ---")

    if patterns:
        for item in patterns:
            print(f"[WARNING] {item}")
    else:
        print("[OK] No listed weak patterns detected")

    print("\n--- Password Policy Compliance ---")

    if policy_issues:
        print("Status: NOT COMPLIANT")

        for issue in policy_issues:
            print(f"[FAIL] {issue}")

    else:
        print("Status: COMPLIANT")
        print("[OK] Password satisfies the configured policy")

    print("\n--- Recommendations ---")

    for recommendation in recommendations:
        print(f"- {recommendation}")

    print("\n" + "=" * 50)
    print("Note: This is an educational password auditor.")
    print("It does not guarantee resistance to password attacks.")
    print("=" * 50)


# ==========================================
# 7. MAIN PROGRAM
# ==========================================

def main():

    print("=" * 50)
    print("       PASSWORD STRENGTH AUDITOR")
    print("   PASSWORD-POLICY COMPLIANCE CHECKER")
    print("=" * 50)

    while True:

        password = getpass.getpass(
            "\nEnter a TEST password (hidden): "
        )

        if not password:
            print("Password cannot be empty.")
            continue

        audit_password(password)

        choice = input(
            "\nAudit another password? (y/n): "
        ).strip().lower()

        if choice != "y":
            print("\nThank you for using Password Auditor!")
            break


if __name__ == "__main__":
    main()
