# **Secure Open Source Training Repository**  

## 🛠️ **What You'll Learn**  
This repository is designed for **hands-on exercises** to help you **secure open-source projects on GitHub**. You'll learn how to:  

- **Find and fix vulnerabilities** using **CodeQL and Copilot Autofix**  
- **Detect and remove hardcoded secrets** using **GitHub Secret Scanning & Push Protection**  
- **Keep dependencies secure** with **Dependabot**  
- **Prevent unreviewed code from being merged** by enabling **branch protection**  
- **Set up responsible security reporting** with **SECURITY.md and Private Vulnerability Reporting (PVR)**  

Each section contains a **practical exercise** to apply these security best practices.  

---

## 🔒 **Hands-on Security Exercises**  

### **1. Running Code Scanning (CodeQL) & Using Copilot Autofix**  
📌 **Objective:** Use **CodeQL scanning** to detect vulnerabilities and **Copilot Autofix** to quickly fix them.  

#### **Steps**  
1. **Fork this repository** to your GitHub account.  
2. **Enable Code Scanning**:  
   - Go to **Settings > Security > Code Security > Code Scanning**.  
   - Click **Enable Default Setup** for **CodeQL Analysis**.  
   - Click **Enable CodeQL**.  
   - In the **Actions** tab, wait for the CodeQL setup to complete.  
3. **Review vulnerabilities flagged by CodeQL**:  
   - Open the **Security** tab   
   - 📝 **Note:** If, the **Security** tab is not in the main navigation bar, click the **ellipsis menu (…)** in the top-right corner and select **Security**.  
   - Click on **Code scanning alerts** to view issues.  
4. **Fix a detected vulnerability using Copilot Autofix**:  
   - Click on a detected vulnerability.  
   - Click **Generate fix**.  
   - Commit the fix to a **new branch**.  
   - Click **Commit change** to open a **pull request**.  
   - Click **Ready for review** and **Merge pull request**.  

✅ **Now, your repository has CodeQL enabled and can automatically detect vulnerabilities!**  

---

### **2. Detecting and Managing Secrets (Secret Scanning & Push Protection)**  
📌 **Objective:** Learn how to verify **Secret Scanning and Push Protection settings**, commit a secret using the GitHub UI, view secret alerts, and properly remove exposed secrets.  

#### **Steps**  

##### **1. Verify Secret Scanning & Push Protection Are Enabled**  
- Navigate to **Settings > Code security & analysis**.  
- Ensure that both **"Secret scanning"** and **"Push protection"** are enabled.  

##### **2. Commit a Secret Using the GitHub**  
- Navigate to **`config.js`** and click the **pencil (✏️) edit button**.  
- Replace the placeholder values with an [AWS secret](https://drive.google.com/file/d/1ZGOQD1YCvp_h2Qhak76fIoK_3kFLFyfi/view?usp=sharing). 
- Scroll down, enter a commit message (e.g., **"Adding AWS keys to test push protection"**), and click **Commit changes**.  

##### **3. Observe GitHub’s Behavior**  
- **If Push Protection is enabled**, GitHub will **block the commit** with a security warning.  
- If prompted, **bypass the alert** (for testing purposes).  
- If you force the commit, **Secret Scanning will detect the secret later**.  

##### **4. View Secret Scanning Alerts**  
- Go to **Security > Secret Scanning**.  
- 📝 **Note:** The **Security** tab is under the **ellipsis menu (…)** in the top-right corner.

##### **5. Respond to a Secret Scanning Alert**  
- Locate the **alert for the committed secret**.  
- Follow GitHub’s **recommended steps** to:  
  - **Revoke the exposed secret** (if applicable).  
  - **Remove it from the codebase** properly.  


#### **📌 N.B.: Revoking Secrets from the Service Provider**  
🔴 **Removing the secret from your repository does not revoke its access.** If a real AWS key (or any secret) is exposed, you must:  
1. **Go to your AWS account or the service provider** where the key was generated.  
2. **Revoke or rotate the secret** to prevent unauthorized use.  
3. **Update your application** with a new, secure secret stored safely (e.g., environment variables).
   
✅ **Now, your repository is protected against secret leaks!**  

---

### **3. Updating Dependencies (Dependabot)**  
📌 **Objective:** Use **Dependabot** to detect and update outdated dependencies.  

#### **Steps**  
1. **Enable Dependabot**:  
   - Navigate to **Security > Dependabot Alerts**.  
   - Enable **Dependabot alerts** if not already active.  
   - 📝 **Note:** The **Security** tab is under the **ellipsis menu (…)** in the top-right corner.  
2. **Check for dependency alerts**:  
   - Go to **Security > Dependabot Alerts**.  
3. **Apply Dependabot's suggested fixes**:  
   - Click on a **Dependabot security alert**.  
   - Follow instructions to **create a pull request (PR)** for the update.  
   - **Merge the PR** to apply the update.  

✅ **Now, your repository is set up to detect and fix vulnerable dependencies!**  

---

### **4. Configuring Branch Protection**  
📌 **Objective:** Set up **branch protection rules** to enforce security best practices.  

#### **Steps**  

##### **1. Navigate to Branch Protection Settings**  
- Go to **Settings > Branches**.  
- Click **"Add Rule"** under **Branch protection rules**.  
- In the **Branch name pattern** field, type `main`.  

##### **2. Enable the Following Protection Settings**  
- ✅ **Require pull requests before merging**  
- ✅ **Require at least one approval before merging**  
- ✅ **Require status checks to pass before merging**  
- ✅ **Prevent force pushes to `main`**  

##### **3. Save the Changes and Test**  
- Try making a change via the GitHub UI:  
  - Click the **pencil (✏️) edit button** on `README.md`.  
  - Make a small change and click **"Commit changes"**.  
- GitHub should **block direct commits** and suggest creating a **pull request**.  
- Click **"Create pull request"**, add a description, and submit it.  
- **Request approval** (if required) and merge the pull request.  

✅ **Now, your repository is protected against unreviewed changes!**  

---

### **5. Handling a Security Report (`SECURITY.md` & Private Vulnerability Reporting)**  
📌 **Objective:** Learn how to **set up a security policy, report, and manage vulnerabilities responsibly**.  

#### **Steps**  

##### **1. Create a Security Policy (`SECURITY.md`)**  
- Navigate to **Settings > Security > Security Policy**.  
- Click **"Set up a security policy"**.  
- Define your policy, including:  
  - **How to report security issues**  
  - **Expected response times**  
  - **Preferred contact method** (e.g., Private Vulnerability Reporting, email)  

##### **2. Enable Private Vulnerability Reporting (PVR)**  
- Go to **Settings > Security > Private Vulnerability Reporting**.  
- Click **"Enable"** to allow responsible disclosure of vulnerabilities.  

##### **3. Simulate a Security Report**  
- Navigate to **Security > Private Vulnerability Reporting**.  
- Click **"Report a Vulnerability"** and submit a sample report.  

##### **4. Apply a Security Fix & Publish a Security Advisory**  
- Fix the vulnerability in your repository.  
- Navigate to **Security > Security Advisories**.  
- Click **"New Draft Advisory"**, fill in details, and **publish** once the fix is deployed.  

✅ **Now, your repository has a structured process for handling vulnerabilities!**  

---

## **💡 Final Notes**  
- Follow each exercise **step by step**.  
- **Fix vulnerabilities** flagged by GitHub security tools.  
- Explore **GitHub’s security features** in real-time.  

**Happy Securing! 🔒**  
