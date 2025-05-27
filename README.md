# Phishing Email Analysis

This repository contains a Python script to analyze phishing emails by checking sender spoofing, suspicious links, urgent language, and grammar issues.

## Files Included

- **test.py**  
  Python script that parses the raw email, extracts headers, checks for suspicious links, analyzes the email body for urgent language and grammar errors, and generates a phishing analysis report.

- **phishing_email.txt**  
  Sample phishing email text file used as input to the analysis script.

- **report.txt**  
  A formatted report summarizing the phishing characteristics found in the sample email.


## How to Run

1. Make sure you have Python 3 installed. You can download it from [python.org](https://www.python.org/downloads/) or you can just install the "Python Debugger" and "Code Runner" extension in your VS Code.

2. Place the `phishing_email.txt` and `test.py` files in the same folder.

3. Open your command prompt or terminal and navigate to the project directory.

4. Run the script with:

   ```bash
   python test.py
   ```
5. If using VS Code , you can directly run the code and the report will be displayed in VS code terminal.
6. For creating a report file in the same folder , run the script with :
   
   ```bash
   python test.py > report.txt
   ```
