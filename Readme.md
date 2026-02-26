# UserAssistView

UserAssistView is a forensic analysis tool designed to parse and visualize the **UserAssist** Windows Registry artifact.  
It provides structured insights into user-executed programs, including execution counts, timestamps, focus metrics, digital signature status and YARA RULES

---

## Features

### UserAssist Parsing

* Parses UserAssist registry entries directly from Windows
* Automatic ROT13 / {GUID} decoding of stored paths

### Execution Metadata

* Extracts and displays:

  * **Run Count**
  * **Focus Count**
  * **Focus Time**
  * **Last Execution Time**

* Helps reconstruct user activity timelines

### Yara Rules Integration

* Includes a set of YARA rules to detect possible cheats or suspicious PE files.
* May produce false positives, so results should be manually validated.

### Digital Signature

* Verifies executable signatures and categorizes them as:

  * **Signed**
  * **Unsigned**
  * **Cheat**
  * **Fake Signature**
  * **Not Found**

---

## Data Shown Per Entry

Each UserAssist entry includes:

* Executable path
* Signature status
* Execution count
* Focus count
* Focus Time
* Last execution timestamp

## Hideable Colums

Right-click on the column header to select which column to hide.