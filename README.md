# Process-Hollowing
A demonstration of process hollowing for replacing the memory of a legitimate process with malicious code.

## Requirements
- Visual Studio 2019 or higher
- Windows SDK (for access to Windows APIs)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/nffdev/Process-Hollowing.git
   ```
2. Open the project in Visual Studio.
3. Compile the project using the `Release` or `Debug` configuration.

## Use 

1. Compile and run the application.
2. When prompted, enter the path to the legitimate target process executable (e.g., `C:\Windows\System32\svchost.exe`).
3. Enter the path to the malicious application you want to inject into the target process (e.g., `C:\Path\To\MaliciousApp.exe`).
4. The program will perform process hollowing and let you know if it was successful.

## TECHNICAL DETAILS

- **CreateProcessA**: Launches the legitimate process in a suspended state, enabling modifications before execution.  
- **GetThreadContext**: Retrieves the context of the suspended thread, including registers like `Rcx` or `Rdx`.  
- **ReadProcessMemory**: Reads the memory of the target process to retrieve the original image base address.  
- **ZwUnmapViewOfSection**: Unmaps the legitimate process's memory section to prepare for loading the malicious image.  
- **VirtualAllocEx**: Allocates memory in the target process for the malicious image.  
- **WriteProcessMemory**: Writes the malicious image (PE headers and sections) into the allocated memory in the target process.  
- **SetThreadContext**: Modifies the entry point of the target process to point to the malicious image’s entry point.  
- **ResumeThread**: Resumes the target process's primary thread, allowing execution of the malicious code.

## Resources 

- [Official Microsoft documentation on Windows APIs](https://docs.microsoft.com/en-us/windows/win32/)

## Demo

![Demo](https://raw.githubusercontent.com/nffdev/Process-Hollowing/main/demo.gif)
