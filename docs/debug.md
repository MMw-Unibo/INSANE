# How To Debug

## Debug with VSCode and gdb in Privilaged Mode

1. Install the following packages:
    ```bash
    sudo apt-get install gdbserver
    ```
3. Add the following to your `launch.json`:
    ```json
    {
        "name": "Debug",
        "type": "cppdbg",
        "request": "launch",
        "program": "${workspaceFolder}/build/your_executable",
        "args": [],
        "stopAtEntry": false,
        "cwd": "${workspaceFolder}",
        "environment": [],
        "externalConsole": false,
        "MIMode": "gdb",
        "setupCommands": [
            {
                "description": "Enable pretty-printing for gdb",
                "text": "-enable-pretty-printing",
                "ignoreFailures": true
            }
        ],
        "preLaunchTask": "build"
    }
    ```
4. Add the following to your `tasks.json`:
    ```json
    {
        "version": "2.0.0",
        "tasks": [
            {
                "label": "build",
                "type": "shell",
                "command": "./build.sh",
                "group": {
                    "kind": "build",
                    "isDefault": true
                }
            }
        ]
    }
    ```
5. Start the gdb server on the target:
    ```bash
    gdbserver :2345 your_executable
    ```
6. Start the debug session in VSCode.