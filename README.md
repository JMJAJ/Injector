# Pseudo-Injector v1.0.2

A robust DLL injection tool with comprehensive logging and multiple injection methods.

## Features

- Multiple injection methods:
  - Manual mapping
  - LoadLibrary
- Comprehensive logging system
- Real-time console feedback
- F1 hotkey for injection
- Automatic game process detection
- Configuration persistence
- Admin privileges verification

## Requirements

- Windows operating system
- Visual Studio 2019 or later
- Administrator privileges for injection

## Building

1. Open `Pseudo-Injector.sln` in Visual Studio
2. Select Release configuration and x64 platform
3. Build solution (F7)

## Usage

1. Run the injector as administrator
2. Select the launcher path if not already configured
3. Launch the game through the launcher
4. Press F1 when ready to inject
5. Check the console and `injector.log` for detailed status

## Configuration

Configuration is stored in `config.json` and includes:
- Launcher path
- Injection method preference (default: "loadLibrary")

## Logging

Detailed logs are written to:
- Console output (real-time)
- `injector.log` file (persistent)

## Version History

### v1.0.2 (Stable Release)
- Fixed configuration saving issues
  - Properly saves launcher path when selected
  - Fixed JSON pointer related issues
  - Changed config file name to config.json
  - Set default injection method to loadLibrary

### v1.0.1
- Enhanced stability and improved anti-detection
  - Fixed compilation issues with PathFindFileName
  - Improved NT syscall implementations
  - Enhanced stealth techniques
  - Added better error handling

### v1.0.0
- Implemented reliable SetWindowsHookEx-based injection
- Enhanced error handling and logging
- Improved injection success rate
- Added comprehensive logging system
- Added configuration persistence
- Added F1 hotkey injection trigger

### v0.0.1b (Initial Beta)
- Initial release with basic functionality
- Implemented manual mapping and LoadLibrary injection methods
- Added basic logging system
- Added configuration persistence

## License

This project is licensed under the MIT License - see the LICENSE file for details.
