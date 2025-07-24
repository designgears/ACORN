# ACORN - Nintendo Switch Multi-XCI Creator

![ACORN Banner](https://img.shields.io/badge/ACORN-Nintendo%20Switch%20Toolkit-blue)
![Python](https://img.shields.io/badge/Python-3.7%2B-green)
![License](https://img.shields.io/badge/License-MIT-green)

**ACORN** is a specialized tool for creating multi-content XCI gamecard images from Nintendo Switch content files. It packages NSP, NCA, NSZ, and NCZ files into XCI gamecard format.

## 🎯 What ACORN Does

- **Create Multi-XCI Files**: Package multiple Nintendo Switch content files into XCI gamecard images
- **Decompress Compressed Files**: Automatically handles NSZ, XCZ, and NCZ decompression during processing
- **Extract Game Metadata**: Reads game titles and metadata from CONTROL NCA files
- **Generate Proper Filenames**: Creates descriptive filenames based on game content and metadata

## 📁 File Types ACORN Works With

| File Type | What It Is |
|-----------|------------|
| **NSP** | Digital game files from the eShop |
| **XCI** | Game card backup files |
| **NCA** | Individual game content files |
| **NSZ** | Compressed NSP files (smaller size) |
| **XCZ** | Compressed XCI files (smaller size) |
| **NCZ** | Compressed NCA files (smaller size) |

## 🚀 How to Get Started

### Step 1: Install Python
Make sure you have Python 3.7 or newer installed on your computer.

### Step 2: Download ACORN
1. Download this project to your computer
2. Open a command prompt/terminal in the ACORN folder

### Step 3: Install Required Programs
```bash
pip install -r requirements.txt
```

Note: The requirements.txt includes all necessary dependencies:
- rich (for enhanced console output)
- zstandard (for NSZ/XCZ/NCZ decompression)
- pycryptodome (for NCA encryption handling)
- art (for ASCII banner display)

## 💡 How to Use ACORN

### Basic Examples

**Create XCI from multiple NSP files:**
```bash
python acorn.py game.nsp update.nsp dlc.nsp
```

**Save to a specific folder:**
```bash
python acorn.py -o C:\MyXCIs game.nsp update.nsp
```

**Use a file list:**
```bash
python acorn.py -tfile myfiles.txt
```

## 📋 Command Options

| Command | What It Does | Example |
|---------|--------------|----------|
| `python acorn.py file1 file2` | Create XCI from input files | `python acorn.py game.nsp update.nsp` |
| `-o folder` | Set output folder | `-o C:\XCIs` |
| `-tfile filename.txt` | Use a file list | `-tfile games.txt` |
| `-b number` | Set buffer size for file operations | `-b 65536` |

**Output**: ACORN always creates XCI gamecard image files as output.



## 📝 Creating a File List

To process multiple files easily, create a text file (like `games.txt`) and list your files:
```
C:\Games\MyGame.nsp
C:\Games\MyGame_Update.nsp
C:\Games\MyGame_DLC.nsp
```

## 🙏 Credits and Acknowledgments

ACORN is built using publicly available documentation and open-source libraries. This project acknowledges:

### Key Projects and Documentation
- **blawar** - For nut.py and foundational Nintendo Switch file format research
- **LucaFraga** - For hacbuild and XCI creation techniques
- **julesontheroad** - For NSC_Builder/squirrel library and compression implementations
- **[Nintendo Switch Brew XCI Documentation](https://switchbrew.org/wiki/XCI)** - Official technical specification for the XCI gamecard format

### Open Source Libraries
- **pycryptodome** - Cryptographic operations for NCA file handling
- **zstandard** - Compression/decompression for NSZ/XCZ/NCZ formats
- **rich** - Enhanced console output and formatting
- **art** - ASCII art generation for the banner

### Community Resources
- Nintendo Switch homebrew community for file format research and documentation
- Open-source implementations of Nintendo Switch file parsing techniques
- Community-developed compression standards for Nintendo Switch files

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

*ACORN is developed for educational purposes and to support legitimate backup and archival use cases.*
