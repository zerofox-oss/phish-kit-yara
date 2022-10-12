## phish-kit-yara

`phish-kit-yara` is a yara module (imported as `phishkit`) and pre-built docker container designed to aid in fingerprinting phishing kits. Archives and their contents are expanded in memory allowing for functions to; find specific strings, regexes, hashes, file and directory paths. This project contains an environment to allow you to quickly spin up a container with the compiled `phish-kit-yara` module and run rules within `./rules/` against any archives within `./files/`.

## Yara Functions

The module provides several additional functions to aid in fingerprinting malicious indicators or specific phishing kits. Some functions support additional flags represented as `f` and `cf`. An overview of values for these flags are defined at the bottom of this section.

- **`phishkit.has_file("file.php", f)`**  
  Return a match if the file is present within the archive.  
  If `f` is `0` the file path must be an exact match. If `f` is `1` any matching filenames will return a match regardless of which directory it is in.

- **`phishkit.has_string("string", cf)`**  
  Return a match if the provided string is present within any file in the archive.  
  `cf` should be `0` for case-sensitive matching or `1` for case-insensitive.

- **`phishkit.file_has_string("file.php", "string", f, cf)`**  
  Return a match if the specified file within the archive contains the provided string.  
   If `f` is `0` the path must be exact. If `f` is `1` the function will run on any matching filenames regardless of parent directory. `cf` should be `0` for case-sensitive matching or `1` for case-insensitive.

- **`phishkit.has_regex(/regex/)`**  
  Return a match if there are any matches for the provided regular expression within the archive.

- **`phishkit.file_has_regex("file.php", /regex/, f)`**  
  Return a match if the specified file contains a matching regex within the archive.  
  If `f` is `0` the path must be exact. If `f` is `1` the function will run on any matching filenames regardless of parent directory.

- **`phishkit.has_dir("root/subdir/", f)`**  
  Return a match if the specified directory exists within the archive.  
  If `f` is `0` the path must be exact. If `f` is `1` the path can be partial.

- **`phishkit.has_sha1("sha1hash")`**
  Return a match if the specified SHA1 hash exists within the archive.

- **`phishkit.file_has_sha1("file.php", "sha1hash", f)`**
  Return a match if the specified file has the provided SHA1 hash.
  If `f` is `0` the path must be exact. If `f` is `1` the path can be partial.

| Flag | Value | Description            | Example                           | Supported Functions                                                         |
| ---- | ----- | ---------------------- | --------------------------------- | --------------------------------------------------------------------------- |
| `f`  | `0`   | Match on exact path    | `func("root/subdir/file.php", 0)` | `has_file`, `file_has_string`, `file_has_regex`, `has_dir`, `file_has_sha1` |
| `f`  | `1`   | Match on file name     | `func("file.php", 1)`             | `has_file`, `file_has_string`, `file_has_regex`, `has_dir`, `file_has_sha1` |
| `cf` | `0`   | Case sensitive match   | `func("string", 0)`               | `has_string`, `file_has_string`                                             |
| `cf` | `1`   | Case insensitive match | `func("StRiNg", 1)`               | `has_string`, `file_has_string`                                             |

## Examples

```yara
import "phishkit"
rule example_rule
{
    meta:
        description = "Example rule"
        author = "@sysgoblin"

    condition:
        phishkit.has_file("page1.php", 0) or                                 // Match if page1.php exists
        phishkit.has_string("echo", 0) or                                    // Match if string "echo" (case-sensitive) exists anywhere
        phishkit.file_has_string("page2.php", "This is a phish!", 0, 0) or   // Match if string (case-sensitive) exists in file page2.php
        phishkit.has_regex(/\sphish\!/) or                                   // Match if regex exists anywhere
        phishkit.file_has_regex("page2.php", /\sphish\!/, 0) or              // Match if regex exists in page2.php
        phishkit.has_dir("subdir/", 0)                                       // Match if directory exists
}
```

## Contributing

Feature requests and rules wanted. Submit a PR with your rules to be merged in to `main` branch.

## Usage

1. Download `docker` and `docker compose`
2. `git clone https://github.com/zerofox-oss/phish-kit-yara.git`
3. `cd ./phish-kit-yara/`
4. `docker compose build`

and either

5. `docker compose up -d`
6. `./get_shell.sh phishkityara`  
   _(Drop yourself in a shell in the docker container)_

or

5. `docker-compose run --rm phishkityara yara rules/example.yar files/example_phish.zip`  
   _(This will auto remove the container once execution has finished)_

## Installation

If you wish to install the module and its dependencies locally you need to compile yara with the modules from source.
_(Only tested with Yara v.4.0.0)_

1. `wget https://github.com/VirusTotal/yara/archive/v4.0.0.tar.gz -O yara.tar.gz`
2. `tar -xzvf yara.tar.gz`
3. `cp ./libyara/miniz.c yara-4.0.0/libyara/miniz.c`
4. `cp ./libyara/include/yara/miniz.h yara-4.0.0/libyara/include/yara/miniz.h`
5. `cp ./libyara/modules/phishkit.c yara-4.0.0/libyara/modules/phishkit.c`
6. `cp ./libyara/modules/module_list yara-4.0.0/libyara/modules/module_list`
7. `cp ./libyara/Makefile.am yara-4.0.0/libyara/Makefile.am`
8. `cd yara-4.0.0`
9. `./bootstrap.sh`
10. `./configure --enable-cuckoo`
11. `make`
12. `make install`

More information can be found here: https://yara.readthedocs.io/en/v4.0.0/gettingstarted.html

## Thanks to

Shout out to VT for maintining the [Yara](https://github.com/VirusTotal/yara) project, richgel999 for the data compression library [miniz](https://github.com/richgel999/miniz/), and to stoerchl whose [zip](https://github.com/stoerchl/yara_zip_module) module served as the inspiration/foundation for this project.
